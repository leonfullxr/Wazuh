"""Initialize and supervise a private, loopback-only AI SOC deployment."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import secrets
import signal
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import IO, Any, Final
from urllib.parse import quote, urlsplit

import httpx
import psycopg
import uvicorn

from ai_soc.workspace.migrate import apply_migrations
from ai_soc.workspace.model.provider import OpenAICompatibleProvider, ProviderUnavailable
from ai_soc.workspace.partitions import ensure_partitions
from ai_soc.workspace.provision import provision_runtime_role
from ai_soc.workspace.runtime import PipelineConfig, PipelineRuntime, load_pipeline_config

_PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
_COMPOSE_FILE: Final[Path] = _PROJECT_ROOT / "docker-compose.workspace.yml"
_DEFAULT_STATE: Final[Path] = Path.home() / ".local" / "state" / "ai-soc"
_POSTGRES_USER: Final[str] = "workspace_owner"
_POSTGRES_DATABASE: Final[str] = "ai_soc_workspace"
_APP_ROLE: Final[str] = "workspace_app"
_PARTITION_HISTORY_DAYS: Final[int] = 1
_PARTITION_HORIZON_DAYS: Final[int] = 364
_LOG_BYTES: Final[int] = 5 * 1024 * 1024


class LauncherError(RuntimeError):
    """An operator-safe launcher failure."""


def _paths(state_dir: Path) -> dict[str, Path]:
    return {
        "config": state_dir / "config.json",
        "credentials": state_dir / "credentials",
        "indexer_credential": state_dir / "credentials" / "indexer.json",
        "indexer_ca": state_dir / "credentials" / "indexer-ca.pem",
        "secrets": state_dir / "secrets",
        "postgres_password": state_dir / "secrets" / "postgres-password",
        "app_password": state_dir / "secrets" / "app-password",
        "cursor_secret": state_dir / "secrets" / "cursor-secret",
        "runtime": state_dir / "runtime",
        "database_env": state_dir / "runtime" / "database.env",
        "sign_in_key": state_dir / "runtime" / "sign-in.key",
        "supervisor": state_dir / "runtime" / "supervisor.json",
        "lock": state_dir / "runtime" / "launcher.lock",
        "logs": state_dir / "logs",
        "poll_log": state_dir / "logs" / "poll.log",
        "worker_log": state_dir / "logs" / "worker.log",
        "docker_host": state_dir / "runtime" / "docker-host",
    }


def _canonical_state(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    if resolved == Path("/"):
        raise LauncherError("the state directory cannot be the filesystem root")
    return resolved


def _ensure_directory(path: Path) -> None:
    created = False
    try:
        info = path.lstat()
    except FileNotFoundError:
        try:
            path.mkdir(mode=0o700, parents=True)
            os.chmod(path, 0o700)
            info = path.lstat()
            created = True
        except OSError as exc:
            raise LauncherError("a private state directory could not be created") from exc
    except OSError as exc:
        raise LauncherError("a private state directory is unavailable") from exc
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise LauncherError("a private state path is not a directory")
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        action = "created with unsafe permissions" if created else "has unsafe permissions"
        raise LauncherError(f"private state directory {action}: {path}")


def _validate_private(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise LauncherError(f"required private file is unavailable: {path.name}") from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise LauncherError(f"private path must be a regular file: {path.name}")
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise LauncherError(f"private file must be owned by this user with mode 0600: {path.name}")


def _write_private(path: Path, content: bytes, *, replace: bool = False) -> None:
    _ensure_directory(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
    flags |= os.O_TRUNC if replace else os.O_EXCL
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        raise LauncherError(f"private file already exists: {path.name}") from None
    except OSError as exc:
        raise LauncherError(f"could not create private file: {path.name}") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        if not replace:
            path.unlink(missing_ok=True)
        raise
    os.chmod(path, 0o600)


def _read_private(path: Path, *, maximum: int = 65_536) -> bytes:
    _validate_private(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as handle:
            content = handle.read(maximum + 1)
    except OSError as exc:
        raise LauncherError(f"could not read private file: {path.name}") from exc
    if len(content) > maximum:
        raise LauncherError(f"private file exceeds its size limit: {path.name}")
    return content


def _secret(path: Path, size: int) -> bytes:
    if not path.exists():
        _write_private(path, secrets.token_bytes(size))
    value = _read_private(path, maximum=4096)
    if len(value) < size:
        raise LauncherError(f"private secret is too short: {path.name}")
    return value


def _password(path: Path) -> str:
    if not path.exists():
        _write_private(path, (secrets.token_urlsafe(32) + "\n").encode())
    try:
        value = _read_private(path, maximum=4096).decode("ascii").strip()
    except UnicodeError:
        raise LauncherError(f"private password is invalid: {path.name}") from None
    if len(value) < 32 or any(ord(character) < 33 or ord(character) > 126 for character in value):
        raise LauncherError(f"private password is invalid: {path.name}")
    return value


def _project_name(state_dir: Path) -> str:
    digest = hashlib.sha256(os.fsencode(state_dir)).hexdigest()[:12]
    return f"ai-soc-local-{digest}"


def _docker_metadata_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for name in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
        environment.pop(name, None)
    return environment


def _docker_metadata(*arguments: str) -> str:
    try:
        result = subprocess.run(
            ["docker", *arguments],
            env=_docker_metadata_environment(),
            check=True,
            text=True,
            capture_output=True,
        )
    except FileNotFoundError as exc:
        raise LauncherError("Docker Compose is required for the local database") from exc
    except subprocess.CalledProcessError as exc:
        raise LauncherError("the Docker context could not be resolved") from exc
    return result.stdout.strip()


def _validate_docker_host(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "unix"
        or parsed.netloc
        or not parsed.path.startswith("/")
        or parsed.query
        or parsed.fragment
    ):
        raise LauncherError("the local deployment requires a Unix Docker endpoint")
    socket_path = Path(parsed.path)
    try:
        info = socket_path.stat()
    except OSError as exc:
        raise LauncherError("the configured Unix Docker socket is unavailable") from exc
    if not stat.S_ISSOCK(info.st_mode):
        raise LauncherError("the configured Docker endpoint is not a Unix socket")
    return f"unix://{socket_path}"


def _resolve_docker_host() -> str:
    requested_context = os.environ.get("DOCKER_CONTEXT", "").strip()
    requested_host = os.environ.get("DOCKER_HOST", "").strip()
    if requested_context and requested_host:
        raise LauncherError("set either DOCKER_CONTEXT or DOCKER_HOST, not both")
    if requested_context:
        endpoint = _docker_metadata(
            "context",
            "inspect",
            "--format",
            "{{.Endpoints.docker.Host}}",
            requested_context,
        )
    elif requested_host:
        endpoint = requested_host
    else:
        context = _docker_metadata("context", "show")
        if not context or "\n" in context:
            raise LauncherError("the active Docker context is invalid")
        endpoint = _docker_metadata(
            "context", "inspect", "--format", "{{.Endpoints.docker.Host}}", context
        )
    return _validate_docker_host(endpoint)


def _docker_host(state_dir: Path) -> str:
    path = _paths(state_dir)["docker_host"]
    if path.exists():
        try:
            value = _read_private(path, maximum=4096).decode("ascii").strip()
        except UnicodeError:
            raise LauncherError("the recorded Docker endpoint is invalid") from None
        return _validate_docker_host(value)
    value = _resolve_docker_host()
    _write_private(path, (value + "\n").encode("ascii"))
    return value


def _compose_environment(state_dir: Path) -> dict[str, str]:
    paths = _paths(state_dir)
    environment = dict(os.environ)
    for name in tuple(environment):
        if name.startswith("COMPOSE_") or name in {
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
        }:
            environment.pop(name, None)
    environment.update(
        {
            "COMPOSE_DISABLE_ENV_FILE": "1",
            "WS_PG_DATABASE": _POSTGRES_DATABASE,
            "WS_PG_ADMIN_USER": _POSTGRES_USER,
            "WS_PG_PASSWORD_FILE": str(paths["postgres_password"]),
            "WS_PG_SECRET_FILE": str(paths["postgres_password"]),
            "WS_PG_PORT": "",
        }
    )
    return environment


def _compose(
    state_dir: Path, *arguments: str, capture: bool = False
) -> subprocess.CompletedProcess[str]:
    if not _COMPOSE_FILE.is_file():
        raise LauncherError("the workspace Compose definition is not installed")
    try:
        return subprocess.run(
            [
                "docker",
                "--host",
                _docker_host(state_dir),
                "compose",
                "--env-file",
                "/dev/null",
                "--project-name",
                _project_name(state_dir),
                "--file",
                str(_COMPOSE_FILE),
                *arguments,
            ],
            cwd=_PROJECT_ROOT,
            env=_compose_environment(state_dir),
            check=True,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
        )
    except FileNotFoundError as exc:
        raise LauncherError("Docker Compose is required for the local database") from exc
    except subprocess.CalledProcessError as exc:
        raise LauncherError("the local database operation failed") from exc


def _database_port(state_dir: Path) -> int:
    result = _compose(state_dir, "port", "postgres", "5432", capture=True)
    try:
        return int(result.stdout.strip().splitlines()[-1].rsplit(":", 1)[1])
    except (IndexError, ValueError) as exc:
        raise LauncherError("Docker did not report the local database port") from exc


def _dsn(username: str, password: str, port: int) -> str:
    return (
        f"postgresql://{quote(username)}:{quote(password)}@127.0.0.1:{port}/"
        f"{quote(_POSTGRES_DATABASE)}"
    )


def _write_database_environment(path: Path, owner_dsn: str, runtime_dsn: str) -> None:
    content = f"WS_DATABASE_URL={owner_dsn}\nWS_APP_DATABASE_URL={runtime_dsn}\n".encode()
    if path.exists():
        _validate_private(path)
        _write_private(path, content, replace=True)
    else:
        _write_private(path, content)


def _register_sites(conn: psycopg.Connection[Any], config: PipelineConfig) -> None:
    for site in config.sites:
        conn.execute("SELECT set_config('app.site_id', %s, true)", (site.site_id,))
        row = conn.execute(
            """
            INSERT INTO public.sites (site_id, label, wazuh_version) VALUES (%s, %s, %s)
            ON CONFLICT (site_id) DO UPDATE
            SET label = excluded.label, wazuh_version = excluded.wazuh_version
            WHERE sites.wazuh_version IS NULL OR sites.wazuh_version = excluded.wazuh_version
            RETURNING site_id
            """,
            (site.site_id, site.label, site.wazuh_version),
        ).fetchone()
        if row is None:
            raise LauncherError("a registered site has a different Wazuh version")


def _prepare_database(state_dir: Path, config: PipelineConfig) -> None:
    paths = _paths(state_dir)
    postgres_password = _password(paths["postgres_password"])
    app_password = _password(paths["app_password"])
    try:
        _compose(state_dir, "up", "--detach", "--wait", "postgres")
        port = _database_port(state_dir)
        owner_dsn = _dsn(_POSTGRES_USER, postgres_password, port)
        runtime_dsn = _dsn(_APP_ROLE, app_password, port)
        with psycopg.connect(owner_dsn) as conn:
            apply_migrations(conn)
            with conn.transaction():
                provision_runtime_role(conn, role=_APP_ROLE, password=app_password)
            today = datetime.now(UTC).date()
            with conn.transaction():
                _register_sites(conn, config)
                ensure_partitions(
                    conn,
                    today - timedelta(days=_PARTITION_HISTORY_DAYS),
                    today + timedelta(days=_PARTITION_HORIZON_DAYS + 1),
                )
        _write_database_environment(paths["database_env"], owner_dsn, runtime_dsn)
    except (LauncherError, OSError, psycopg.Error, ValueError, PermissionError) as exc:
        try:
            _compose(state_dir, "down")
        except LauncherError:
            pass
        if isinstance(exc, LauncherError):
            raise
        raise LauncherError(f"database preparation failed ({type(exc).__name__})") from exc


def _preflight_source(config: PipelineConfig) -> None:
    try:
        with PipelineRuntime(config, trust_env=False) as runtime:
            for site in config.sites:
                _validate_private(site.credential_file)
                runtime.resolve_site(site.site_id)
    except (OSError, ValueError, httpx.HTTPError) as exc:
        raise LauncherError(
            f"Wazuh read-only source validation failed ({type(exc).__name__})"
        ) from exc


def _ensure_private_file(path: Path, content: bytes) -> None:
    if path.exists():
        _validate_private(path)
        return
    _write_private(path, content)


def _preflight_models(config: PipelineConfig) -> None:
    for site in config.sites:
        assessment = site.lab_assessment
        if assessment is None or not assessment.enabled:
            continue
        try:
            OpenAICompatibleProvider(
                assessment.base_url, assessment.model, assessment.credential_file
            ).validate_credentials()
        except (ProviderUnavailable, ValueError) as exc:
            raise LauncherError(
                "check the assessment endpoint and private credential file"
            ) from exc


def _init(state_dir: Path) -> None:
    paths = _paths(state_dir)
    for directory in (
        state_dir,
        paths["credentials"],
        paths["secrets"],
        paths["runtime"],
        paths["logs"],
    ):
        _ensure_directory(directory)
    _ensure_private_file(
        paths["indexer_credential"],
        b'{\n  "username": "replace-with-read-only-user",\n  "password": "replace-me"\n}\n',
    )
    _ensure_private_file(
        paths["indexer_ca"],
        b"# Replace this file with the PEM CA that signs the Wazuh Indexer certificate.\n",
    )
    template: dict[str, object] = {
        "schema_version": 1,
        "database_env_file": str(paths["database_env"]),
        "sites": [
            {
                "site_id": "local",
                "label": "Local Wazuh",
                "wazuh_version": "4.14.7",
                "indexer_url": "https://127.0.0.1:9200",
                "ca_file": str(paths["indexer_ca"]),
                "credential_file": str(paths["indexer_credential"]),
                "index_pattern": "wazuh-alerts-*",
                "expected_roles": ["replace-with-dedicated-read-only-role"],
                "full_visibility_attestation": "operator-review-required",
                "context_sources": {},
                "context_history": [],
                "correlation_enabled": False,
            }
        ],
    }
    _ensure_private_file(paths["config"], (json.dumps(template, indent=2) + "\n").encode())
    _password(paths["postgres_password"])
    _password(paths["app_password"])
    _secret(paths["cursor_secret"], 32)
    print(f"Local state initialized at {state_dir}")
    print("Edit config.json and replace the two files under credentials/ before starting.")


def _load_config(state_dir: Path) -> PipelineConfig:
    path = _paths(state_dir)["config"]
    _validate_private(path)
    try:
        config = load_pipeline_config(path)
    except ValueError as exc:
        raise LauncherError("config.json is invalid") from exc
    if any("replace-with-dedicated-read-only-role" in site.expected_roles for site in config.sites):
        raise LauncherError("config.json requires the dedicated Indexer account roles")
    if any(site.full_visibility_attestation == "operator-review-required" for site in config.sites):
        raise LauncherError("config.json requires a reviewed full_visibility_attestation")
    expected = _paths(state_dir)["database_env"]
    if config.database_env_file.resolve() != expected:
        raise LauncherError("config.json must use this state directory's runtime/database.env")
    return config


def _configured_app_dsn(config: PipelineConfig) -> str:
    content = _read_private(config.database_env_file).decode("utf-8")
    for line in content.splitlines():
        if line.startswith("WS_APP_DATABASE_URL="):
            value = line.partition("=")[2]
            if value:
                return value
    raise LauncherError("the restricted database identity is unavailable")


def _open_log(path: Path) -> IO[bytes]:
    _ensure_directory(path.parent)
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    os.chmod(path, 0o600)
    return os.fdopen(descriptor, "ab", buffering=0)


class _RotatingLog:
    """Keep one private current log and one bounded previous generation."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._backup = path.with_name(path.name + ".1")
        self._handle = _open_log(path)

    def __enter__(self) -> _RotatingLog:
        return self

    def __exit__(self, *_error: object) -> None:
        self._handle.close()

    def write(self, content: bytes) -> None:
        if not content:
            return
        if len(content) > _LOG_BYTES:
            content = content[-_LOG_BYTES:]
        size = os.fstat(self._handle.fileno()).st_size
        if size + len(content) > _LOG_BYTES:
            self._rotate()
        self._handle.write(content)

    def _rotate(self) -> None:
        self._handle.close()
        if self._backup.exists():
            _validate_private(self._backup)
            self._backup.unlink()
        if self._path.exists():
            _validate_private(self._path)
            os.replace(self._path, self._backup)
            self._trim_backup()
        self._handle = _open_log(self._path)

    def _trim_backup(self) -> None:
        if self._backup.stat().st_size <= _LOG_BYTES:
            return
        descriptor = os.open(self._backup, os.O_RDWR | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "r+b", buffering=0) as handle:
            handle.seek(-_LOG_BYTES, os.SEEK_END)
            retained = handle.read(_LOG_BYTES)
            handle.seek(0)
            handle.write(retained)
            handle.truncate()
            os.fsync(handle.fileno())


def _pump_output(stream: IO[bytes], log: _RotatingLog) -> None:
    while True:
        try:
            content = os.read(stream.fileno(), 65_536)
        except OSError:
            return
        if not content:
            return
        log.write(content)


class _PeriodicProcess:
    def __init__(
        self,
        name: str,
        command: Sequence[str],
        *,
        environment: dict[str, str],
        log_path: Path,
        interval: float,
    ) -> None:
        self._name = name
        self._command = tuple(command)
        self._environment = environment
        self._log_path = log_path
        self._interval = interval
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._process: subprocess.Popen[bytes] | None = None
        self._thread = threading.Thread(target=self._run, name=f"ai-soc-{name}", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            process = self._process
        if process is not None and process.poll() is None:
            process.terminate()

    def join(self, timeout: float) -> None:
        self._thread.join(timeout)
        if self._thread.is_alive():
            with self._lock:
                process = self._process
            if process is not None and process.poll() is None:
                process.kill()
            self._thread.join(5)

    def _run(self) -> None:
        with _RotatingLog(self._log_path) as log:
            while not self._stop.is_set():
                return_code = -1
                try:
                    process = subprocess.Popen(
                        self._command,
                        cwd=_PROJECT_ROOT,
                        env=self._environment,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                    )
                    assert process.stdout is not None
                    pump = threading.Thread(
                        target=_pump_output,
                        args=(process.stdout, log),
                        name=f"ai-soc-{self._name}-log",
                        daemon=True,
                    )
                    pump.start()
                    with self._lock:
                        self._process = process
                        stopping = self._stop.is_set()
                    if stopping and process.poll() is None:
                        process.terminate()
                    return_code = process.wait()
                    pump.join(5)
                    if pump.is_alive():
                        process.stdout.close()
                        pump.join(1)
                    if return_code not in {0, -signal.SIGTERM}:
                        message = (
                            f"{datetime.now(UTC).isoformat()} {self._name} degraded "
                            f"exit={return_code}\n"
                        )
                        log.write(message.encode())
                except OSError as exc:
                    message = (
                        f"{datetime.now(UTC).isoformat()} {self._name} unavailable "
                        f"error={type(exc).__name__}\n"
                    )
                    log.write(message.encode())
                finally:
                    with self._lock:
                        self._process = None
                delay = self._interval if return_code == 0 else max(self._interval, 60)
                self._stop.wait(delay)


def _worker_environment(state_dir: Path) -> dict[str, str]:
    excluded = {
        "ws_app_database_url",
        "ws_database_url",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    }
    environment = {
        name: value for name, value in os.environ.items() if name.lower() not in excluded
    }
    environment.update(
        {
            "WS_WORKER_CONFIG": str(_paths(state_dir)["config"]),
            "WS_WORKER_ID": f"local-{_project_name(state_dir)}",
        }
    )
    return environment


def _runtime_processes(state_dir: Path) -> tuple[_PeriodicProcess, _PeriodicProcess]:
    paths = _paths(state_dir)
    environment = _worker_environment(state_dir)
    poll = _PeriodicProcess(
        "poll",
        (
            sys.executable,
            "-m",
            "ai_soc.workspace.poll",
            "--watch",
            "--interval",
            "60",
            "--reconcile",
        ),
        environment=environment,
        log_path=paths["poll_log"],
        interval=60,
    )
    worker = _PeriodicProcess(
        "worker",
        (
            sys.executable,
            "-m",
            "ai_soc.workspace.worker",
            "--watch",
            "--interval",
            "5",
            "--batch-size",
            "100",
            "--max-jobs",
            "100000",
        ),
        environment=environment,
        log_path=paths["worker_log"],
        interval=5,
    )
    return poll, worker


def _write_supervisor(path: Path, port: int) -> None:
    record = {
        "schema_version": 1,
        "pid": os.getpid(),
        "port": port,
        "started_at": datetime.now(UTC).isoformat(),
    }
    content = (json.dumps(record, sort_keys=True) + "\n").encode()
    if path.exists():
        _validate_private(path)
        _write_private(path, content, replace=True)
    else:
        _write_private(path, content)


def _pid_is_running(pid: int) -> bool:
    if pid <= 1:
        return False
    status = Path("/proc") / str(pid) / "stat"
    if status.exists():
        try:
            fields = status.read_text().split()
        except OSError:
            fields = []
        if len(fields) > 2 and fields[2] == "Z":
            return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _recorded_pid(path: Path) -> int | None:
    if not path.exists():
        return None
    try:
        value = json.loads(_read_private(path).decode())
        pid = value.get("pid")
    except (UnicodeError, json.JSONDecodeError, AttributeError):
        raise LauncherError("the supervisor record is invalid") from None
    if not isinstance(pid, int) or pid <= 1:
        raise LauncherError("the supervisor record is invalid")
    return pid


def _command_matches(pid: int, state_dir: Path) -> bool:
    command_path = Path("/proc") / str(pid) / "cmdline"
    if not command_path.exists():
        return False
    try:
        arguments = [item for item in command_path.read_bytes().split(b"\0") if item]
    except OSError:
        return False
    if not any(b"ai_soc.local.launcher" in item for item in arguments):
        return False
    configured: bytes | None = None
    for index, argument in enumerate(arguments):
        if argument == b"--state-dir" and index + 1 < len(arguments):
            configured = arguments[index + 1]
            break
        if argument.startswith(b"--state-dir="):
            configured = argument.partition(b"=")[2]
            break
    if configured is None:
        return state_dir == _DEFAULT_STATE.expanduser().resolve()
    try:
        candidate = Path(os.fsdecode(configured)).expanduser()
        if not candidate.is_absolute():
            candidate = (Path(f"/proc/{pid}/cwd").resolve() / candidate).resolve()
        else:
            candidate = candidate.resolve()
    except OSError:
        return False
    return candidate == state_dir


def _up(state_dir: Path, port: int) -> None:
    if not 1 <= port <= 65_535 or port == 80:
        raise LauncherError("choose an explicit local HTTP port between 1 and 65535, excluding 80")
    paths = _paths(state_dir)
    _ensure_directory(paths["runtime"])
    lock_descriptor = os.open(paths["lock"], os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    os.chmod(paths["lock"], 0o600)
    try:
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise LauncherError("the local supervisor is already running") from None
        existing = _recorded_pid(paths["supervisor"])
        if existing is not None and _pid_is_running(existing):
            raise LauncherError("the local supervisor is already running")
        config = _load_config(state_dir)
        _preflight_models(config)
        _preflight_source(config)
        _prepare_database(state_dir, config)
        try:
            assets = _PROJECT_ROOT / "web" / "dist"
            if not assets.is_dir():
                raise LauncherError("browser assets are missing; build web/dist before starting")
            cursor_secret = _secret(paths["cursor_secret"], 32)
            sign_in_key = secrets.token_hex(32)
            if paths["sign_in_key"].exists():
                _validate_private(paths["sign_in_key"])
                _write_private(paths["sign_in_key"], (sign_in_key + "\n").encode(), replace=True)
            else:
                _write_private(paths["sign_in_key"], (sign_in_key + "\n").encode())
            _write_supervisor(paths["supervisor"], port)

            from ai_soc.local.app import create_local_app

            app = create_local_app(
                config,
                dsn=lambda: _configured_app_dsn(config),
                origin=f"http://127.0.0.1:{port}",
                key=sign_in_key,
                secret=cursor_secret,
                assets=assets,
            )
            processes = _runtime_processes(state_dir)
            started: list[_PeriodicProcess] = []
            try:
                for process in processes:
                    process.start()
                    started.append(process)
                print(f"AI SOC is starting on http://127.0.0.1:{port}")
                print(f"The private sign-in key is stored at {paths['sign_in_key']}")
                uvicorn.run(
                    app,
                    host="127.0.0.1",
                    port=port,
                    proxy_headers=False,
                    access_log=False,
                    log_level="warning",
                )
            finally:
                for process in started:
                    process.stop()
                for process in started:
                    process.join(10)
        finally:
            paths["supervisor"].unlink(missing_ok=True)
            _compose(state_dir, "down")
    finally:
        os.close(lock_descriptor)


def _down(state_dir: Path) -> None:
    paths = _paths(state_dir)
    pid = _recorded_pid(paths["supervisor"])
    if pid is not None and _pid_is_running(pid):
        if not _command_matches(pid, state_dir):
            raise LauncherError("refusing to signal a process that is not this local supervisor")
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 20
        while _pid_is_running(pid) and time.monotonic() < deadline:
            time.sleep(0.2)
        if _pid_is_running(pid):
            os.kill(pid, signal.SIGKILL)
            deadline = time.monotonic() + 5
            while _pid_is_running(pid) and time.monotonic() < deadline:
                time.sleep(0.1)
        if _pid_is_running(pid):
            raise LauncherError("the local supervisor did not stop")
    paths["supervisor"].unlink(missing_ok=True)
    if paths["postgres_password"].exists():
        _compose(state_dir, "down")
    print("AI SOC is stopped; its database volume was preserved.")


def _add_common_options(parser: argparse.ArgumentParser, *, include_port: bool) -> None:
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=_DEFAULT_STATE,
        help=f"private deployment state (default: {_DEFAULT_STATE})",
    )
    if include_port:
        parser.add_argument("--port", type=int, default=8000)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="create private editable local configuration")
    _add_common_options(init, include_port=True)
    up = commands.add_parser("up", help="start the local database, workers, API, and UI")
    _add_common_options(up, include_port=True)
    down = commands.add_parser("down", help="stop services while preserving local data")
    _add_common_options(down, include_port=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    state_dir = _canonical_state(args.state_dir)
    try:
        if args.command == "init":
            _init(state_dir)
        elif args.command == "up":
            _up(state_dir, args.port)
        else:
            _down(state_dir)
    except (LauncherError, OSError) as exc:
        print(f"local launcher error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
