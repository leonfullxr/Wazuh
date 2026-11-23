"""Dedicated local model scheduler, preparation worker and runtime provisioning."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import pwd
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID

import psycopg
from psycopg import sql

from ai_soc.workspace.db import RUNTIME_SEQUENCES, RUNTIME_TABLES, site_transaction
from ai_soc.workspace.model.cli_profile import CodexProfile, ProfileError
from ai_soc.workspace.model.narrate import (
    NarrativePreparationHandler,
    load_generation,
    supported_generation,
)
from ai_soc.workspace.worker import run_once

DEFAULT_STATE_DIRECTORY = Path(__file__).resolve().parents[4] / "build/model-state"


@dataclass(frozen=True, slots=True)
class ModelConfig:
    site_ids: frozenset[str]
    host_id: str
    runtime_id: str
    slot_directory: Path
    worker_id: str = "workspace-model"
    codex_path: str | None = None
    auth_path: str | None = None
    bwrap_path: str | None = None
    authority_path: Path | None = None
    state_directory: Path = DEFAULT_STATE_DIRECTORY
    authority_slot_directory: Path | None = None

    def __post_init__(self) -> None:
        if (
            not self.site_ids
            or not all(self.site_ids)
            or not self.host_id
            or not self.runtime_id
            or not self.worker_id
            or not self.slot_directory.is_absolute()
            or not self.state_directory.is_absolute()
            or any(
                path is not None and ("\x00" in path or not Path(path).is_absolute())
                for path in (self.codex_path, self.auth_path, self.bwrap_path)
            )
            or (self.authority_path is not None and not self.authority_path.is_absolute())
            or (
                self.authority_slot_directory is not None
                and (
                    not self.authority_slot_directory.is_absolute()
                    or "\x00" in str(self.authority_slot_directory)
                    or ".." in self.authority_slot_directory.parts
                    or self.authority_slot_directory == self.slot_directory
                )
            )
        ):
            raise ValueError("invalid_model_configuration")

    def codex_profile(self) -> CodexProfile:
        return CodexProfile(
            codex_path=self.codex_path or "",
            auth_path=self.auth_path or "",
            bwrap_path=self.bwrap_path or "",
            state_directory=self.state_directory,
        )

    def require_configured(self) -> None:
        if not all((self.codex_path, self.auth_path, self.bwrap_path, self.authority_path)):
            raise ValueError("model_configuration_incomplete")
        if self.authority_path != host_authority_path():
            raise PermissionError("host_authority_path_required")


def host_authority_path() -> Path:
    """Pin the authority independently of checkout configuration and HOME overrides."""
    return Path(pwd.getpwuid(os.geteuid()).pw_dir) / ".local/state/ai-soc/narrative-runtime.json"


def local_host_id() -> str:
    return hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()


def load_config(path: Path) -> ModelConfig:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("invalid_model_configuration")
    data = cast(dict[str, Any], value)
    if set(data) - {
        "site_ids",
        "host_id",
        "runtime_id",
        "slot_directory",
        "worker_id",
        "codex_path",
        "auth_path",
        "bwrap_path",
        "authority_path",
        "state_directory",
        "authority_slot_directory",
    }:
        raise ValueError("unknown_model_configuration_field")
    if not isinstance(data.get("site_ids"), list) or not all(
        isinstance(site, str) for site in cast(list[object], data["site_ids"])
    ):
        raise ValueError("invalid_model_sites")
    for key in (
        "codex_path",
        "auth_path",
        "bwrap_path",
        "authority_path",
        "state_directory",
        "authority_slot_directory",
    ):
        if key in data and (
            not isinstance(data[key], str)
            or not data[key]
            or "\x00" in data[key]
            or not Path(data[key]).is_absolute()
            or (
                key == "authority_slot_directory"
                and (data[key] != os.path.normpath(data[key]) or data[key].startswith("//"))
            )
        ):
            raise ValueError("invalid_model_configuration")
    return ModelConfig(
        frozenset(data["site_ids"]),
        str(data["host_id"]),
        str(data["runtime_id"]),
        Path(data["slot_directory"]),
        str(data.get("worker_id", "workspace-model")),
        data.get("codex_path"),
        data.get("auth_path"),
        data.get("bwrap_path"),
        Path(data["authority_path"]) if "authority_path" in data else None,
        Path(data["state_directory"]) if "state_directory" in data else DEFAULT_STATE_DIRECTORY,
        Path(data["authority_slot_directory"]) if "authority_slot_directory" in data else None,
    )


class PhysicalSlot:
    """A shared open-file-description lock; release by closing, never LOCK_UN."""

    def __init__(self, fd: int, legacy_fd: int):
        self.fd = fd
        self.legacy_fd = legacy_fd

    def close(self) -> None:
        if self.legacy_fd >= 0:
            os.close(self.legacy_fd)
            self.legacy_fd = -1
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> PhysicalSlot:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def protected_directory(path: Path) -> os.stat_result:
    if path != path.resolve():
        raise PermissionError("slot_directory_must_be_canonical")
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise PermissionError("slot_directory_must_be_private")
    return info


def _verify_slot_file(directory_fd: int, fd: int) -> None:
    info = os.fstat(fd)
    try:
        entry = os.stat("slot-0.lock", dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        raise PermissionError("slot_file_changed") from None
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
        or info.st_nlink != 1
        or not os.path.samestat(info, entry)
    ):
        raise PermissionError("slot_file_changed")


def acquire_slot(directory: Path, *, create: bool = True) -> PhysicalSlot | None:
    expected = protected_directory(directory)
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    fd = -1
    flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        info = os.fstat(directory_fd)
        if not os.path.samestat(info, expected):
            raise PermissionError("slot_directory_changed")
        try:
            fcntl.flock(directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fd = os.open(
                "slot-0.lock", flags | (os.O_CREAT if create else 0), 0o600, dir_fd=directory_fd
            )
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            if fd >= 0:
                os.close(fd)
            os.close(directory_fd)
            return None
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise PermissionError("slot_file_must_be_private")
        _verify_slot_file(directory_fd, fd)
        if not os.path.samestat(os.fstat(directory_fd), protected_directory(directory)):
            raise PermissionError("slot_directory_changed")
        return PhysicalSlot(directory_fd, fd)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        os.close(directory_fd)
        raise


def authority_material(config: ModelConfig, info: os.stat_result) -> bytes:
    return json.dumps(
        {
            "host_id": config.host_id,
            "runtime_id": config.runtime_id,
            "slot_directory": str(config.authority_slot_directory or config.slot_directory),
            "device": info.st_dev,
            "inode": info.st_ino,
        },
        sort_keys=True,
    ).encode()


def _authority_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def verify_authority(config: ModelConfig, info: os.stat_result) -> None:
    assert config.authority_path is not None
    path = config.authority_path

    alias_observed = False

    def check_alias() -> None:
        nonlocal alias_observed
        alias = config.authority_slot_directory
        if alias is not None:
            try:
                canonical = protected_directory(config.slot_directory)
                target = alias.stat()
                alias_observed = True
                resolved = alias.resolve(strict=True)
            except FileNotFoundError:
                if alias_observed:
                    raise PermissionError("authority_slot_directory_changed") from None
                raise
            if (
                resolved != config.slot_directory
                or (canonical.st_dev, canonical.st_ino) != (info.st_dev, info.st_ino)
                or (target.st_dev, target.st_ino) != (info.st_dev, info.st_ino)
            ):
                raise PermissionError("authority_slot_directory_changed")

    check_alias()
    locator = path.parent.resolve(strict=True) / path.name
    observed = _authority_identity(path.lstat())

    def locator_changed() -> bool:
        try:
            return (
                path.parent.resolve(strict=True) / path.name != locator
                or _authority_identity(path.lstat()) != observed
            )
        except FileNotFoundError:
            return True

    if locator_changed():
        raise PermissionError("host_authority_changed")
    if not stat.S_ISREG(observed[3]):
        raise PermissionError("host_runtime_already_bound")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        reason = "host_authority_changed" if locator_changed() else "host_runtime_already_bound"
        raise PermissionError(reason) from None
    try:
        meta = os.fstat(fd)
        if _authority_identity(meta) != observed:
            raise PermissionError("host_authority_changed")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            material = stream.read(4097)
        check_alias()
        if locator_changed() or _authority_identity(os.fstat(fd)) != observed:
            raise PermissionError("host_authority_changed")
        if (
            meta.st_uid != os.geteuid()
            or meta.st_mode & 0o077
            or material != authority_material(config, info)
        ):
            raise PermissionError("host_runtime_already_bound")
    finally:
        os.close(fd)


def _acquire_model_slot(config: ModelConfig) -> PhysicalSlot | None:
    if config.authority_slot_directory is not None:
        return acquire_slot(config.slot_directory, create=False)
    return acquire_slot(config.slot_directory)


def verify_binding(
    conn: psycopg.Connection[Any], config: ModelConfig, site_id: str, *, slot_fd: int | None = None
) -> None:
    config.require_configured()
    if config.host_id != local_host_id():
        raise PermissionError("configured_host_is_not_local")
    info = protected_directory(config.slot_directory)
    if slot_fd is not None and not os.path.samestat(info, os.fstat(slot_fd)):
        raise PermissionError("slot_directory_changed")
    verify_authority(config, info)
    if slot_fd is not None and not os.path.samestat(
        os.fstat(slot_fd), protected_directory(config.slot_directory)
    ):
        raise PermissionError("slot_directory_changed")
    row = conn.execute(
        "SELECT host_id,runtime_id,slot_directory,directory_device,directory_inode,"
        "slot_count FROM narrative_runtime_bindings WHERE site_id=%s",
        (site_id,),
    ).fetchone()
    expected = (
        config.host_id,
        config.runtime_id,
        str(config.slot_directory),
        info.st_dev,
        info.st_ino,
        1,
    )
    if row != expected:
        raise PermissionError("runtime_binding_not_provisioned_or_changed")


def provision_binding(conn: psycopg.Connection[Any], config: ModelConfig, *, now: datetime) -> None:
    config.require_configured()
    if config.host_id != local_host_id():
        raise PermissionError("configured_host_is_not_local")
    if config.authority_slot_directory is None:
        config.slot_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    slot = _acquire_model_slot(config)
    if slot is None:
        raise PermissionError("slot_busy")
    with slot:
        _provision_binding_locked(conn, config, now=now, slot=slot)


def _provision_binding_locked(
    conn: psycopg.Connection[Any], config: ModelConfig, *, now: datetime, slot: PhysicalSlot
) -> None:
    info = protected_directory(config.slot_directory)
    if not os.path.samestat(info, os.fstat(slot.fd)):
        raise PermissionError("slot_directory_changed")
    # A host manifest prevents other databases and checkouts inventing a second slot.
    assert config.authority_path is not None
    manifest_path = config.authority_path
    if config.authority_slot_directory is not None:
        verify_authority(config, info)
    else:
        manifest_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        material = authority_material(config, info)
        try:
            fd = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        except FileExistsError:
            verify_authority(config, info)
        else:
            with os.fdopen(fd, "wb") as stream:
                stream.write(material)
                stream.flush()
                os.fsync(stream.fileno())
    if not os.path.samestat(os.fstat(slot.fd), protected_directory(config.slot_directory)):
        raise PermissionError("slot_directory_changed")
    _verify_slot_file(slot.fd, slot.legacy_fd)
    for site_id in sorted(config.site_ids):
        with site_transaction(conn, site_id, config.site_ids):
            prior = conn.execute(
                "SELECT 1 FROM narrative_runtime_bindings WHERE site_id=%s", (site_id,)
            ).fetchone()
            if prior is None:
                conn.execute(
                    "INSERT INTO narrative_runtime_bindings(site_id,host_id,runtime_id,"
                    "slot_directory,directory_device,directory_inode,slot_count,provisioned_at)"
                    " VALUES (%s,%s,%s,%s,%s,%s,1,%s)",
                    (
                        site_id,
                        config.host_id,
                        config.runtime_id,
                        str(config.slot_directory),
                        info.st_dev,
                        info.st_ino,
                        now,
                    ),
                )
            verify_binding(conn, config, site_id, slot_fd=slot.fd)


def provision_model_role(conn: psycopg.Connection[Any], role: str) -> None:
    """Provision table grants only; no account credentials are loaded or modified."""
    existing = conn.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,)).fetchone()
    if existing is None:
        conn.execute(
            sql.SQL(
                "CREATE ROLE {} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE NOREPLICATION NOBYPASSRLS"
            ).format(sql.Identifier(role))
        )
    else:
        from ai_soc.workspace.db import (
            _validate_runtime_role,  # pyright: ignore[reportPrivateUsage]
        )

        # Provisioning an existing role must not silently make an elevated identity acceptable.
        conn.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(role)))
        _validate_runtime_role(conn)
        conn.execute("RESET ROLE")
    for table in RUNTIME_TABLES:
        conn.execute(
            sql.SQL("REVOKE ALL ON {} FROM {}").format(sql.Identifier(table), sql.Identifier(role))
        )
        conn.execute(
            sql.SQL("GRANT SELECT ON {} TO {}").format(sql.Identifier(table), sql.Identifier(role))
        )
    for table in (
        "narrative_generations",
        "narrative_calls",
        "narrative_outcomes",
        "narrative_runtime_bindings",
    ):
        conn.execute(
            sql.SQL("GRANT INSERT ON {} TO {}").format(sql.Identifier(table), sql.Identifier(role))
        )
    for table in ("jobs", "incident_narrative_heads"):
        conn.execute(
            sql.SQL("GRANT INSERT,UPDATE ON {} TO {}").format(
                sql.Identifier(table), sql.Identifier(role)
            )
        )
    conn.execute(sql.SQL("GRANT INSERT ON audit_outbox TO {}").format(sql.Identifier(role)))
    conn.execute(
        sql.SQL("GRANT UPDATE(incident_id) ON incidents TO {}").format(sql.Identifier(role))
    )
    conn.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(role)))
    for sequence in RUNTIME_SEQUENCES:
        conn.execute(
            sql.SQL("REVOKE ALL ON SEQUENCE {} FROM {}").format(
                sql.Identifier(sequence), sql.Identifier(role)
            )
        )
    conn.execute(
        sql.SQL("GRANT USAGE ON SEQUENCE jobs_job_id_seq TO {}").format(sql.Identifier(role))
    )
    conn.execute(sql.SQL("ALTER ROLE {} SET search_path TO public").format(sql.Identifier(role)))


def model_status(
    conn: psycopg.Connection[Any], config: ModelConfig, profile: CodexProfile | None = None
) -> dict[str, object]:
    profile = profile if profile is not None else config.codex_profile()
    counts = {"queued": 0, "deferred": 0, "running": 0, "dead": 0, "done": 0, "blocked": 0}
    unavailable_reason: str | None = None
    try:
        profile.verify_runtime()
    except ProfileError as exc:
        unavailable_reason = str(exc)
    now = datetime.now(UTC)
    for site_id in sorted(config.site_ids):
        with site_transaction(conn, site_id, config.site_ids):
            verify_binding(conn, config, site_id)
            rows = conn.execute(
                "SELECT state,run_after,payload FROM jobs WHERE site_id=%s AND kind='narrate'",
                (site_id,),
            ).fetchall()
            for state, run_after, payload in rows:
                key = "deferred" if state == "queued" and run_after > now else str(state)
                counts[key] += 1
                if state == "queued":
                    generation = load_generation(
                        conn, site_id=site_id, generation_id=UUID(str(payload["generation_id"]))
                    )
                    if unavailable_reason is not None or not supported_generation(
                        generation, profile
                    ):
                        counts["blocked"] += 1
    slot = _acquire_model_slot(config)
    held = slot is None
    if slot is not None:
        slot.close()
    # Availability here is observed executable/catalog metadata, never an account probe.
    return {
        **counts,
        "slot_held": held,
        "provider_observed_available": unavailable_reason is None,
        "provider_unavailable_reason": unavailable_reason,
    }


def run_model_once(
    conn: psycopg.Connection[Any],
    *,
    config: ModelConfig,
    config_path: Path,
    dsn: str | None = None,
    wait: bool = True,
) -> int:
    """Acquire before admission; guardian inherits ownership and performs the DB claim."""
    config.require_configured()
    slot = _acquire_model_slot(config)
    if slot is None:
        return 0
    try:
        for site_id in sorted(config.site_ids):
            with site_transaction(conn, site_id, config.site_ids):
                verify_binding(conn, config, site_id, slot_fd=slot.fd)
        env = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "PYTHONPATH": os.pathsep.join(sys.path),
            "WS_MODEL_DATABASE_URL": dsn or conn.info.dsn,
        }
        child = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "ai_soc.workspace.model.guardian",
                "--config",
                str(config_path),
                "--slot-fd",
                str(slot.fd),
                "--legacy-slot-fd",
                str(slot.legacy_fd),
            ],
            pass_fds=(slot.fd, slot.legacy_fd),
            close_fds=True,
            start_new_session=True,
            env=env,
        )
    finally:
        # The child and each cost-capable descendant retain the same open file description.
        slot.close()
    if wait:
        code = child.wait()
        if code not in (0, 3):
            raise RuntimeError("narrative_guardian_failed")
        return 1 if code == 0 else 0
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "drain", "watch", "status", "provision"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--max-jobs", type=int, default=100)
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    parser.add_argument("--role", help="owner-only model role grant provisioning")
    args = parser.parse_args()
    if not 1 <= args.max_jobs <= 100000:
        parser.error("--max-jobs must be in 1..100000")
    if not 1 <= args.poll_seconds <= 300:
        parser.error("--poll-seconds must be in 1..300")
    config = load_config(args.config)
    config.require_configured()
    dsn = os.environ.get("WS_MODEL_DATABASE_URL")
    if not dsn:
        parser.error("WS_MODEL_DATABASE_URL is required")
    with psycopg.connect(dsn) as conn:
        if args.command == "provision":
            if args.role:
                with conn.transaction():
                    provision_model_role(conn, args.role)
            else:
                provision_binding(conn, config, now=datetime.now(UTC))
            print("provisioned")
        elif args.command == "status":
            print(json.dumps(model_status(conn, config), sort_keys=True))
        else:
            while True:
                count = 0
                for _ in range(args.max_jobs):
                    prepared = run_once(
                        conn,
                        worker_id=config.worker_id,
                        site_ids=config.site_ids,
                        handler=NarrativePreparationHandler(profile=config.codex_profile()),
                        batch_size=1,
                    )
                    count += prepared
                    if args.command == "prepare":
                        if not prepared:
                            break
                    else:
                        called = run_model_once(
                            conn, config=config, config_path=args.config, dsn=dsn
                        )
                        count += called
                        if not prepared and not called:
                            break
                print(f"processed={count}", flush=True)
                if args.command != "watch":
                    break
                time.sleep(args.poll_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
