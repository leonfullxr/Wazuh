#!/usr/bin/env python3
"""Manage this checkout's isolated local workspace Postgres instance."""

from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "docker-compose.workspace.yml"
SECRET_DIR = ROOT / ".secrets"
PASSWORD_FILE = SECRET_DIR / "workspace-pg-password"
ENV_FILE = ROOT / ".env.workspace"
RUNTIME_FILE = ROOT / "build" / "workspace-db.env"


def project_name() -> str:
    digest = hashlib.sha256(str(ROOT).encode()).hexdigest()[:10]
    base = "".join(character.lower() if character.isalnum() else "-" for character in ROOT.name)
    return f"ws-{base[:20]}-{digest}"


def _env_file_values() -> dict[str, str]:
    values: dict[str, str] = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            values[key.strip()] = value.strip().strip("\"'")
    return values


def _ensure_secret() -> None:
    SECRET_DIR.mkdir(mode=0o700, exist_ok=True)
    if not PASSWORD_FILE.exists():
        descriptor = os.open(PASSWORD_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as secret_file:
            secret_file.write(secrets.token_urlsafe(32))
    os.chmod(PASSWORD_FILE, 0o600)


def _compose_env() -> dict[str, str]:
    values = _env_file_values()
    password_path = Path(values.get("WS_PG_PASSWORD_FILE", str(PASSWORD_FILE)))
    if not password_path.is_absolute():
        password_path = ROOT / password_path
    if password_path == PASSWORD_FILE:
        _ensure_secret()
    if not password_path.is_file():
        raise RuntimeError("workspace Postgres password file is missing")
    return {
        **os.environ,
        **values,
        "WS_PG_PASSWORD_FILE": str(password_path),
        "WS_PG_SECRET_FILE": str(password_path),
    }


def _run_compose(*arguments: str, capture: bool = False) -> subprocess.CompletedProcess[str]:
    command = ["docker", "compose", "--project-name", project_name(), "-f", str(COMPOSE)]
    if ENV_FILE.exists():
        command.extend(["--env-file", str(ENV_FILE)])
    command.extend(arguments)
    return subprocess.run(
        command,
        cwd=ROOT,
        env=_compose_env(),
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
    )


def _port() -> int:
    result = _run_compose("port", "postgres", "5432", capture=True)
    address = result.stdout.strip().splitlines()[-1]
    return int(address.rsplit(":", 1)[1])


def up() -> None:
    _run_compose("up", "-d", "--wait", "postgres")
    port = _port()
    values = _env_file_values()
    database = values.get("WS_PG_DATABASE", "ai_soc_workspace")
    username = values.get("WS_PG_ADMIN_USER", "workspace_owner")
    password = _compose_env()["WS_PG_PASSWORD_FILE"]
    secret = Path(password).read_text(encoding="utf-8").strip()
    from urllib.parse import quote

    dsn = f"postgresql://{quote(username)}:{quote(secret)}@127.0.0.1:{port}/{quote(database)}"
    RUNTIME_FILE.parent.mkdir(parents=True, exist_ok=True)
    RUNTIME_FILE.write_text(f"WS_DATABASE_URL={dsn}\nWS_PG_PORT={port}\n", encoding="utf-8")
    os.chmod(RUNTIME_FILE, 0o600)
    print(f"workspace Postgres is ready on 127.0.0.1:{port}")


def down() -> None:
    _run_compose("down")


def migrate() -> None:
    if not RUNTIME_FILE.exists():
        raise RuntimeError("run `make ws-db-up` first")
    env = os.environ.copy()
    for line in RUNTIME_FILE.read_text(encoding="utf-8").splitlines():
        key, value = line.split("=", 1)
        env[key] = value
    result = subprocess.run(
        ["uv", "run", "--locked", "python", "-m", "ai_soc.workspace.migrate"],
        cwd=ROOT,
        env=env,
        check=False,
    )
    if result.returncode:
        raise RuntimeError("workspace migration command failed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("up", "down", "port", "migrate"))
    args = parser.parse_args()
    try:
        if args.command == "up":
            up()
        elif args.command == "down":
            down()
        elif args.command == "port":
            print(_port())
        else:
            migrate()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"workspace database error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
