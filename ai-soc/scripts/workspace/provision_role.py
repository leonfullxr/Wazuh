#!/usr/bin/env python3
"""Create the restricted runtime role after schema migrations have completed."""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit

import psycopg

from ai_soc.workspace.provision import provision_runtime_role

ROOT = Path(__file__).resolve().parents[2]
RUNTIME_FILE = ROOT / "build" / "workspace-db.env"
APP_PASSWORD_FILE = ROOT / ".secrets" / "workspace-app-password"
APP_ROLE = "workspace_app"


def _runtime_dsn() -> str:
    if "WS_DATABASE_URL" in os.environ:
        return os.environ["WS_DATABASE_URL"]
    runtime_file = Path(os.environ.get("WS_WORKSPACE_RUNTIME_FILE", RUNTIME_FILE))
    if not runtime_file.exists():
        raise RuntimeError("run `make ws-db-up` first")
    for line in runtime_file.read_text(encoding="utf-8").splitlines():
        if line.startswith("WS_DATABASE_URL="):
            return line.partition("=")[2]
    raise RuntimeError("workspace database URL is missing")


def _password_file() -> Path:
    return Path(os.environ.get("WS_APP_PASSWORD_FILE", APP_PASSWORD_FILE))


def _runtime_file() -> Path:
    return Path(os.environ.get("WS_WORKSPACE_RUNTIME_FILE", RUNTIME_FILE))


def _write_secret(password: str) -> None:
    secret_file = _password_file()
    secret_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(secret_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as secret_file:
        secret_file.write(password)
    os.chmod(_password_file(), 0o600)


def _app_dsn(owner_dsn: str, password: str, role: str) -> str:
    parsed = urlsplit(owner_dsn)
    if not parsed.hostname:
        raise RuntimeError("workspace database URL must include a host")
    host = parsed.hostname
    if parsed.port:
        host = f"{host}:{parsed.port}"
    netloc = f"{quote(role)}:{quote(password)}@{host}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def _write_runtime_value(key: str, value: str) -> None:
    existing: list[str] = []
    runtime_file = _runtime_file()
    runtime_file.parent.mkdir(parents=True, exist_ok=True)
    if runtime_file.exists():
        existing = [
            line
            for line in runtime_file.read_text(encoding="utf-8").splitlines()
            if not line.startswith(f"{key}=")
        ]
    existing.append(f"{key}={value}")
    runtime_file.write_text("\n".join(existing) + "\n", encoding="utf-8")
    os.chmod(runtime_file, 0o600)


def main() -> int:
    owner_dsn = _runtime_dsn()
    role = os.environ.get("WS_APP_ROLE", APP_ROLE)
    password = secrets.token_urlsafe(32)
    try:
        with psycopg.connect(owner_dsn) as conn:
            provision_runtime_role(conn, role=role, password=password)
        _write_secret(password)
        app_dsn = _app_dsn(owner_dsn, password, role)
        _write_runtime_value("WS_APP_DATABASE_URL", app_dsn)
    except (OSError, psycopg.Error, RuntimeError) as exc:
        print(f"workspace role provisioning failed: {type(exc).__name__}", file=sys.stderr)
        return 2
    print("restricted workspace_app role provisioned; credentials stored in ignored local files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
