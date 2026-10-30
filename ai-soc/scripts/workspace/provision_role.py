#!/usr/bin/env python3
"""Create the restricted runtime role after schema migrations have completed."""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

import psycopg
from psycopg import sql

from ai_soc.workspace.db import RUNTIME_SEQUENCES, RUNTIME_TABLES

ROOT = Path(__file__).resolve().parents[2]
RUNTIME_FILE = ROOT / "build" / "workspace-db.env"
APP_PASSWORD_FILE = ROOT / ".secrets" / "workspace-app-password"
APP_ROLE = "workspace_app"
TABLES = RUNTIME_TABLES


class ProvisioningError(RuntimeError):
    """The existing role cannot be safely reused as the workspace runtime role."""


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


def _assert_existing_role_is_safe(conn: psycopg.Connection[Any], role: str) -> None:
    with conn.cursor() as cursor:
        cursor.execute(
            """
            SELECT
                r.rolsuper OR r.rolbypassrls OR r.rolcreatedb OR
                    r.rolcreaterole OR r.rolreplication,
                EXISTS (SELECT 1 FROM pg_auth_members AS m WHERE m.member = r.oid),
                EXISTS (SELECT 1 FROM pg_database AS d WHERE d.datdba = r.oid),
                EXISTS (SELECT 1 FROM pg_namespace AS n WHERE n.nspowner = r.oid),
                EXISTS (SELECT 1 FROM pg_class AS c WHERE c.relowner = r.oid),
                EXISTS (SELECT 1 FROM pg_proc AS p WHERE p.proowner = r.oid),
                EXISTS (SELECT 1 FROM pg_type AS t WHERE t.typowner = r.oid),
                has_database_privilege(r.oid, current_database(), 'CREATE'),
                EXISTS (
                    SELECT 1 FROM pg_namespace AS n
                    WHERE has_schema_privilege(r.oid, n.oid, 'CREATE')
                ),
                EXISTS (
                    SELECT 1 FROM pg_class AS c
                    JOIN pg_namespace AS n ON n.oid = c.relnamespace
                    WHERE c.relkind = 'S'
                      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
                      AND NOT (n.nspname = 'public' AND c.relname = ANY(%s))
                      AND (has_sequence_privilege(r.oid, c.oid, 'USAGE')
                           OR has_sequence_privilege(r.oid, c.oid, 'SELECT')
                           OR has_sequence_privilege(r.oid, c.oid, 'UPDATE'))
                ),
                EXISTS (
                    SELECT 1 FROM pg_proc AS p
                    JOIN pg_namespace AS n ON n.oid = p.pronamespace
                    WHERE p.prosecdef
                      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
                      AND has_schema_privilege(r.oid, n.oid, 'USAGE')
                      AND has_function_privilege(r.oid, p.oid, 'EXECUTE')
                ),
                EXISTS (
                    SELECT 1
                    FROM pg_class AS c
                    JOIN pg_namespace AS n ON n.oid = c.relnamespace
                    WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
                      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
                      AND (
                          has_table_privilege(r.oid, c.oid, 'SELECT')
                          OR has_table_privilege(r.oid, c.oid, 'INSERT')
                          OR has_table_privilege(r.oid, c.oid, 'UPDATE')
                          OR has_table_privilege(r.oid, c.oid, 'DELETE')
                          OR has_table_privilege(r.oid, c.oid, 'TRUNCATE')
                          OR has_table_privilege(r.oid, c.oid, 'REFERENCES')
                          OR has_table_privilege(r.oid, c.oid, 'TRIGGER')
                      )
                      AND NOT (
                          n.nspname = 'public'
                          AND ((c.relname = ANY(%s)
                                AND NOT (has_table_privilege(r.oid, c.oid, 'TRUNCATE')
                                         OR has_table_privilege(r.oid, c.oid, 'REFERENCES')
                                         OR has_table_privilege(r.oid, c.oid, 'TRIGGER')))
                               OR (c.relname = 'audit_outbox'
                                   AND NOT (has_table_privilege(r.oid, c.oid, 'DELETE')
                                            OR has_table_privilege(r.oid, c.oid, 'TRUNCATE')
                                            OR has_table_privilege(r.oid, c.oid, 'REFERENCES')
                                            OR has_table_privilege(r.oid, c.oid, 'TRIGGER'))))
                      )
                )
            FROM pg_roles AS r
            WHERE r.rolname = %s
            """,
            (list(RUNTIME_SEQUENCES), [table for table in TABLES if table != "audit_outbox"], role),
        )
        row = cursor.fetchone()
    if row is None:
        return
    names = (
        "elevated role attributes",
        "role memberships",
        "database ownership",
        "schema ownership",
        "relation ownership",
        "function ownership",
        "type ownership",
        "database CREATE privilege",
        "schema CREATE privilege",
        "unrelated sequence privileges",
        "reachable SECURITY DEFINER functions",
        "unrelated relation privileges",
    )
    unsafe = [name for name, present in zip(names, row, strict=True) if bool(present)]
    if unsafe:
        raise ProvisioningError(f"existing role has unsafe privileges: {', '.join(unsafe)}")


def main() -> int:
    owner_dsn = _runtime_dsn()
    role = os.environ.get("WS_APP_ROLE", APP_ROLE)
    password = secrets.token_urlsafe(32)
    try:
        with psycopg.connect(owner_dsn) as conn:
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (0x4159534F43524F4C,))
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,))
                exists = cursor.fetchone() is not None
            if not exists:
                conn.execute(sql.SQL("CREATE ROLE {} LOGIN").format(sql.Identifier(role)))
            else:
                _assert_existing_role_is_safe(conn, role)
            conn.execute(
                sql.SQL(
                    "ALTER ROLE {} WITH LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOREPLICATION NOBYPASSRLS PASSWORD {}"
                ).format(sql.Identifier(role), sql.Literal(password))
            )
            conn.execute(
                sql.SQL("ALTER ROLE {} SET search_path TO public").format(sql.Identifier(role))
            )
            conn.execute(
                sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                    sql.Identifier(conn.info.dbname or "ai_soc_workspace"),
                    sql.Identifier(role),
                )
            )
            conn.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(role)))
            for table in TABLES:
                privileges = (
                    "SELECT, INSERT, UPDATE"
                    if table == "audit_outbox"
                    else "SELECT, INSERT, UPDATE, DELETE"
                )
                conn.execute(
                    sql.SQL("GRANT {} ON TABLE {} TO {}").format(
                        sql.SQL(privileges), sql.Identifier(table), sql.Identifier(role)
                    )
                )
            for sequence in RUNTIME_SEQUENCES:
                conn.execute(
                    sql.SQL("GRANT USAGE, SELECT, UPDATE ON SEQUENCE {} TO {}").format(
                        sql.Identifier(sequence), sql.Identifier(role)
                    )
                )
        _write_secret(password)
        app_dsn = _app_dsn(owner_dsn, password, role)
        _write_runtime_value("WS_APP_DATABASE_URL", app_dsn)
    except (OSError, psycopg.Error, RuntimeError) as exc:
        print(f"workspace role provisioning failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print("restricted workspace_app role provisioned; credentials stored in ignored local files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
