"""Transactional, checksum-verified forward SQL migration runner."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, LiteralString, cast

import psycopg
from psycopg.pq import TransactionStatus

MIGRATIONS_DIR: Final[Path] = Path(__file__).with_name("migrations")
RESERVED_MIGRATION_VERSIONS: Final[frozenset[int]] = frozenset({5, 9, 17, 18, 19})
_MIGRATION_NAME: Final[re.Pattern[str]] = re.compile(r"^(\d{4})_[a-z0-9_]+\.sql$")
_LOCK_KEY: Final[int] = 0x4159534F434D4947


class MigrationError(RuntimeError):
    """Raised when migration history is missing, edited, or invalid."""


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    path: Path
    sql: str
    sha256: str


def _require_idle(conn: psycopg.Connection[Any]) -> None:
    if conn.info.transaction_status is not TransactionStatus.IDLE:
        raise MigrationError("migration operations require an idle connection")


def _discover(migrations_dir: Path) -> list[Migration]:
    found: list[Migration] = []
    versions: set[int] = set()
    for path in sorted(migrations_dir.glob("*.sql")):
        match = _MIGRATION_NAME.fullmatch(path.name)
        if match is None:
            raise MigrationError(f"invalid migration filename: {path.name}")
        version = int(match.group(1))
        if version in versions:
            raise MigrationError(f"duplicate migration version: {version}")
        versions.add(version)
        raw = path.read_bytes()
        found.append(Migration(version, path, raw.decode("utf-8"), hashlib.sha256(raw).hexdigest()))
    for previous, current in zip(found, found[1:], strict=False):
        missing = set(range(previous.version + 1, current.version)) - RESERVED_MIGRATION_VERSIONS
        if missing:
            raise MigrationError(f"missing migration versions: {sorted(missing)}")
    return found


def _ensure_history_table(conn: psycopg.Connection[Any]) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version integer PRIMARY KEY,
            applied_at timestamptz NOT NULL DEFAULT now(),
            sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$')
        )
        """
    )


def current_version(conn: psycopg.Connection[Any]) -> int:
    """Return the greatest applied migration version, or zero for an empty DB."""
    with conn.transaction():
        with conn.cursor() as cursor:
            cursor.execute("SELECT to_regclass('schema_migrations')")
            table = cursor.fetchone()
            if table is None or table[0] is None:
                return 0
            cursor.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")
            row = cursor.fetchone()
        return 0 if row is None else int(row[0])


def _applied(conn: psycopg.Connection[Any]) -> dict[int, str]:
    with conn.cursor() as cursor:
        cursor.execute("SELECT version, sha256 FROM schema_migrations ORDER BY version")
        return {int(version): str(checksum) for version, checksum in cursor.fetchall()}


def apply_migrations(
    conn: psycopg.Connection[Any], migrations_dir: Path = MIGRATIONS_DIR
) -> list[int]:
    """Apply pending migrations, each in its own transaction, under a DB advisory lock."""
    _require_idle(conn)
    migrations = _discover(migrations_dir)
    applied_now: list[int] = []
    conn.execute("SELECT pg_advisory_lock(%s)", (_LOCK_KEY,))
    conn.commit()  # Session lock survives while each migration commits independently.
    try:
        with conn.transaction():
            _ensure_history_table(conn)
        with conn.transaction():
            existing = _applied(conn)
            known = {migration.version: migration for migration in migrations}
            unknown = sorted(set(existing) - set(known))
            if unknown:
                raise MigrationError(f"database contains unknown applied versions: {unknown}")
            highest_applied = max(existing, default=0)
            missing_records = [
                migration.version
                for migration in migrations
                if migration.version <= highest_applied and migration.version not in existing
            ]
            if missing_records:
                raise MigrationError(
                    f"database is missing applied migration records: {missing_records}"
                )
            for migration in migrations:
                recorded = existing.get(migration.version)
                if recorded is not None and recorded != migration.sha256:
                    raise MigrationError(f"applied migration {migration.version} checksum changed")
        conn.commit()  # End validation before the independently committed migration files.
        for migration in migrations:
            if migration.version in existing:
                continue
            try:
                with conn.transaction():
                    conn.execute(cast(LiteralString, migration.sql), prepare=False)
                    conn.execute(
                        "INSERT INTO schema_migrations (version, sha256) VALUES (%s, %s)",
                        (migration.version, migration.sha256),
                    )
            except psycopg.Error as exc:
                raise MigrationError(f"migration {migration.version} failed") from exc
            applied_now.append(migration.version)
    finally:
        try:
            conn.execute("SELECT pg_advisory_unlock(%s)", (_LOCK_KEY,))
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
    return applied_now


def main() -> int:
    """Apply migrations using ``WS_DATABASE_URL``."""
    import os
    import sys

    dsn = os.environ.get("WS_DATABASE_URL")
    if not dsn:
        print("WS_DATABASE_URL is required", file=sys.stderr)
        return 2
    with psycopg.connect(dsn) as conn:
        applied = apply_migrations(conn)
        print(f"applied migrations: {applied}; current version: {current_version(conn)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
