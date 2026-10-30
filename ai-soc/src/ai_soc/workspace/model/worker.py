"""Dedicated local model scheduler, preparation worker and runtime provisioning."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
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

DEFAULT_SLOT_DIRECTORY = Path.home() / ".local/state/ai-soc/narrative-slot"


@dataclass(frozen=True, slots=True)
class ModelConfig:
    site_ids: frozenset[str]
    host_id: str
    runtime_id: str
    slot_directory: Path
    worker_id: str = "workspace-model"

    def __post_init__(self) -> None:
        if (
            not self.site_ids
            or not all(self.site_ids)
            or not self.host_id
            or not self.runtime_id
            or not self.worker_id
            or not self.slot_directory.is_absolute()
        ):
            raise ValueError("invalid_model_configuration")


def local_host_id() -> str:
    return hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()


def load_config(path: Path) -> ModelConfig:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("invalid_model_configuration")
    data = cast(dict[str, Any], value)
    if set(data) - {"site_ids", "host_id", "runtime_id", "slot_directory", "worker_id"}:
        raise ValueError("unknown_model_configuration_field")
    if not isinstance(data.get("site_ids"), list) or not all(
        isinstance(site, str) for site in cast(list[object], data["site_ids"])
    ):
        raise ValueError("invalid_model_sites")
    return ModelConfig(
        frozenset(data["site_ids"]),
        str(data["host_id"]),
        str(data["runtime_id"]),
        Path(data["slot_directory"]),
        str(data.get("worker_id", "workspace-model")),
    )


class PhysicalSlot:
    """A shared open-file-description lock; release by closing, never LOCK_UN."""

    def __init__(self, fd: int):
        self.fd = fd

    def close(self) -> None:
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


def acquire_slot(directory: Path) -> PhysicalSlot | None:
    protected_directory(directory)
    fd = os.open(
        directory / "slot-0.lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600
    )
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise PermissionError("slot_file_must_be_private")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            return None
        return PhysicalSlot(fd)
    except BaseException:
        os.close(fd)
        raise


def verify_binding(conn: psycopg.Connection[Any], config: ModelConfig, site_id: str) -> None:
    if config.host_id != local_host_id():
        raise PermissionError("configured_host_is_not_local")
    info = protected_directory(config.slot_directory)
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
    if config.host_id != local_host_id():
        raise PermissionError("configured_host_is_not_local")
    config.slot_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = protected_directory(config.slot_directory)
    # A host manifest prevents other databases and checkouts inventing a second slot.
    manifest_path = DEFAULT_SLOT_DIRECTORY.parent / "narrative-runtime.json"
    manifest_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    material = json.dumps(
        {
            "host_id": config.host_id,
            "runtime_id": config.runtime_id,
            "slot_directory": str(config.slot_directory),
            "device": info.st_dev,
            "inode": info.st_ino,
        },
        sort_keys=True,
    ).encode()
    try:
        fd = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    except FileExistsError:
        if manifest_path.read_bytes() != material:
            raise PermissionError("host_runtime_already_bound") from None
    else:
        with os.fdopen(fd, "wb") as stream:
            stream.write(material)
            stream.flush()
            os.fsync(stream.fileno())
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
            verify_binding(conn, config, site_id)


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
    profile = profile or CodexProfile()
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
    slot = acquire_slot(config.slot_directory)
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
    slot = acquire_slot(config.slot_directory)
    if slot is None:
        return 0
    try:
        for site_id in sorted(config.site_ids):
            with site_transaction(conn, site_id, config.site_ids):
                verify_binding(conn, config, site_id)
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
            ],
            pass_fds=(slot.fd,),
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
                        handler=NarrativePreparationHandler(),
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
