"""Per-call guardian: lease, bounded external process tree and final safe receipt."""

from __future__ import annotations

import argparse
import os
import signal
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import FrameType
from typing import Any
from uuid import UUID, uuid4

import psycopg

from ai_soc.workspace.db import site_transaction
from ai_soc.workspace.jobs import Job, LeaseLost, heartbeat_job
from ai_soc.workspace.model.cli_profile import CodexProfile, ProfileError
from ai_soc.workspace.model.cli_provider import (
    CodexCLIProvider,
    GenerationRequest,
    GenerationResult,
    ProviderUnavailable,
    TokenUsage,
)
from ai_soc.workspace.model.narrate import (
    Generation,
    authorize_call,
    finish_call,
    load_generation,
    recover_abandoned_calls,
    supported_generation,
)
from ai_soc.workspace.model.worker import ModelConfig, load_config, verify_binding
from ai_soc.workspace.worker import LEASE

ConnectionFactory = Callable[[], psycopg.Connection[Any]]


def _clock() -> datetime:
    return datetime.now(UTC)


@contextmanager
def _short_transaction(
    conn: psycopg.Connection[Any], site_id: str, sites: frozenset[str]
) -> Iterator[None]:
    with site_transaction(conn, site_id, sites):
        conn.execute("SET LOCAL lock_timeout = '2s'")
        conn.execute("SET LOCAL statement_timeout = '5s'")
        yield


def _claim_supported(
    conn: psycopg.Connection[Any],
    config: ModelConfig,
    site_id: str,
    profile: CodexProfile,
    now: datetime,
) -> tuple[Job, Generation] | None:
    # Unsupported bundles remain queued without consuming attempts. Inspect/claim one row at a time.
    rows = conn.execute(
        "SELECT j.job_id,j.site_id,j.kind,j.subject,j.payload,j.attempts "
        "FROM jobs j JOIN narrative_generations g ON "
        "(g.site_id,g.narrate_job_id)=(j.site_id,j.job_id) "
        "WHERE j.site_id=%s AND j.kind='narrate' AND j.state='queued' "
        "AND j.attempts<5 AND j.run_after<=%s ORDER BY j.run_after,j.job_id "
        "FOR UPDATE OF j SKIP LOCKED",
        (site_id, now),
    ).fetchall()
    for job_id, job_site, kind, subject, payload, attempts in rows:
        generation = load_generation(
            conn, site_id=site_id, generation_id=UUID(str(payload["generation_id"]))
        )
        if not supported_generation(generation, profile):
            continue
        token = uuid4()
        until = now + LEASE
        conn.execute(
            "UPDATE jobs SET state='running',attempts=attempts+1,locked_by=%s,"
            "locked_until=%s,lease_token=%s WHERE site_id=%s AND job_id=%s",
            (config.worker_id, until, token, site_id, job_id),
        )
        return (
            Job(
                int(job_id),
                str(job_site),
                str(kind),
                str(subject),
                dict(payload),
                int(attempts) + 1,
                token,
                until,
            ),
            generation,
        )
    return None


def _heartbeat(
    connect: ConnectionFactory,
    config: ModelConfig,
    job: Job,
    stop: threading.Event,
    cancelled: threading.Event,
    *,
    interval: float,
) -> None:
    while not stop.wait(interval):
        try:
            with connect() as conn, _short_transaction(conn, job.site_id, config.site_ids):
                heartbeat_job(
                    conn,
                    job_id=job.job_id,
                    worker_id=config.worker_id,
                    lease_token=job.lease_token,
                    now=_clock(),
                    lease=LEASE,
                )
        except Exception:
            # Cancel actual children before releasing capacity after a failed heartbeat.
            cancelled.set()
            return


def run_guardian(
    *,
    config: ModelConfig,
    slot_fd: int,
    connect: ConnectionFactory,
    profile: CodexProfile | None = None,
    provider: CodexCLIProvider | None = None,
    heartbeat_interval: float = 10.0,
    cancel_event: threading.Event | None = None,
) -> int:
    """Execute at most one authorization. Return 1 for a call and 0 for no ready work."""
    profile = profile or CodexProfile()
    provider = provider or CodexCLIProvider(profile)
    if not 0 < heartbeat_interval <= 10:
        raise ValueError("invalid_heartbeat_interval")
    info = os.fstat(slot_fd)
    expected = (config.slot_directory / "slot-0.lock").stat()
    if (info.st_dev, info.st_ino) != (expected.st_dev, expected.st_ino):
        raise PermissionError("inherited_slot_identity_mismatch")
    os.set_inheritable(slot_fd, False)
    job_and_generation: tuple[Job, Generation] | None = None
    call_id: UUID | None = None
    # Slot admission precedes recovery and every claim. Reconcile all configured sites first.
    with connect() as conn:
        for site_id in sorted(config.site_ids):
            with _short_transaction(conn, site_id, config.site_ids):
                verify_binding(conn, config, site_id)
                recover_abandoned_calls(
                    conn,
                    site_id=site_id,
                    host_id=config.host_id,
                    runtime_id=config.runtime_id,
                    slot_fd=slot_fd,
                    now=_clock(),
                )
        for site_id in sorted(config.site_ids):
            with _short_transaction(conn, site_id, config.site_ids):
                pending = conn.execute(
                    "SELECT 1 FROM narrative_calls c LEFT JOIN narrative_outcomes o "
                    "USING(site_id,call_id) WHERE c.site_id=%s AND c.host_id=%s "
                    "AND c.runtime_id=%s AND o.call_id IS NULL LIMIT 1",
                    (site_id, config.host_id, config.runtime_id),
                ).fetchone()
                if pending is not None:
                    return 0
        # Recover first, then block unavailable installed bundles before any claim/attempt.
        # This preflight checks binaries/catalog only; credentials remain broker-owned.
        try:
            profile.verify_runtime()
        except ProfileError:
            return 0
        for site_id in sorted(config.site_ids):
            with _short_transaction(conn, site_id, config.site_ids):
                job_and_generation = _claim_supported(conn, config, site_id, profile, _clock())
                if job_and_generation is not None:
                    job, generation = job_and_generation
                    call_id = authorize_call(
                        conn,
                        job=job,
                        worker_id=config.worker_id,
                        generation=generation,
                        host_id=config.host_id,
                        runtime_id=config.runtime_id,
                        boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                        guardian_pid=os.getpid(),
                        guardian_start=Path("/proc/self/stat").read_text().split()[21],
                        now=_clock(),
                    )
            if job_and_generation is not None:
                break
    if job_and_generation is None or call_id is None:
        return 0
    job, generation = job_and_generation
    stop = threading.Event()
    cancelled = cancel_event or threading.Event()
    heartbeat = threading.Thread(
        target=_heartbeat,
        args=(connect, config, job, stop, cancelled),
        kwargs={"interval": heartbeat_interval},
        daemon=True,
    )
    heartbeat.start()
    started = time.monotonic()
    result: GenerationResult | None = None
    failure: ProviderUnavailable | None = None
    try:
        try:
            result = provider.generate(
                GenerationRequest(
                    generation.pack,
                    job.site_id,
                    generation.incident_id,
                    generation.incident_revision_id,
                ),
                frozen=generation.execution,
                slot_fds=(slot_fd,),
                cancel_event=cancelled,
            )
        except ProviderUnavailable as error:
            failure = error
        if cancelled.is_set():
            # The provider has already reaped its children; an expired owner writes nothing.
            return 1
        elapsed_ms = min(2_147_483_647, int((time.monotonic() - started) * 1000))
        # Retry persistence while the independently renewed lease remains valid.
        for attempt in range(3):
            try:
                with connect() as conn, _short_transaction(conn, job.site_id, config.site_ids):
                    finish_call(
                        conn,
                        job=job,
                        worker_id=config.worker_id,
                        call_id=call_id,
                        generation=generation,
                        now=_clock(),
                        result=result,
                        error_code=None if failure is None else failure.code,
                        usage=TokenUsage(None, None, None) if failure is None else failure.usage,
                        provenance=None if failure is None else failure.provenance,
                        elapsed_ms=elapsed_ms,
                    )
                return 1
            except LeaseLost:
                cancelled.set()
                return 1
            except psycopg.Error:
                if attempt == 2 or cancelled.wait(0.1 * (attempt + 1)):
                    raise
        return 1
    finally:
        stop.set()
        heartbeat.join(timeout=15)
        if heartbeat.is_alive():
            cancelled.set()
            heartbeat.join()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--slot-fd", type=int, required=True)
    args = parser.parse_args()
    config = load_config(args.config)
    dsn = os.environ.get("WS_MODEL_DATABASE_URL")
    if not dsn:
        parser.error("WS_MODEL_DATABASE_URL is required")
    cancelled = threading.Event()

    def cancel(_signal: int, _frame: FrameType | None) -> None:
        cancelled.set()

    signal.signal(signal.SIGTERM, cancel)
    signal.signal(signal.SIGINT, cancel)
    try:
        count = run_guardian(
            config=config,
            slot_fd=args.slot_fd,
            connect=lambda: psycopg.connect(dsn, connect_timeout=3),
            cancel_event=cancelled,
        )
        return 0 if count else 3
    finally:
        os.close(args.slot_fd)


if __name__ == "__main__":
    raise SystemExit(main())
