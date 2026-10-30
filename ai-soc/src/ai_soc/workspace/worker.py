"""Fenced worker batches whose effects, successors and completion commit together."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

import psycopg

from ai_soc.workspace.db import site_transaction
from ai_soc.workspace.jobs import Job, LeaseLost, claim_job, complete_job, fail_job, lock_live_job

LEASE = timedelta(seconds=60)


class BatchHandler(Protocol):
    def __call__(
        self, conn: psycopg.Connection[Any], jobs: tuple[Job, ...], now: datetime
    ) -> None: ...


def _ping_handler(conn: psycopg.Connection[Any], jobs: tuple[Job, ...], now: datetime) -> None:
    for job in jobs:
        if job.kind != "workspace_ping":
            raise ValueError(f"unsupported job kind: {job.kind}")


def run_once(
    conn: psycopg.Connection[Any],
    *,
    worker_id: str,
    site_ids: frozenset[str],
    handler: BatchHandler = _ping_handler,
    batch_size: int = 1,
    job_kinds: frozenset[str] | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> int:
    """Claim a bounded batch, then atomically handle it under its live lease locks.

    A crash between claim and handler leaves recoverable leases. Handler exceptions
    roll back all effects and successors before fenced retry scheduling. An expired
    handler cannot commit effects even if nobody has reclaimed its job yet.
    """
    if not 1 <= batch_size <= 500:
        raise ValueError("worker batch size must be in 1..500")
    if job_kinds is None:
        job_kinds = getattr(handler, "job_kinds", None)
    for site_id in sorted(site_ids):
        claimed: list[Job] = []
        with site_transaction(conn, site_id, site_ids):
            for _ in range(batch_size):
                job = claim_job(
                    conn,
                    worker_id=worker_id,
                    now=clock(),
                    lease=LEASE,
                    site_id=site_id,
                    authorized_sites=site_ids,
                    kind=claimed[0].kind if claimed else None,
                    job_kinds=job_kinds,
                )
                if job is None:
                    break
                preclaim = getattr(handler, "preclaim", None)
                preclaim_with_connection = getattr(handler, "preclaim_with_connection", None)
                if callable(preclaim_with_connection):
                    preclaim_with_connection(conn, job)
                elif callable(preclaim):
                    preclaim(job)
                claimed.append(job)
                # Score work may traverse a large retained membership. Claim it
                # only when it can run immediately, without aging other leases.
                if job.kind in {
                    "enrich_group",
                    "rescore_group",
                    "prepare_correlation",
                    "correlate_window",
                }:
                    break
        if not claimed:
            continue
        _process_batch(
            conn,
            tuple(claimed),
            worker_id=worker_id,
            site_ids=site_ids,
            handler=handler,
            clock=clock,
        )
        return len(claimed)
    return 0


def _process_batch(
    conn: psycopg.Connection[Any],
    jobs: tuple[Job, ...],
    *,
    worker_id: str,
    site_ids: frozenset[str],
    handler: BatchHandler,
    clock: Callable[[], datetime],
) -> None:
    if not jobs:
        return
    first = jobs[0]
    site_id = first.site_id
    try:
        with site_transaction(conn, site_id, site_ids):
            for job in jobs:
                lock_live_job(conn, job=job, worker_id=worker_id, now=clock())
            handler(conn, jobs, clock())
            for job in jobs:
                complete_job(
                    conn,
                    job_id=job.job_id,
                    worker_id=worker_id,
                    lease_token=job.lease_token,
                    now=clock(),
                )
    except Exception as exc:
        if len(jobs) > 1:
            # The failed transaction left no effects. Split to isolate a poison
            # job rather than spending healthy neighbors' retry budgets on it.
            middle = len(jobs) // 2
            for half in (jobs[:middle], jobs[middle:]):
                _process_batch(
                    conn,
                    half,
                    worker_id=worker_id,
                    site_ids=site_ids,
                    handler=handler,
                    clock=clock,
                )
            return
        job = first
        try:
            with site_transaction(conn, site_id, site_ids):
                fail_job(
                    conn,
                    job_id=job.job_id,
                    worker_id=worker_id,
                    lease_token=job.lease_token,
                    now=clock(),
                    error=type(exc).__name__,
                )
        except LeaseLost:
            # Recovery belongs to the next claimant after expiry.
            pass


def main() -> int:
    from ai_soc.workspace.pipeline import PipelineHandler
    from ai_soc.workspace.runtime import PipelineRuntime, load_pipeline_config

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--drain", action="store_true", help="process until no jobs are ready")
    parser.add_argument("--max-jobs", type=int, default=100_000)
    parser.add_argument("--batch-size", type=int, default=100)
    args = parser.parse_args()
    source = os.environ.get("WS_WORKER_CONFIG")
    if not source:
        parser.error("WS_WORKER_CONFIG must reference the explicit pipeline configuration")
    if not 1 <= args.max_jobs <= 1_000_000:
        parser.error("--max-jobs must be in 1..1000000")
    config = load_pipeline_config(Path(source))
    site_ids = frozenset(site.site_id for site in config.sites)
    worker_id = os.environ.get("WS_WORKER_ID", "workspace-worker")
    handled = 0
    with PipelineRuntime(config) as runtime, runtime.connect() as conn:
        handler = PipelineHandler(config)
        while handled < args.max_jobs:
            count = run_once(
                conn,
                worker_id=worker_id,
                site_ids=site_ids,
                handler=handler,
                batch_size=min(args.batch_size, args.max_jobs - handled),
            )
            handled += count
            if not args.drain or not count:
                break
        dead = 0
        outstanding = 0
        deferred = 0
        for site_id in sorted(site_ids):
            with site_transaction(conn, site_id, site_ids):
                row = conn.execute(
                    "SELECT count(*) FILTER (WHERE state = 'dead'), "
                    "count(*) FILTER (WHERE "
                    "(state = 'queued' AND run_after <= now()) OR "
                    "(state = 'running' AND locked_until <= now()) OR "
                    "(state = 'running' AND locked_until > now())), "
                    "count(*) FILTER (WHERE state = 'queued' AND run_after > now()) FROM jobs "
                    "WHERE site_id = %s AND kind = ANY(%s)",
                    (site_id, sorted(handler.job_kinds)),
                ).fetchone()
                assert row is not None
                dead += int(row[0])
                outstanding += int(row[1])
                deferred += int(row[2])
    print(f"processed={handled} outstanding={outstanding} deferred={deferred} dead={dead}")
    return 1 if dead or (args.drain and outstanding) else 0


if __name__ == "__main__":
    sys.exit(main())
