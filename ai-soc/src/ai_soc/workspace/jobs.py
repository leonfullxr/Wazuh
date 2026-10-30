"""Site-scoped PostgreSQL job queue with fenced, expiring leases."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, LiteralString
from uuid import UUID, uuid4

import psycopg
from psycopg.pq import TransactionStatus
from psycopg.types.json import Jsonb

MAX_ATTEMPTS = 5


class LeaseLost(RuntimeError):
    """The worker no longer owns the live lease for a job."""


@dataclass(frozen=True, slots=True)
class Job:
    job_id: int
    site_id: str
    kind: str
    subject: str
    payload: dict[str, Any]
    attempts: int
    lease_token: UUID
    locked_until: datetime


def _require_site(conn: psycopg.Connection[Any], site_id: str) -> None:
    if conn.info.transaction_status is TransactionStatus.IDLE:
        raise PermissionError("job operation requires an active transaction for its site")
    with conn.cursor() as cursor:
        cursor.execute("SELECT current_setting('app.site_id', true)")
        row = cursor.fetchone()
    if row is None or row[0] != site_id:
        raise PermissionError("job operation requires an active transaction for its site")


def enqueue_job(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    kind: str,
    subject: str,
    payload: dict[str, Any],
    run_after: datetime | None = None,
) -> int:
    """Insert an idempotent job in the caller's site transaction."""
    _require_site(conn, site_id)
    if run_after is not None and (run_after.tzinfo is None or run_after.utcoffset() is None):
        raise ValueError("run_after must be timezone-aware")
    with conn.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO jobs (site_id, kind, subject, payload, run_after)
            VALUES (%s, %s, %s, %s, COALESCE(%s, now()))
            ON CONFLICT (site_id, kind, subject) DO UPDATE SET kind = EXCLUDED.kind
            RETURNING job_id
            """,
            (site_id, kind, subject, Jsonb(payload), run_after),
        )
        row = cursor.fetchone()
    if row is None:
        raise RuntimeError("job upsert did not return an id")
    return int(row[0])


def _expire_exhausted(
    conn: psycopg.Connection[Any], *, now: datetime, job_kinds: frozenset[str] | None
) -> None:
    conn.execute(
        """
        WITH exhausted AS MATERIALIZED (
            SELECT job_id FROM jobs
            WHERE site_id = current_setting('app.site_id', true)
              AND state = 'running' AND locked_until <= %s AND attempts >= %s
              AND (%s::text[] IS NULL OR kind = ANY(%s))
            ORDER BY locked_until, job_id
            FOR UPDATE SKIP LOCKED
        )
        UPDATE jobs AS j
        SET state = 'dead', locked_by = NULL, locked_until = NULL,
            lease_token = NULL, last_error = COALESCE(j.last_error, 'lease expired')
        FROM exhausted
        WHERE j.job_id = exhausted.job_id
        """,
        (
            now,
            MAX_ATTEMPTS,
            None if job_kinds is None else sorted(job_kinds),
            None if job_kinds is None else sorted(job_kinds),
        ),
    )


def claim_job(
    conn: psycopg.Connection[Any],
    *,
    worker_id: str,
    now: datetime,
    lease: timedelta,
    site_id: str,
    authorized_sites: frozenset[str],
    kind: str | None = None,
    job_kinds: frozenset[str] | None = None,
) -> Job | None:
    """Claim one ready job for a configured site using SKIP LOCKED."""
    if site_id not in authorized_sites:
        raise PermissionError("worker is not configured for this site")
    if not worker_id or lease <= timedelta(0):
        raise ValueError("worker_id and a positive lease are required")
    _require_site(conn, site_id)
    _expire_exhausted(conn, now=now, job_kinds=job_kinds)
    token = uuid4()
    with conn.cursor() as cursor:
        cursor.execute(
            """
            WITH candidate AS (
                SELECT job_id FROM jobs
                WHERE site_id = %s
                  AND (%s::text IS NULL OR kind = %s)
                  AND (%s::text[] IS NULL OR kind = ANY(%s))
                  AND attempts < %s
                  AND run_after <= %s
                  AND (state = 'queued' OR (state = 'running' AND locked_until <= %s))
                ORDER BY run_after, job_id
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            UPDATE jobs AS j
            SET state = 'running', attempts = j.attempts + 1, locked_by = %s,
                locked_until = %s, lease_token = %s
            FROM candidate
            WHERE j.job_id = candidate.job_id
            RETURNING j.job_id, j.site_id, j.kind, j.subject, j.payload,
                      j.attempts, j.lease_token, j.locked_until
            """,
            (
                site_id,
                kind,
                kind,
                None if job_kinds is None else sorted(job_kinds),
                None if job_kinds is None else sorted(job_kinds),
                MAX_ATTEMPTS,
                now,
                now,
                worker_id,
                now + lease,
                token,
            ),
        )
        row = cursor.fetchone()
    if row is None:
        return None
    return Job(
        job_id=int(row[0]),
        site_id=str(row[1]),
        kind=str(row[2]),
        subject=str(row[3]),
        payload=dict(row[4]),
        attempts=int(row[5]),
        lease_token=row[6],
        locked_until=row[7],
    )


def _lease_update(
    conn: psycopg.Connection[Any],
    *,
    job_id: int,
    worker_id: str,
    lease_token: UUID,
    now: datetime,
    statement: LiteralString,
    parameters: tuple[object, ...] = (),
) -> None:
    with conn.cursor() as cursor:
        cursor.execute(
            statement,
            (*parameters, job_id, _active_site(conn), worker_id, lease_token, now),
        )
        if cursor.rowcount != 1:
            raise LeaseLost(f"worker {worker_id!r} no longer owns job {job_id}")


def _active_site(conn: psycopg.Connection[Any]) -> str:
    if conn.info.transaction_status is TransactionStatus.IDLE:
        raise PermissionError("job operation requires an active site transaction")
    with conn.cursor() as cursor:
        cursor.execute("SELECT current_setting('app.site_id', true)")
        row = cursor.fetchone()
    if row is None or not row[0]:
        raise PermissionError("job operation requires an active site transaction")
    return str(row[0])


def heartbeat_job(
    conn: psycopg.Connection[Any],
    *,
    job_id: int,
    worker_id: str,
    lease_token: UUID,
    now: datetime,
    lease: timedelta,
) -> datetime:
    """Extend a live lease only while its worker and fencing token match."""
    if lease <= timedelta(0):
        raise ValueError("lease must be positive")
    locked_until = now + lease
    _lease_update(
        conn,
        job_id=job_id,
        worker_id=worker_id,
        lease_token=lease_token,
        now=now,
        statement="""
            UPDATE jobs SET locked_until = %s
            WHERE job_id = %s AND site_id = %s AND state = 'running'
              AND locked_by = %s AND lease_token = %s AND locked_until > %s
        """,
        parameters=(locked_until,),
    )
    return locked_until


def lock_live_job(
    conn: psycopg.Connection[Any], *, job: Job, worker_id: str, now: datetime
) -> None:
    """Fence transactional handler effects against a live lease before they start."""
    _require_site(conn, job.site_id)
    row = conn.execute(
        "SELECT job_id FROM jobs WHERE site_id = %s AND job_id = %s "
        "AND state = 'running' AND locked_by = %s AND lease_token = %s "
        "AND locked_until > %s FOR UPDATE",
        (job.site_id, job.job_id, worker_id, job.lease_token, now),
    ).fetchone()
    if row is None:
        raise LeaseLost("job lease expired before the handler transaction")


def complete_job(
    conn: psycopg.Connection[Any],
    *,
    job_id: int,
    worker_id: str,
    lease_token: UUID,
    now: datetime,
) -> None:
    """Complete a job while its fencing token and lease are still valid."""
    _lease_update(
        conn,
        job_id=job_id,
        worker_id=worker_id,
        lease_token=lease_token,
        now=now,
        statement="""
            UPDATE jobs SET state = 'done', completed_at = %s,
                            locked_by = NULL, locked_until = NULL, lease_token = NULL
            WHERE job_id = %s AND site_id = %s AND state = 'running'
              AND locked_by = %s AND lease_token = %s AND locked_until > %s
        """,
        parameters=(now,),
    )


def fail_job(
    conn: psycopg.Connection[Any],
    *,
    job_id: int,
    worker_id: str,
    lease_token: UUID,
    now: datetime,
    error: str,
    retryable: bool = True,
) -> None:
    """Retry with capped exponential backoff or dead-letter on attempt five."""
    _lease_update(
        conn,
        job_id=job_id,
        worker_id=worker_id,
        lease_token=lease_token,
        now=now,
        statement="""
            UPDATE jobs
            SET state = CASE WHEN attempts >= %s THEN 'dead' ELSE 'queued' END,
                run_after = CASE WHEN attempts >= %s THEN run_after ELSE
                    %s + make_interval(secs => LEAST(300, (2 ^ attempts)::integer)) END,
                locked_by = NULL, locked_until = NULL, lease_token = NULL, last_error = %s
            WHERE job_id = %s AND site_id = %s AND state = 'running'
              AND locked_by = %s AND lease_token = %s AND locked_until > %s
        """,
        parameters=(
            MAX_ATTEMPTS if retryable else 0,
            MAX_ATTEMPTS if retryable else 0,
            now,
            error[:2000],
        ),
    )
