"""Durable coalescing for bounded correlation preparation."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Concatenate, cast

import psycopg
from psycopg.pq import TransactionStatus
from psycopg.types.json import Jsonb

from ai_soc.workspace.db import require_site_transaction
from ai_soc.workspace.jobs import Job, enqueue_job


def identity(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def correlation_savepoint[**P, R](
    function: Callable[Concatenate[psycopg.Connection[Any], P], R],
) -> Callable[Concatenate[psycopg.Connection[Any], P], R]:
    @wraps(function)
    def wrapped(conn: psycopg.Connection[Any], *args: P.args, **kwargs: P.kwargs) -> R:
        if conn.info.transaction_status is TransactionStatus.IDLE:
            raise PermissionError("correlation operation requires an active site transaction")
        with conn.transaction():
            return function(conn, *args, **kwargs)

    return wrapped


@correlation_savepoint
def request_correlation(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    enabled: bool,
    config: dict[str, str],
    now: datetime,
) -> int | None:
    """Record every eligible score request and enqueue at most one active prepare."""
    require_site_transaction(conn, site_id)
    if type(enabled) is not bool:
        raise ValueError("correlation_enabled must be a boolean")
    if not enabled:
        return None
    from ai_soc.workspace.correlate.runner import rule_from_config

    rule_from_config(config)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("request cutoff must be timezone-aware")
    conn.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
        (f"correlation-request:{site_id}",),
    )
    config_id = identity(config)
    row = conn.execute(
        "SELECT requested_seq, prepared_seq, generation, active_prepare_job_id, "
        "desired_config_identity FROM correlation_requests WHERE site_id = %s FOR UPDATE",
        (site_id,),
    ).fetchone()
    if row is None:
        generation = 1
        prepare_id = enqueue_job(
            conn,
            site_id=site_id,
            kind="prepare_correlation",
            subject=f"{site_id}:1",
            payload={"generation": 1, "config": config, "config_identity": config_id},
            run_after=now,
        )
        conn.execute(
            """INSERT INTO correlation_requests
               (site_id, requested_seq, prepared_seq, generation, latest_requested_at,
                active_prepare_job_id, active_config_identity, desired_config,
                desired_config_identity, updated_at)
               VALUES (%s, 1, 0, %s, %s, %s, %s, %s, %s, %s)""",
            (site_id, generation, now, prepare_id, config_id, Jsonb(config), config_id, now),
        )
        return prepare_id

    requested, _prepared, generation, active_id, _desired_id = row
    next_seq = int(requested) + 1
    conn.execute(
        """UPDATE correlation_requests SET requested_seq=%s,
           latest_requested_at=GREATEST(latest_requested_at,%s),
           desired_config=%s, desired_config_identity=%s, updated_at=%s WHERE site_id=%s""",
        (next_seq, now, Jsonb(config), config_id, now, site_id),
    )
    if active_id is not None:
        return int(active_id)
    generation = int(generation) + 1
    job_id = enqueue_job(
        conn,
        site_id=site_id,
        kind="prepare_correlation",
        subject=f"{site_id}:{generation}",
        payload={"generation": generation, "config": config, "config_identity": config_id},
        run_after=now,
    )
    conn.execute(
        """UPDATE correlation_requests SET generation=%s, active_prepare_job_id=%s,
           active_config_identity=%s WHERE site_id=%s""",
        (generation, job_id, config_id, site_id),
    )
    return job_id


def request_snapshot(conn: psycopg.Connection[Any], *, site_id: str) -> dict[str, object] | None:
    if conn.info.transaction_status is TransactionStatus.IDLE:
        raise PermissionError("correlation snapshot requires an active site transaction")
    try:
        require_site_transaction(conn, site_id)
    except PermissionError:
        # Match other tenant-private reads: an unrelated active site sees no state.
        return None
    row = conn.execute(
        """SELECT requested_seq, prepared_seq, generation, latest_requested_at,
                  active_prepare_job_id, active_config_identity, desired_config_identity,
                  desired_config
           FROM correlation_requests WHERE site_id=%s""",
        (site_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "requested_seq": int(row[0]),
        "prepared_seq": int(row[1]),
        "generation": int(row[2]),
        "latest_requested_at": row[3],
        "active_prepare_job_id": row[4],
        "active_config_identity": row[5],
        "desired_config_identity": row[6],
        "desired_config": row[7],
        "pending": int(row[0]) > int(row[1]),
    }


@correlation_savepoint
def prepare_request(
    conn: psycopg.Connection[Any], *, job: Job, now: datetime, code_identity: str
) -> None:
    """Capture without a request lock, build, then briefly fence progress at completion."""
    from ai_soc.workspace.correlate.repository import enqueue_correlation, freeze_manifest
    from ai_soc.workspace.correlate.runner import build_frozen_inputs, rule_from_config

    require_site_transaction(conn, job.site_id)
    generation = job.payload.get("generation")
    config = job.payload.get("config")
    config_id = job.payload.get("config_identity")
    if (
        type(generation) is not int
        or not isinstance(config, dict)
        or identity(cast(dict[str, object], config)) != config_id
    ):
        raise ValueError("preparation job has an invalid frozen configuration")
    pinned_rule = rule_from_config(cast(dict[str, object], config), supported_code=code_identity)
    captured = conn.execute(
        """SELECT requested_seq, prepared_seq, generation, latest_requested_at,
                  active_prepare_job_id, active_config_identity, desired_config_identity
           FROM correlation_requests WHERE site_id=%s""",
        (job.site_id,),
    ).fetchone()
    if captured is None:
        raise LookupError("correlation request state is missing")
    seq, _prepared, current_generation, cutoff, active_job, active_config, desired_config = captured
    if int(current_generation) != generation or int(active_job or -1) != job.job_id:
        return
    if str(active_config) != config_id:
        raise ValueError("active preparation configuration differs from its immutable job")
    prepared = False
    if str(desired_config) == config_id:
        if cutoff is None or now < cutoff:
            raise ValueError("preparation must run no earlier than its captured cutoff")
        inputs = build_frozen_inputs(
            conn,
            site_id=job.site_id,
            start=cutoff - timedelta(hours=12),
            end=cutoff,
            as_of=now,
            computation_version=code_identity,
        )
        manifest_id = freeze_manifest(conn, inputs=inputs, rule=pinned_rule, now=now)
        enqueue_correlation(conn, manifestid=manifest_id, siteid=job.site_id, now=now)
        prepared = True
    _finish_preparation(
        conn,
        job=job,
        captured_seq=int(seq),
        captured_generation=generation,
        captured_config=str(config_id),
        prepared=prepared,
        now=now,
    )


def _finish_preparation(
    conn: psycopg.Connection[Any],
    *,
    job: Job,
    captured_seq: int,
    captured_generation: int,
    captured_config: str,
    prepared: bool,
    now: datetime,
) -> None:
    row = conn.execute(
        """SELECT requested_seq, prepared_seq, generation, active_prepare_job_id,
                  desired_config, desired_config_identity
           FROM correlation_requests WHERE site_id=%s FOR UPDATE""",
        (job.site_id,),
    ).fetchone()
    if row is None:
        raise LookupError("correlation request state is missing")
    requested, _prepared, generation, active_job, desired, desired_id = row
    if int(generation) != captured_generation or int(active_job or -1) != job.job_id:
        raise RuntimeError("stale correlation preparation generation")
    if prepared:
        conn.execute(
            "UPDATE correlation_requests SET prepared_seq=GREATEST(prepared_seq,%s), "
            "active_prepare_job_id=NULL, updated_at=%s WHERE site_id=%s",
            (captured_seq, now, job.site_id),
        )
    if int(requested) > captured_seq or str(desired_id) != captured_config:
        next_generation = int(generation) + 1
        next_config = cast(dict[str, str], desired)
        next_id = str(desired_id)
        next_job = enqueue_job(
            conn,
            site_id=job.site_id,
            kind="prepare_correlation",
            subject=f"{job.site_id}:{next_generation}",
            payload={
                "generation": next_generation,
                "config": next_config,
                "config_identity": next_id,
            },
            run_after=now,
        )
        conn.execute(
            """UPDATE correlation_requests SET generation=%s, active_prepare_job_id=%s,
               active_config_identity=%s, updated_at=%s WHERE site_id=%s""",
            (next_generation, next_job, next_id, now, job.site_id),
        )


@correlation_savepoint
def recover_request(conn: psycopg.Connection[Any], *, site_id: str, now: datetime) -> int:
    """Create a fresh preparation generation after the recorded active job is terminal."""
    require_site_transaction(conn, site_id)
    row = conn.execute(
        """SELECT r.requested_seq, r.prepared_seq, r.generation, r.active_prepare_job_id,
                  r.desired_config, r.desired_config_identity, j.state
           FROM correlation_requests r LEFT JOIN jobs j
             ON (j.site_id,j.job_id)=(r.site_id,r.active_prepare_job_id)
           WHERE r.site_id=%s FOR UPDATE OF r""",
        (site_id,),
    ).fetchone()
    if row is None:
        raise LookupError("correlation request state is unavailable")
    requested, prepared, generation, active_id, config, config_id, state = row
    if int(requested) <= int(prepared):
        raise ValueError("correlation request has no pending preparation")
    if active_id is not None and state not in {"dead", "done", "failed"}:
        raise ValueError("active preparation is not terminal")
    next_generation = int(generation) + 1
    job_id = enqueue_job(
        conn,
        site_id=site_id,
        kind="prepare_correlation",
        subject=f"{site_id}:{next_generation}",
        payload={
            "generation": next_generation,
            "config": config,
            "config_identity": str(config_id),
        },
        run_after=now,
    )
    conn.execute(
        """UPDATE correlation_requests SET generation=%s, active_prepare_job_id=%s,
           active_config_identity=%s, updated_at=%s WHERE site_id=%s""",
        (next_generation, job_id, config_id, now, site_id),
    )
    return next_generation
