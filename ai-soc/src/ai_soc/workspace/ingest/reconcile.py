"""Closed-hour source-count reconciliation with durable before/after evidence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from uuid import UUID, uuid4

import psycopg

from ai_soc.workspace.db import site_transaction
from ai_soc.workspace.ingest.indexer_reader import IndexerAuthError, IndexerError, Reader
from ai_soc.workspace.ingest.poller import (
    PIPELINE_VERSION,
    IngestionFailure,
    acquire_source_lock,
    ingest_window,
    lock_key,
    release_source_lock,
    require_ingestion_connection,
)
from ai_soc.workspace.normalize.models import MappingProfile


@dataclass(frozen=True, slots=True)
class ReconcileResult:
    run_id: UUID
    hour: datetime
    source_count: int | None
    registry_before: int
    registry_after: int | None
    outcome: Literal["matched_count", "repaired_count", "mismatch", "failed"]
    alarm: bool
    error_code: str | None


def reconcile_hour(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    authorized_sites: frozenset[str],
    reader: Reader,
    index_pattern: str,
    profile: MappingProfile,
    hour: datetime,
    page_size: int = 500,
    max_restarts: int = 3,
) -> ReconcileResult:
    """Compare the exact source count with registry identities and backfill differences."""
    require_ingestion_connection(conn)
    if not site_id or site_id not in authorized_sites:
        raise PermissionError("worker is not configured for this site")
    if not index_pattern:
        raise ValueError("an explicit alert index pattern is required")
    start = _utc_hour(hour)
    end = start + timedelta(hours=1)
    if page_size < 1 or page_size > 5000:
        raise ValueError("page size must be in 1..5000")
    if max_restarts < 0 or max_restarts > 8:
        raise ValueError("traversal restart count must be in 0..8")

    key = lock_key(site_id, index_pattern)
    acquire_source_lock(conn, key)
    try:
        run_id = uuid4()
        _start_reconcile_run(
            conn,
            site_id=site_id,
            authorized_sites=authorized_sites,
            run_id=run_id,
            hour=start,
        )
        with site_transaction(conn, site_id, authorized_sites):
            before = _registry_count(
                conn, site_id=site_id, index_pattern=index_pattern, start=start, end=end
            )
        try:
            expected = reader.count_window(
                index_pattern=index_pattern,
                start=start,
                end=end,
                time_field=profile.time_field,
            )
        except IndexerError as exc:
            _persist_result(
                conn,
                site_id=site_id,
                authorized_sites=authorized_sites,
                run_id=run_id,
                hour=start,
                index_pattern=index_pattern,
                expected=None,
                before=before,
                after=None,
                outcome="failed",
                error_code=_error_code(exc),
            )
            return ReconcileResult(
                run_id, start, None, before, None, "failed", True, _error_code(exc)
            )

        if before == expected:
            outcome: Literal["matched_count", "repaired_count", "mismatch", "failed"] = (
                "matched_count"
            )
            after = before
        else:
            try:
                ingest_window(
                    conn,
                    kind="backfill",
                    site_id=site_id,
                    authorized_sites=authorized_sites,
                    reader=reader,
                    index_pattern=index_pattern,
                    profile=profile,
                    start=start,
                    end=end,
                    page_size=page_size,
                    max_restarts=max_restarts,
                    checkpoint_before=None,
                    overlap_seconds=0,
                )
            except Exception as exc:
                with site_transaction(conn, site_id, authorized_sites):
                    after = _registry_count(
                        conn,
                        site_id=site_id,
                        index_pattern=index_pattern,
                        start=start,
                        end=end,
                    )
                _persist_result(
                    conn,
                    site_id=site_id,
                    authorized_sites=authorized_sites,
                    run_id=run_id,
                    hour=start,
                    index_pattern=index_pattern,
                    expected=expected,
                    before=before,
                    after=after,
                    outcome="failed",
                    error_code=_error_code(exc),
                )
                return ReconcileResult(
                    run_id,
                    start,
                    expected,
                    before,
                    after,
                    "failed",
                    True,
                    _error_code(exc),
                )
            with site_transaction(conn, site_id, authorized_sites):
                after = _registry_count(
                    conn, site_id=site_id, index_pattern=index_pattern, start=start, end=end
                )
            outcome = "repaired_count" if after == expected else "mismatch"

        _persist_result(
            conn,
            site_id=site_id,
            authorized_sites=authorized_sites,
            run_id=run_id,
            hour=start,
            index_pattern=index_pattern,
            expected=expected,
            before=before,
            after=after,
            outcome=outcome,
            error_code=None,
        )
        return ReconcileResult(
            run_id,
            start,
            expected,
            before,
            after,
            outcome,
            after != expected,
            None,
        )
    finally:
        release_source_lock(conn, key)


def reconcile_closed_hours(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    authorized_sites: frozenset[str],
    reader: Reader,
    index_pattern: str,
    profile: MappingProfile,
    now: datetime,
    hours: int = 48,
    page_size: int = 500,
) -> tuple[ReconcileResult, ...]:
    if hours < 1 or hours > 168:
        raise ValueError("reconciliation lookback must be in 1..168 closed hours")
    upper = _utc(now).replace(minute=0, second=0, microsecond=0)
    start = upper - timedelta(hours=hours)
    results: list[ReconcileResult] = []
    for offset in range(hours):
        results.append(
            result := reconcile_hour(
                conn,
                site_id=site_id,
                authorized_sites=authorized_sites,
                reader=reader,
                index_pattern=index_pattern,
                profile=profile,
                hour=start + timedelta(hours=offset),
                page_size=page_size,
            )
        )
        if result.error_code == "AUTH_FAILED":
            break
    return tuple(results)


def _start_reconcile_run(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    authorized_sites: frozenset[str],
    run_id: UUID,
    hour: datetime,
) -> None:
    with site_transaction(conn, site_id, authorized_sites):
        conn.execute(
            """
            INSERT INTO pipeline_runs
                (run_id, site_id, kind, started_at, window_from, window_to, pipeline_version)
            VALUES (%s, %s, 'reconcile', now(), %s, %s, %s)
            """,
            (run_id, site_id, hour, hour + timedelta(hours=1), PIPELINE_VERSION),
        )


def _registry_count(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    index_pattern: str,
    start: datetime,
    end: datetime,
) -> int:
    with conn.cursor() as cursor:
        cursor.execute(
            """
            SELECT count(*)
            FROM alert_registry AS registry
            JOIN alert_sources AS source
              ON source.site_id = registry.site_id
             AND source.alert_key = registry.alert_key
            WHERE registry.site_id = %s AND source.index_pattern = %s
              AND registry.original_event_ts >= %s AND registry.original_event_ts < %s
            """,
            (site_id, index_pattern, start, end),
        )
        row = cursor.fetchone()
    if row is None:
        raise RuntimeError("registry count query returned no row")
    return int(row[0])


def _persist_result(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    authorized_sites: frozenset[str],
    run_id: UUID,
    hour: datetime,
    index_pattern: str,
    expected: int | None,
    before: int,
    after: int | None,
    outcome: Literal["matched_count", "repaired_count", "mismatch", "failed"],
    error_code: str | None,
) -> None:
    count_equal = expected is not None and after == expected
    successful = count_equal and outcome in {"matched_count", "repaired_count"}
    alarm = not successful
    partial_reason = None
    if not successful:
        partial_reason = (
            f"closed-hour reconciliation {outcome}"
            if error_code is None
            else f"closed-hour reconciliation {outcome}: {error_code}"
        )
    with site_transaction(conn, site_id, authorized_sites):
        conn.execute(
            """
            INSERT INTO alert_reconciliation
                (site_id, run_id, hour, source_count, registry_before, registry_after,
                 count_equal, alarm, outcome, error_code, index_pattern)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (site_id, run_id, hour) DO UPDATE
            SET source_count = EXCLUDED.source_count,
                registry_before = EXCLUDED.registry_before,
                registry_after = EXCLUDED.registry_after,
                count_equal = EXCLUDED.count_equal,
                alarm = EXCLUDED.alarm,
                outcome = EXCLUDED.outcome,
                error_code = EXCLUDED.error_code,
                index_pattern = EXCLUDED.index_pattern,
                checked_at = now()
            """,
            (
                site_id,
                run_id,
                hour,
                expected,
                before,
                after,
                count_equal,
                alarm,
                outcome,
                error_code,
                index_pattern,
            ),
        )
        conn.execute(
            """
            UPDATE pipeline_runs
            SET finished_at = now(),
                outcome = CASE WHEN %s THEN 'ok' ELSE 'partial' END,
                reconcile_expected = %s,
                reconcile_stored = %s,
                error_code = %s,
                partial_reason = %s
            WHERE site_id = %s AND run_id = %s
            """,
            (successful, expected, after, error_code, partial_reason, site_id, run_id),
        )
        if not successful:
            health = "auth_failed" if error_code == "AUTH_FAILED" else "lagging"
            conn.execute(
                """
                UPDATE sites SET health = %s, health_detail = %s, updated_at = now()
                WHERE site_id = %s
                """,
                (
                    health,
                    f"closed-hour reconciliation {hour.isoformat()} is incomplete",
                    site_id,
                ),
            )


def _error_code(error: Exception) -> str:
    return (
        "AUTH_FAILED"
        if isinstance(error, IndexerAuthError)
        or isinstance(error, IngestionFailure)
        and error.reason == "AUTH_FAILED"
        else "RECONCILE_FAILED"
    )


def _utc_hour(value: datetime) -> datetime:
    value = _utc(value)
    if value.minute or value.second or value.microsecond:
        raise ValueError("reconciliation requires an exact UTC hour boundary")
    return value


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("reconciliation timestamps must be timezone-aware")
    return value.astimezone(UTC)
