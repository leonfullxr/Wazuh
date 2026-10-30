"""Fixed-window, bounded-page polling and idempotent historical backfill."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, cast
from uuid import UUID, uuid4

import psycopg
from psycopg.pq import TransactionStatus

from ai_soc.workspace.db import site_transaction
from ai_soc.workspace.ingest.indexer_reader import (
    IndexerAuthError,
    IndexerError,
    Reader,
    TraversalRestart,
)
from ai_soc.workspace.ingest.repository import InsertCounts, insert_alert_page
from ai_soc.workspace.normalize.models import MappingProfile

DEFAULT_PAGE_SIZE = 500
DEFAULT_OVERLAP = timedelta(minutes=15)
INITIAL_LOOKBACK = timedelta(hours=24)
MAX_WINDOW = timedelta(days=31)
MAX_TRAVERSAL_RESTARTS = 3
PIPELINE_VERSION = "m1-ingestion-v1"


class ConcurrentIngestion(RuntimeError):
    """Another poll or backfill owns this site's source traversal."""


class IngestionConnectionError(RuntimeError):
    """Ingestion requires a dedicated autocommit connection outside caller transactions."""


class IngestionFailure(RuntimeError):
    """A partial or failed traversal was recorded and did not advance the checkpoint."""

    def __init__(self, run_id: UUID, reason: str) -> None:
        self.run_id = run_id
        self.reason = reason
        super().__init__(f"ingestion run {run_id} was partial: {reason}")


@dataclass(frozen=True, slots=True)
class IngestResult:
    run_id: UUID
    kind: Literal["poll", "backfill"]
    window_from: datetime
    window_to: datetime
    read_count: int
    inserted_count: int
    duplicate_count: int
    mutation_count: int
    outcome: Literal["ok"]


def poll_once(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    authorized_sites: frozenset[str],
    reader: Reader,
    index_pattern: str,
    profile: MappingProfile,
    now: datetime,
    page_size: int = DEFAULT_PAGE_SIZE,
    overlap: timedelta = DEFAULT_OVERLAP,
    initial_lookback: timedelta = INITIAL_LOOKBACK,
    max_restarts: int = MAX_TRAVERSAL_RESTARTS,
) -> IngestResult:
    """Poll on a dedicated autocommit connection from the prior upper bound through ``now``."""
    require_ingestion_connection(conn)
    _validate_settings(site_id, authorized_sites, index_pattern, profile, page_size, max_restarts)
    upper = _utc(now)
    if overlap < timedelta(0) or overlap > timedelta(days=1):
        raise ValueError("poll overlap must be between zero and one day")
    if initial_lookback <= timedelta(0) or initial_lookback > MAX_WINDOW:
        raise ValueError("initial lookback must be positive and at most 31 days")
    key = lock_key(site_id, index_pattern)
    acquire_source_lock(conn, key)
    try:
        with site_transaction(conn, site_id, authorized_sites):
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT checkpoint_ts FROM checkpoints
                    WHERE site_id = %s AND index_pattern = %s
                    """,
                    (site_id, index_pattern),
                )
                row = cursor.fetchone()
        if row is None:
            start = upper - initial_lookback
            checkpoint_before: datetime | None = None
        else:
            stored_checkpoint = row[0]
            if stored_checkpoint is None:
                raise RuntimeError("stored checkpoint timestamp is null")
            checkpoint_before = cast(datetime, stored_checkpoint)
            checkpoint_before = _utc(checkpoint_before)
            start = checkpoint_before - overlap
            if checkpoint_before > upper:
                upper = checkpoint_before
        return ingest_window(
            conn,
            kind="poll",
            site_id=site_id,
            authorized_sites=authorized_sites,
            reader=reader,
            index_pattern=index_pattern,
            profile=profile,
            start=start,
            end=upper,
            page_size=page_size,
            max_restarts=max_restarts,
            checkpoint_before=checkpoint_before,
            overlap_seconds=int(overlap.total_seconds()),
        )
    finally:
        release_source_lock(conn, key)


def backfill(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    authorized_sites: frozenset[str],
    reader: Reader,
    index_pattern: str,
    profile: MappingProfile,
    start: datetime,
    end: datetime,
    page_size: int = DEFAULT_PAGE_SIZE,
    max_restarts: int = MAX_TRAVERSAL_RESTARTS,
) -> IngestResult:
    """Re-read a fixed window on a dedicated autocommit connection."""
    require_ingestion_connection(conn)
    _validate_settings(site_id, authorized_sites, index_pattern, profile, page_size, max_restarts)
    lower = _utc(start)
    upper = _utc(end)
    if lower >= upper or upper - lower > MAX_WINDOW:
        raise ValueError("backfill must be a non-empty window no longer than 31 days")
    key = lock_key(site_id, index_pattern)
    acquire_source_lock(conn, key)
    try:
        return ingest_window(
            conn,
            kind="backfill",
            site_id=site_id,
            authorized_sites=authorized_sites,
            reader=reader,
            index_pattern=index_pattern,
            profile=profile,
            start=lower,
            end=upper,
            page_size=page_size,
            max_restarts=max_restarts,
            checkpoint_before=None,
            overlap_seconds=0,
        )
    finally:
        release_source_lock(conn, key)


def ingest_window(
    conn: psycopg.Connection[Any],
    *,
    kind: Literal["poll", "backfill"],
    site_id: str,
    authorized_sites: frozenset[str],
    reader: Reader,
    index_pattern: str,
    profile: MappingProfile,
    start: datetime,
    end: datetime,
    page_size: int,
    max_restarts: int,
    checkpoint_before: datetime | None,
    overlap_seconds: int,
) -> IngestResult:
    require_ingestion_connection(conn)
    run_id = uuid4()
    _start_run(
        conn,
        site_id=site_id,
        authorized_sites=authorized_sites,
        run_id=run_id,
        kind=kind,
        start=start,
        end=end,
    )
    counts = InsertCounts(0, 0, 0, 0)
    completed = False
    failure: IndexerError | None = None
    for attempt in range(max_restarts + 1):
        try:
            for page in reader.iter_window(
                index_pattern=index_pattern,
                start=start,
                end=end,
                page_size=page_size,
                time_field=profile.time_field,
            ):
                with site_transaction(conn, site_id, authorized_sites):
                    page_counts = insert_alert_page(
                        conn,
                        site_id=site_id,
                        index_pattern=index_pattern,
                        run_id=str(run_id),
                        hits=page.hits,
                        profile=profile,
                    )
                counts = _add_counts(counts, page_counts)
            completed = True
            break
        except IndexerAuthError as exc:
            failure = exc
            break
        except TraversalRestart as exc:
            failure = exc
            if attempt < max_restarts:
                continue
            break
        except IndexerError as exc:
            failure = exc
            break
        except Exception as exc:
            _finish_failed_run(
                conn,
                site_id=site_id,
                authorized_sites=authorized_sites,
                run_id=run_id,
                now=end,
                error_code="INGESTION_ERROR",
                reason=type(exc).__name__,
                auth_failed=False,
            )
            raise IngestionFailure(run_id, type(exc).__name__) from exc

    if not completed:
        reason = "AUTH_FAILED" if isinstance(failure, IndexerAuthError) else "SOURCE_INCOMPLETE"
        detail = (
            "pipeline indexer authorization failed"
            if isinstance(failure, IndexerAuthError)
            else str(failure)
        )
        _finish_failed_run(
            conn,
            site_id=site_id,
            authorized_sites=authorized_sites,
            run_id=run_id,
            now=end,
            error_code=reason,
            reason=detail,
            auth_failed=isinstance(failure, IndexerAuthError),
        )
        raise IngestionFailure(run_id, reason) from failure

    with site_transaction(conn, site_id, authorized_sites):
        if kind == "poll":
            _complete_checkpoint(
                conn,
                site_id=site_id,
                index_pattern=index_pattern,
                checkpoint_before=checkpoint_before,
                upper=end,
                overlap_seconds=overlap_seconds,
            )
        conn.execute(
            """
            UPDATE pipeline_runs
            SET finished_at = now(), outcome = 'ok', error_code = NULL, partial_reason = NULL
            WHERE site_id = %s AND run_id = %s
            """,
            (site_id, run_id),
        )
        conn.execute(
            """
            UPDATE sites SET health = 'ok', health_detail = NULL, updated_at = now()
            WHERE site_id = %s
            """,
            (site_id,),
        )
    return IngestResult(
        run_id,
        kind,
        start,
        end,
        counts.read,
        counts.inserted,
        counts.duplicates,
        counts.mutations,
        "ok",
    )


def _start_run(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    authorized_sites: frozenset[str],
    run_id: UUID,
    kind: Literal["poll", "backfill"],
    start: datetime,
    end: datetime,
) -> None:
    with site_transaction(conn, site_id, authorized_sites):
        conn.execute(
            """
            INSERT INTO pipeline_runs
                (run_id, site_id, kind, started_at, window_from, window_to, pipeline_version)
            VALUES (%s, %s, %s, now(), %s, %s, %s)
            """,
            (run_id, site_id, kind, start, end, PIPELINE_VERSION),
        )


def _complete_checkpoint(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    index_pattern: str,
    checkpoint_before: datetime | None,
    upper: datetime,
    overlap_seconds: int,
) -> None:
    if checkpoint_before is None:
        conn.execute(
            """
            INSERT INTO checkpoints
                (site_id, index_pattern, checkpoint_ts, last_sort, overlap_seconds)
            VALUES (%s, %s, %s, NULL, %s)
            ON CONFLICT (site_id, index_pattern) DO UPDATE
            SET checkpoint_ts = GREATEST(checkpoints.checkpoint_ts, EXCLUDED.checkpoint_ts),
                last_sort = NULL,
                overlap_seconds = EXCLUDED.overlap_seconds,
                updated_at = now()
            """,
            (site_id, index_pattern, upper, overlap_seconds),
        )
        return
    with conn.cursor() as cursor:
        cursor.execute(
            """
            UPDATE checkpoints
            SET checkpoint_ts = GREATEST(checkpoint_ts, %s), last_sort = NULL,
                overlap_seconds = %s, updated_at = now()
            WHERE site_id = %s AND index_pattern = %s AND checkpoint_ts = %s
            RETURNING checkpoint_ts
            """,
            (upper, overlap_seconds, site_id, index_pattern, checkpoint_before),
        )
        if cursor.fetchone() is None:
            raise RuntimeError("checkpoint changed while this poller held its source fence")


def _finish_failed_run(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    authorized_sites: frozenset[str],
    run_id: UUID,
    now: datetime,
    error_code: str,
    reason: str,
    auth_failed: bool,
) -> None:
    health = "auth_failed" if auth_failed else "lagging"
    safe_reason = reason[:500]
    with site_transaction(conn, site_id, authorized_sites):
        conn.execute(
            """
            UPDATE pipeline_runs
            SET finished_at = %s, outcome = 'partial', error_code = %s, partial_reason = %s
            WHERE site_id = %s AND run_id = %s
            """,
            (now, error_code, safe_reason, site_id, run_id),
        )
        conn.execute(
            """
            UPDATE sites SET health = %s, health_detail = %s, updated_at = now()
            WHERE site_id = %s
            """,
            (health, safe_reason, site_id),
        )


def _validate_settings(
    site_id: str,
    authorized_sites: frozenset[str],
    index_pattern: str,
    profile: MappingProfile,
    page_size: int,
    max_restarts: int,
) -> None:
    if not site_id or site_id not in authorized_sites:
        raise PermissionError("worker is not configured for this site")
    if not index_pattern:
        raise ValueError("an explicit alert index pattern is required")
    if page_size < 1 or page_size > 5000:
        raise ValueError("page size must be in 1..5000")
    if max_restarts < 0 or max_restarts > 8:
        raise ValueError("traversal restart count must be in 0..8")
    if not profile.profile_id or not profile.time_field:
        raise ValueError("a pinned mapping profile is required")


def require_ingestion_connection(conn: psycopg.Connection[Any]) -> None:
    """Reject caller transactions so each site_transaction commits durably per page."""
    if not conn.autocommit:
        raise IngestionConnectionError("ingestion requires a dedicated autocommit connection")
    if conn.info.transaction_status is not TransactionStatus.IDLE:
        raise IngestionConnectionError("ingestion cannot run inside a caller-owned transaction")


def _add_counts(left: InsertCounts, right: InsertCounts) -> InsertCounts:
    return InsertCounts(
        left.read + right.read,
        left.inserted + right.inserted,
        left.duplicates + right.duplicates,
        left.mutations + right.mutations,
    )


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("window and polling timestamps must be timezone-aware")
    return value.astimezone(UTC)


def lock_key(site_id: str, index_pattern: str) -> tuple[int, int]:
    digest = hashlib.sha256(f"{site_id}\0{index_pattern}".encode()).digest()
    first = int.from_bytes(digest[:4], "big", signed=True)
    second = int.from_bytes(digest[4:8], "big", signed=True)
    return first, second


def acquire_source_lock(conn: psycopg.Connection[Any], key: tuple[int, int]) -> None:
    with conn.cursor() as cursor:
        cursor.execute("SELECT pg_try_advisory_lock(%s, %s)", key)
        row = cursor.fetchone()
    if row is None or not row[0]:
        raise ConcurrentIngestion("another traversal owns this source")


def release_source_lock(conn: psycopg.Connection[Any], key: tuple[int, int]) -> None:
    if conn.closed:
        return
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_unlock(%s, %s)", key)
    except psycopg.Error:
        # Connection loss releases session locks; the caller's traversal has already failed.
        return
