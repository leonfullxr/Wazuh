"""Transactional audit event creation and acknowledged outbox delivery."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol, cast
from uuid import UUID, uuid4

import psycopg
from psycopg.pq import TransactionStatus
from psycopg.types.json import Jsonb


class AuditSink(Protocol):
    """Audit destination that returns true only after durable acknowledgement."""

    def send(self, event: AuditEvent, /) -> bool: ...


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Complete immutable audit envelope stored by the caller's transaction."""

    event_id: UUID
    site_id: str
    kind: str
    actor_key: str | None
    payload: dict[str, object]
    created_at: datetime


def _require_site_transaction(conn: psycopg.Connection[Any], site_id: str) -> None:
    if conn.info.transaction_status is TransactionStatus.IDLE:
        raise RuntimeError("audit writes require the caller's site transaction")
    with conn.cursor() as cursor:
        cursor.execute("SELECT current_setting('app.site_id', true)")
        row = cursor.fetchone()
    if row is None or row[0] != site_id:
        raise PermissionError("audit operation requires an active transaction for its site")


def record_audit(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    kind: str,
    actor_key: str | None,
    payload: dict[str, Any],
) -> UUID:
    """Write an audit event in the caller's transaction and return its dedupe key."""
    _require_site_transaction(conn, site_id)
    event_id = uuid4()
    conn.execute(
        """
        INSERT INTO audit_outbox (event_id, site_id, kind, actor_key, payload)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (event_id, site_id, kind, actor_key, Jsonb(payload)),
    )
    return event_id


def _pending_for_site(
    conn: psycopg.Connection[Any], *, site_id: str, now: datetime
) -> tuple[Any, ...] | None:
    with conn.cursor() as cursor:
        cursor.execute(
            """
            SELECT event_id, site_id, kind, actor_key, payload, created_at
            FROM audit_outbox
            WHERE site_id = %s AND sent_at IS NULL
              AND retry_at <= %s
            ORDER BY retry_at, created_at, event_id
            LIMIT 1 FOR UPDATE SKIP LOCKED
            """,
            (site_id, now),
        )
        return cursor.fetchone()


def relay_audit_once(
    conn: psycopg.Connection[Any],
    sink: AuditSink,
    now: datetime,
    *,
    site_id: str,
    authorized_sites: frozenset[str],
) -> int:
    """Deliver one pending event; mark it sent only after the sink acknowledges it."""
    if site_id not in authorized_sites:
        raise PermissionError("audit relay is not configured for this site")
    if conn.info.transaction_status is TransactionStatus.IDLE:
        from ai_soc.workspace.db import site_transaction

        with site_transaction(conn, site_id, authorized_sites):
            return relay_audit_once(
                conn, sink, now, site_id=site_id, authorized_sites=authorized_sites
            )
    _require_site_transaction(conn, site_id)
    row = _pending_for_site(conn, site_id=site_id, now=now)
    if row is None:
        return 0
    event = AuditEvent(
        event_id=cast(UUID, row[0]),
        site_id=str(row[1]),
        kind=str(row[2]),
        actor_key=None if row[3] is None else str(row[3]),
        payload=cast(dict[str, object], row[4]),
        created_at=row[5],
    )
    try:
        acknowledged = sink.send(event)
        failure = None if acknowledged else "sink did not acknowledge"
    except Exception as exc:
        acknowledged = False
        failure = type(exc).__name__

    if acknowledged:
        conn.execute(
            "UPDATE audit_outbox SET attempts = attempts + 1, last_attempt_at = %s, sent_at = %s "
            "WHERE event_id = %s AND site_id = %s AND sent_at IS NULL",
            (now, now, event.event_id, site_id),
        )
        return 1
    conn.execute(
        """
        UPDATE audit_outbox
        SET attempts = attempts + 1,
            last_attempt_at = %s,
            retry_at = %s + make_interval(
                secs => LEAST(300, (2 ^ LEAST(attempts, 9))::integer)
            ),
            last_error = %s
        WHERE event_id = %s AND site_id = %s AND sent_at IS NULL
        """,
        (now, now, failure, event.event_id, site_id),
    )
    return 0


def oldest_pending_age_seconds(
    conn: psycopg.Connection[Any], *, site_id: str, now: datetime
) -> float | None:
    """Return the oldest pending event's age for the current site's metric."""
    _require_site_transaction(conn, site_id)
    with conn.cursor() as cursor:
        cursor.execute(
            "SELECT EXTRACT(EPOCH FROM (%s - MIN(created_at))) "
            "FROM audit_outbox WHERE site_id = %s AND sent_at IS NULL",
            (now, site_id),
        )
        row = cursor.fetchone()
    if row is None or row[0] is None:
        return None
    return float(row[0])
