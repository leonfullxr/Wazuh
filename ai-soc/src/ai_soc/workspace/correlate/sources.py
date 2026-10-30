"""Bounded, immutable projections of retained raw file integrity events."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, cast

import psycopg
from psycopg.pq import TransactionStatus

from ai_soc.workspace.ingest.repository import canonical_source_hash

MAX_SOURCE_PATH = 4096
MAX_EXTRACTION_VERSION = 80
_EVENTS = {"550": "modified", "553": "deleted", "554": "added"}


@dataclass(frozen=True, slots=True)
class SourceProjection:
    site_id: str
    alert_key: str
    event_ts: datetime
    source_hash: str
    extraction_version: str
    projection_digest: str
    availability: str
    path: str | None
    event: str | None


def _raw_projection(raw: object) -> tuple[str | None, str | None, str]:
    if not isinstance(raw, dict):
        return None, None, "raw_unavailable"
    raw_value = cast(dict[str, Any], raw)
    syscheck_value: object = raw_value.get("syscheck")
    if not isinstance(syscheck_value, dict):
        return None, None, "syscheck_unavailable"
    syscheck = cast(dict[str, Any], syscheck_value)
    path = syscheck.get("path")
    raw_event = syscheck.get("event")
    rule_value: object = raw_value.get("rule")
    rule = cast(dict[str, Any], rule_value) if isinstance(rule_value, dict) else {}
    rule_id = rule.get("id")
    if not isinstance(path, str) or not path or len(path) > MAX_SOURCE_PATH:
        return None, None, "path_unavailable"
    if not isinstance(raw_event, str) or not isinstance(rule_id, (str, int)):
        return None, None, "event_unavailable"
    event = raw_event
    expected = _EVENTS.get(str(rule_id))
    if event not in {"modified", "deleted", "added"} or expected != event:
        return None, None, "unsupported_event_pair"
    return path, event, "available"


def _projection_digest(projection: SourceProjection) -> str:
    value = {
        "site_id": projection.site_id,
        "alert_key": projection.alert_key,
        "event_ts": projection.event_ts.astimezone(UTC).isoformat(),
        "source_hash": projection.source_hash,
        "extraction_version": projection.extraction_version,
        "availability": projection.availability,
        "path": projection.path,
        "event": projection.event,
    }
    return sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
    ).hexdigest()


def project_retained_sources(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    alert_keys: tuple[str, ...],
    extraction_version: str,
    create: bool = True,
) -> dict[str, SourceProjection]:
    """Batch verify registry/raw/projection witnesses, retaining evidence after raw expiry.

    ``create=False`` only reads existing immutable projections during replay. A
    present raw payload is always verified, even when a projection already exists.
    """
    if not site_id or any(not key for key in alert_keys) or not extraction_version:
        raise ValueError("site, alert and extraction version are required")
    if len(extraction_version) > MAX_EXTRACTION_VERSION:
        raise ValueError("extraction version is too long")
    if conn.info.transaction_status is TransactionStatus.IDLE:
        raise PermissionError("source projection requires an active site transaction")
    active_site = conn.execute("SELECT current_setting('app.site_id', true)").fetchone()
    if active_site is None or active_site[0] != site_id:
        raise PermissionError("source projection requires an active transaction for its site")
    keys = set(alert_keys)
    with conn.transaction():
        rows = conn.execute(
            """SELECT r.alert_key,r.original_event_ts,r.source_hash,a.raw,a.source_hash,
                      p.event_ts,p.source_hash,p.projection_digest,p.availability,
                      p.source_path,p.source_event
               FROM alert_registry r
               LEFT JOIN alerts a ON a.site_id=r.site_id AND a.alert_key=r.alert_key
                 AND a.event_ts=r.original_event_ts
               LEFT JOIN correlation_source_projections p ON p.site_id=r.site_id
                 AND p.alert_key=r.alert_key AND p.extraction_version=%s
               WHERE r.site_id=%s AND r.alert_key=ANY(%s)""",
            (extraction_version, site_id, list(keys)),
        ).fetchall()
        if len(rows) != len(keys):
            raise LookupError("original alert registry identity is unavailable")
        result: dict[str, SourceProjection] = {}
        missing: list[tuple[object, ...]] = []
        for row in rows:
            key, event_ts, registry_hash, raw, retained_hash = row[:5]
            saved: SourceProjection | None = None
            if row[7] is not None:
                saved = SourceProjection(
                    site_id,
                    key,
                    row[5],
                    str(row[6]),
                    extraction_version,
                    row[7],
                    row[8],
                    row[9],
                    row[10],
                )
                if (
                    saved.event_ts != event_ts
                    or saved.source_hash != str(registry_hash)
                    or _projection_digest(saved) != saved.projection_digest
                ):
                    raise ValueError("source projection differs from its original evidence")
            if retained_hash is not None:
                if canonical_source_hash(raw) != str(registry_hash) or str(retained_hash) != str(
                    registry_hash
                ):
                    raise ValueError("retained source does not match its original registry hash")
                path, event, availability = _raw_projection(raw)
            elif saved is not None:
                result[key] = saved
                continue
            else:
                path, event, availability = None, None, "raw_unavailable"
            projected = SourceProjection(
                site_id,
                key,
                event_ts,
                str(registry_hash),
                extraction_version,
                "",
                availability,
                path,
                event,
            )
            digest = _projection_digest(projected)
            projected = SourceProjection(
                site_id,
                key,
                event_ts,
                str(registry_hash),
                extraction_version,
                digest,
                availability,
                path,
                event,
            )
            if saved is not None:
                if saved != projected:
                    raise ValueError(
                        "source projection version already contains different evidence"
                    )
            elif not create:
                raise LookupError("frozen source projection is unavailable")
            else:
                missing.append(
                    (
                        site_id,
                        key,
                        event_ts,
                        registry_hash,
                        extraction_version,
                        digest,
                        availability,
                        path,
                        event,
                    )
                )
            result[key] = projected
        if missing:
            with conn.cursor() as cursor:
                cursor.executemany(
                    """INSERT INTO correlation_source_projections
                       (site_id,alert_key,event_ts,source_hash,extraction_version,
                        projection_digest,availability,source_path,source_event)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                       ON CONFLICT (site_id,alert_key,extraction_version) DO NOTHING""",
                    missing,
                )
            # A concurrent creator can win the insert. Verify its full evidence.
            saved_rows = conn.execute(
                """SELECT alert_key,event_ts,source_hash,projection_digest,availability,
                          source_path,source_event FROM correlation_source_projections
                   WHERE site_id=%s AND extraction_version=%s AND alert_key=ANY(%s)""",
                (site_id, extraction_version, [row[1] for row in missing]),
            ).fetchall()
            for row in saved_rows:
                actual = SourceProjection(
                    site_id,
                    row[0],
                    row[1],
                    str(row[2]),
                    extraction_version,
                    row[3],
                    row[4],
                    row[5],
                    row[6],
                )
                if actual != result[row[0]]:
                    raise ValueError(
                        "source projection version already contains different evidence"
                    )
            if len(saved_rows) != len(missing):
                raise RuntimeError("source projection insert was not visible")
        return result


def project_retained_source(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    alert_key: str,
    extraction_version: str,
) -> SourceProjection:
    """Verify one retained source in the caller's active site transaction."""
    return project_retained_sources(
        conn, site_id=site_id, alert_keys=(alert_key,), extraction_version=extraction_version
    )[alert_key]
