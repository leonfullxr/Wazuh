"""Idempotent normalized records, entity links and hourly count writes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

import psycopg
from psycopg.types.json import Jsonb

from ai_soc.workspace.jobs import Job, complete_job
from ai_soc.workspace.normalize.models import MappingProfile, NormalizedAlert
from ai_soc.workspace.normalize.normalizer import normalize_alert


class MappingRevisionConflict(RuntimeError):
    """Stored normalization belongs to another immutable profile revision."""


@dataclass(frozen=True, slots=True)
class NormalizeCounts:
    normalized: int
    already_normalized: int
    entities_linked: int


def normalize_batch(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    alert_keys: tuple[str, ...],
    profile: MappingProfile,
    now: datetime,
) -> NormalizeCounts:
    if not alert_keys:
        return NormalizeCounts(0, 0, 0)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("normalization timestamp must be timezone-aware")
    normalized_count = 0
    already_count = 0
    links_count = 0
    with conn.cursor() as cursor:
        cursor.execute(
            """
            SELECT alert_key, event_ts, raw, mapping_profile, normalized_at
            FROM alerts
            WHERE site_id = %s AND alert_key = ANY(%s)
            ORDER BY event_ts, alert_key
            FOR UPDATE
            """,
            (site_id, list(dict.fromkeys(alert_keys))),
        )
        rows = cursor.fetchall()
    seen: set[str] = set()
    for alert_key, event_ts, raw, stored_profile, normalized_at in rows:
        if alert_key in seen:
            continue
        seen.add(str(alert_key))
        if normalized_at is not None:
            if stored_profile != profile.profile_id:
                raise MappingRevisionConflict("alert already uses another mapping profile")
            already_count += 1
            continue
        if stored_profile != profile.profile_id:
            raise MappingRevisionConflict(
                "job mapping profile does not match immutable alert profile"
            )
        if not isinstance(raw, dict):
            raise ValueError("stored source payload is malformed")
        result = normalize_alert(cast(dict[str, object], raw), profile)
        normalized = _normalized_json(result)
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE alerts
                SET normalized = %s, normalized_at = %s, normalize_gaps = %s
                WHERE site_id = %s AND alert_key = %s AND event_ts = %s
                  AND normalized_at IS NULL
                RETURNING alert_key
                """,
                (
                    Jsonb(normalized),
                    now.astimezone(UTC),
                    list(result.gaps),
                    site_id,
                    alert_key,
                    event_ts,
                ),
            )
            updated = cursor.fetchone()
        if updated is None:
            raise RuntimeError("normalized alert changed while its row lock was held")
        links_count += _upsert_entities(
            conn,
            site_id=site_id,
            alert_key=str(alert_key),
            event_ts=event_ts,
            entities=result,
        )
        _record_rollup(conn, site_id=site_id, event_ts=event_ts, alert=result)
        normalized_count += 1
    return NormalizeCounts(normalized_count, already_count, links_count)


def normalize_job(
    conn: psycopg.Connection[Any],
    *,
    job: Job,
    worker_id: str,
    now: datetime,
    profile: MappingProfile,
) -> NormalizeCounts:
    """Commit normalization and its fenced job completion in the caller's site tx."""
    if job.kind != "normalize_alert" or job.site_id != _active_site(conn):
        raise PermissionError("normalization job is outside the active site transaction")
    if job.payload.get("mapping_profile") != profile.profile_id:
        raise MappingRevisionConflict("job profile does not match loaded profile")
    alert_key = job.payload.get("alert_key")
    if not isinstance(alert_key, str) or alert_key != job.subject:
        raise ValueError("normalization job subject is malformed")
    result = normalize_batch(
        conn,
        site_id=job.site_id,
        alert_keys=(alert_key,),
        profile=profile,
        now=now,
    )
    complete_job(
        conn,
        job_id=job.job_id,
        worker_id=worker_id,
        lease_token=job.lease_token,
        now=now,
    )
    return result


def _normalized_json(alert: NormalizedAlert) -> dict[str, object]:
    return {
        "wazuh_id": alert.wazuh_id,
        "rule_id": alert.rule_id,
        "rule_level": alert.rule_level,
        "rule_description": alert.rule_description,
        "rule_groups": list(alert.rule_groups),
        "mitre_tactics": list(alert.mitre_tactics),
        "mitre_techniques": list(alert.mitre_techniques),
        "agent_id": alert.agent_id,
        "agent_name": alert.agent_name,
        "agent_ip": alert.agent_ip,
        "manager": alert.manager,
        "decoder": alert.decoder,
        "location": alert.location,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "src_user": alert.src_user,
        "dst_user": alert.dst_user,
    }


def _upsert_entities(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    alert_key: str,
    event_ts: datetime,
    entities: NormalizedAlert,
) -> int:
    inserted_links = 0
    for entity in entities.entities:
        value_norm = _entity_value(entity.kind, entity.value)
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO entities
                    (site_id, kind, value_norm, classification, first_seen, last_seen)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (site_id, kind, value_norm)
                DO UPDATE SET first_seen = LEAST(entities.first_seen, EXCLUDED.first_seen),
                              last_seen = GREATEST(entities.last_seen, EXCLUDED.last_seen),
                              classification = COALESCE(
                                  entities.classification, EXCLUDED.classification
                              )
                RETURNING entity_id
                """,
                (site_id, entity.kind, value_norm, entity.classification, event_ts, event_ts),
            )
            row = cursor.fetchone()
        if row is None:
            raise RuntimeError("entity upsert did not return an id")
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO alert_entities (site_id, alert_key, event_ts, entity_id, role)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
                RETURNING entity_id
                """,
                (site_id, alert_key, event_ts, int(row[0]), entity.role),
            )
            if cursor.fetchone() is not None:
                inserted_links += 1
    return inserted_links


def _record_rollup(
    conn: psycopg.Connection[Any], *, site_id: str, event_ts: datetime, alert: NormalizedAlert
) -> None:
    level_band = _level_band(alert.rule_level)
    rule_id = alert.rule_id or ""
    agent_id = alert.agent_id or ""
    hour = event_ts.astimezone(UTC).replace(minute=0, second=0, microsecond=0)
    conn.execute(
        """
        INSERT INTO alert_hourly (site_id, hour, level_band, rule_id, agent_id, count)
        VALUES (%s, %s, %s, %s, %s, 1)
        ON CONFLICT (site_id, hour, level_band, rule_id, agent_id)
        DO UPDATE SET count = alert_hourly.count + 1
        """,
        (site_id, hour, level_band, rule_id, agent_id),
    )


def _level_band(level: int | None) -> str:
    if level is None:
        return "unknown"
    if 0 <= level <= 6:
        return "0-6"
    if level <= 9:
        return "7-9"
    if level <= 12:
        return "10-12"
    if level <= 15:
        return "13-15"
    return "unknown"


def _entity_value(kind: str, value: str) -> str:
    if kind in {"host", "user", "process", "file", "hash", "rule_group"}:
        return value.casefold()
    if kind == "cve":
        return value.upper()
    return value


def _active_site(conn: psycopg.Connection[Any]) -> str | None:
    with conn.cursor() as cursor:
        cursor.execute("SELECT current_setting('app.site_id', true)")
        row = cursor.fetchone()
    return None if row is None or not row[0] else str(row[0])
