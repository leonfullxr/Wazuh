"""Site-scoped persistence for stable groups and retained member evidence."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, cast

import psycopg
from psycopg.pq import TransactionStatus
from psycopg.types.json import Jsonb

from ai_soc.workspace.jobs import enqueue_job
from ai_soc.workspace.triage.grouping import GroupAlert, group_alerts
from ai_soc.workspace.triage.score import SCORE_VERSION


@dataclass(frozen=True, slots=True)
class PersistedGroup:
    site_id: str
    group_id: str
    revision: str
    bucket_start: datetime
    first_ts: datetime
    last_ts: datetime
    member_keys: tuple[str, ...]
    created: bool


def _require_site(conn: psycopg.Connection[Any], site_id: str) -> None:
    if conn.info.transaction_status is TransactionStatus.IDLE:
        raise PermissionError("triage writes require an active site transaction")
    row = conn.execute("SELECT current_setting('app.site_id', true)").fetchone()
    if row is None or row[0] != site_id:
        raise PermissionError("triage operation requires an active transaction for its site")


def group_batch(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    alert_keys: tuple[str, ...] | list[str],
    pipeline_version: str,
    now: datetime,
) -> tuple[PersistedGroup, ...]:
    """Group normalized alerts, merge retained members, and enqueue enrichment atomically.

    The caller owns the transaction and site RLS context. `alert_keys` bounds the new
    normalization cohort; each stable group revision is rebuilt from its entire latest
    retained membership so a late arrival never drops prior members.
    """
    _require_site(conn, site_id)
    if not pipeline_version or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("pipeline_version and timezone-aware now are required")
    keys = tuple(dict.fromkeys(alert_keys))
    if not keys:
        return ()
    rows = conn.execute(
        """
        SELECT a.alert_key, a.event_ts, a.source_hash, a.normalized
        FROM alerts AS a
        WHERE a.site_id = %s AND a.alert_key = ANY(%s) AND a.normalized_at IS NOT NULL
        ORDER BY a.event_ts, a.alert_key
        """,
        (site_id, list(keys)),
    ).fetchall()
    input_alerts: list[GroupAlert] = []
    normalized_by_key: dict[str, dict[str, Any]] = {}
    source_by_key: dict[str, str] = {}
    event_by_key: dict[str, datetime] = {}
    for alert_key, event_ts, source_hash, raw_normalized in rows:
        normalized = cast(dict[str, Any], raw_normalized or {})
        primary = _primary_entity(conn, site_id, str(alert_key), normalized)
        input_alerts.append(
            GroupAlert(
                site_id=site_id,
                alert_key=str(alert_key),
                source_hash=str(source_hash),
                event_ts=event_ts,
                rule_id=_optional_str(normalized.get("rule_id")),
                agent_id=_optional_str(normalized.get("agent_id")),
                primary_entity=primary,
            )
        )
        normalized_by_key[str(alert_key)] = normalized
        source_by_key[str(alert_key)] = str(source_hash)
        event_by_key[str(alert_key)] = event_ts
    if len(input_alerts) != len(set(keys)):
        missing = sorted(set(keys) - set(normalized_by_key))
        raise ValueError(f"alerts must be normalized before grouping: {missing[:5]}")

    drafts = group_alerts(tuple(input_alerts))
    persisted: list[PersistedGroup] = []
    for input_draft in drafts:
        # Serialize writes to this stable identity before reading the prior cohort.
        conn.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (f"{site_id}:{input_draft.group_id}",),
        )
        prior = _latest_members(conn, site_id=site_id, group_id=input_draft.group_id)
        combined = dict(prior)
        for alert in (item for item in input_alerts if item.alert_key in input_draft.member_keys):
            combined[alert.alert_key] = alert
        full_drafts = group_alerts(
            tuple(sorted(combined.values(), key=lambda item: item.alert_key))
        )
        if len(full_drafts) != 1 or full_drafts[0].group_id != input_draft.group_id:
            raise RuntimeError("retained group members do not match their stable fingerprint")
        draft = full_drafts[0]
        first_normalized = normalized_by_key.get(draft.member_keys[0])
        if first_normalized is None:
            first_normalized = _snapshot_for_member(
                conn, site_id=site_id, group_id=draft.group_id, member_key=draft.member_keys[0]
            )
        title = _group_title(first_normalized)
        conn.execute(
            """
            INSERT INTO subject_registry (site_id, subject_kind, subject_id)
            VALUES (%s, 'group', %s)
            ON CONFLICT DO NOTHING
            """,
            (site_id, draft.group_id),
        )
        conn.execute(
            """
            INSERT INTO groups
                (site_id, group_id, fingerprint_spec, fingerprint, bucket_start, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (site_id, group_id) DO NOTHING
            """,
            (
                site_id,
                draft.group_id,
                draft.fingerprint_spec,
                draft.fingerprint,
                draft.bucket_start,
                now,
            ),
        )
        identity = conn.execute(
            """SELECT fingerprint_spec, fingerprint, bucket_start FROM groups
               WHERE site_id = %s AND group_id = %s""",
            (site_id, draft.group_id),
        ).fetchone()
        if identity != (draft.fingerprint_spec, draft.fingerprint, draft.bucket_start):
            raise RuntimeError("stable group identity collision")

        existing_revision = conn.execute(
            "SELECT pipeline_version FROM group_revisions "
            "WHERE site_id = %s AND group_id = %s AND revision = %s",
            (site_id, draft.group_id, draft.revision),
        ).fetchone()
        created = existing_revision is None
        latest_enrichment_job = None
        if not created:
            latest_enrichment_job = conn.execute(
                """
                SELECT job_id, payload->>'pipeline_version'
                FROM jobs
                WHERE site_id = %s AND kind IN ('enrich_group', 'rescore_group')
                  AND payload->>'group_id' = %s
                  AND payload->>'group_revision' = %s
                  AND payload ? 'pipeline_version'
                    ORDER BY job_id DESC
                LIMIT 1
                """,
                (site_id, draft.group_id, draft.revision),
            ).fetchone()
        latest_pipeline_version = None
        if not created:
            latest_pipeline_version = (
                str(existing_revision[0])
                if latest_enrichment_job is None or latest_enrichment_job[1] is None
                else str(latest_enrichment_job[1])
            )
        if created:
            conn.execute(
                """
                INSERT INTO group_revisions
                    (site_id, group_id, revision, first_ts, last_ts, alert_count, rule_id,
                     agent_id, primary_entity, title, pipeline_version, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    site_id,
                    draft.group_id,
                    draft.revision,
                    draft.first_ts,
                    draft.last_ts,
                    len(draft.member_keys),
                    _optional_str(first_normalized.get("rule_id")),
                    _optional_str(first_normalized.get("agent_id")),
                    _primary_entity(conn, site_id, draft.member_keys[0], first_normalized),
                    title,
                    pipeline_version,
                    now,
                ),
            )
            for member in draft.member_keys:
                if member in normalized_by_key:
                    snapshot = dict(normalized_by_key[member])
                    event_ts = event_by_key[member]
                    source_hash = source_by_key[member]
                    snapshot["_primary_entity"] = _primary_entity(conn, site_id, member, snapshot)
                    snapshot["_entity_refs"] = _member_entities(
                        conn, site_id=site_id, alert_key=member
                    )
                else:
                    snapshot_row = conn.execute(
                        """
                        SELECT gm.event_ts, gm.source_hash, gm.normalized_snapshot
                        FROM group_members AS gm
                        WHERE gm.site_id = %s AND gm.group_id = %s
                          AND gm.alert_key = %s
                        ORDER BY gm.group_revision DESC LIMIT 1
                        """,
                        (site_id, draft.group_id, member),
                    ).fetchone()
                    if snapshot_row is None:
                        raise RuntimeError("retained group member snapshot disappeared")
                    event_ts, source_hash, snapshot = snapshot_row
                    snapshot = dict(snapshot)
                conn.execute(
                    """
                    INSERT INTO group_members
                        (site_id, group_id, group_revision, alert_key, event_ts, source_hash,
                         normalized_snapshot)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        site_id,
                        draft.group_id,
                        draft.revision,
                        member,
                        event_ts,
                        source_hash,
                        Jsonb(snapshot),
                    ),
                )
            conn.execute(
                """
                INSERT INTO group_heads (site_id, group_id, current_revision, updated_at)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (site_id, group_id) DO UPDATE
                SET current_revision = EXCLUDED.current_revision,
                    updated_at = EXCLUDED.updated_at
                """,
                (site_id, draft.group_id, draft.revision, now),
            )
            conn.execute(
                """
                INSERT INTO work_items (site_id, group_id, status, owner_key, updated_at)
                VALUES (%s, %s, 'new', NULL, %s)
                ON CONFLICT (site_id, group_id) DO NOTHING
                """,
                (site_id, draft.group_id, now),
            )
            enqueue_job(
                conn,
                site_id=site_id,
                kind="enrich_group",
                subject=f"{draft.group_id}:{draft.revision}",
                payload={
                    "group_id": draft.group_id,
                    "group_revision": draft.revision,
                    "pipeline_version": pipeline_version,
                    "computation_version": SCORE_VERSION,
                    "as_of": now.isoformat(),
                },
            )
            bucket_end = draft.bucket_start + timedelta(hours=1)
            if now < bucket_end:
                closure_cutoff = bucket_end.isoformat()
                enqueue_job(
                    conn,
                    site_id=site_id,
                    kind="enrich_group",
                    subject=(
                        f"{draft.group_id}:{draft.revision}:bucket-close:"
                        f"{closure_cutoff}:{SCORE_VERSION}"
                    ),
                    payload={
                        "group_id": draft.group_id,
                        "group_revision": draft.revision,
                        "pipeline_version": pipeline_version,
                        "computation_version": SCORE_VERSION,
                        "as_of": closure_cutoff,
                    },
                    run_after=bucket_end,
                )
        elif latest_pipeline_version != pipeline_version:
            # A context bundle or pipeline version changed while this immutable
            # membership revision stayed the same. Keep the old revision metadata
            # and evidence intact, and enqueue a distinct job pinned to the new
            # version so the same input can be evaluated under a new identity.
            version_key = hashlib.sha256(pipeline_version.encode("utf-8")).hexdigest()
            previous_job_id = (
                "revision" if latest_enrichment_job is None else str(latest_enrichment_job[0])
            )
            enqueue_job(
                conn,
                site_id=site_id,
                kind="enrich_group",
                subject=(
                    f"{draft.group_id}:{draft.revision}:pipeline:{version_key}:after:{previous_job_id}"
                ),
                payload={
                    "group_id": draft.group_id,
                    "group_revision": draft.revision,
                    "pipeline_version": pipeline_version,
                    "computation_version": SCORE_VERSION,
                    "as_of": now.isoformat(),
                },
            )
            bucket_end = draft.bucket_start + timedelta(hours=1)
            if now < bucket_end:
                closure_cutoff = bucket_end.isoformat()
                enqueue_job(
                    conn,
                    site_id=site_id,
                    kind="enrich_group",
                    subject=(
                        f"{draft.group_id}:{draft.revision}:pipeline:{version_key}:"
                        f"after:{previous_job_id}:bucket-close:{closure_cutoff}:{SCORE_VERSION}"
                    ),
                    payload={
                        "group_id": draft.group_id,
                        "group_revision": draft.revision,
                        "pipeline_version": pipeline_version,
                        "computation_version": SCORE_VERSION,
                        "as_of": closure_cutoff,
                    },
                    run_after=bucket_end,
                )
        persisted.append(
            PersistedGroup(
                site_id=site_id,
                group_id=draft.group_id,
                revision=draft.revision,
                bucket_start=draft.bucket_start,
                first_ts=draft.first_ts,
                last_ts=draft.last_ts,
                member_keys=draft.member_keys,
                created=created,
            )
        )
    return tuple(persisted)


def _latest_members(
    conn: psycopg.Connection[Any], *, site_id: str, group_id: str
) -> dict[str, GroupAlert]:
    rows = conn.execute(
        """
        SELECT gm.alert_key, gm.event_ts, gm.source_hash, gm.normalized_snapshot
        FROM group_heads AS h
        JOIN group_members AS gm
          ON (gm.site_id, gm.group_id, gm.group_revision) =
             (h.site_id, h.group_id, h.current_revision)
        WHERE h.site_id = %s AND h.group_id = %s
        ORDER BY gm.alert_key
        """,
        (site_id, group_id),
    ).fetchall()
    result: dict[str, GroupAlert] = {}
    for key, event_ts, source_hash, snapshot in rows:
        values = cast(dict[str, Any], snapshot)
        result[str(key)] = GroupAlert(
            site_id=site_id,
            alert_key=str(key),
            source_hash=str(source_hash),
            event_ts=event_ts,
            rule_id=_optional_str(values.get("rule_id")),
            agent_id=_optional_str(values.get("agent_id")),
            primary_entity=_optional_str(values.get("_primary_entity")),
        )
    return result


def _snapshot_for_member(
    conn: psycopg.Connection[Any], *, site_id: str, group_id: str, member_key: str
) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT normalized_snapshot FROM group_members
        WHERE site_id = %s AND group_id = %s AND alert_key = %s
        ORDER BY group_revision DESC LIMIT 1
        """,
        (site_id, group_id, member_key),
    ).fetchone()
    if row is None:
        raise RuntimeError("group member has no retained normalized snapshot")
    return cast(dict[str, Any], row[0])


def _primary_entity(
    conn: psycopg.Connection[Any], site_id: str, alert_key: str, normalized: dict[str, Any]
) -> str | None:
    for key, kind in (("src_ip", "ip"), ("src_user", "user"), ("dst_user", "user")):
        value = normalized.get(key)
        if isinstance(value, str) and value:
            return f"{kind}:{value.casefold()}"
    row = conn.execute(
        """
        SELECT e.kind, e.value_norm
        FROM alert_entities AS ae JOIN entities AS e
          ON (e.site_id, e.entity_id) = (ae.site_id, ae.entity_id)
        WHERE ae.site_id = %s AND ae.alert_key = %s AND e.kind IN ('file', 'cve')
        ORDER BY CASE e.kind WHEN 'file' THEN 1 ELSE 2 END, e.value_norm LIMIT 1
        """,
        (site_id, alert_key),
    ).fetchone()
    if row is None:
        return None
    return f"{row[0]}:{row[1]}"


def _member_entities(
    conn: psycopg.Connection[Any], *, site_id: str, alert_key: str
) -> list[dict[str, str]]:
    rows = conn.execute(
        """
        SELECT e.entity_id, e.kind, e.value_norm, ae.role
        FROM alert_entities AS ae JOIN entities AS e
          ON (e.site_id, e.entity_id) = (ae.site_id, ae.entity_id)
        WHERE ae.site_id = %s AND ae.alert_key = %s
        ORDER BY e.kind, e.value_norm, ae.role
        """,
        (site_id, alert_key),
    ).fetchall()
    return [
        {
            "entity_id": str(entity_id),
            "kind": str(kind),
            "value": str(value),
            "role": str(role),
        }
        for entity_id, kind, value, role in rows
    ]


def _group_title(normalized: dict[str, Any]) -> str:
    description = normalized.get("rule_description")
    if not isinstance(description, str) or not description.strip():
        description = f"Wazuh rule {normalized.get('rule_id') or 'unknown'}"
    agent = normalized.get("agent_name") or normalized.get("agent_id")
    return (
        f"{description.strip()} on {agent}"
        if isinstance(agent, str) and agent
        else description.strip()
    )


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None
