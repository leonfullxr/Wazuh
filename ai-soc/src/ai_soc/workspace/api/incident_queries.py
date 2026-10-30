"""Bounded read projections for incident summaries, evidence events, and context."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, LiteralString, cast
from uuid import UUID

import psycopg

from ai_soc.contracts.models import AskRequest
from ai_soc.validation.findings import (
    BoundTextRejected,
    _bound_display_text,  # pyright: ignore[reportPrivateUsage]
)


def list_incidents(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    filters: dict[str, object],
    after: tuple[datetime, str] | None,
    limit: int,
) -> list[dict[str, Any]]:
    clauses = ["i.site_id=%s"]
    params: list[Any] = [site_id]
    for key, expr in (("status", "i.status"), ("owner_key", "i.owner_key")):
        if filters.get(key) is not None:
            clauses.append(f"{expr}=%s")
            params.append(filters[key])
    if filters.get("unassigned"):
        clauses.append("i.owner_key IS NULL")
    if filters.get("min_priority") is not None:
        clauses.append("e.priority >= %s")
        params.append(filters["min_priority"])
    if filters.get("max_priority") is not None:
        clauses.append("e.priority <= %s")
        params.append(filters["max_priority"])
    if filters.get("from") is not None:
        clauses.append("i.created_at >= %s")
        params.append(filters["from"])
    if filters.get("to") is not None:
        clauses.append("i.created_at <= %s")
        params.append(filters["to"])
    if after is not None:
        clauses.append("(i.created_at,i.incident_id::text)<(%s,%s)")
        params.extend(after)
    params.append(limit)
    query = (
        "SELECT i.incident_id,i.title,i.owner_key,i.status,i.work_version,i.evidence_head,"
        "e.revision_seq,e.priority,i.created_at,i.created_by FROM incidents i "
        "JOIN incident_evidence_revisions e ON (e.site_id,e.incident_id,e.incident_revision_id)="
        "(i.site_id,i.incident_id,i.evidence_head) WHERE "
        + " AND ".join(clauses)
        + " ORDER BY i.created_at DESC,i.incident_id DESC LIMIT %s"
    )
    rows = conn.execute(cast(LiteralString, query), tuple(params)).fetchall()
    keys = (
        "incident_id",
        "title",
        "owner_key",
        "status",
        "work_version",
        "evidence_head",
        "revision_seq",
        "priority",
        "created_at",
        "created_by",
    )
    return [dict(zip(keys, row, strict=True)) for row in rows]


def incident_events(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    incident_id: UUID,
    evidence_revision: UUID,
    start: datetime | None,
    end: datetime | None,
    after: tuple[datetime, str] | None,
    limit: int,
) -> list[dict[str, Any]]:
    clauses = ["m.site_id=%s", "m.incident_id=%s", "m.incident_revision_id=%s"]
    params: list[Any] = [site_id, incident_id, evidence_revision]
    if start is not None:
        clauses.append("gm.event_ts >= %s")
        params.append(start)
    if end is not None:
        clauses.append("gm.event_ts < %s")
        params.append(end)
    if after is not None:
        clauses.append("(gm.event_ts,gm.alert_key)>(%s,%s)")
        params.extend(after)
    params.append(limit)
    query = (
        "SELECT gm.event_ts,gm.alert_key,gm.normalized_snapshot,m.group_id,m.group_revision,"
        "r.rule_id FROM incident_revision_members m JOIN group_members gm ON gm.site_id=m.site_id "
        "AND gm.group_id=m.group_id AND gm.group_revision=m.group_revision "
        "JOIN group_revisions r ON (r.site_id,r.group_id,r.revision)="
        "(m.site_id,m.group_id,m.group_revision) WHERE "
        + " AND ".join(clauses)
        + " ORDER BY gm.event_ts,gm.alert_key LIMIT %s"
    )
    rows = conn.execute(cast(LiteralString, query), tuple(params)).fetchall()
    stage_rows = conn.execute(
        "SELECT s.event_ts,s.alert_key,s.stage_id,s.group_id,s.group_revision,s.confidence "
        "FROM incident_evidence_revisions e JOIN correlation_stage_evidence s ON "
        "(s.site_id,s.chain_id,s.revision_digest,s.manifest_id)="
        "(e.site_id,e.promotion_chain_id,e.promotion_revision_digest,e.promotion_manifest_id) "
        "WHERE e.site_id=%s AND e.incident_id=%s AND e.incident_revision_id=%s "
        "AND e.promotion_chain_id IS NOT NULL AND s.outcome='matched' ORDER BY s.ordinal LIMIT 8",
        (site_id, incident_id, evidence_revision),
    ).fetchall()
    stages: dict[str, list[dict[str, Any]]] = {}
    for event_ts, alert_key, stage_id, group_id, group_revision, confidence in stage_rows:
        stages.setdefault(str(alert_key), []).append(
            {
                "stage_id": str(stage_id),
                "group_id": str(group_id),
                "group_revision": str(group_revision),
                "confidence": float(confidence),
                "event_ts": event_ts,
            }
        )
    return [
        {
            "kind": "alert",
            "event_ts": row[0],
            "event_id": str(row[1]),
            "alert_key": str(row[1]),
            "group_id": str(row[3]),
            "group_revision": str(row[4]),
            "rule_id": row[5],
            "fields": row[2],
            "stages": stages.get(str(row[1]), []),
        }
        for row in rows
    ]


def incident_context(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    incident_id: UUID,
    evidence_revision: UUID,
    start: datetime | None,
    end: datetime | None,
    limit: int,
) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT as_of,content_digest FROM incident_evidence_revisions WHERE site_id=%s "
        "AND incident_id=%s AND incident_revision_id=%s",
        (site_id, incident_id, evidence_revision),
    ).fetchone()
    if row is None:
        return None
    bounds = conn.execute(
        "SELECT min(gr.first_ts),max(gr.last_ts) FROM incident_revision_members m "
        "JOIN group_revisions gr ON gr.site_id=m.site_id AND gr.group_id=m.group_id "
        "AND gr.revision=m.group_revision WHERE m.site_id=%s AND m.incident_id=%s "
        "AND m.incident_revision_id=%s",
        (site_id, incident_id, evidence_revision),
    ).fetchone()
    source_start, source_end = bounds or (None, None)
    to_time = end or (source_end + timedelta(microseconds=1) if source_end is not None else row[0])
    from_time = start or max(source_start or to_time, to_time - timedelta(hours=24))
    if source_start is None and start is None:
        from_time = to_time - timedelta(hours=24)
    if not from_time < to_time or to_time - from_time > timedelta(hours=48):
        raise ValueError("context window must be positive and at most 48 hours")
    sample = conn.execute(
        "SELECT sampled.event_ts,sampled.alert_key,sampled.normalized_snapshot "
        "FROM incident_revision_members im CROSS JOIN LATERAL ("
        "SELECT gm.event_ts,gm.alert_key,gm.normalized_snapshot FROM group_members gm "
        "WHERE gm.site_id=im.site_id AND gm.group_id=im.group_id "
        "AND gm.group_revision=im.group_revision AND gm.event_ts >= %s AND gm.event_ts < %s "
        "ORDER BY gm.event_ts,gm.alert_key LIMIT %s) sampled "
        "WHERE im.site_id=%s AND im.incident_id=%s AND im.incident_revision_id=%s "
        "ORDER BY sampled.event_ts,sampled.alert_key LIMIT %s",
        (from_time, to_time, limit + 1, site_id, incident_id, evidence_revision, limit + 1),
    ).fetchall()
    chosen = sample[:limit]
    entity_values, omitted_entities, entity_scan_capped = _sampled_entities(chosen)
    labels = [
        f"{item['kind']}={item['value']}"
        for item in entity_values
        if len(item["value"].encode("utf-8")) <= 256
    ][:8]
    question = (
        f"Investigate incident {incident_id}, frozen evidence {evidence_revision}, "
        f"for UTC [{from_time.isoformat()}, {to_time.isoformat()})."
    )
    if labels:
        question += " Sampled entities: " + "; ".join(labels) + "."
    draft = AskRequest(question=question, environment_id=site_id, timezone="UTC")
    return {
        "evidence_revision": str(evidence_revision),
        "evidence_digest": row[1],
        "entities": entity_values,
        "from": from_time,
        "to": to_time,
        "sampled_alerts": [
            {"event_ts": r[0], "alert_key": str(r[1]), "fields": r[2]} for r in chosen
        ],
        "sample_limit": limit,
        "omitted_count": max(0, len(sample) - len(chosen)),
        "omitted_count_is_lower_bound": len(sample) > limit,
        "omitted_entity_count": omitted_entities,
        "omissions_capped": len(sample) > limit or entity_scan_capped,
        "question_draft": {"editable": True, "request": draft.model_dump(mode="json")},
    }


def _sampled_entities(
    samples: list[tuple[Any, ...]],
) -> tuple[list[dict[str, str]], int, bool]:
    found: set[tuple[str, str, str]] = set()
    capped = False
    for sample in samples:
        snapshot = cast(dict[str, Any], sample[2])
        refs = snapshot.get("_entity_refs", [])
        if not isinstance(refs, list):
            continue
        items = cast(list[object], refs)
        capped |= len(items) > 128
        for item in items[:128]:
            if not isinstance(item, dict):
                continue
            ref = cast(dict[str, object], item)
            kind, value, role = ref.get("kind"), ref.get("value"), ref.get("role")
            if (
                not isinstance(kind, str)
                or kind not in {"host", "ip", "user", "process", "file", "hash", "cve", "rule"}
                or not isinstance(value, str)
                or not isinstance(role, str)
                or not value
                or len(role) > 80
            ):
                continue
            try:
                found.add((kind, _bound_display_text(value), _bound_display_text(role)))
            except BoundTextRejected:
                continue
    values = [{"kind": k, "value": v, "role": r} for k, v, r in sorted(found)[:100]]
    return values, max(0, len(found) - len(values)), capped or len(found) > 100
