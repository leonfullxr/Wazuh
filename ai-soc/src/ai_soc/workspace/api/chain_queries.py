"""Bounded deterministic chain-candidate projections for the API."""

from __future__ import annotations

from typing import Any, LiteralString, cast

import psycopg


def list_candidates(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    filters: dict[str, object],
    after: tuple[Any, str] | None,
    limit: int,
) -> list[dict[str, Any]]:
    clauses = ["h.site_id=%s"]
    params: list[Any] = [site_id]
    if filters.get("state") is not None:
        clauses.append("COALESCE(d.state,'open')=%s")
        params.append(filters["state"])
    if filters.get("rule_id") is not None:
        clauses.append("c.rule_id=%s")
        params.append(filters["rule_id"])
    diagnostic = filters.get("diagnostic")
    if diagnostic == "missing_stage":
        clauses.append("jsonb_array_length(COALESCE(r.result->'missing_stages','[]'::jsonb))>0")
    elif diagnostic == "fallback_join":
        clauses.append("r.result->>'fallback_used'='true'")
    elif diagnostic == "weak_heuristic":
        clauses.append(
            "EXISTS (SELECT 1 FROM correlation_stage_evidence s WHERE s.site_id=h.site_id "
            "AND s.chain_id=h.chain_id AND s.revision_digest=h.revision_digest "
            "AND s.manifest_id=h.manifest_id AND s.outcome='matched' AND s.confidence<0.5)"
        )
    elif diagnostic == "score_unavailable":
        clauses.append("r.result->>'score' IS NULL")
    elif diagnostic == "promotion_eligible":
        clauses.append("r.result->>'eligible_for_promotion'='true'")
    if filters.get("min_score") is not None:
        clauses.append("(r.result->>'score')::double precision >= %s")
        params.append(filters["min_score"])
    if filters.get("max_score") is not None:
        clauses.append("(r.result->>'score')::double precision <= %s")
        params.append(filters["max_score"])
    if filters.get("from") is not None:
        clauses.append("m.window_start >= %s")
        params.append(filters["from"])
    if filters.get("to") is not None:
        clauses.append("m.window_end <= %s")
        params.append(filters["to"])
    if after is not None:
        clauses.append("(c.created_at,c.chain_id)<(%s,%s)")
        params.extend(after)
    params.append(limit)
    query = (
        "SELECT c.chain_id,h.revision_digest,h.manifest_id,c.rule_id,c.rule_version,"
        "COALESCE(d.state,'open') AS state,COALESCE(d.version,0) AS decision_version,"
        "c.created_at,h.updated_at,r.result->>'score' AS score,"
        "(r.result->>'score') IS NOT NULL AS score_available,r.result,"
        "EXISTS (SELECT 1 FROM correlation_stage_evidence s WHERE s.site_id=h.site_id "
        "AND s.chain_id=h.chain_id AND s.revision_digest=h.revision_digest "
        "AND s.manifest_id=h.manifest_id AND s.outcome='matched' AND s.confidence<0.5) AS weak "
        "FROM correlation_heads h JOIN correlation_chains c USING(site_id,chain_id) "
        "JOIN correlation_chain_revisions r ON "
        "(r.site_id,r.chain_id,r.revision_digest,r.manifest_id)="
        "(h.site_id,h.chain_id,h.revision_digest,h.manifest_id) "
        "JOIN correlation_manifests m ON (m.site_id,m.manifest_id)=(h.site_id,h.manifest_id) "
        "LEFT JOIN correlation_decisions d ON "
        "(d.site_id,d.chain_id)=(h.site_id,h.chain_id) WHERE "
        + " AND ".join(clauses)
        + " ORDER BY c.created_at DESC,c.chain_id DESC LIMIT %s"
    )
    rows = conn.execute(cast(LiteralString, query), tuple(params)).fetchall()
    columns = (
        "chain_id",
        "revision_digest",
        "manifest_id",
        "rule_id",
        "rule_version",
        "state",
        "decision_version",
        "created_at",
        "updated_at",
        "score",
        "score_available",
        "result",
        "weak",
    )
    return [dict(zip(columns, row, strict=True)) for row in rows]


def get_candidate(
    conn: psycopg.Connection[Any], *, site_id: str, chain_id: str
) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT c.chain_id,h.revision_digest,h.manifest_id,c.rule_id,c.rule_version,"
        "COALESCE(d.state,'open') AS state,COALESCE(d.version,0) AS decision_version,"
        "c.created_at,h.updated_at,r.result->>'score' AS score,"
        "(r.result->>'score') IS NOT NULL AS score_available,r.result,"
        "EXISTS (SELECT 1 FROM correlation_stage_evidence s WHERE s.site_id=h.site_id "
        "AND s.chain_id=h.chain_id AND s.revision_digest=h.revision_digest "
        "AND s.manifest_id=h.manifest_id AND s.outcome='matched' AND s.confidence<0.5) AS weak "
        "FROM correlation_heads h JOIN correlation_chains c USING(site_id,chain_id) "
        "JOIN correlation_chain_revisions r ON "
        "(r.site_id,r.chain_id,r.revision_digest,r.manifest_id)="
        "(h.site_id,h.chain_id,h.revision_digest,h.manifest_id) "
        "LEFT JOIN correlation_decisions d ON "
        "(d.site_id,d.chain_id)=(h.site_id,h.chain_id) "
        "WHERE h.site_id=%s AND h.chain_id=%s",
        (site_id, chain_id),
    ).fetchone()
    if row is None:
        return None
    keys = (
        "chain_id",
        "revision_digest",
        "manifest_id",
        "rule_id",
        "rule_version",
        "state",
        "decision_version",
        "created_at",
        "updated_at",
        "score",
        "score_available",
        "result",
        "weak",
    )
    value: dict[str, Any] = dict(zip(keys, row, strict=True))
    value["stages"] = conn.execute(
        "SELECT s.ordinal,s.stage_id,s.outcome,s.group_id,s.group_revision,s.alert_key,"
        "s.event_ts,s.confidence,i.source_hash,p.availability "
        "FROM correlation_stage_evidence s LEFT JOIN correlation_input_members i ON "
        "(i.site_id,i.manifest_id,i.group_id,i.group_revision,i.alert_key,i.event_ts)="
        "(s.site_id,s.manifest_id,s.group_id,s.group_revision,s.alert_key,s.event_ts) "
        "LEFT JOIN correlation_source_projections p ON "
        "(p.site_id,p.alert_key,p.extraction_version,p.projection_digest)="
        "(i.site_id,i.alert_key,i.projection_version,i.projection_digest) "
        "WHERE s.site_id=%s AND s.chain_id=%s AND s.revision_digest=%s "
        "AND s.manifest_id=%s ORDER BY s.ordinal LIMIT 8",
        (site_id, chain_id, value["revision_digest"], value["manifest_id"]),
    ).fetchall()
    value["edges"] = conn.execute(
        "SELECT edge_id,from_group,from_revision,from_alert_key,to_group,to_revision,to_alert_key,"
        "edge_type,confidence,reason,time_delta_seconds,shared_fields FROM correlation_edges "
        "WHERE site_id=%s AND manifest_id=%s AND EXISTS ("
        "SELECT 1 FROM correlation_stage_evidence f WHERE f.site_id=correlation_edges.site_id "
        "AND f.chain_id=%s AND f.revision_digest=%s AND f.manifest_id=%s "
        "AND f.outcome='matched' AND f.group_id=correlation_edges.from_group "
        "AND f.group_revision=correlation_edges.from_revision "
        "AND f.alert_key=correlation_edges.from_alert_key) AND EXISTS ("
        "SELECT 1 FROM correlation_stage_evidence t WHERE t.site_id=correlation_edges.site_id "
        "AND t.chain_id=%s AND t.revision_digest=%s AND t.manifest_id=%s "
        "AND t.outcome='matched' AND t.group_id=correlation_edges.to_group "
        "AND t.group_revision=correlation_edges.to_revision "
        "AND t.alert_key=correlation_edges.to_alert_key) "
        "ORDER BY edge_id LIMIT 200",
        (
            site_id,
            value["manifest_id"],
            chain_id,
            value["revision_digest"],
            value["manifest_id"],
            chain_id,
            value["revision_digest"],
            value["manifest_id"],
        ),
    ).fetchall()
    value["score_pins"] = conn.execute(
        "SELECT ig.group_id,ig.group_revision,ig.score_version,ig.score_digest,ig.score "
        "FROM correlation_input_groups ig WHERE ig.site_id=%s AND ig.manifest_id=%s "
        "AND EXISTS (SELECT 1 FROM correlation_stage_evidence s WHERE s.site_id=ig.site_id "
        "AND s.manifest_id=ig.manifest_id AND s.chain_id=%s AND s.revision_digest=%s "
        "AND s.outcome='matched' AND s.group_id=ig.group_id "
        "AND s.group_revision=ig.group_revision) "
        "ORDER BY ig.group_id,ig.group_revision LIMIT 8",
        (site_id, value["manifest_id"], chain_id, value["revision_digest"]),
    ).fetchall()
    return value
