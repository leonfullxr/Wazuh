"""Bounded incident workflow state and immutable evidence snapshots."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, cast
from uuid import UUID, uuid4

import psycopg
from psycopg import sql
from psycopg.pq import TransactionStatus
from psycopg.types.json import Jsonb

from ai_soc.workspace.audit_outbox import record_audit
from ai_soc.workspace.jobs import enqueue_job
from ai_soc.workspace.triage.grouping import digest
from ai_soc.workspace.triage.score_selection import select_score_references

WorkStatus = Literal["new", "in_progress", "resolved", "closed"]
DispositionLabel = Literal[
    "true_positive", "benign_true_positive", "false_positive", "duplicate", "undetermined"
]
FALSE_POSITIVE_REASONS = frozenset(
    {"expected_admin_activity", "known_scanner", "misconfigured_rule", "test_activity", "other"}
)


class IncidentConflict(RuntimeError):
    """An incident version, decision, or idempotency precondition conflicted."""


@dataclass(frozen=True, slots=True)
class IncidentSnapshot:
    incident_id: UUID
    title: str
    owner_key: str | None
    status: WorkStatus
    work_version: int
    evidence_head: UUID
    revision_seq: int
    priority: float | None


@contextmanager
def _savepoint(conn: psycopg.Connection[Any]) -> Iterator[None]:
    with conn.transaction():
        yield


def _require_site(conn: psycopg.Connection[Any], site_id: str) -> None:
    if conn.info.transaction_status is TransactionStatus.IDLE:
        raise PermissionError("incident operation requires an active site transaction")
    row = conn.execute("SELECT current_setting('app.site_id', true)").fetchone()
    if row is None or row[0] != site_id:
        raise PermissionError("incident operation requires the active site's transaction")


def _validate_actor(actor_key: str, principal_key: str, key: str, now: datetime) -> None:
    _aware(now)
    if not actor_key or len(actor_key) > 256 or not principal_key or len(principal_key) > 256:
        raise ValueError("actor and principal are required and limited to 256 characters")
    if not 16 <= len(key) <= 128 or any(ord(c) < 33 or ord(c) > 126 for c in key):
        raise ValueError("idempotency key must be 16..128 visible ASCII characters")


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")


def _idempotent(
    conn: psycopg.Connection[Any],
    site_id: str,
    principal: str,
    route: str,
    key: str,
    request: Mapping[str, object],
) -> dict[str, Any] | None:
    conn.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
        (f"idempotency:{site_id}:{principal}:{route}:{key}",),
    )
    row = conn.execute(
        "SELECT request_digest,response FROM workspace_idempotency WHERE site_id=%s "
        "AND principal_key=%s AND route_key=%s AND idempotency_key=%s",
        (site_id, principal, route, key),
    ).fetchone()
    if row is None:
        return None
    if row[0] != digest(request):
        raise IncidentConflict("idempotency key was reused with different request content")
    return dict(row[1])


def _save_idempotent(
    conn: psycopg.Connection[Any],
    site_id: str,
    principal: str,
    route: str,
    key: str,
    request: Mapping[str, object],
    response: dict[str, object],
    now: datetime,
) -> None:
    conn.execute(
        "INSERT INTO workspace_idempotency(site_id,principal_key,route_key,idempotency_key,"
        "request_digest,response,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
        (site_id, principal, route, key, digest(request), Jsonb(response), now),
    )


def _response(snapshot: IncidentSnapshot) -> dict[str, object]:
    return {
        "incident_id": str(snapshot.incident_id),
        "title": snapshot.title,
        "owner_key": snapshot.owner_key,
        "status": snapshot.status,
        "work_version": snapshot.work_version,
        "evidence_head": str(snapshot.evidence_head),
        "revision_seq": snapshot.revision_seq,
        "priority": snapshot.priority,
    }


def _snapshot(value: dict[str, Any]) -> IncidentSnapshot:
    return IncidentSnapshot(
        incident_id=UUID(str(value["incident_id"])),
        title=str(value["title"]),
        owner_key=None if value["owner_key"] is None else str(value["owner_key"]),
        status=value["status"],
        work_version=int(value["work_version"]),
        evidence_head=UUID(str(value["evidence_head"])),
        revision_seq=int(value["revision_seq"]),
        priority=None if value["priority"] is None else float(value["priority"]),
    )


def _active_site_groups(
    conn: psycopg.Connection[Any],
    site_id: str,
    ids: tuple[str, ...],
    now: datetime,
    revisions: Mapping[str, str] | None = None,
    score_pins: Mapping[str, tuple[str | None, str | None, float | None]] | None = None,
) -> list[tuple[Any, ...]]:
    if not 1 <= len(ids) <= 100 or len(set(ids)) != len(ids):
        raise ValueError("group_ids must contain 1..100 unique groups")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    if revisions is None:
        rows = conn.execute(
            "SELECT gh.group_id,gh.current_revision,gr.title FROM group_heads gh "
            "JOIN group_revisions gr ON (gr.site_id,gr.group_id,gr.revision)="
            "(gh.site_id,gh.group_id,gh.current_revision) WHERE gh.site_id=%s "
            "AND gh.group_id=ANY(%s) AND gh.updated_at<=%s AND gr.created_at<=%s "
            "ORDER BY gh.group_id FOR SHARE OF gh",
            (site_id, list(ids), now, now),
        ).fetchall()
        if len(rows) != len(ids):
            missing = set(ids) - {str(row[0]) for row in rows}
            heads = {
                str(row[0])
                for row in conn.execute(
                    "SELECT group_id FROM group_heads WHERE site_id=%s AND group_id=ANY(%s)",
                    (site_id, list(missing)),
                ).fetchall()
            }
            if missing <= heads:
                raise IncidentConflict("a group changed during the request; refresh and retry")
    else:
        if set(revisions) != set(ids):
            raise ValueError("pinned revisions must exactly match group ids")
        rows = conn.execute(
            "SELECT gr.group_id,gr.revision,gr.title FROM unnest(%s::text[],%s::text[]) "
            "AS p(group_id,revision) JOIN group_revisions gr ON gr.site_id=%s "
            "AND gr.group_id=p.group_id AND gr.revision=p.revision ORDER BY gr.group_id",
            (list(ids), [revisions[group] for group in ids], site_id),
        ).fetchall()
    if len(rows) != len(ids):
        raise LookupError("one or more groups are unknown or belong to another site")
    if score_pins is None:
        refs = select_score_references(
            conn,
            site_id=site_id,
            group_revisions=tuple((str(row[0]), str(row[1])) for row in rows),
            as_of=now,
        )
        scores = {
            str(row[0]): (
                None
                if (ref := refs.get((str(row[0]), str(row[1])))) is None
                else ref.computation_version,
                None if ref is None else ref.input_digest,
                None if ref is None else ref.total,
            )
            for row in rows
        }
    else:
        if set(score_pins) != set(ids):
            raise ValueError("pinned score references must exactly match group ids")
        if revisions is None:
            raise ValueError("pinned scores require exact pinned group revisions")
        available: list[tuple[str, str, str, str]] = []
        for group in ids:
            version, score_digest, score = score_pins[group]
            if (version is None) != (score_digest is None):
                raise ValueError("pinned score version and digest must both be present or absent")
            if score is not None and (version is None or not 0 <= score <= 100):
                raise ValueError("pinned numeric score requires a valid score reference")
            if version is not None and score_digest is not None:
                available.append((group, revisions[group], version, score_digest))
        if available:
            actual = conn.execute(
                "SELECT p.group_id,p.revision,s.total FROM unnest(%s::text[],%s::text[],"
                "%s::text[],%s::text[]) AS p(group_id,revision,version,input_digest) "
                "JOIN scores s ON s.site_id=%s AND s.group_id=p.group_id "
                "AND s.group_revision=p.revision AND s.computation_version=p.version "
                "AND s.input_digest=p.input_digest",
                (
                    [item[0] for item in available],
                    [item[1] for item in available],
                    [item[2] for item in available],
                    [item[3] for item in available],
                    site_id,
                ),
            ).fetchall()
            if len(actual) != len(available):
                raise LookupError("a pinned score reference is not retained for its exact revision")
            pin_scores = {group: score_pins[group][2] for group, *_rest in available}
            for group, revision, total in actual:
                expected = pin_scores[str(group)]
                observed = None if total is None else float(total)
                if observed != expected:
                    raise ValueError(
                        f"pinned score for {group}@{revision} differs from its retained score row"
                    )
        scores = {group: score_pins[group] for group in ids}

    selected: list[tuple[Any, ...]] = []
    for group_id, revision, title in rows:
        version, score_digest, score = scores[str(group_id)]
        selected.append(
            (
                group_id,
                revision,
                title,
                version,
                score_digest,
                score,
            )
        )
    return selected


def _create_evidence(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    incident_id: UUID,
    group_ids: tuple[str, ...],
    actor_key: str,
    now: datetime,
    promotion: tuple[str, str, UUID] | None = None,
    pinned_revisions: Mapping[str, str] | None = None,
    pinned_scores: Mapping[str, tuple[str | None, str | None, float | None]] | None = None,
) -> tuple[UUID, int, float | None]:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    current_cutoff = conn.execute(
        "SELECT e.as_of FROM incidents i JOIN incident_evidence_revisions e "
        "ON (e.site_id,e.incident_revision_id)=(i.site_id,i.evidence_head) "
        "WHERE i.site_id=%s AND i.incident_id=%s FOR UPDATE OF i",
        (site_id, incident_id),
    ).fetchone()
    if current_cutoff is not None and now < current_cutoff[0]:
        raise IncidentConflict("evidence cutoff cannot precede the current evidence cutoff")
    rows = _active_site_groups(conn, site_id, group_ids, now, pinned_revisions, pinned_scores)
    memberships = conn.execute(
        "SELECT group_id,membership_id FROM incident_membership_intervals "
        "WHERE site_id=%s AND incident_id=%s AND removed_at IS NULL ORDER BY group_id",
        (site_id, incident_id),
    ).fetchall()
    membership_ids = {str(group): UUID(str(mid)) for group, mid in memberships}
    if set(membership_ids) != set(group_ids):
        raise ValueError("evidence members must exactly match active incident membership")
    scores: list[float] = []
    material: list[dict[str, object]] = []
    for group_id, revision, _title, version, score_digest, score in rows:
        numeric_score = None if score is None else float(score)
        if numeric_score is not None:
            scores.append(numeric_score)
        material.append(
            {
                "group_id": group_id,
                "group_revision": revision,
                "group_title": _title,
                "score_version": version,
                "score_digest": score_digest,
                "score": numeric_score,
                "membership_id": str(membership_ids[str(group_id)]),
            }
        )
    priority = max(scores) if scores else None
    seqrow = conn.execute(
        "SELECT COALESCE(max(revision_seq),0)+1 FROM incident_evidence_revisions "
        "WHERE site_id=%s AND incident_id=%s",
        (site_id, incident_id),
    ).fetchone()
    if seqrow is None:
        raise RuntimeError("revision sequence query returned no row")
    sequence = int(seqrow[0])
    evidence_id = uuid4()
    content_digest = digest(
        {
            "policy": "workspace.incident-priority.v1",
            "as_of": now.isoformat(),
            "members": material,
            "promotion": (
                None if promotion is None else [promotion[0], promotion[1], str(promotion[2])]
            ),
        }
    )
    pchain, prev, pmanifest = (None, None, None) if promotion is None else promotion
    conn.execute(
        "INSERT INTO incident_evidence_revisions(site_id,incident_revision_id,incident_id,revision_seq,"  # noqa: E501
        "content_digest,as_of,policy_id,priority,promotion_chain_id,promotion_revision_digest,"
        "promotion_manifest_id,created_at) VALUES (%s,%s,%s,%s,%s,%s,'workspace.incident-priority.v1',%s,%s,%s,%s,%s)",  # noqa: E501
        (
            site_id,
            evidence_id,
            incident_id,
            sequence,
            content_digest,
            now,
            priority,
            pchain,
            prev,
            pmanifest,
            now,
        ),
    )
    for item in material:
        conn.execute(
            "INSERT INTO incident_revision_members(site_id,incident_id,incident_revision_id,group_id,"  # noqa: E501
            "membership_id,group_revision,score_version,score_digest,score) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",  # noqa: E501
            (
                site_id,
                incident_id,
                evidence_id,
                item["group_id"],
                item["membership_id"],
                item["group_revision"],
                item["score_version"],
                item["score_digest"],
                item["score"],
            ),
        )
    conn.execute(
        "UPDATE incidents SET evidence_head=%s WHERE site_id=%s AND incident_id=%s",
        (evidence_id, site_id, incident_id),
    )
    enqueue_job(
        conn,
        site_id=site_id,
        kind="prepare_narrative",
        subject=str(evidence_id),
        payload={
            "incident_id": str(incident_id),
            "incident_revision_id": str(evidence_id),
            "revision_seq": sequence,
        },
    )
    return evidence_id, sequence, priority


def _record_history(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    incident_id: UUID,
    revision_id: UUID,
    version: int,
    actor_key: str,
    action: str,
    before: object,
    after: dict[str, object],
    now: datetime,
) -> None:
    conn.execute(
        "INSERT INTO incident_history(site_id,history_id,incident_id,incident_revision_id,work_version,"  # noqa: E501
        "actor_key,action,before_value,after_value,at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (
            site_id,
            uuid4(),
            incident_id,
            revision_id,
            version,
            actor_key,
            action,
            None if before is None else Jsonb(before),
            Jsonb(after),
            now,
        ),
    )


def create_incident(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    group_ids: tuple[str, ...],
    actor_key: str,
    principal_key: str,
    idempotency_key: str,
    now: datetime,
    title: str | None = None,
    owner_key: str | None = None,
) -> IncidentSnapshot:
    _require_site(conn, site_id)
    _validate_actor(actor_key, principal_key, idempotency_key, now)
    if owner_key is not None and not 1 <= len(owner_key) <= 256:
        raise ValueError("owner_key must be null or 1..256 characters")
    if title is not None and not 1 <= len(title) <= 240:
        raise ValueError("title must contain 1..240 characters")
    request: dict[str, object] = {
        "group_ids": list(group_ids),
        "title": title,
        "owner_key": owner_key,
        "actor_key": actor_key,
    }
    route = "/incidents/create"
    with _savepoint(conn):
        prior = _idempotent(conn, site_id, principal_key, route, idempotency_key, request)
        if prior is not None:
            return _snapshot(prior)
        groups = _active_site_groups(conn, site_id, group_ids, now)
        incident_id = uuid4()
        resolved_title = title if title is not None else str(groups[0][2])[:240]
        conn.execute(
            "INSERT INTO subject_registry(site_id,subject_kind,subject_id) VALUES (%s,'incident',%s)",  # noqa: E501
            (site_id, str(incident_id)),
        )
        for group_id in group_ids:
            conn.execute(
                "INSERT INTO incident_membership_intervals(site_id,membership_id,incident_id,group_id,added_by,added_at) "  # noqa: E501
                "VALUES (%s,%s,%s,%s,%s,%s)",
                (site_id, uuid4(), incident_id, group_id, actor_key, now),
            )
        conn.execute(
            "INSERT INTO incidents(site_id,incident_id,title,owner_key,status,work_version,created_at,created_by) "  # noqa: E501
            "VALUES (%s,%s,%s,%s,'new',1,%s,%s)",
            (site_id, incident_id, resolved_title, owner_key, now, actor_key),
        )
        evidence_id, seq, priority = _create_evidence(
            conn,
            site_id=site_id,
            incident_id=incident_id,
            group_ids=group_ids,
            actor_key=actor_key,
            now=now,
        )
        snapshot = IncidentSnapshot(
            incident_id, resolved_title, owner_key, "new", 1, evidence_id, seq, priority
        )
        _record_history(
            conn,
            site_id=site_id,
            incident_id=incident_id,
            revision_id=evidence_id,
            version=1,
            actor_key=actor_key,
            action="created",
            before=None,
            after={"title": resolved_title, "member_count": len(group_ids)},
            now=now,
        )
        event = record_audit(
            conn,
            site_id=site_id,
            kind="incident_created",
            actor_key=actor_key,
            payload={
                "incident_id": str(incident_id),
                "evidence_revision_id": str(evidence_id),
                "member_count": len(group_ids),
                "revision_seq": seq,
            },
        )
        del event
        response = _response(snapshot)
        _save_idempotent(
            conn, site_id, principal_key, route, idempotency_key, request, response, now
        )
        return snapshot


def promote_chain(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    chain_id: str,
    expected_chain_revision: str,
    expected_manifest_id: UUID,
    expected_decision_version: int,
    actor_key: str,
    principal_key: str,
    idempotency_key: str,
    now: datetime,
    title_override: str | None = None,
) -> IncidentSnapshot:
    _require_site(conn, site_id)
    _validate_actor(actor_key, principal_key, idempotency_key, now)
    _integer(expected_decision_version, minimum=0)
    if title_override is not None and not 1 <= len(title_override) <= 240:
        raise ValueError("title_override must contain 1..240 characters")
    if len(expected_chain_revision) != 64:
        raise ValueError("expected_chain_revision must be a SHA-256 digest")
    conn.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
        (f"correlation-decision:{site_id}:{chain_id}",),
    )
    request = {
        "chain_id": chain_id,
        "revision": expected_chain_revision,
        "manifest_id": str(expected_manifest_id),
        "decision_version": expected_decision_version,
        "actor_key": actor_key,
        "title": title_override,
    }
    route = f"/chains/{chain_id}/promote"
    with _savepoint(conn):
        prior = _idempotent(conn, site_id, principal_key, route, idempotency_key, request)
        if prior is not None:
            return _snapshot(prior)
        existing = conn.execute(
            "SELECT i.incident_id,i.title,i.owner_key,i.status,i.work_version,i.evidence_head,"
            "current.revision_seq,current.priority,e.promotion_revision_digest,e.promotion_manifest_id "  # noqa: E501
            "FROM incident_evidence_revisions e JOIN incidents i USING(site_id,incident_id) "
            "JOIN incident_evidence_revisions current ON (current.site_id,current.incident_id,"
            "current.incident_revision_id)=(i.site_id,i.incident_id,i.evidence_head) "
            "WHERE e.site_id=%s AND e.promotion_chain_id=%s",
            (site_id, chain_id),
        ).fetchone()
        if existing is not None:
            if (
                str(existing[8]) != expected_chain_revision
                or existing[9] != expected_manifest_id
                or (title_override is not None and existing[1] != title_override)
            ):
                raise IncidentConflict("candidate is already promoted by a different intent")
            snapshot = IncidentSnapshot(
                existing[0],
                existing[1],
                existing[2],
                existing[3],
                int(existing[4]),
                existing[5],
                int(existing[6]),
                None if existing[7] is None else float(existing[7]),
            )
            _save_idempotent(
                conn,
                site_id,
                principal_key,
                route,
                idempotency_key,
                request,
                _response(snapshot),
                now,
            )
            return snapshot
        head = conn.execute(
            "SELECT h.revision_digest,h.manifest_id,c.rule_id,c.anchor_group_id,c.anchor_alert_key,"
            "d.version,d.state,c.anchor_identity,r.result->>'is_candidate',m.complete "
            "FROM correlation_heads h JOIN correlation_chains c USING(site_id,chain_id) "
            "JOIN correlation_chain_revisions r ON (r.site_id,r.chain_id,r.revision_digest,r.manifest_id)="  # noqa: E501
            "(h.site_id,h.chain_id,h.revision_digest,h.manifest_id) "
            "JOIN correlation_manifests m ON (m.site_id,m.manifest_id)=(h.site_id,h.manifest_id) "
            "LEFT JOIN correlation_decisions d ON d.site_id=h.site_id AND d.chain_id=h.chain_id "
            "WHERE h.site_id=%s AND h.chain_id=%s FOR UPDATE OF h",
            (site_id, chain_id),
        ).fetchone()
        if head is None:
            raise LookupError("unknown candidate")
        current_version = 0 if head[5] is None else int(head[5])
        if (
            str(head[0]) != expected_chain_revision
            or head[1] != expected_manifest_id
            or current_version != expected_decision_version
        ):
            raise IncidentConflict(
                "candidate evidence or decision changed; refresh before promotion"
            )
        if head[6] == "dismissed":
            raise IncidentConflict("dismissed candidate cannot be promoted")
        if head[8] != "true" or not bool(head[9]):
            raise ValueError("candidate head is not a complete accepted chain")
        stages = conn.execute(
            "SELECT s.ordinal,s.stage_id,s.outcome,s.group_id,gr.title,ig.group_revision,"
            "ig.score_version,ig.score_digest,ig.score "
            "FROM correlation_stage_evidence s "  # noqa: E501
            "LEFT JOIN group_revisions gr ON gr.site_id=s.site_id AND gr.group_id=s.group_id "
            "AND gr.revision=(SELECT ig.group_revision FROM correlation_input_groups ig WHERE "
            "ig.site_id=s.site_id AND ig.manifest_id=s.manifest_id AND ig.group_id=s.group_id) "
            "LEFT JOIN correlation_input_groups ig ON ig.site_id=s.site_id "
            "AND ig.manifest_id=s.manifest_id AND ig.group_id=s.group_id "
            "WHERE s.site_id=%s AND s.chain_id=%s AND s.revision_digest=%s AND s.manifest_id=%s "
            "ORDER BY s.ordinal",
            (site_id, chain_id, expected_chain_revision, expected_manifest_id),
        ).fetchall()
        matched = [r for r in stages if r[2] == "matched" and r[3] is not None]
        pinned_revisions: dict[str, str] = {}
        pinned_scores: dict[str, tuple[str | None, str | None, float | None]] = {}
        for row in matched:
            group_id = str(row[3])
            revision = str(row[5])
            score_pin = (
                None if row[6] is None else str(row[6]),
                None if row[7] is None else str(row[7]),
                None if row[8] is None else float(row[8]),
            )
            if group_id in pinned_revisions and (
                pinned_revisions[group_id] != revision or pinned_scores[group_id] != score_pin
            ):
                raise ValueError("candidate manifest contains conflicting pins for a matched group")
            pinned_revisions[group_id] = revision
            pinned_scores[group_id] = score_pin
        groups = tuple(dict.fromkeys(pinned_revisions))
        if not groups or len(groups) > 100:
            raise ValueError(
                "candidate must have a complete accepted chain with 1..100 matched groups"
            )
        incident_id = uuid4()
        conn.execute(
            "INSERT INTO subject_registry(site_id,subject_kind,subject_id) VALUES (%s,'incident',%s)",  # noqa: E501
            (site_id, str(incident_id)),
        )
        anchor_title = next(
            (str(row[4]) for row in stages if row[3] == head[3] and row[4] is not None),
            str(head[3]),
        )
        title = title_override or f"{head[2]}: {anchor_title}"[:240]
        for group_id in groups:
            conn.execute(
                "INSERT INTO incident_membership_intervals(site_id,membership_id,incident_id,group_id,added_by,added_at) "  # noqa: E501
                "VALUES (%s,%s,%s,%s,%s,%s)",
                (site_id, uuid4(), incident_id, group_id, actor_key, now),
            )
        conn.execute(
            "INSERT INTO incidents(site_id,incident_id,title,owner_key,status,work_version,created_at,created_by) "  # noqa: E501
            "VALUES (%s,%s,%s,NULL,'new',1,%s,%s)",
            (site_id, incident_id, title, now, actor_key),
        )
        evidence_id, seq, priority = _create_evidence(
            conn,
            site_id=site_id,
            incident_id=incident_id,
            group_ids=groups,
            actor_key=actor_key,
            now=now,
            promotion=(chain_id, expected_chain_revision, expected_manifest_id),
            pinned_revisions=pinned_revisions,
            pinned_scores=pinned_scores,
        )
        snapshot = IncidentSnapshot(incident_id, title, None, "new", 1, evidence_id, seq, priority)
        decision_version = current_version + 1
        audit_id = record_audit(
            conn,
            site_id=site_id,
            kind="incident_candidate_promoted",
            actor_key=actor_key,
            payload={
                "incident_id": str(incident_id),
                "chain_id": chain_id,
                "evidence_revision_id": str(evidence_id),
                "revision_seq": seq,
                "version": decision_version,
                "idempotency_key": idempotency_key,
            },
        )
        conn.execute(
            "INSERT INTO correlation_decision_history(site_id,chain_id,decision_id,audit_event_id,"
            "idempotency_key,version,state,reason,actor_key,at) "
            "VALUES (%s,%s,%s,%s,%s,%s,'promoted',NULL,%s,%s)",
            (
                site_id,
                chain_id,
                uuid4(),
                audit_id,
                idempotency_key,
                decision_version,
                actor_key,
                now,
            ),
        )
        conn.execute(
            "INSERT INTO correlation_decisions(site_id,chain_id,version,state,reason,actor_key,updated_at) "  # noqa: E501
            "VALUES (%s,%s,%s,'promoted',NULL,%s,%s) ON CONFLICT(site_id,chain_id) DO UPDATE "
            "SET version=EXCLUDED.version,state='promoted',reason=NULL,"
            "actor_key=EXCLUDED.actor_key,updated_at=EXCLUDED.updated_at",
            (site_id, chain_id, decision_version, actor_key, now),
        )
        _record_history(
            conn,
            site_id=site_id,
            incident_id=incident_id,
            revision_id=evidence_id,
            version=1,
            actor_key=actor_key,
            action="promoted",
            before=None,
            after={"chain_id": chain_id},
            now=now,
        )
        _save_idempotent(
            conn, site_id, principal_key, route, idempotency_key, request, _response(snapshot), now
        )
        return snapshot


def _integer(value: object, *, minimum: int = 1) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError("expected version must be a bounded integer")


def validate_expected_work_version(value: object) -> None:
    """Validate a public analyst work-version precondition, rejecting bools."""
    _integer(value)


def get_incident(
    conn: psycopg.Connection[Any], *, site_id: str, incident_id: UUID
) -> IncidentSnapshot:
    _require_site(conn, site_id)
    row = conn.execute(
        "SELECT i.incident_id,i.title,i.owner_key,i.status,i.work_version,i.evidence_head,"
        "e.revision_seq,e.priority FROM incidents i JOIN incident_evidence_revisions e "
        "ON (e.site_id,e.incident_id,e.incident_revision_id)=(i.site_id,i.incident_id,i.evidence_head) "  # noqa: E501
        "WHERE i.site_id=%s AND i.incident_id=%s",
        (site_id, incident_id),
    ).fetchone()
    if row is None:
        raise LookupError("unknown incident")
    return IncidentSnapshot(
        row[0],
        row[1],
        row[2],
        row[3],
        int(row[4]),
        row[5],
        int(row[6]),
        None if row[7] is None else float(row[7]),
    )


def _mutate_work(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    incident_id: UUID,
    expected_work_version: int,
    actor_key: str,
    principal_key: str,
    idempotency_key: str,
    now: datetime,
    action: Literal["assign", "status"],
    value: str | None,
) -> IncidentSnapshot:
    _require_site(conn, site_id)
    _validate_actor(actor_key, principal_key, idempotency_key, now)
    _integer(expected_work_version)
    if action == "assign" and value is not None and not 1 <= len(value) <= 256:
        raise ValueError("owner_key must be null or 1..256 characters")
    if action == "status" and value not in {"new", "in_progress", "resolved", "closed"}:
        raise ValueError("unsupported status")
    request = {
        "incident_id": str(incident_id),
        "expected_work_version": expected_work_version,
        action: value,
        "actor_key": actor_key,
    }
    route = f"/incidents/{incident_id}/{action}"
    with _savepoint(conn):
        prior = _idempotent(conn, site_id, principal_key, route, idempotency_key, request)
        if prior is not None:
            return _snapshot(prior)
        row = conn.execute(
            "SELECT title,owner_key,status,work_version,evidence_head FROM incidents "
            "WHERE site_id=%s AND incident_id=%s FOR UPDATE",
            (site_id, incident_id),
        ).fetchone()
        if row is None:
            raise LookupError("unknown incident")
        if int(row[3]) != expected_work_version:
            raise IncidentConflict("incident work version changed")
        new_owner = value if action == "assign" else row[1]
        new_status = value if action == "status" else row[2]
        version = expected_work_version + 1
        conn.execute(
            "UPDATE incidents SET owner_key=%s,status=%s,work_version=%s WHERE site_id=%s AND incident_id=%s",  # noqa: E501
            (new_owner, new_status, version, site_id, incident_id),
        )
        revision_id = UUID(str(row[4]))
        _record_history(
            conn,
            site_id=site_id,
            incident_id=incident_id,
            revision_id=revision_id,
            version=version,
            actor_key=actor_key,
            action="assigned" if action == "assign" else "status_changed",
            before={"owner_key": row[1], "status": row[2]},
            after={"owner_key": new_owner, "status": new_status},
            now=now,
        )
        record_audit(
            conn,
            site_id=site_id,
            kind=f"incident_{action}",
            actor_key=actor_key,
            payload={"incident_id": str(incident_id), "work_version": version, action: value},
        )
        evidence_row = conn.execute(
            "SELECT revision_seq,priority FROM incident_evidence_revisions "
            "WHERE site_id=%s AND incident_revision_id=%s",
            (site_id, revision_id),
        ).fetchone()
        if evidence_row is None:
            raise RuntimeError("incident evidence head is missing")
        snapshot = IncidentSnapshot(
            incident_id,
            row[0],
            new_owner,
            cast(WorkStatus, new_status),
            version,
            revision_id,
            int(evidence_row[0]),
            None if evidence_row[1] is None else float(evidence_row[1]),
        )
        _save_idempotent(
            conn, site_id, principal_key, route, idempotency_key, request, _response(snapshot), now
        )
        return snapshot


def assign_incident(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    incident_id: UUID,
    owner_key: str | None,
    expected_work_version: int,
    actor_key: str,
    principal_key: str,
    idempotency_key: str,
    now: datetime,
) -> IncidentSnapshot:
    return _mutate_work(
        conn,
        site_id=site_id,
        incident_id=incident_id,
        expected_work_version=expected_work_version,
        actor_key=actor_key,
        principal_key=principal_key,
        idempotency_key=idempotency_key,
        now=now,
        action="assign",
        value=owner_key,
    )


def change_incident_status(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    incident_id: UUID,
    status: WorkStatus,
    expected_work_version: int,
    actor_key: str,
    principal_key: str,
    idempotency_key: str,
    now: datetime,
) -> IncidentSnapshot:
    return _mutate_work(
        conn,
        site_id=site_id,
        incident_id=incident_id,
        expected_work_version=expected_work_version,
        actor_key=actor_key,
        principal_key=principal_key,
        idempotency_key=idempotency_key,
        now=now,
        action="status",
        value=status,
    )


def refresh_incident_evidence(
    conn: psycopg.Connection[Any], *, site_id: str, incident_id: UUID, now: datetime
) -> IncidentSnapshot:
    _require_site(conn, site_id)
    _aware(now)
    with _savepoint(conn):
        row = conn.execute(
            "SELECT i.title,i.owner_key,i.status,i.work_version,i.evidence_head,e.as_of "
            "FROM incidents i JOIN incident_evidence_revisions e ON "
            "(e.site_id,e.incident_id,e.incident_revision_id)="
            "(i.site_id,i.incident_id,i.evidence_head) "
            "WHERE i.site_id=%s AND i.incident_id=%s FOR UPDATE OF i",
            (site_id, incident_id),
        ).fetchone()
        if row is None:
            raise LookupError("unknown incident")
        if row[5] > now:
            current = conn.execute(
                "SELECT revision_seq,priority FROM incident_evidence_revisions "
                "WHERE site_id=%s AND incident_revision_id=%s",
                (site_id, row[4]),
            ).fetchone()
            if current is None:
                raise RuntimeError("incident evidence head is missing")
            return IncidentSnapshot(
                incident_id,
                row[0],
                row[1],
                row[2],
                int(row[3]),
                UUID(str(row[4])),
                int(current[0]),
                None if current[1] is None else float(current[1]),
            )
        memberships = conn.execute(
            "SELECT group_id FROM incident_membership_intervals WHERE site_id=%s "
            "AND incident_id=%s AND removed_at IS NULL ORDER BY group_id",
            (site_id, incident_id),
        ).fetchall()
        group_ids = tuple(str(r[0]) for r in memberships)
        if not group_ids:
            raise ValueError("incident must retain an active member")
        current_material = conn.execute(
            "SELECT group_id,group_revision,score_version,score_digest,score "
            "FROM incident_revision_members WHERE site_id=%s AND incident_revision_id=%s "
            "ORDER BY group_id",
            (site_id, row[4]),
        ).fetchall()
        latest = _active_site_groups(conn, site_id, group_ids, now)
        latest_material = [
            (str(r[0]), str(r[1]), r[3], r[4], None if r[5] is None else float(r[5]))
            for r in latest
        ]
        if [
            (str(r[0]), str(r[1]), r[2], r[3], None if r[4] is None else float(r[4]))
            for r in current_material
        ] != latest_material:
            evidence_id, seq, priority = _create_evidence(
                conn,
                site_id=site_id,
                incident_id=incident_id,
                group_ids=group_ids,
                actor_key="system:refresh",
                now=now,
            )
            _record_history(
                conn,
                site_id=site_id,
                incident_id=incident_id,
                revision_id=evidence_id,
                version=int(row[3]),
                actor_key="system:refresh",
                action="evidence_refreshed",
                before={"evidence_revision_id": str(row[4])},
                after={"evidence_revision_id": str(evidence_id), "revision_seq": seq},
                now=now,
            )
            record_audit(
                conn,
                site_id=site_id,
                kind="incident_evidence_refreshed",
                actor_key="system:refresh",
                payload={
                    "incident_id": str(incident_id),
                    "evidence_revision_id": str(evidence_id),
                    "revision_seq": seq,
                },
            )
        else:
            evidence_id = UUID(str(row[4]))
            seq_priority = conn.execute(
                "SELECT revision_seq,priority FROM incident_evidence_revisions "
                "WHERE site_id=%s AND incident_revision_id=%s",
                (site_id, evidence_id),
            ).fetchone()
            if seq_priority is None:
                raise RuntimeError("incident evidence head is missing")
            seq, priority = (
                int(seq_priority[0]),
                None if seq_priority[1] is None else float(seq_priority[1]),
            )
        return IncidentSnapshot(
            incident_id, row[0], row[1], row[2], int(row[3]), evidence_id, seq, priority
        )


def change_incident_members(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    incident_id: UUID,
    add_group_ids: tuple[str, ...],
    remove_group_ids: tuple[str, ...],
    expected_work_version: int,
    actor_key: str,
    principal_key: str,
    idempotency_key: str,
    now: datetime,
) -> IncidentSnapshot:
    _require_site(conn, site_id)
    _validate_actor(actor_key, principal_key, idempotency_key, now)
    _integer(expected_work_version)
    if (
        len(add_group_ids) > 100
        or len(remove_group_ids) > 100
        or len(set(add_group_ids)) != len(add_group_ids)
        or len(set(remove_group_ids)) != len(remove_group_ids)
        or set(add_group_ids) & set(remove_group_ids)
        or not add_group_ids
        and not remove_group_ids
    ):
        raise ValueError("membership changes require bounded, disjoint unique group lists")
    request = {
        "incident_id": str(incident_id),
        "add": list(add_group_ids),
        "remove": list(remove_group_ids),
        "expected_work_version": expected_work_version,
        "actor_key": actor_key,
    }
    route = f"/incidents/{incident_id}/members"
    with _savepoint(conn):
        prior = _idempotent(conn, site_id, principal_key, route, idempotency_key, request)
        if prior is not None:
            return _snapshot(prior)
        incident = conn.execute(
            "SELECT title,owner_key,status,work_version,evidence_head FROM incidents "
            "WHERE site_id=%s AND incident_id=%s FOR UPDATE",
            (site_id, incident_id),
        ).fetchone()
        if incident is None:
            raise LookupError("unknown incident")
        if int(incident[3]) != expected_work_version:
            raise IncidentConflict("incident work version changed")
        current_cutoff = conn.execute(
            "SELECT as_of FROM incident_evidence_revisions "
            "WHERE site_id=%s AND incident_revision_id=%s",
            (site_id, incident[4]),
        ).fetchone()
        if current_cutoff is not None and now < current_cutoff[0]:
            raise IncidentConflict("membership cutoff cannot precede the current evidence cutoff")
        active = {
            str(row[0])
            for row in conn.execute(
                "SELECT group_id FROM incident_membership_intervals WHERE site_id=%s AND incident_id=%s "  # noqa: E501
                "AND removed_at IS NULL FOR UPDATE",
                (site_id, incident_id),
            ).fetchall()
        }
        if not set(remove_group_ids) <= active:
            raise ValueError("only active incident members can be removed")
        if set(add_group_ids) & active:
            raise ValueError("an active incident member cannot be added a second time")
        next_groups = (active - set(remove_group_ids)) | set(add_group_ids)
        if not next_groups or len(next_groups) > 100:
            raise ValueError("incident membership must remain between 1 and 100 groups")
        _active_site_groups(
            conn, site_id, tuple(sorted(set(add_group_ids))), now
        ) if add_group_ids else []
        pending_adds = list(add_group_ids)
        pending_removes = list(remove_group_ids)
        current_count = len(active)
        while pending_adds or pending_removes:
            remove_first = current_count == 100 or not pending_adds
            if remove_first and pending_removes and current_count > 1:
                group_id = pending_removes.pop(0)
                conn.execute(
                    "UPDATE incident_membership_intervals SET removed_by=%s,removed_at=%s "
                    "WHERE site_id=%s AND incident_id=%s AND group_id=%s AND removed_at IS NULL",
                    (actor_key, now, site_id, incident_id, group_id),
                )
                current_count -= 1
            elif pending_adds and current_count < 100:
                group_id = pending_adds.pop(0)
                conn.execute(
                    "INSERT INTO incident_membership_intervals "
                    "(site_id,membership_id,incident_id,group_id,added_by,added_at) "
                    "VALUES (%s,%s,%s,%s,%s,%s)",
                    (site_id, uuid4(), incident_id, group_id, actor_key, now),
                )
                current_count += 1
            elif pending_removes and current_count > 1:
                group_id = pending_removes.pop(0)
                conn.execute(
                    "UPDATE incident_membership_intervals SET removed_by=%s,removed_at=%s "
                    "WHERE site_id=%s AND incident_id=%s AND group_id=%s AND removed_at IS NULL",
                    (actor_key, now, site_id, incident_id, group_id),
                )
                current_count -= 1
            else:
                raise ValueError("membership transition cannot preserve 1..100 active groups")
        version = expected_work_version + 1
        conn.execute(
            "UPDATE incidents SET work_version=%s WHERE site_id=%s AND incident_id=%s",
            (version, site_id, incident_id),
        )
        revision_id, seq, priority = _create_evidence(
            conn,
            site_id=site_id,
            incident_id=incident_id,
            group_ids=tuple(sorted(next_groups)),
            actor_key=actor_key,
            now=now,
        )
        _record_history(
            conn,
            site_id=site_id,
            incident_id=incident_id,
            revision_id=revision_id,
            version=version,
            actor_key=actor_key,
            action="members_changed",
            before={"member_count": len(active)},
            after={"added": list(add_group_ids), "removed": list(remove_group_ids)},
            now=now,
        )
        record_audit(
            conn,
            site_id=site_id,
            kind="incident_members_changed",
            actor_key=actor_key,
            payload={
                "incident_id": str(incident_id),
                "work_version": version,
                "added": list(add_group_ids),
                "removed": list(remove_group_ids),
            },
        )
        snapshot = IncidentSnapshot(
            incident_id, incident[0], incident[1], incident[2], version, revision_id, seq, priority
        )
        _save_idempotent(
            conn, site_id, principal_key, route, idempotency_key, request, _response(snapshot), now
        )
        return snapshot


def add_incident_comment(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    incident_id: UUID,
    body: str,
    expected_work_version: int,
    actor_key: str,
    principal_key: str,
    idempotency_key: str,
    now: datetime,
) -> UUID:
    _require_site(conn, site_id)
    _validate_actor(actor_key, principal_key, idempotency_key, now)
    _integer(expected_work_version)
    if not 1 <= len(body) <= 4000:
        raise ValueError("comment body must contain 1..4000 characters")
    request: dict[str, object] = {
        "incident_id": str(incident_id),
        "body": body,
        "expected_work_version": expected_work_version,
        "actor_key": actor_key,
    }
    route = f"/incidents/{incident_id}/comments"
    with _savepoint(conn):
        prior = _idempotent(conn, site_id, principal_key, route, idempotency_key, request)
        if prior is not None:
            return UUID(str(prior["comment_id"]))
        row = conn.execute(
            "SELECT work_version,evidence_head FROM incidents WHERE site_id=%s AND incident_id=%s FOR UPDATE",  # noqa: E501
            (site_id, incident_id),
        ).fetchone()
        if row is None:
            raise LookupError("unknown incident")
        if int(row[0]) != expected_work_version:
            raise IncidentConflict("incident work version changed")
        version = expected_work_version + 1
        comment_id = uuid4()
        conn.execute(
            "UPDATE incidents SET work_version=%s WHERE site_id=%s AND incident_id=%s",
            (version, site_id, incident_id),
        )
        conn.execute(
            "INSERT INTO incident_comments(site_id,comment_id,incident_id,incident_revision_id,work_version,actor_key,body,at) "  # noqa: E501
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            (site_id, comment_id, incident_id, row[1], version, actor_key, body, now),
        )
        _record_history(
            conn,
            site_id=site_id,
            incident_id=incident_id,
            revision_id=row[1],
            version=version,
            actor_key=actor_key,
            action="commented",
            before=None,
            after={"comment_id": str(comment_id)},
            now=now,
        )
        record_audit(
            conn,
            site_id=site_id,
            kind="incident_comment_added",
            actor_key=actor_key,
            payload={
                "incident_id": str(incident_id),
                "comment_id": str(comment_id),
                "work_version": version,
            },
        )
        _save_idempotent(
            conn,
            site_id,
            principal_key,
            route,
            idempotency_key,
            request,
            {"comment_id": str(comment_id)},
            now,
        )
        return comment_id


def record_incident_disposition(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    incident_id: UUID,
    label: DispositionLabel,
    expected_work_version: int,
    expected_evidence_revision: UUID,
    actor_key: str,
    principal_key: str,
    idempotency_key: str,
    now: datetime,
    reason_code: str | None = None,
    note: str | None = None,
    propagate_to_members: bool = False,
) -> UUID:
    _require_site(conn, site_id)
    _validate_actor(actor_key, principal_key, idempotency_key, now)
    _integer(expected_work_version)
    labels = {
        "true_positive",
        "benign_true_positive",
        "false_positive",
        "duplicate",
        "undetermined",
    }
    if label not in labels:
        raise ValueError("unsupported disposition label")
    if propagate_to_members:
        raise ValueError("incident dispositions cannot propagate to member alerts")
    if reason_code is not None and (not reason_code or len(reason_code) > 64):
        raise ValueError("reason_code must be null or 1..64 characters")
    if note is not None and len(note) > 2000:
        raise ValueError("note must be at most 2000 characters")
    if label == "false_positive" and reason_code not in FALSE_POSITIVE_REASONS:
        raise ValueError("false-positive dispositions require a supported reason")
    if reason_code == "other" and not note:
        raise ValueError("reason_code 'other' requires a note")
    request: dict[str, object] = {
        "incident_id": str(incident_id),
        "label": label,
        "reason_code": reason_code,
        "note": note,
        "propagate_to_members": propagate_to_members,
        "expected_work_version": expected_work_version,
        "expected_evidence_revision": str(expected_evidence_revision),
        "actor_key": actor_key,
    }
    route = f"/incidents/{incident_id}/disposition"
    with _savepoint(conn):
        prior = _idempotent(conn, site_id, principal_key, route, idempotency_key, request)
        if prior is not None:
            return UUID(str(prior["disposition_id"]))
        row = conn.execute(
            "SELECT work_version,evidence_head FROM incidents WHERE site_id=%s AND incident_id=%s FOR UPDATE",  # noqa: E501
            (site_id, incident_id),
        ).fetchone()
        if row is None:
            raise LookupError("unknown incident")
        if int(row[0]) != expected_work_version:
            raise IncidentConflict("incident work version changed")
        if row[1] != expected_evidence_revision:
            raise IncidentConflict("incident evidence revision changed")
        version = expected_work_version + 1
        disposition_id = uuid4()
        conn.execute(
            "UPDATE incidents SET work_version=%s WHERE site_id=%s AND incident_id=%s",
            (version, site_id, incident_id),
        )
        conn.execute(
            "INSERT INTO incident_dispositions(site_id,disposition_id,incident_id,incident_revision_id,work_version,label,reason_code,note,actor_key,at) "  # noqa: E501
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                site_id,
                disposition_id,
                incident_id,
                row[1],
                version,
                label,
                reason_code,
                note,
                actor_key,
                now,
            ),
        )
        _record_history(
            conn,
            site_id=site_id,
            incident_id=incident_id,
            revision_id=row[1],
            version=version,
            actor_key=actor_key,
            action="disposition",
            before=None,
            after={
                "disposition_id": str(disposition_id),
                "label": label,
                "reason_code": reason_code,
            },
            now=now,
        )
        record_audit(
            conn,
            site_id=site_id,
            kind="incident_disposition_recorded",
            actor_key=actor_key,
            payload={
                "incident_id": str(incident_id),
                "disposition_id": str(disposition_id),
                "label": label,
                "reason_code": reason_code,
                "work_version": version,
            },
        )
        _save_idempotent(
            conn,
            site_id,
            principal_key,
            route,
            idempotency_key,
            request,
            {"disposition_id": str(disposition_id)},
            now,
        )
        return disposition_id


@dataclass(frozen=True, slots=True)
class IncidentMembership:
    membership_id: UUID
    group_id: str
    added_by: str
    added_at: datetime
    removed_by: str | None
    removed_at: datetime | None


@dataclass(frozen=True, slots=True)
class IncidentEvidenceMember:
    group_id: str
    group_revision: str
    title: str
    first_ts: datetime
    last_ts: datetime
    alert_count: int
    score_version: str | None
    score_digest: str | None
    score: float | None


@dataclass(frozen=True, slots=True)
class IncidentHistoryEntry:
    history_id: UUID
    work_version: int
    actor_key: str
    action: str
    before_value: object | None
    after_value: dict[str, object]
    at: datetime


@dataclass(frozen=True, slots=True)
class IncidentComment:
    comment_id: UUID
    revision_id: UUID
    work_version: int
    actor_key: str
    body: str
    at: datetime


@dataclass(frozen=True, slots=True)
class IncidentDisposition:
    disposition_id: UUID
    revision_id: UUID
    work_version: int
    label: DispositionLabel
    reason_code: str | None
    note: str | None
    actor_key: str
    at: datetime


@dataclass(frozen=True, slots=True)
class IncidentDetail:
    incident: IncidentSnapshot
    memberships: tuple[IncidentMembership, ...]
    evidence_members: tuple[IncidentEvidenceMember, ...]
    history: tuple[IncidentHistoryEntry, ...]
    comments: tuple[IncidentComment, ...]
    dispositions: tuple[IncidentDisposition, ...]
    next_membership_cursor: tuple[datetime, UUID] | None
    next_history_cursor: tuple[datetime, UUID] | None
    next_comment_cursor: tuple[datetime, UUID] | None
    next_disposition_cursor: tuple[datetime, UUID] | None


def get_incident_detail(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    incident_id: UUID,
    limit: int = 50,
    membership_before: tuple[datetime, UUID] | None = None,
    history_before: tuple[datetime, UUID] | None = None,
    comments_before: tuple[datetime, UUID] | None = None,
    dispositions_before: tuple[datetime, UUID] | None = None,
) -> IncidentDetail:
    """Read the current frozen group projection and bounded analyst history."""
    _require_site(conn, site_id)
    _integer(limit)
    if limit > 100:
        raise ValueError("incident detail limit cannot exceed 100")
    incident = get_incident(conn, site_id=site_id, incident_id=incident_id)
    membership_rows = _keyset_rows(
        conn,
        table="incident_membership_intervals",
        columns=("membership_id", "group_id", "added_by", "added_at", "removed_by", "removed_at"),
        site_id=site_id,
        incident_id=incident_id,
        cursor=membership_before,
        limit=limit,
        sort_column="added_at",
        id_column="membership_id",
    )
    evidence_rows = conn.execute(
        "SELECT m.group_id,m.group_revision,g.title,g.first_ts,g.last_ts,g.alert_count,"
        "m.score_version,m.score_digest,m.score FROM incident_revision_members m "
        "JOIN group_revisions g ON (g.site_id,g.group_id,g.revision)="
        "(m.site_id,m.group_id,m.group_revision) WHERE m.site_id=%s "
        "AND m.incident_revision_id=%s ORDER BY m.group_id LIMIT 101",
        (site_id, incident.evidence_head),
    ).fetchall()
    if len(evidence_rows) > 100:
        raise RuntimeError("incident evidence exceeds its 100-member invariant")
    history_rows = _keyset_rows(
        conn,
        table="incident_history",
        columns=(
            "history_id",
            "work_version",
            "actor_key",
            "action",
            "before_value",
            "after_value",
            "at",
        ),
        site_id=site_id,
        incident_id=incident_id,
        cursor=history_before,
        limit=limit,
        sort_column="at",
        id_column="history_id",
    )
    comment_rows = _keyset_rows(
        conn,
        table="incident_comments",
        columns=("comment_id", "incident_revision_id", "work_version", "actor_key", "body", "at"),
        site_id=site_id,
        incident_id=incident_id,
        cursor=comments_before,
        limit=limit,
        sort_column="at",
        id_column="comment_id",
    )
    disposition_rows = _keyset_rows(
        conn,
        table="incident_dispositions",
        columns=(
            "disposition_id",
            "incident_revision_id",
            "work_version",
            "label",
            "reason_code",
            "note",
            "actor_key",
            "at",
        ),
        site_id=site_id,
        incident_id=incident_id,
        cursor=dispositions_before,
        limit=limit,
        sort_column="at",
        id_column="disposition_id",
    )
    membership_has_more = len(membership_rows) > limit
    history_has_more = len(history_rows) > limit
    comments_has_more = len(comment_rows) > limit
    dispositions_has_more = len(disposition_rows) > limit
    membership_rows = membership_rows[:limit]
    history_rows = history_rows[:limit]
    comment_rows = comment_rows[:limit]
    disposition_rows = disposition_rows[:limit]
    return IncidentDetail(
        incident=incident,
        memberships=tuple(
            IncidentMembership(
                UUID(str(row[0])),
                str(row[1]),
                str(row[2]),
                row[3],
                None if row[4] is None else str(row[4]),
                row[5],
            )
            for row in membership_rows
        ),
        evidence_members=tuple(
            IncidentEvidenceMember(
                str(row[0]),
                str(row[1]),
                str(row[2]),
                row[3],
                row[4],
                int(row[5]),
                None if row[6] is None else str(row[6]),
                None if row[7] is None else str(row[7]),
                None if row[8] is None else float(row[8]),
            )
            for row in evidence_rows
        ),
        history=tuple(
            IncidentHistoryEntry(
                UUID(str(row[0])),
                int(row[1]),
                str(row[2]),
                str(row[3]),
                cast(object | None, row[4]),
                cast(dict[str, object], row[5]),
                row[6],
            )
            for row in history_rows
        ),
        comments=tuple(
            IncidentComment(
                UUID(str(row[0])), UUID(str(row[1])), int(row[2]), str(row[3]), str(row[4]), row[5]
            )
            for row in comment_rows
        ),
        dispositions=tuple(
            IncidentDisposition(
                UUID(str(row[0])),
                UUID(str(row[1])),
                int(row[2]),
                cast(DispositionLabel, row[3]),
                None if row[4] is None else str(row[4]),
                None if row[5] is None else str(row[5]),
                str(row[6]),
                row[7],
            )
            for row in disposition_rows
        ),
        next_membership_cursor=(membership_rows[-1][3], UUID(str(membership_rows[-1][0])))
        if membership_has_more
        else None,
        next_history_cursor=(history_rows[-1][6], UUID(str(history_rows[-1][0])))
        if history_has_more
        else None,
        next_comment_cursor=(comment_rows[-1][5], UUID(str(comment_rows[-1][0])))
        if comments_has_more
        else None,
        next_disposition_cursor=(disposition_rows[-1][7], UUID(str(disposition_rows[-1][0])))
        if dispositions_has_more
        else None,
    )


def _keyset_rows(
    conn: psycopg.Connection[Any],
    *,
    table: str,
    columns: tuple[str, ...],
    site_id: str,
    incident_id: UUID,
    cursor: tuple[datetime, UUID] | None,
    limit: int,
    sort_column: str,
    id_column: str,
) -> list[tuple[Any, ...]]:
    select = sql.SQL(",").join(sql.Identifier(column) for column in columns)
    if cursor is None:
        query = sql.SQL(
            "SELECT {} FROM {} WHERE site_id=%s AND incident_id=%s "
            "ORDER BY {} DESC,{} DESC LIMIT %s"
        ).format(
            select, sql.Identifier(table), sql.Identifier(sort_column), sql.Identifier(id_column)
        )
        params: tuple[object, ...] = (site_id, incident_id, limit + 1)
    else:
        query = sql.SQL(
            "SELECT {} FROM {} WHERE site_id=%s AND incident_id=%s "
            "AND ({},{})<(%s,%s) ORDER BY {} DESC,{} DESC LIMIT %s"
        ).format(
            select,
            sql.Identifier(table),
            sql.Identifier(sort_column),
            sql.Identifier(id_column),
            sql.Identifier(sort_column),
            sql.Identifier(id_column),
        )
        params = (site_id, incident_id, *cursor, limit + 1)
    return list(conn.execute(query, params).fetchall())
