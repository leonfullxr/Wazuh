"""Typed immutable persistence for bounded selected-scope correlation evaluations."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import wraps
from typing import Any, Concatenate, LiteralString, cast
from uuid import UUID, uuid4

import psycopg
from psycopg.pq import TransactionStatus
from psycopg.types.json import Jsonb
from pydantic import BaseModel

from ai_soc.workspace.audit_outbox import record_audit
from ai_soc.workspace.correlate.chains import evaluate_chain, parse_chain_rule
from ai_soc.workspace.correlate.edges import build_edges
from ai_soc.workspace.correlate.models import (
    ChainMatch,
    ChainRule,
    CorrelationInput,
    CorrelationObservation,
    EdgeDraft,
)
from ai_soc.workspace.correlate.sources import SourceProjection, project_retained_sources
from ai_soc.workspace.jobs import enqueue_job
from ai_soc.workspace.triage.grouping import digest


class CorrelationConflict(RuntimeError):
    """An immutable identity was reused for different persisted evidence."""


class CorrelationEvidenceError(ValueError):
    """A supplied frozen input or result is not supported by retained evidence."""


MAX_INPUT_GROUPS = 512
MAX_INPUT_OBSERVATIONS = 100_000
# Additional explicit storage bound, independent of the core count caps. No truncation.
MAX_FROZEN_BYTES = 256 * 1024 * 1024


def _require_site(conn: psycopg.Connection[Any], site_id: str) -> None:
    if conn.info.transaction_status is TransactionStatus.IDLE:
        raise PermissionError("correlation operation requires an active site transaction")
    row = conn.execute("SELECT current_setting('app.site_id', true)").fetchone()
    if row is None or row[0] != site_id:
        raise PermissionError("correlation operation requires an active transaction for its site")


def _savepoint[**P, R](
    function: Callable[Concatenate[psycopg.Connection[Any], P], R],
) -> Callable[Concatenate[psycopg.Connection[Any], P], R]:
    """Require an outer transaction; failures undo only this method's effects."""

    @wraps(function)
    def wrapped(conn: psycopg.Connection[Any], *args: P.args, **kwargs: P.kwargs) -> R:
        if conn.info.transaction_status is TransactionStatus.IDLE:
            raise PermissionError("correlation operation requires an active site transaction")
        with conn.transaction():
            return function(conn, *args, **kwargs)

    return wrapped


def _plain(value: BaseModel) -> dict[str, Any]:
    return value.model_dump(mode="json")


def _canonical(value: object) -> str:
    # Same encoding as the authoritative core digest (including ASCII escaping).
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def _aware(value: datetime, name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")


def _operation_cutoff(inputs: CorrelationInput, now: datetime) -> None:
    _aware(now, "now")
    if inputs.as_of > now:
        raise CorrelationEvidenceError("correlation cutoff is later than the operation clock")


def _score_cutoff(value: object, cutoff: datetime) -> None:
    if not isinstance(value, str):
        raise CorrelationEvidenceError("score manifest cutoff is unavailable")
    try:
        frozen_at = datetime.fromisoformat(value)
        _aware(frozen_at, "score manifest cutoff")
    except ValueError as exc:
        raise CorrelationEvidenceError("score manifest cutoff is invalid") from exc
    if frozen_at > cutoff:
        raise CorrelationEvidenceError("score manifest cutoff is later than correlation cutoff")


def _rule_payload(rule: ChainRule) -> dict[str, Any]:
    if rule.source_yaml is None:
        raise CorrelationEvidenceError("chain rule must retain its exact source YAML")
    parsed = parse_chain_rule(rule.source_yaml.encode("utf-8"))
    if parsed.model_dump() != rule.model_dump():
        raise CorrelationEvidenceError("chain rule differs from its exact source YAML")
    return _plain(parsed)


def _canonical_input(inputs: CorrelationInput) -> CorrelationInput:
    # Revalidate even model_construct/model_copy callers; JSON is the strict boundary.
    validated = CorrelationInput.model_validate_json(inputs.model_dump_json())
    raw = _canonical(validated.canonical_payload)
    if len(raw.encode()) > MAX_FROZEN_BYTES:
        raise CorrelationEvidenceError("serialized frozen input exceeds 256 MiB storage bound")
    return CorrelationInput.model_validate_json(raw)


def _scope_digest(inputs: CorrelationInput) -> str:
    payload = inputs.canonical_payload
    return digest(
        {
            "site_id": inputs.site_id,
            "window_start": payload["window_start"],
            "window_end": payload["window_end"],
            "group_ids": sorted(group.group_id for group in inputs.groups),
        }
    )


def _validate_snapshot(observation: CorrelationObservation, snapshot: dict[str, Any]) -> None:
    for field in ("rule_id", "decoder", "agent_id", "src_ip", "dst_ip", "src_user", "dst_user"):
        if getattr(observation, field) != snapshot.get(field):
            raise CorrelationEvidenceError(f"observation {field} differs from retained membership")
    for field in ("rule_groups", "mitre_tactics"):
        if sorted(getattr(observation, field)) != sorted(snapshot.get(field) or ()):
            raise CorrelationEvidenceError(f"observation {field} differs from retained membership")
    refs = cast(list[dict[str, Any]], snapshot.get("_entity_refs", []))
    hashes = sorted(str(entity["value"]) for entity in refs if entity.get("kind") == "hash")
    if sorted(observation.hashes) != hashes:
        raise CorrelationEvidenceError("observation hashes differ from retained membership")


@dataclass(frozen=True)
class _Member:
    observation: CorrelationObservation
    snapshot: dict[str, Any]
    projection: SourceProjection


def _validate_evidence(
    conn: psycopg.Connection[Any],
    inputs: CorrelationInput,
    *,
    create: bool,
) -> list[_Member]:
    """Validate complete selected revisions in [start,end), with batched witnesses."""
    groups = inputs.groups
    group_rows = conn.execute(
        """SELECT g.group_id,g.revision,s.total,sm.manifest->>'as_of'
           FROM unnest(%s::text[],%s::text[],%s::text[],%s::text[])
             AS chosen(gid,rev,sv,sd)
           JOIN group_revisions g ON g.site_id=%s AND g.group_id=chosen.gid
             AND g.revision=chosen.rev
           LEFT JOIN scores s ON s.site_id=g.site_id AND s.group_id=g.group_id
             AND s.group_revision=g.revision AND s.computation_version=chosen.sv
             AND s.input_digest=chosen.sd
           LEFT JOIN score_manifests sm
             ON (sm.site_id,sm.group_id,sm.group_revision,sm.computation_version,sm.input_digest)
              = (s.site_id,s.group_id,s.group_revision,s.computation_version,s.input_digest)""",
        (
            [g.group_id for g in groups],
            [g.revision for g in groups],
            [g.computation_version for g in groups],
            [g.input_digest for g in groups],
            inputs.site_id,
        ),
    ).fetchall()
    by_group = {(g.group_id, g.revision): g for g in groups}
    if len(group_rows) != len(groups):
        raise CorrelationEvidenceError("frozen group has no retained revision")
    for gid, rev, total, frozen_at in group_rows:
        group = by_group[(gid, rev)]
        if group.computation_version is not None and total is None:
            raise CorrelationEvidenceError("score reference has no exact immutable score row")
        if group.computation_version is not None:
            _score_cutoff(frozen_at, inputs.as_of)
        if group.score is not None and (total is None or float(total) != group.score):
            raise CorrelationEvidenceError("measured score differs from its referenced score row")
    rows = conn.execute(
        """SELECT gm.group_id,gm.group_revision,gm.alert_key,gm.event_ts,gm.source_hash,
                  gm.normalized_snapshot,r.original_event_ts,r.source_hash
           FROM unnest(%s::text[],%s::text[]) AS chosen(gid,rev)
           JOIN group_members gm ON gm.site_id=%s AND gm.group_id=chosen.gid
             AND gm.group_revision=chosen.rev
           LEFT JOIN alert_registry r ON r.site_id=gm.site_id AND r.alert_key=gm.alert_key
           WHERE gm.event_ts >= %s AND gm.event_ts < %s LIMIT %s""",
        (
            [g.group_id for g in groups],
            [g.revision for g in groups],
            inputs.site_id,
            inputs.window_start,
            inputs.window_end,
            MAX_INPUT_OBSERVATIONS + 1,
        ),
    ).fetchall()
    observations = {(o.group_id, o.group_revision, o.alert_key): o for o in inputs.observations}
    if len(rows) != len(observations):
        raise CorrelationEvidenceError("frozen observations omit or add members inside the window")
    snapshots: dict[str, dict[str, Any]] = {}
    for gid, rev, key, event_ts, source_hash, snapshot, registry_ts, registry_hash in rows:
        observation = observations.get((gid, rev, key))
        if (
            observation is None
            or event_ts != registry_ts
            or source_hash != registry_hash
            or observation.event_ts != event_ts
            or observation.source_hash != source_hash
        ):
            raise CorrelationEvidenceError(
                "observation differs from exact retained membership witness"
            )
        value = cast(dict[str, Any], snapshot)
        _validate_snapshot(observation, value)
        snapshots[key] = value
    projections = project_retained_sources(
        conn,
        site_id=inputs.site_id,
        alert_keys=tuple(o.alert_key for o in inputs.observations),
        extraction_version="syscheck-v1",
        create=create,
    )
    members: list[_Member] = []
    for observation in inputs.observations:
        projection = projections[observation.alert_key]
        if (
            observation.file_path != projection.path
            or observation.file_event != projection.event
            or observation.source_hash != projection.source_hash
            or observation.event_ts != projection.event_ts
        ):
            raise CorrelationEvidenceError(
                "file evidence differs from verified raw syscheck source"
            )
        members.append(_Member(observation, snapshots[observation.alert_key], projection))
    return members


@_savepoint
def freeze_manifest(
    conn: psycopg.Connection[Any],
    *,
    inputs: CorrelationInput,
    rule: ChainRule,
    now: datetime,
) -> UUID:
    """Retain canonical evidence; complete means only the declared selected scope.

    The serialized input storage cap is 256 MiB; core caps remain 512 groups and
    100,000 observations. Exceeding a cap fails atomically without truncation.
    """
    _require_site(conn, inputs.site_id)
    _aware(now, "now")
    inputs = _canonical_input(inputs)
    _operation_cutoff(inputs, now)
    rule_json = _rule_payload(rule)
    key = digest([inputs.site_id, inputs.canonical_digest, rule.content_digest])
    conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", (key,))
    existing = conn.execute(
        """SELECT manifest_id FROM correlation_manifests
           WHERE site_id=%s AND input_digest=%s AND rule_digest=%s""",
        (inputs.site_id, inputs.canonical_digest, rule.content_digest),
    ).fetchone()
    if existing is not None:
        retained_inputs, retained_rule = load_manifest(
            conn, siteid=inputs.site_id, manifestid=existing[0]
        )
        if retained_inputs != inputs or retained_rule != rule:
            raise CorrelationConflict("manifest content key contains different immutable bytes")
        return cast(UUID, existing[0])
    members = _validate_evidence(conn, inputs, create=True)
    manifest_id = uuid4()
    conn.execute(
        """INSERT INTO correlation_manifests
           (site_id,manifest_id,input_digest,rule_id,rule_version,rule_digest,scope_digest,
            computation_version,window_start,window_end,as_of,complete,frozen_input,frozen_rule,created_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,true,%s,%s,%s)""",
        (
            inputs.site_id,
            manifest_id,
            inputs.canonical_digest,
            rule.id,
            rule.version,
            rule.content_digest,
            _scope_digest(inputs),
            inputs.computation_version,
            inputs.window_start,
            inputs.window_end,
            inputs.as_of,
            Jsonb(inputs.canonical_payload),
            Jsonb(rule_json),
            now,
        ),
    )
    with conn.cursor() as cursor:
        cursor.executemany(
            """INSERT INTO correlation_input_groups
               (site_id,manifest_id,group_id,group_revision,score_version,score_digest,score)
               VALUES (%s,%s,%s,%s,%s,%s,%s)""",
            [
                (
                    inputs.site_id,
                    manifest_id,
                    g.group_id,
                    g.revision,
                    g.computation_version,
                    g.input_digest,
                    g.score,
                )
                for g in inputs.groups
            ],
        )
        cursor.executemany(
            """INSERT INTO correlation_input_members
               (site_id,manifest_id,group_id,group_revision,alert_key,event_ts,source_hash,
                normalized_snapshot,projection_version,projection_digest)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            [
                (
                    inputs.site_id,
                    manifest_id,
                    m.observation.group_id,
                    m.observation.group_revision,
                    m.observation.alert_key,
                    m.observation.event_ts,
                    m.observation.source_hash,
                    Jsonb(m.snapshot),
                    m.projection.extraction_version,
                    m.projection.projection_digest,
                )
                for m in members
            ],
        )
    return manifest_id


@_savepoint
def enqueue_correlation(
    conn: psycopg.Connection[Any],
    *,
    manifestid: UUID,
    siteid: str,
    now: datetime,
) -> int:
    """Serialize intents in site/window/selected-group scope; unchanged current input retries.

    Job kind is ``correlate_window``, subject is ``str(intent_id)``, payload is
    exactly ``{"manifest_id": str(manifestid), "intent_id": str(intent_id)}``.
    Handlers must pass both pins to persist_results. A returning manifest gets a
    fresh intent/job after an intervening manifest within the same scope.
    """
    _require_site(conn, siteid)
    _aware(now, "now")
    inputs, _ = load_manifest(conn, siteid=siteid, manifestid=manifestid)
    _operation_cutoff(inputs, now)
    scope = _scope_digest(inputs)
    conn.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
        (f"correlation-intent:{siteid}:{scope}",),
    )
    latest = conn.execute(
        """SELECT i.manifest_id,i.intent_id,i.job_id,j.kind,j.subject,j.payload
           FROM correlation_publication_intents i JOIN jobs j USING (site_id,job_id)
           WHERE i.site_id=%s AND i.scope_digest=%s ORDER BY i.intent_seq DESC LIMIT 1""",
        (siteid, scope),
    ).fetchone()
    if latest is not None and latest[0] == manifestid:
        payload = {"manifest_id": str(manifestid), "intent_id": str(latest[1])}
        if latest[3] != "correlate_window" or latest[4] != str(latest[1]) or latest[5] != payload:
            raise CorrelationConflict("durable correlation job differs from its frozen intent")
        return int(latest[2])
    intent_id = uuid4()
    payload = {"manifest_id": str(manifestid), "intent_id": str(intent_id)}
    job_id = enqueue_job(
        conn,
        site_id=siteid,
        kind="correlate_window",
        subject=str(intent_id),
        payload=payload,
        run_after=now,
    )
    saved = conn.execute(
        "SELECT kind,subject,payload FROM jobs WHERE site_id=%s AND job_id=%s", (siteid, job_id)
    ).fetchone()
    if saved != ("correlate_window", str(intent_id), payload):
        raise CorrelationConflict("durable correlation job differs from its frozen intent")
    conn.execute(
        """INSERT INTO correlation_publication_intents
           (site_id,intent_id,manifest_id,scope_digest,job_id,created_at)
           VALUES (%s,%s,%s,%s,%s,%s)""",
        (siteid, intent_id, manifestid, scope, job_id, now),
    )
    return job_id


def load_manifest(
    conn: psycopg.Connection[Any],
    *,
    siteid: str,
    manifestid: UUID,
) -> tuple[CorrelationInput, ChainRule]:
    """Restore strict models through serialized JSON, checking every retained witness."""
    _require_site(conn, siteid)
    row = conn.execute(
        """SELECT input_digest,rule_digest,frozen_input,frozen_rule,rule_id,rule_version,
                  computation_version,window_start,window_end,as_of,complete,scope_digest
           FROM correlation_manifests WHERE site_id=%s AND manifest_id=%s""",
        (siteid, manifestid),
    ).fetchone()
    if row is None:
        raise LookupError("correlation manifest is unavailable for this site")
    inputs = CorrelationInput.model_validate_json(_canonical(row[2]))
    rule = ChainRule.model_validate_json(_canonical(row[3]))
    _rule_payload(rule)
    if (
        inputs.canonical_digest != row[0]
        or rule.content_digest != row[1]
        or inputs.canonical_payload != row[2]
        or inputs.site_id != siteid
        or rule.id != row[4]
        or rule.version != row[5]
        or inputs.computation_version != row[6]
        or inputs.window_start != row[7]
        or inputs.window_end != row[8]
        or inputs.as_of != row[9]
        or row[10] is not True
        or _scope_digest(inputs) != row[11]
    ):
        raise CorrelationConflict("manifest metadata differs from its canonical frozen evidence")
    members = _validate_evidence(conn, inputs, create=False)
    group_rows = conn.execute(
        """SELECT group_id,group_revision,score_version,score_digest,score
           FROM correlation_input_groups WHERE site_id=%s AND manifest_id=%s""",
        (siteid, manifestid),
    ).fetchall()
    expected_groups = {
        (g.group_id, g.revision, g.computation_version, g.input_digest, g.score)
        for g in inputs.groups
    }
    if {
        (r[0], r[1], r[2], r[3], None if r[4] is None else float(r[4])) for r in group_rows
    } != expected_groups:
        raise CorrelationConflict("typed score association differs from frozen input")
    member_rows = conn.execute(
        """SELECT group_id,group_revision,alert_key,event_ts,source_hash,normalized_snapshot,
                  projection_version,projection_digest FROM correlation_input_members
           WHERE site_id=%s AND manifest_id=%s""",
        (siteid, manifestid),
    ).fetchall()
    expected_members = {
        (m.observation.group_id, m.observation.group_revision, m.observation.alert_key): m
        for m in members
    }
    if len(member_rows) != len(expected_members):
        raise CorrelationConflict("frozen observation is missing its typed membership association")
    for r in member_rows:
        member = expected_members.get((r[0], r[1], r[2]))
        if member is None or (r[3], r[4], r[5], r[6], r[7]) != (
            member.observation.event_ts,
            member.observation.source_hash,
            member.snapshot,
            member.projection.extraction_version,
            member.projection.projection_digest,
        ):
            raise CorrelationConflict("typed member differs from retained frozen evidence")
    return inputs, rule


def _verify_pure_outputs(
    inputs: CorrelationInput,
    rule: ChainRule,
    edges: tuple[EdgeDraft, ...],
    chains: tuple[ChainMatch, ...],
) -> tuple[tuple[EdgeDraft, ...], tuple[ChainMatch, ...]]:
    expected_edges = build_edges(inputs)
    expected_chains = evaluate_chain(rule, inputs)
    if edges != expected_edges:
        raise CorrelationEvidenceError("edge output differs from the frozen input evaluation")
    if chains != expected_chains:
        raise CorrelationEvidenceError("chain output differs from the frozen rule evaluation")
    return expected_edges, expected_chains


@_savepoint
def persist_results(
    conn: psycopg.Connection[Any],
    *,
    siteid: str,
    manifestid: UUID,
    intentid: UUID,
    edges: tuple[EdgeDraft, ...],
    chains: tuple[ChainMatch, ...],
    now: datetime,
) -> dict[str, int]:
    """Persist validated derived results, then advance only an authoritative head."""
    _require_site(conn, siteid)
    _aware(now, "now")
    inputs, rule = load_manifest(conn, siteid=siteid, manifestid=manifestid)
    _operation_cutoff(inputs, now)
    edges, chains = _verify_pure_outputs(inputs, rule, edges, chains)
    intent = conn.execute(
        """SELECT i.intent_seq, m.as_of, m.complete FROM correlation_publication_intents i
           JOIN correlation_manifests m USING (site_id, manifest_id)
           WHERE i.site_id=%s AND i.intent_id=%s AND i.manifest_id=%s FOR UPDATE""",
        (siteid, intentid, manifestid),
    ).fetchone()
    if intent is None:
        raise LookupError("publication intent does not refer to this manifest")
    intent_seq, cutoff, complete = int(intent[0]), intent[1], bool(intent[2])
    member_refs = {(o.group_id, o.group_revision, o.alert_key) for o in inputs.observations}
    for edge in edges:
        if edge.site_id != siteid:
            raise CorrelationEvidenceError("edge belongs to another site")
        left = (
            str(edge.from_group),
            str(edge.from_revision),
            str(edge.from_alert_key),
        )
        right = (
            str(edge.to_group),
            str(edge.to_revision),
            str(edge.to_alert_key),
        )
        if left not in member_refs or right not in member_refs or left[:2] == right[:2]:
            raise CorrelationEvidenceError(
                "edge endpoints are not exact frozen input member witnesses"
            )
        if not 0 <= float(edge.confidence) <= 1:
            raise CorrelationEvidenceError("edge confidence is outside its supported range")
    for edge in edges:
        edge_payload = _plain(edge)
        values = (
            siteid,
            manifestid,
            edge_payload["edge_id"],
            edge_payload["from_group"],
            edge_payload["from_revision"],
            edge_payload["from_alert_key"],
            edge_payload["to_group"],
            edge_payload["to_revision"],
            edge_payload["to_alert_key"],
            edge_payload["edge_type"],
            edge_payload["confidence"],
            edge_payload["weak"],
            edge_payload["reason"],
            edge_payload["time_delta_seconds"],
            Jsonb(edge_payload["shared_fields"]),
        )
        _insert_immutable(
            conn,
            """INSERT INTO correlation_edges
            (site_id, manifest_id, edge_id, from_group, from_revision, from_alert_key, to_group,
             to_revision, to_alert_key, edge_type, confidence, weak, reason, time_delta_seconds,
             shared_fields)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
            values,
            "SELECT edge_id, from_group, from_revision, from_alert_key, to_group, to_revision, "
            "to_alert_key, edge_type, confidence, weak, reason, time_delta_seconds, shared_fields "
            "FROM correlation_edges WHERE site_id=%s AND manifest_id=%s AND edge_id=%s",
            (siteid, manifestid, edge_payload["edge_id"]),
            (
                edge_payload["edge_id"],
                edge_payload["from_group"],
                edge_payload["from_revision"],
                edge_payload["from_alert_key"],
                edge_payload["to_group"],
                edge_payload["to_revision"],
                edge_payload["to_alert_key"],
                edge_payload["edge_type"],
                edge_payload["confidence"],
                edge_payload["weak"],
                edge_payload["reason"],
                edge_payload["time_delta_seconds"],
                _canonical(edge_payload["shared_fields"]),
            ),
        )

    candidates = tuple(chain for chain in chains if chain.is_candidate)
    published = 0
    for chain in candidates:
        chain_id = chain.chain_id
        if chain.rule_id != rule.id or chain.rule_version != rule.version:
            raise CorrelationEvidenceError("chain result does not belong to the frozen rule")
        stages = tuple(chain.stages)
        anchor = str(chain.anchor_alert_key)
        anchor_ref = next((ref for ref in member_refs if ref[2] == anchor), None)
        if anchor_ref is None:
            raise CorrelationEvidenceError("chain anchor is not a frozen input member")
        for stage in stages:
            witness = (
                str(stage.group_id),
                str(stage.group_revision),
                str(stage.alert_key),
            )
            if witness not in member_refs:
                raise CorrelationEvidenceError(
                    "chain stage is not an exact frozen input member witness"
                )
        subject = conn.execute(
            "SELECT subject_kind FROM subject_registry WHERE site_id=%s AND subject_id=%s",
            (siteid, chain_id),
        ).fetchone()
        if subject is not None and subject[0] != "chain":
            raise CorrelationEvidenceError(
                "chain identity is already registered for another subject kind"
            )
        semantic_identity = conn.execute(
            """SELECT chain_id FROM correlation_chains WHERE site_id=%s AND rule_id=%s
               AND rule_version=%s AND anchor_group_id=%s AND anchor_identity=%s""",
            (
                siteid,
                chain.rule_id,
                chain.rule_version,
                anchor_ref[0],
                chain.anchor_identity,
            ),
        ).fetchone()
        if semantic_identity is not None and str(semantic_identity[0]) != chain_id:
            raise CorrelationEvidenceError(
                "the same semantic chain candidate changed its stable chain identity"
            )
        conn.execute(
            "INSERT INTO subject_registry(site_id,subject_kind,subject_id) "
            "VALUES (%s,'chain',%s) ON CONFLICT DO NOTHING",
            (siteid, chain_id),
        )
        chain_values = (
            siteid,
            chain_id,
            chain.rule_id,
            chain.rule_version,
            chain.anchor_alert_key,
            anchor_ref[0],
            chain.anchor_identity,
            now,
        )
        _insert_immutable(
            conn,
            """INSERT INTO correlation_chains
            (site_id,chain_id,rule_id,rule_version,anchor_alert_key,anchor_group_id,
             anchor_identity,created_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
            chain_values,
            "SELECT rule_id,rule_version,anchor_group_id,anchor_identity "
            "FROM correlation_chains WHERE site_id=%s AND chain_id=%s",
            (siteid, chain_id),
            (
                chain.rule_id,
                chain.rule_version,
                anchor_ref[0],
                chain.anchor_identity,
            ),
        )
        result_payload = _plain(chain)
        revision = str(chain.revision_digest)
        _insert_immutable(
            conn,
            """INSERT INTO correlation_chain_revisions
            (site_id,chain_id,revision_digest,manifest_id,rule_id,rule_version,anchor_alert_key,
             anchor_group_id,anchor_group_revision,result,created_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
            (
                siteid,
                chain_id,
                revision,
                manifestid,
                chain.rule_id,
                chain.rule_version,
                anchor,
                anchor_ref[0],
                anchor_ref[1],
                Jsonb(result_payload),
                now,
            ),
            "SELECT manifest_id,rule_id,rule_version,anchor_alert_key,anchor_group_id,"
            "anchor_group_revision,result FROM correlation_chain_revisions "
            "WHERE site_id=%s AND chain_id=%s AND revision_digest=%s AND manifest_id=%s",
            (siteid, chain_id, revision, manifestid),
            (
                manifestid,
                chain.rule_id,
                chain.rule_version,
                anchor,
                anchor_ref[0],
                anchor_ref[1],
                _canonical(result_payload),
            ),
        )
        matched_by_id = {str(stage.stage_id): stage for stage in stages}
        missing_ids = {str(stage_id) for stage_id in chain.missing_stages}
        if len(matched_by_id) != len(stages) or len(missing_ids) != len(
            tuple(chain.missing_stages)
        ):
            raise CorrelationEvidenceError("chain result repeats a stage outcome")
        if set(matched_by_id) & missing_ids:
            raise CorrelationEvidenceError("chain stage cannot be both matched and missing")
        rule_stage_ids = [stage.id for stage in rule.stages]
        if len(rule_stage_ids) > 8 or set(matched_by_id) | missing_ids != set(rule_stage_ids):
            raise CorrelationEvidenceError("chain result does not freeze every rule stage outcome")
        stage_rows: list[
            tuple[str, str, str | None, str | None, str | None, datetime | None, float | None]
        ] = []
        for stage_id in rule_stage_ids:
            stage = matched_by_id.get(stage_id)
            if stage is None:
                stage_rows.append(("missing", stage_id, None, None, None, None, None))
            else:
                stage_rows.append(
                    (
                        "matched",
                        stage_id,
                        str(stage.group_id),
                        str(stage.group_revision),
                        str(stage.alert_key),
                        stage.event_ts,
                        float(stage.confidence),
                    )
                )
        if len(stage_rows) > 8:
            raise CorrelationEvidenceError("chain result exceeds the supported stage bound")
        for ordinal, (
            outcome,
            stage_id,
            group_id,
            group_revision,
            alert_key,
            event_ts,
            confidence,
        ) in enumerate(stage_rows):
            evidence = (
                siteid,
                chain_id,
                revision,
                manifestid,
                ordinal,
                stage_id,
                outcome,
                group_id,
                group_revision,
                alert_key,
                event_ts,
                confidence,
            )
            _insert_immutable(
                conn,
                """INSERT INTO correlation_stage_evidence
                   (site_id,chain_id,revision_digest,manifest_id,ordinal,stage_id,outcome,
                    group_id,group_revision,alert_key,event_ts,confidence)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                evidence,
                """SELECT stage_id,outcome,group_id,group_revision,alert_key,event_ts,confidence
                   FROM correlation_stage_evidence WHERE site_id=%s AND chain_id=%s
                     AND revision_digest=%s AND manifest_id=%s AND ordinal=%s""",
                (siteid, chain_id, revision, manifestid, ordinal),
                (stage_id, outcome, group_id, group_revision, alert_key, event_ts, confidence),
            )
        if complete:
            prior = conn.execute(
                "SELECT cutoff,intent_seq FROM correlation_heads "
                "WHERE site_id=%s AND chain_id=%s FOR UPDATE",
                (siteid, chain_id),
            ).fetchone()
            if prior is None or (cutoff, intent_seq) > (prior[0], int(prior[1])):
                head = conn.execute(
                    """INSERT INTO correlation_heads
                       (site_id,chain_id,revision_digest,manifest_id,intent_id,cutoff,intent_seq,updated_at)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                       ON CONFLICT (site_id,chain_id) DO UPDATE
                       SET revision_digest=EXCLUDED.revision_digest,
                         manifest_id=EXCLUDED.manifest_id,intent_id=EXCLUDED.intent_id,
                         cutoff=EXCLUDED.cutoff,
                         intent_seq=EXCLUDED.intent_seq,updated_at=EXCLUDED.updated_at
                       WHERE (EXCLUDED.cutoff,EXCLUDED.intent_seq) >
                             (correlation_heads.cutoff,correlation_heads.intent_seq)
                       RETURNING chain_id""",
                    (siteid, chain_id, revision, manifestid, intentid, cutoff, intent_seq, now),
                ).fetchone()
                published += int(head is not None)
    return {"edges": len(edges), "chains": len(candidates), "published": published}


def _insert_immutable(
    conn: psycopg.Connection[Any],
    insert_sql: LiteralString,
    values: tuple[Any, ...],
    read_sql: LiteralString,
    read_values: tuple[Any, ...],
    expected: tuple[Any, ...],
) -> None:
    conn.execute(insert_sql, values)
    row = conn.execute(read_sql, read_values).fetchone()
    if row is None:
        raise RuntimeError("immutable correlation insert was not visible")
    actual = tuple(
        _canonical(cast(object, value)) if isinstance(value, (dict, list)) else value
        for value in row
    )
    if actual != expected:
        raise CorrelationConflict("correlation identity already contains different immutable bytes")


@_savepoint
def _dismiss_candidate(
    conn: psycopg.Connection[Any],
    *,
    siteid: str,
    chainid: str,
    actor_key: str,
    reason: str,
    expected_version: int,
    idempotency_key: str,
    now: datetime,
    reviewed_pins: dict[str, object] | None = None,
) -> int:
    """Append an audited analyst dismissal without coupling it to derived revisions."""
    _require_site(conn, siteid)
    _aware(now, "now")
    if (
        not actor_key
        or len(actor_key) > 256
        or not reason
        or len(reason) > 512
        or not 16 <= len(idempotency_key) <= 128
    ):
        raise ValueError("actor, bounded reason and idempotency key are required")
    conn.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
        (f"correlation-decision:{siteid}:{chainid}",),
    )
    existing = conn.execute(
        "SELECT version,state,reason,actor_key FROM correlation_decision_history "
        "WHERE site_id=%s AND chain_id=%s AND idempotency_key=%s",
        (siteid, chainid, idempotency_key),
    ).fetchone()
    if existing is not None:
        if tuple(existing[1:]) != ("dismissed", reason, actor_key):
            raise CorrelationConflict("decision idempotency key was reused with different content")
        return int(existing[0])
    current = conn.execute(
        "SELECT version,state FROM correlation_decisions "
        "WHERE site_id=%s AND chain_id=%s FOR UPDATE",
        (siteid, chainid),
    ).fetchone()
    current_version = 0 if current is None else int(current[0])
    if current is not None and current[1] in {"dismissed", "promoted"}:
        raise CorrelationConflict("candidate already has a terminal analyst decision")
    if current_version != expected_version:
        raise CorrelationConflict("analyst decision version changed")
    version = current_version + 1
    audit_event_id = record_audit(
        conn,
        site_id=siteid,
        kind="correlation_candidate_dismissed",
        actor_key=actor_key,
        payload={
            "chain_id": chainid,
            "version": version,
            "reason": reason,
            "idempotency_key": idempotency_key,
            **(reviewed_pins or {}),
        },
    )
    conn.execute(
        """INSERT INTO correlation_decision_history
           (site_id,chain_id,decision_id,audit_event_id,idempotency_key,version,state,reason,actor_key,at)
           VALUES (%s,%s,%s,%s,%s,%s,'dismissed',%s,%s,%s)""",
        (
            siteid,
            chainid,
            uuid4(),
            audit_event_id,
            idempotency_key,
            version,
            reason,
            actor_key,
            now,
        ),
    )
    conn.execute(
        """INSERT INTO correlation_decisions
           (site_id,chain_id,version,state,reason,actor_key,updated_at)
           VALUES (%s,%s,%s,'dismissed',%s,%s,%s)
           ON CONFLICT (site_id,chain_id) DO UPDATE
           SET version=EXCLUDED.version,state=EXCLUDED.state,
             reason=EXCLUDED.reason,actor_key=EXCLUDED.actor_key,updated_at=EXCLUDED.updated_at""",
        (siteid, chainid, version, reason, actor_key, now),
    )
    return version


@dataclass(frozen=True, slots=True)
class CandidateDecision:
    chain_id: str
    version: int
    updated_at: datetime


def dismiss_candidate(
    conn: psycopg.Connection[Any],
    *,
    siteid: str,
    chainid: str,
    actor_key: str,
    reason: str,
    expected_version: int,
    idempotency_key: str,
    now: datetime,
) -> int:
    """Legacy internal dismissal; interactive callers use reviewed evidence pins."""
    return _dismiss_candidate(
        conn,
        siteid=siteid,
        chainid=chainid,
        actor_key=actor_key,
        reason=reason,
        expected_version=expected_version,
        idempotency_key=idempotency_key,
        now=now,
    )


@_savepoint
def dismiss_reviewed_candidate(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    chain_id: str,
    expected_revision: str,
    expected_manifest_id: UUID,
    expected_decision_version: int,
    actor_key: str,
    principal_key: str,
    reason: str,
    idempotency_key: str,
    now: datetime,
) -> CandidateDecision:
    """Atomically dismiss reviewed evidence and retain its original retry result."""
    _require_site(conn, site_id)
    _aware(now, "now")
    if not actor_key or len(actor_key) > 256 or not principal_key or len(principal_key) > 256:
        raise ValueError("actor and principal are required and limited to 256 characters")
    if not 16 <= len(idempotency_key) <= 128 or any(
        ord(char) < 33 or ord(char) > 126 for char in idempotency_key
    ):
        raise ValueError("idempotency key must be 16..128 visible ASCII characters")
    if len(expected_revision) != 64 or any(c not in "0123456789abcdef" for c in expected_revision):
        raise ValueError("expected_revision must be a SHA-256 digest")
    if type(expected_decision_version) is not int or expected_decision_version < 0:
        raise ValueError("expected_decision_version must be a nonnegative integer")
    if not reason or len(reason) > 512:
        raise ValueError("bounded reason is required")
    route = f"/chains/{chain_id}/dismiss"
    intent = {
        "chain_id": chain_id,
        "revision": expected_revision,
        "manifest_id": str(expected_manifest_id),
        "decision_version": expected_decision_version,
        "reason": reason,
        "actor_key": actor_key,
    }
    # Same decision lock order as promotion. Retries precede mutable-head checks.
    conn.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
        (f"correlation-decision:{site_id}:{chain_id}",),
    )
    conn.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
        (f"idempotency:{site_id}:{principal_key}:{route}:{idempotency_key}",),
    )
    previous = conn.execute(
        "SELECT request_digest,response FROM workspace_idempotency WHERE site_id=%s "
        "AND principal_key=%s AND route_key=%s AND idempotency_key=%s",
        (site_id, principal_key, route, idempotency_key),
    ).fetchone()
    if previous is not None:
        if previous[0] != digest(intent):
            raise CorrelationConflict("idempotency key was reused with different request content")
        value = previous[1]
        at = datetime.fromisoformat(str(value["updated_at"]))
        _aware(at, "stored decision timestamp")
        return CandidateDecision(str(value["chain_id"]), int(value["version"]), at)
    head = conn.execute(
        "SELECT h.revision_digest,h.manifest_id,COALESCE(d.version,0) "
        "FROM correlation_heads h LEFT JOIN correlation_decisions d USING(site_id,chain_id) "
        "WHERE h.site_id=%s AND h.chain_id=%s FOR UPDATE OF h",
        (site_id, chain_id),
    ).fetchone()
    if head is None:
        raise LookupError("unknown candidate")
    if (str(head[0]), head[1], int(head[2])) != (
        expected_revision,
        expected_manifest_id,
        expected_decision_version,
    ):
        raise CorrelationConflict(
            "candidate evidence or decision changed; refresh before dismissal"
        )
    history_key = digest(
        [
            principal_key,
            idempotency_key,
            chain_id,
            expected_revision,
            str(expected_manifest_id),
            expected_decision_version,
            reason,
        ]
    )
    version = _dismiss_candidate(
        conn,
        siteid=site_id,
        chainid=chain_id,
        actor_key=actor_key,
        reason=reason,
        expected_version=expected_decision_version,
        idempotency_key=history_key,
        now=now,
        reviewed_pins={
            "reviewed_revision": expected_revision,
            "reviewed_manifest_id": str(expected_manifest_id),
            "expected_decision_version": expected_decision_version,
        },
    )
    at = now.astimezone(UTC)
    response = {
        "chain_id": chain_id,
        "state": "dismissed",
        "version": version,
        "updated_at": at.isoformat(),
    }
    conn.execute(
        "INSERT INTO workspace_idempotency(site_id,principal_key,route_key,idempotency_key,"
        "request_digest,response,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
        (site_id, principal_key, route, idempotency_key, digest(intent), Jsonb(response), now),
    )
    return CandidateDecision(chain_id, version, at)
