"""Transactional analyst state, dispositions, asset tags, and idempotent writes."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Literal, cast
from uuid import uuid4

import psycopg
from psycopg.pq import TransactionStatus
from psycopg.types.json import Jsonb

from ai_soc.workspace.audit_outbox import record_audit
from ai_soc.workspace.jobs import enqueue_job
from ai_soc.workspace.triage.grouping import digest
from ai_soc.workspace.triage.score import SCORE_VERSION

WorkStatus = Literal["new", "in_progress", "resolved", "closed"]
DispositionLabel = Literal[
    "true_positive", "benign_true_positive", "false_positive", "duplicate", "undetermined"
]
FALSE_POSITIVE_REASONS = frozenset(
    {"expected_admin_activity", "known_scanner", "misconfigured_rule", "test_activity", "other"}
)


class FeedbackConflict(RuntimeError):
    """Optimistic state or idempotency preconditions conflict with persisted data."""


def assign_group(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    group_id: str,
    owner_key: str | None,
    actor_key: str,
    now: datetime,
    principal_key: str,
    idempotency_key: str,
    expected_updated_at: datetime | None = None,
) -> dict[str, Any]:
    request = {"owner_key": owner_key, "expected_updated_at": _iso(expected_updated_at)}
    route = f"/groups/{group_id}/assign"
    prior = _idempotent_result(conn, site_id, principal_key, route, idempotency_key, request)
    if prior is not None:
        return prior
    _validate_common(conn, site_id, group_id, actor_key, now)
    if owner_key is not None and (not owner_key or len(owner_key) > 256):
        raise ValueError("owner_key must be null or 1..256 characters")
    row = conn.execute(
        """SELECT status, owner_key, updated_at FROM work_items
           WHERE site_id = %s AND group_id = %s FOR UPDATE""",
        (site_id, group_id),
    ).fetchone()
    if row is None:
        raise LookupError("unknown group")
    before = _work_state(row)
    if expected_updated_at is not None and row[2] != expected_updated_at:
        raise FeedbackConflict("group work item changed since it was read")
    updated_at = _next_work_version(row[2], now)
    conn.execute(
        """UPDATE work_items SET owner_key = %s, updated_at = %s
           WHERE site_id = %s AND group_id = %s""",
        (owner_key, updated_at, site_id, group_id),
    )
    result = {
        "group_id": group_id,
        "status": before["status"],
        "owner_key": owner_key,
        "updated_at": updated_at.isoformat(),
        "work_history_id": str(uuid4()),
    }
    _history(
        conn,
        site_id=site_id,
        group_id=group_id,
        actor_key=actor_key,
        action="assign",
        before=before,
        after=result,
        now=now,
        history_id=str(result["work_history_id"]),
    )
    record_audit(
        conn,
        site_id=site_id,
        kind="group_assigned",
        actor_key=actor_key,
        payload={"group_id": group_id, "before": before, "after": result},
    )
    _save_idempotent(conn, site_id, principal_key, route, idempotency_key, request, result, now)
    return result


def change_group_status(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    group_id: str,
    status: WorkStatus,
    expected_updated_at: datetime,
    actor_key: str,
    now: datetime,
    principal_key: str,
    idempotency_key: str,
) -> dict[str, Any]:
    request = {"status": status, "expected_updated_at": _iso(expected_updated_at)}
    route = f"/groups/{group_id}/status"
    prior = _idempotent_result(conn, site_id, principal_key, route, idempotency_key, request)
    if prior is not None:
        return prior
    _validate_common(conn, site_id, group_id, actor_key, now)
    if status not in {"new", "in_progress", "resolved", "closed"}:
        raise ValueError("unsupported work status")
    row = conn.execute(
        """SELECT status, owner_key, updated_at FROM work_items
           WHERE site_id = %s AND group_id = %s FOR UPDATE""",
        (site_id, group_id),
    ).fetchone()
    if row is None:
        raise LookupError("unknown group")
    before = _work_state(row)
    if row[2] != expected_updated_at:
        raise FeedbackConflict("group work item changed since it was read")
    updated_at = _next_work_version(row[2], now)
    conn.execute(
        "UPDATE work_items SET status = %s, updated_at = %s WHERE site_id = %s AND group_id = %s",
        (status, updated_at, site_id, group_id),
    )
    result = {
        "group_id": group_id,
        "status": status,
        "owner_key": before["owner_key"],
        "updated_at": updated_at.isoformat(),
        "work_history_id": str(uuid4()),
    }
    _history(
        conn,
        site_id=site_id,
        group_id=group_id,
        actor_key=actor_key,
        action="status",
        before=before,
        after=result,
        now=now,
        history_id=result["work_history_id"],
    )
    record_audit(
        conn,
        site_id=site_id,
        kind="group_status_changed",
        actor_key=actor_key,
        payload={"group_id": group_id, "before": before, "after": result},
    )
    _save_idempotent(conn, site_id, principal_key, route, idempotency_key, request, result, now)
    return result


def record_group_disposition(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    group_id: str,
    label: DispositionLabel,
    actor_key: str,
    now: datetime,
    principal_key: str,
    idempotency_key: str,
    reason_code: str | None = None,
    note: str | None = None,
    propagate_to_members: bool = False,
) -> dict[str, Any]:
    request = {
        "label": label,
        "reason_code": reason_code,
        "note": note,
        "propagate_to_members": propagate_to_members,
    }
    route = f"/groups/{group_id}/disposition"
    prior = _idempotent_result(conn, site_id, principal_key, route, idempotency_key, request)
    if prior is not None:
        return prior
    _validate_common(conn, site_id, group_id, actor_key, now)
    _validate_disposition(label, reason_code, note)
    revision_row = conn.execute(
        """
        SELECT gr.revision, gr.pipeline_version
        FROM group_heads AS gh JOIN group_revisions AS gr
          ON (gr.site_id, gr.group_id, gr.revision) =
             (gh.site_id, gh.group_id, gh.current_revision)
        WHERE gh.site_id = %s AND gh.group_id = %s
        """,
        (site_id, group_id),
    ).fetchone()
    if revision_row is None:
        raise LookupError("unknown group")
    revision = str(revision_row[0])
    pipeline_version = str(revision_row[1])
    member_keys = conn.execute(
        """SELECT alert_key FROM group_members
           WHERE site_id = %s AND group_id = %s AND group_revision = %s
           ORDER BY alert_key""",
        (site_id, group_id, revision),
    ).fetchall()
    disposition_id = uuid4()
    conn.execute(
        """
        INSERT INTO dispositions
            (site_id, disposition_id, group_id, label, reason_code, note,
             propagate_to_members, actor_key, at, group_revision_seen, pipeline_version_seen)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            site_id,
            disposition_id,
            group_id,
            label,
            reason_code,
            note,
            propagate_to_members,
            actor_key,
            now,
            revision,
            pipeline_version,
        ),
    )
    member_digest = digest([str(item[0]) for item in member_keys])
    result = {
        "disposition_id": str(disposition_id),
        "group_id": group_id,
        "label": label,
        "reason_code": reason_code,
        "note": note,
        "actor_key": actor_key,
        "at": now.isoformat(),
        "propagate_to_members": propagate_to_members,
        "group_revision_seen": revision,
        "pipeline_version_seen": pipeline_version,
        "member_count": len(member_keys),
    }
    history_id = str(uuid4())
    _history(
        conn,
        site_id=site_id,
        group_id=group_id,
        actor_key=actor_key,
        action="disposition",
        before=None,
        after={**result, "member_keys_digest": member_digest},
        now=now,
        history_id=history_id,
    )
    record_audit(
        conn,
        site_id=site_id,
        kind="group_disposition_recorded",
        actor_key=actor_key,
        payload={
            "group_id": group_id,
            "disposition_id": str(disposition_id),
            "label": label,
            "reason_code": reason_code,
            "propagate_to_members": propagate_to_members,
            "group_revision_seen": revision,
            "member_count": len(member_keys),
            "member_keys_digest": member_digest,
        },
    )
    _save_idempotent(conn, site_id, principal_key, route, idempotency_key, request, result, now)
    return result


def bulk_group_action(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    group_ids: list[str] | tuple[str, ...],
    action: dict[str, Any],
    actor_key: str,
    principal_key: str,
    idempotency_key: str,
    now: datetime,
) -> dict[str, Any]:
    ids = tuple(group_ids)
    request = {"group_ids": list(ids), "action": action}
    route = "/bulk"
    prior = _idempotent_result(conn, site_id, principal_key, route, idempotency_key, request)
    if prior is not None:
        return prior
    if not 1 <= len(ids) <= 100 or len(set(ids)) != len(ids):
        raise ValueError("bulk requires 1..100 unique group ids")
    _require_site(conn, site_id)
    if not actor_key:
        raise ValueError("actor_key is required")
    existing = conn.execute(
        """SELECT group_id FROM groups WHERE site_id = %s AND group_id = ANY(%s)
           ORDER BY group_id FOR UPDATE""",
        (site_id, list(ids)),
    ).fetchall()
    if {str(row[0]) for row in existing} != set(ids):
        raise LookupError("one or more groups do not exist in this site")
    kind = action.get("kind")
    if kind == "assign":
        owner = action.get("owner_key")
        if owner is not None and (not isinstance(owner, str) or not owner or len(owner) > 256):
            raise ValueError("owner_key must be null or 1..256 characters")
    elif kind == "status":
        owner = None
        if action.get("status") not in {"new", "in_progress", "resolved", "closed"}:
            raise ValueError("unsupported work status")
    elif kind == "disposition":
        owner = None
        _validate_disposition(action.get("label"), action.get("reason_code"), action.get("note"))
    else:
        raise ValueError("bulk action kind must be assign, status, or disposition")
    updated: list[dict[str, Any]] = []
    for group_id in ids:
        if kind == "assign":
            updated.append(_bulk_assign(conn, site_id, group_id, owner, actor_key, now))
        elif kind == "status":
            updated.append(
                _bulk_status(conn, site_id, group_id, cast(str, action["status"]), actor_key, now)
            )
        else:
            updated.append(
                _bulk_disposition(
                    conn,
                    site_id,
                    group_id,
                    cast(str, action["label"]),
                    cast(str | None, action.get("reason_code")),
                    cast(str | None, action.get("note")),
                    bool(action.get("propagate_to_members", False)),
                    actor_key,
                    now,
                )
            )
    result = {"updated": len(updated), "items": updated}
    record_audit(
        conn,
        site_id=site_id,
        kind="group_bulk_action",
        actor_key=actor_key,
        payload={"action": action, "group_ids": list(ids), "updated": len(updated)},
    )
    _save_idempotent(conn, site_id, principal_key, route, idempotency_key, request, result, now)
    return result


def upsert_asset_tag(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    entity_id: int,
    criticality: int,
    tags: list[str] | tuple[str, ...],
    actor_key: str,
    principal_key: str,
    idempotency_key: str,
    now: datetime,
) -> dict[str, Any]:
    normalized_tags = tuple(tags)
    request = {"entity_id": entity_id, "criticality": criticality, "tags": list(normalized_tags)}
    route = "/assets"
    prior = _idempotent_result(conn, site_id, principal_key, route, idempotency_key, request)
    if prior is not None:
        return prior
    _require_site(conn, site_id)
    if not actor_key or entity_id <= 0 or not 0 <= criticality <= 3:
        raise ValueError("actor, entity id, or criticality is invalid")
    if (
        len(normalized_tags) > 32
        or len(set(normalized_tags)) != len(normalized_tags)
        or any(not tag or len(tag) > 64 for tag in normalized_tags)
    ):
        raise ValueError("tags must be unique nonempty strings up to 64 characters")
    entity = conn.execute(
        "SELECT kind FROM entities WHERE site_id = %s AND entity_id = %s FOR UPDATE",
        (site_id, entity_id),
    ).fetchone()
    if entity is None or entity[0] != "host":
        raise LookupError("unknown host entity")
    canonical_rows = conn.execute(
        """
        SELECT DISTINCT canonical.entity_id
        FROM alert_entities AS alias_ref
        JOIN entities AS alias
          ON (alias.site_id, alias.entity_id) = (alias_ref.site_id, alias_ref.entity_id)
        JOIN alerts AS a
          ON (a.site_id, a.alert_key) = (alias_ref.site_id, alias_ref.alert_key)
        JOIN entities AS canonical
          ON canonical.site_id = a.site_id
         AND canonical.kind = 'host'
         AND canonical.value_norm = lower(a.normalized->>'agent_id')
        WHERE alias_ref.site_id = %s AND alias_ref.entity_id = %s
          AND alias_ref.role = 'agent' AND alias.kind = 'host'
          AND a.normalized_at IS NOT NULL
        ORDER BY canonical.entity_id
        """,
        (site_id, entity_id),
    ).fetchall()
    canonical_ids = {int(row[0]) for row in canonical_rows}
    if not canonical_ids:
        legacy_link = conn.execute(
            """
            SELECT 1 FROM alert_entities AS ae
            JOIN alerts AS a USING (site_id, alert_key)
            WHERE ae.site_id = %s AND ae.entity_id = %s AND ae.role = 'agent'
              AND a.normalized_at IS NOT NULL
              AND NULLIF(a.normalized->>'agent_id', '') IS NOT NULL
            LIMIT 1
            """,
            (site_id, entity_id),
        ).fetchone()
        if legacy_link is None:
            raise LookupError("host entity is not linked to a normalized agent identity")
        canonical_ids.add(entity_id)
    if len(canonical_ids) != 1:
        raise ValueError("host entity is linked to multiple agent identities")
    canonical_entity_id = canonical_ids.pop()
    previous = conn.execute(
        """SELECT revision, criticality, tags FROM asset_tags
           WHERE site_id = %s AND entity_id = %s ORDER BY revision DESC LIMIT 1""",
        (site_id, canonical_entity_id),
    ).fetchone()
    revision = 1 if previous is None else int(previous[0]) + 1
    before = (
        None
        if previous is None
        else {
            "revision": int(previous[0]),
            "criticality": int(previous[1]),
            "tags": list(previous[2]),
        }
    )
    conn.execute(
        """INSERT INTO asset_tags
           (site_id, entity_id, revision, criticality, tags, set_by, set_at)
           VALUES (%s, %s, %s, %s, %s, %s, %s)""",
        (
            site_id,
            canonical_entity_id,
            revision,
            criticality,
            list(normalized_tags),
            actor_key,
            now,
        ),
    )
    history_id = uuid4()
    after = {"revision": revision, "criticality": criticality, "tags": list(normalized_tags)}
    conn.execute(
        """INSERT INTO asset_tag_history
           (site_id, history_id, entity_id, revision, actor_key, before_value, after_value, at)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
        (
            site_id,
            history_id,
            canonical_entity_id,
            revision,
            actor_key,
            None if before is None else Jsonb(before),
            Jsonb(after),
            now,
        ),
    )
    groups = conn.execute(
        """
        WITH affected_groups AS MATERIALIZED (
            SELECT DISTINCT gm.site_id, gm.group_id, gm.group_revision,
                   gr.pipeline_version
            FROM group_heads AS gh
            JOIN group_members AS gm
              ON (gm.site_id, gm.group_id, gm.group_revision) =
                 (gh.site_id, gh.group_id, gh.current_revision)
            JOIN group_revisions AS gr
              ON (gr.site_id, gr.group_id, gr.revision) =
                 (gm.site_id, gm.group_id, gm.group_revision)
            CROSS JOIN LATERAL jsonb_array_elements(
                gm.normalized_snapshot->'_entity_refs'
            ) AS ref
            WHERE gm.site_id = %s AND (ref.value->>'entity_id')::bigint = %s
        )
        SELECT affected.group_id, affected.group_revision,
               COALESCE(latest.pipeline_version, affected.pipeline_version)
        FROM affected_groups AS affected
        LEFT JOIN LATERAL (
            SELECT j.payload->>'pipeline_version' AS pipeline_version
            FROM jobs AS j
            WHERE j.site_id = affected.site_id
              AND j.kind IN ('enrich_group', 'rescore_group')
              AND j.payload->>'group_id' = affected.group_id
              AND j.payload->>'group_revision' = affected.group_revision
              AND j.payload ? 'pipeline_version'
            ORDER BY j.job_id DESC
            LIMIT 1
        ) AS latest ON true
        ORDER BY affected.group_id, affected.group_revision,
                 COALESCE(latest.pipeline_version, affected.pipeline_version)
        """,
        (site_id, canonical_entity_id),
    ).fetchall()
    for group_id, group_revision, pipeline_version in groups:
        enqueue_job(
            conn,
            site_id=site_id,
            kind="rescore_group",
            subject=f"{group_id}:{group_revision}:asset:{canonical_entity_id}:{revision}",
            payload={
                "group_id": str(group_id),
                "group_revision": str(group_revision),
                "pipeline_version": str(pipeline_version),
                "computation_version": SCORE_VERSION,
                "asset_revision": revision,
                "asset_entity_id": canonical_entity_id,
                "as_of": now.isoformat(),
            },
        )
    result = {
        "site_id": site_id,
        "entity_id": entity_id,
        "canonical_entity_id": canonical_entity_id,
        "revision": revision,
        "criticality": criticality,
        "tags": list(normalized_tags),
        "set_by": actor_key,
        "set_at": now.isoformat(),
    }
    record_audit(
        conn,
        site_id=site_id,
        kind="asset_tag_changed",
        actor_key=actor_key,
        payload={
            "entity_id": entity_id,
            "canonical_entity_id": canonical_entity_id,
            "before": before,
            "after": after,
            "affected_group_revisions": len(groups),
        },
    )
    _save_idempotent(conn, site_id, principal_key, route, idempotency_key, request, result, now)
    return result


def _bulk_assign(
    conn: psycopg.Connection[Any],
    site_id: str,
    group_id: str,
    owner: str | None,
    actor: str,
    now: datetime,
) -> dict[str, Any]:
    row = conn.execute(
        """SELECT status, owner_key, updated_at FROM work_items
           WHERE site_id = %s AND group_id = %s FOR UPDATE""",
        (site_id, group_id),
    ).fetchone()
    if row is None:
        raise LookupError("group work state missing")
    before = _work_state(row)
    updated_at = _next_work_version(row[2], now)
    conn.execute(
        """UPDATE work_items SET owner_key = %s, updated_at = %s
           WHERE site_id = %s AND group_id = %s""",
        (owner, updated_at, site_id, group_id),
    )
    result = {
        "group_id": group_id,
        "status": before["status"],
        "owner_key": owner,
        "updated_at": updated_at.isoformat(),
    }
    _history(
        conn,
        site_id=site_id,
        group_id=group_id,
        actor_key=actor,
        action="bulk_assign",
        before=before,
        after=result,
        now=now,
        history_id=str(uuid4()),
    )
    return result


def _bulk_status(
    conn: psycopg.Connection[Any],
    site_id: str,
    group_id: str,
    status: str,
    actor: str,
    now: datetime,
) -> dict[str, Any]:
    row = conn.execute(
        """SELECT status, owner_key, updated_at FROM work_items
           WHERE site_id = %s AND group_id = %s FOR UPDATE""",
        (site_id, group_id),
    ).fetchone()
    if row is None:
        raise LookupError("group work state missing")
    before = _work_state(row)
    updated_at = _next_work_version(row[2], now)
    conn.execute(
        "UPDATE work_items SET status = %s, updated_at = %s WHERE site_id = %s AND group_id = %s",
        (status, updated_at, site_id, group_id),
    )
    result = {
        "group_id": group_id,
        "status": status,
        "owner_key": before["owner_key"],
        "updated_at": updated_at.isoformat(),
    }
    _history(
        conn,
        site_id=site_id,
        group_id=group_id,
        actor_key=actor,
        action="bulk_status",
        before=before,
        after=result,
        now=now,
        history_id=str(uuid4()),
    )
    return result


def _bulk_disposition(
    conn: psycopg.Connection[Any],
    site_id: str,
    group_id: str,
    label: str,
    reason: str | None,
    note: str | None,
    propagate: bool,
    actor: str,
    now: datetime,
) -> dict[str, Any]:
    revision_row = conn.execute(
        """
        SELECT gr.revision, gr.pipeline_version
        FROM group_heads AS gh JOIN group_revisions AS gr
          ON (gr.site_id, gr.group_id, gr.revision) =
             (gh.site_id, gh.group_id, gh.current_revision)
        WHERE gh.site_id = %s AND gh.group_id = %s
        """,
        (site_id, group_id),
    ).fetchone()
    if revision_row is None:
        raise LookupError("group revision missing")
    revision = str(revision_row[0])
    pipeline_version = str(revision_row[1])
    disposition_id = uuid4()
    conn.execute(
        """INSERT INTO dispositions
           (site_id, disposition_id, group_id, label, reason_code, note,
            propagate_to_members, actor_key, at, group_revision_seen, pipeline_version_seen)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (
            site_id,
            disposition_id,
            group_id,
            label,
            reason,
            note,
            propagate,
            actor,
            now,
            revision,
            pipeline_version,
        ),
    )
    result = {
        "disposition_id": str(disposition_id),
        "group_id": group_id,
        "label": label,
        "reason_code": reason,
        "note": note,
        "propagate_to_members": propagate,
        "group_revision_seen": revision,
        "pipeline_version_seen": pipeline_version,
        "at": now.isoformat(),
    }
    _history(
        conn,
        site_id=site_id,
        group_id=group_id,
        actor_key=actor,
        action="bulk_disposition",
        before=None,
        after=result,
        now=now,
        history_id=str(uuid4()),
    )
    return result


def _validate_disposition(label: object, reason_code: object, note: object) -> None:
    if label not in {
        "true_positive",
        "benign_true_positive",
        "false_positive",
        "duplicate",
        "undetermined",
    }:
        raise ValueError("unsupported disposition label")
    if reason_code is not None and (not isinstance(reason_code, str) or len(reason_code) > 64):
        raise ValueError("reason_code must be null or at most 64 characters")
    if note is not None and (not isinstance(note, str) or len(note) > 2000):
        raise ValueError("note must be null or at most 2000 characters")
    if label == "false_positive" and reason_code not in FALSE_POSITIVE_REASONS:
        raise ValueError("false_positive requires an allowed reason code")
    if reason_code == "other" and not note:
        raise ValueError("other reason requires a note")


def _history(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    group_id: str,
    actor_key: str,
    action: str,
    before: dict[str, Any] | None,
    after: dict[str, Any],
    now: datetime,
    history_id: str,
) -> None:
    conn.execute(
        """INSERT INTO work_history
           (site_id, history_id, group_id, actor_key, action, before_value, after_value, at)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
        (
            site_id,
            history_id,
            group_id,
            actor_key,
            action,
            None if before is None else Jsonb(before),
            Jsonb(after),
            now,
        ),
    )


def _work_state(row: Any) -> dict[str, Any]:
    return {
        "status": str(row[0]),
        "owner_key": None if row[1] is None else str(row[1]),
        "updated_at": row[2].isoformat(),
    }


def _next_work_version(previous: datetime, now: datetime) -> datetime:
    if (
        previous.tzinfo is None
        or previous.utcoffset() is None
        or now.tzinfo is None
        or now.utcoffset() is None
    ):
        raise ValueError("work-state version timestamps must be timezone-aware")
    prior = previous.astimezone(UTC)
    proposed = now.astimezone(UTC)
    return max(proposed, prior + timedelta(microseconds=1))


def _validate_common(
    conn: psycopg.Connection[Any], site_id: str, group_id: str, actor_key: str, now: datetime
) -> None:
    _require_site(conn, site_id)
    if not group_id or not actor_key or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("group, actor, and timezone-aware timestamp are required")
    if (
        conn.execute(
            "SELECT 1 FROM groups WHERE site_id = %s AND group_id = %s", (site_id, group_id)
        ).fetchone()
        is None
    ):
        raise LookupError("unknown group")


def _idempotent_result(
    conn: psycopg.Connection[Any],
    site_id: str,
    principal: str,
    route: str,
    key: str,
    request: dict[str, Any],
) -> dict[str, Any] | None:
    _require_site(conn, site_id)
    if (
        not principal
        or not route
        or not 16 <= len(key) <= 128
        or any(ord(char) < 33 or ord(char) > 126 for char in key)
    ):
        raise ValueError("principal and a 16..128 visible ASCII idempotency key are required")
    conn.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
        (f"idempotency:{site_id}:{principal}:{route}:{key}",),
    )
    request_digest = digest(request)
    row = conn.execute(
        """SELECT request_digest, response FROM workspace_idempotency
           WHERE site_id = %s AND principal_key = %s AND route_key = %s
             AND idempotency_key = %s""",
        (site_id, principal, route, key),
    ).fetchone()
    if row is None:
        return None
    if row[0] != request_digest:
        raise FeedbackConflict("idempotency key was already used for a different request")
    return cast(dict[str, Any], row[1])


def _save_idempotent(
    conn: psycopg.Connection[Any],
    site_id: str,
    principal: str,
    route: str,
    key: str,
    request: dict[str, Any],
    response: dict[str, Any],
    now: datetime,
) -> None:
    conn.execute(
        """INSERT INTO workspace_idempotency
           (site_id, principal_key, route_key, idempotency_key, request_digest,
            response, created_at)
           VALUES (%s, %s, %s, %s, %s, %s, %s)""",
        (site_id, principal, route, key, digest(request), Jsonb(response), now),
    )


def _require_site(conn: psycopg.Connection[Any], site_id: str) -> None:
    if conn.info.transaction_status is TransactionStatus.IDLE:
        raise PermissionError("feedback write requires an active site transaction")
    row = conn.execute("SELECT current_setting('app.site_id', true)").fetchone()
    if row is None or row[0] != site_id:
        raise PermissionError("feedback write requires the active site's transaction")


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()
