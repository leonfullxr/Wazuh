"""Read safe narrative receipts against an exact immutable incident revision."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID

import psycopg

from ai_soc.workspace.api.models import NarrativeReadResponse, NarrativeUsage
from ai_soc.workspace.model.narrate import load_generation
from ai_soc.workspace.model.schemas import ValidatedNarrative
from ai_soc.workspace.model.validation import validate_incident_narrative

SAFE_FAILURE_CODES = frozenset(
    {
        "account_limit",
        "auth_rejected",
        "auth_unavailable",
        "rate_limited",
        "timeout",
        "upstream_timeout",
        "upstream_transport_failed",
        "upstream_server_error",
        "tool_attempt",
        "invalid_structured_output",
        "provider_unavailable",
        "process_exit_nonzero",
        "process_start_failed",
        "temporary_storage_unavailable",
        "binary_pin_mismatch",
        "binary_version_mismatch",
        "catalog_pin_mismatch",
        "sandbox_version_mismatch",
        "cancelled",
        "abandoned_unknown",
    }
)


def get_incident_narrative(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    incident_id: UUID,
    evidence_revision: UUID | None,
    now: datetime,
) -> NarrativeReadResponse:
    incident = conn.execute(
        "SELECT evidence_head FROM incidents WHERE site_id=%s AND incident_id=%s",
        (site_id, incident_id),
    ).fetchone()
    if incident is None:
        raise LookupError("unknown incident")
    revision = evidence_revision or incident[0]
    if (
        conn.execute(
            "SELECT 1 FROM incident_evidence_revisions WHERE site_id=%s AND incident_id=%s "
            "AND incident_revision_id=%s",
            (site_id, incident_id, revision),
        ).fetchone()
        is None
    ):
        raise LookupError("unknown incident evidence revision")
    current = revision == incident[0]
    base = NarrativeReadResponse(
        incident_id=incident_id,
        evidence_revision=revision,
        is_current=current,
        status="pending",
        usage=NarrativeUsage(),
    )
    row = conn.execute(
        "SELECT g.generation_id,g.generation_digest,g.pack_digest,j.state,j.attempts,"
        "j.run_after,j.last_error,h.incident_revision_id,"
        "h.desired_generation_id,h.published_call_id "
        "FROM narrative_generations g JOIN jobs j ON (j.site_id,j.job_id)="
        "(g.site_id,g.narrate_job_id) LEFT JOIN incident_narrative_heads h "
        "ON (h.site_id,h.incident_id)=(g.site_id,g.incident_id) "
        "WHERE g.site_id=%s AND g.incident_id=%s AND g.incident_revision_id=%s "
        "ORDER BY (g.generation_id IS NOT DISTINCT FROM h.desired_generation_id) DESC,"
        "g.created_at DESC,g.generation_id DESC LIMIT 1",
        (site_id, incident_id, revision),
    ).fetchone()
    if row is None:
        prep = conn.execute(
            "SELECT state,run_after FROM jobs WHERE site_id=%s AND kind='prepare_narrative' "
            "AND subject=%s AND payload->>'incident_id'=%s ORDER BY job_id DESC LIMIT 1",
            (site_id, str(revision), str(incident_id)),
        ).fetchone()
        if prep is None or prep[0] in {"dead", "done"}:
            return base.model_copy(
                update={"status": "unavailable", "reason_code": "preparation_unavailable"}
            )
        if prep[0] == "running":
            return base.model_copy(update={"status": "running"})
        return base.model_copy(update={"status": "deferred" if prep[1] > now else "pending"})
    base = base.model_copy(
        update={
            "generation_id": row[0],
            "generation_digest": row[1],
            "pack_digest": row[2],
        }
    )
    try:
        generation = load_generation(conn, site_id=site_id, generation_id=row[0])
    except (ValueError, TypeError, KeyError):
        return base.model_copy(
            update={"status": "unavailable", "reason_code": "frozen_evidence_invalid"}
        )
    base = base.model_copy(update={"evidence": generation.pack})
    call = conn.execute(
        "SELECT c.call_id,o.status,o.error_code,o.narrative,o.input_tokens,o.cached_input_tokens,"
        "o.output_tokens,o.finished_at FROM narrative_calls c LEFT JOIN narrative_outcomes o "
        "ON (o.site_id,o.generation_id,o.call_id)=(c.site_id,c.generation_id,c.call_id) "
        "WHERE c.site_id=%s AND c.generation_id=%s "
        "ORDER BY c.producing_attempt DESC,c.call_id DESC LIMIT 1",
        (site_id, row[0]),
    ).fetchone()
    if call is not None:
        base = base.model_copy(
            update={
                "call_id": call[0],
                "completed_at": call[7],
                "usage": NarrativeUsage(
                    input_tokens=call[4], cached_input_tokens=call[5], output_tokens=call[6]
                ),
            }
        )
    if row[3] == "running":
        return base.model_copy(update={"status": "running"})
    if row[3] == "queued":
        state = "retrying" if row[4] else ("deferred" if row[5] > now else "pending")
        return base.model_copy(update={"status": state, "reason_code": _safe_reason(row[6])})
    if call is not None and call[1] == "all_removed":
        try:
            removed = ValidatedNarrative.model_validate_json(json.dumps(call[3]))
            if (
                removed.status != "all_removed"
                or removed.selections
                or removed.pack_digest != generation.pack.content_digest
                or len(removed.removals) > 8
            ):
                raise ValueError("invalid removal receipt")
        except (ValueError, TypeError, KeyError):
            return base.model_copy(
                update={"status": "unavailable", "reason_code": "retained_summary_invalid"}
            )
        return base.model_copy(
            update={
                "status": "unavailable",
                "reason_code": "all_removed",
                "removals": list(removed.removals),
            }
        )
    if call is None or call[1] != "validated":
        reason = (
            "all_removed"
            if call is not None and call[1] == "all_removed"
            else _safe_reason(None if call is None else call[2]) or "generation_unavailable"
        )
        return base.model_copy(update={"status": "unavailable", "reason_code": reason})
    if current and (row[7], row[8], row[9]) != (revision, row[0], call[0]):
        return base.model_copy(update={"status": "unavailable", "reason_code": "not_published"})
    try:
        stored = ValidatedNarrative.model_validate_json(json.dumps(call[3]))
        checked = validate_incident_narrative(
            json.dumps({"selections": [s.model_dump(mode="json") for s in stored.selections]}),
            expected_site_id=site_id,
            expected_incident_id=incident_id,
            expected_revision_id=revision,
            pack=generation.pack,
        )
        if (
            checked.status != "validated"
            or stored.status != "validated"
            or stored.pack_digest != generation.pack.content_digest
            or stored.selections != checked.selections
            or stored.citations != checked.citations
            or stored.rendered_en != checked.rendered_en
            or stored.rendered_es != checked.rendered_es
            or len(stored.removals) > 8
        ):
            raise ValueError("retained narrative failed frozen field validation")
    except (ValueError, TypeError, KeyError):
        return base.model_copy(
            update={"status": "unavailable", "reason_code": "retained_summary_invalid"}
        )
    return base.model_copy(
        update={"status": "available", "summary": stored, "removals": list(stored.removals)}
    )


def _safe_reason(value: object) -> str | None:
    return value if isinstance(value, str) and value in SAFE_FAILURE_CODES else None
