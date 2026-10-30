"""Versioned workspace envelope for the shared durable audit queue."""

from __future__ import annotations

import json
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from ai_soc.workspace.audit_outbox import AuditEvent


class WorkspaceAuditMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    schema_version: Literal["workspace.1"] = "workspace.1"
    event_id: UUID
    site_id: str = Field(min_length=1, max_length=128)
    kind: Literal[
        "group_assigned",
        "group_status_changed",
        "group_disposition_recorded",
        "group_bulk_action",
        "asset_tag_changed",
        "incident_created",
        "incident_candidate_promoted",
        "incident_assign",
        "incident_status",
        "incident_evidence_refreshed",
        "incident_members_changed",
        "incident_comment_added",
        "incident_disposition_recorded",
        "narrative.prepared",
        "narrative.authorized",
        "narrative.finished",
        "narrative.abandoned",
        "correlation_candidate_dismissed",
    ]
    actor_key: str | None = Field(max_length=256)
    payload: dict[str, object]
    created_at: AwareDatetime


def workspace_audit_json(event: WorkspaceAuditMessage) -> str:
    encoded = json.dumps(
        event.model_dump(mode="json"),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )
    if len(encoded.encode()) > 131_072:
        raise ValueError("workspace audit envelope exceeds128KiB")
    return encoded


def audit_message(event: AuditEvent) -> WorkspaceAuditMessage:
    return WorkspaceAuditMessage.model_validate(
        {
            "event_id": event.event_id,
            "site_id": event.site_id,
            "kind": event.kind,
            "actor_key": event.actor_key,
            "payload": event.payload,
            "created_at": event.created_at,
        }
    )
