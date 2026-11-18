"""Shared bounded workspace reads for REST and MCP surfaces."""

from __future__ import annotations

from typing import Any, Literal, overload
from uuid import UUID

from pydantic import TypeAdapter

from ai_soc.workspace.api.assessment_models import AssessmentSummary
from ai_soc.workspace.api.assessment_repository import (
    assessment_records,
    assessment_summary,
    assessments_enabled,
    chain_assessment_preview,
)
from ai_soc.workspace.api.chain_queries import get_candidate
from ai_soc.workspace.api.models import (
    ChainCandidateDetail,
    ChainCandidateDTO,
    Disposition,
    EntityRef,
    GroupSummary,
    QueueSummary,
    ScoreComponent,
    WorkState,
)
from ai_soc.workspace.api.repository import WorkspaceRepository

_SCORE_COMPONENTS: TypeAdapter[list[dict[str, object]]] = TypeAdapter(list[dict[str, object]])


def group_summary(row: dict[str, Any], assessment: AssessmentSummary | None = None) -> GroupSummary:
    """Project one repository row into the public normalized group summary."""
    entity = row["primary_entity"]
    primary_entity = None
    if entity:
        kind, _, value = str(entity).partition(":")
        primary_entity = EntityRef.model_validate(
            {
                "kind": kind,
                "value": value,
                "role": "primary",
                "first_seen": row["primary_first_seen"] or row["first_ts"],
                "last_seen": row["primary_last_seen"] or row["last_ts"],
            }
        )
    disposition = None
    if row.get("disposition_id") is not None:
        disposition = Disposition.model_validate(
            {
                "disposition_id": str(row["disposition_id"]),
                "label": row["label"],
                "reason_code": row["reason_code"],
                "note": row["note"],
                "actor_key": row["actor_key"],
                "at": row["disposition_at"],
                "propagate_to_members": row["propagate_to_members"],
            }
        )
    return GroupSummary(
        group_id=str(row["group_id"]),
        group_revision=str(row["revision"]),
        title=str(row["title"]),
        score=None if row["total"] is None else float(row["total"]),
        computation_version=row["computation_version"],
        input_digest=row["input_digest"],
        components=[
            ScoreComponent.model_validate(item)
            for item in _SCORE_COMPONENTS.validate_python(row["components"] or [])
        ],
        alert_count=int(row["alert_count"]),
        first_ts=row["first_ts"],
        last_ts=row["last_ts"],
        rule_id=row["rule_id"],
        primary_entity=primary_entity,
        status=str(row["status"]),
        owner_key=row["owner_key"],
        disposition=disposition,
        pipeline_version=str(row["pipeline_version"]),
        assessment=assessment,
    )


def work_state(row: dict[str, Any]) -> WorkState:
    return WorkState.model_validate(
        {
            "status": row["status"],
            "owner_key": row["owner_key"],
            "updated_at": row["updated_at"],
        }
    )


def queue_records(
    repo: WorkspaceRepository,
    *,
    filters: dict[str, object],
    sort: str,
    limit: int,
    after: tuple[Any, ...] | None,
    include_assessments: bool,
) -> list[tuple[dict[str, Any], QueueSummary]]:
    """Execute the queue read once and return source rows with public projections."""
    rows = repo.queue_rows(filters=filters, sort=sort, limit=limit, after=after)
    records = (
        assessment_records(repo, rows) if include_assessments and assessments_enabled(repo) else {}
    )
    result: list[tuple[dict[str, Any], QueueSummary]] = []
    for row in rows:
        record = records.get(row["group_id"])
        group = group_summary(row, assessment_summary(record) if record else None)
        result.append(
            (
                row,
                QueueSummary(
                    group=group,
                    work_state=work_state(row),
                    queue_reasons=[
                        component.explanation
                        for component in group.components
                        if component.contribution > 0
                    ][:3],
                ),
            )
        )
    return result


def group_record(
    repo: WorkspaceRepository, group_id: str, *, include_assessment: bool
) -> tuple[dict[str, Any], GroupSummary] | None:
    row = repo.group_detail(group_id)
    if row is None:
        return None
    record = (
        assessment_records(repo, [row]).get(group_id)
        if include_assessment and assessments_enabled(repo)
        else None
    )
    return row, group_summary(row, assessment_summary(record) if record else None)


@overload
def chain_projection(
    value: dict[str, Any], *, detail: Literal[False] = False
) -> ChainCandidateDTO: ...


@overload
def chain_projection(value: dict[str, Any], *, detail: Literal[True]) -> ChainCandidateDetail: ...


def chain_projection(
    value: dict[str, Any], *, detail: bool = False
) -> ChainCandidateDTO | ChainCandidateDetail:
    """Project bounded chain query rows into the sole public REST/MCP contract."""
    stages = value.get("stages", [])
    if stages and isinstance(stages[0], tuple):
        stages = [
            dict(
                zip(
                    (
                        "ordinal",
                        "stage_id",
                        "outcome",
                        "group_id",
                        "group_revision",
                        "alert_key",
                        "event_ts",
                        "confidence",
                        "source_hash",
                        "projection_availability",
                    ),
                    stage,
                    strict=True,
                )
            )
            for stage in stages
        ]
    base: dict[str, Any] = {
        "chain_id": str(value["chain_id"]),
        "revision_digest": str(value["revision_digest"]),
        "manifest_id": str(value["manifest_id"]),
        "rule_id": str(value["rule_id"]),
        "rule_version": str(value["rule_version"]),
        "state": str(value["state"]),
        "decision_version": int(value["decision_version"]),
        "created_at": value["created_at"],
        "updated_at": value["updated_at"],
        "score": None if value["score"] is None else float(value["score"]),
        "score_available": bool(value["score_available"]),
        "result": value["result"],
        "stages": stages,
        "weak_heuristic": bool(value["weak"]),
    }
    if not detail:
        return ChainCandidateDTO.model_validate(base)

    def rows(items: object, columns: tuple[str, ...]) -> list[dict[str, Any]]:
        return [dict(zip(columns, item, strict=True)) for item in items]  # type: ignore[arg-type]

    edges = rows(
        value.get("edges", []),
        (
            "edge_id",
            "from_group",
            "from_revision",
            "from_alert_key",
            "to_group",
            "to_revision",
            "to_alert_key",
            "edge_type",
            "confidence",
            "reason",
            "time_delta_seconds",
            "shared_fields",
        ),
    )
    for edge in edges:
        edge["weak"] = edge["edge_type"] == "same_host"
    base.update(
        edges=edges,
        weak_edges=[edge for edge in edges if edge["edge_type"] == "same_host"],
        score_pins=rows(
            value.get("score_pins", []),
            ("group_id", "group_revision", "score_version", "score_digest", "score"),
        ),
    )
    return ChainCandidateDetail.model_validate(base)


def chain_record(
    repo: WorkspaceRepository, chain_id: str, *, include_assessment: bool
) -> ChainCandidateDetail | None:
    """Read one chain with the same bounded projection and optional fixture assessment."""
    value = get_candidate(repo.conn, site_id=repo.site_id, chain_id=chain_id)
    if value is None:
        return None
    detail = chain_projection(value, detail=True)
    if include_assessment:
        detail = detail.model_copy(
            update={
                "assessment": chain_assessment_preview(
                    repo,
                    chain_id=chain_id,
                    revision=detail.revision_digest,
                    manifest_id=UUID(detail.manifest_id),
                )
            }
        )
    return detail
