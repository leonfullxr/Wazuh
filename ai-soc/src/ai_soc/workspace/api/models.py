"""Strict response models for the read-only workspace API."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator

from ai_soc.workspace.model.schemas import FrozenIncidentPack, RemovedSelection, ValidatedNarrative


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def _parse_json_uuid(value: object) -> object:
    if isinstance(value, str):
        try:
            return UUID(value)
        except ValueError:
            return value
    return value


JsonUUID = Annotated[UUID, BeforeValidator(_parse_json_uuid)]
SiteId = Annotated[str, Field(min_length=1, max_length=64)]


EntityKind = Literal["host", "ip", "user", "process", "file", "hash", "cve", "rule"]
WorkStatus = Literal["new", "in_progress", "resolved", "closed"]
DispositionLabel = Literal[
    "true_positive", "benign_true_positive", "false_positive", "duplicate", "undetermined"
]


class ErrorResponse(StrictModel):
    code: str
    message: str
    retryable: bool
    trace_id: str
    details: dict[str, Any] | None = None


class Page[T](StrictModel):
    items: list[T]
    next_cursor: str | None
    limit: int


class SiteSummary(StrictModel):
    site_id: str
    label: str
    wazuh_version: str | None
    health: str
    health_detail: str | None
    updated_at: datetime


class Window(StrictModel):
    from_: datetime = Field(alias="from")
    to: datetime
    preset: str | None = None


class OverviewTotals(StrictModel):
    alerts: int
    groups: int | None = None
    unassigned_actionable: int | None = None
    open_incidents: int | None = None


class HourlyBucket(StrictModel):
    hour: datetime
    level_band: str
    count: int


class TopCount(StrictModel):
    key: str
    label: str
    count: int


class IngestionFreshness(StrictModel):
    last_success_at: datetime | None
    checkpoint_at: datetime | None
    lag_seconds: int | None
    reconcile_mismatches_48h: int
    state: str


class OverviewResponse(StrictModel):
    site: SiteSummary
    window: Window
    totals: OverviewTotals
    hourly: list[HourlyBucket]
    top_rules: list[TopCount]
    top_agents: list[TopCount]
    top_tactics: list[TopCount]
    top_src_ips: list[TopCount]
    top_users: list[TopCount]
    freshness: IngestionFreshness


class AlertSummary(StrictModel):
    alert_key: str
    event_ts: datetime
    rule_id: str | None
    rule_level: int | None
    rule_description: str | None
    rule_groups: list[str]
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    agent_id: str | None
    agent_name: str | None
    agent_ip: str | None
    src_ip: str | None
    dst_ip: str | None
    src_user: str | None
    dst_user: str | None
    group_id: str | None = None


class EntityRef(StrictModel):
    kind: EntityKind
    value: str
    role: str
    first_seen: datetime
    last_seen: datetime


class AlertDetail(AlertSummary):
    wazuh_id: str | None
    manager: str | None
    decoder: str | None
    location: str | None
    entities: list[EntityRef]
    raw: dict[str, Any]
    normalize_gaps: list[str]
    mapping_profile: str
    ingested_at: datetime
    wazuh_url: str | None = None


class GroupContextResponse(StrictModel):
    group_id: str
    site_id: str
    alerts: list[AlertSummary]
    entities: list[EntityRef]
    enrichments: list[Any]
    related_groups: list[Any]
    window: Window


class IngestionCounts(StrictModel):
    read: int
    inserted: int
    duplicates: int
    normalized: int
    rejected: int | None


class ReconciliationSummary(StrictModel):
    checked_hours: int
    mismatched_hours: int
    last_checked_at: datetime | None


class PipelineRunSummary(StrictModel):
    run_id: str
    kind: str
    started_at: datetime
    finished_at: datetime | None
    outcome: str
    error_code: str | None
    pipeline_version: str


class IngestionHealthResponse(StrictModel):
    site: SiteSummary
    checkpoint_at: datetime | None
    last_success_at: datetime | None
    last_run: PipelineRunSummary | None
    lag_seconds: int | None
    counts: IngestionCounts
    reconciliation: ReconciliationSummary


class ScoreComponent(StrictModel):
    name: str
    value: float | None
    weight: float
    contribution: float
    evidence_ids: list[str]
    explanation: str
    available: bool


class Disposition(StrictModel):
    disposition_id: str
    label: DispositionLabel
    reason_code: str | None
    note: str | None
    actor_key: str
    at: datetime
    propagate_to_members: bool


class WorkState(StrictModel):
    status: WorkStatus
    owner_key: str | None
    updated_at: datetime


class IncidentSnapshotDTO(StrictModel):
    incident_id: str
    title: str
    owner_key: str | None
    status: WorkStatus
    work_version: int
    evidence_head: str
    revision_seq: int
    priority: float | None


class ChainCandidateDTO(StrictModel):
    chain_id: str
    revision_digest: str
    manifest_id: str
    rule_id: str
    rule_version: str
    state: Literal["open", "dismissed", "promoted"]
    decision_version: int
    created_at: datetime
    updated_at: datetime
    score: float | None
    score_available: bool
    result: dict[str, Any]
    stages: list[dict[str, Any]]
    weak_heuristic: bool


class IncidentSummaryDTO(IncidentSnapshotDTO):
    created_at: datetime
    created_by: str


class ChainPromoteRequest(StrictModel):
    site_id: SiteId
    expected_revision: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_manifest_id: JsonUUID
    expected_decision_version: int = Field(ge=0, le=2**63 - 1)
    title_override: str | None = Field(default=None, min_length=1, max_length=240)


class ChainDismissRequest(StrictModel):
    site_id: SiteId
    expected_revision: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_manifest_id: JsonUUID
    expected_decision_version: int = Field(ge=0, le=2**63 - 1)
    reason: str = Field(min_length=1, max_length=512)


class IncidentCreateRequest(StrictModel):
    site_id: SiteId
    group_ids: list[Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]] = Field(
        min_length=1, max_length=100
    )
    title: str | None = Field(default=None, min_length=1, max_length=240)
    owner_key: str | None = Field(default=None, min_length=1, max_length=256)

    @field_validator("group_ids")
    @classmethod
    def unique_group_ids(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("group_ids must be unique")
        if any(
            len(group_id) != 64 or any(char not in "0123456789abcdef" for char in group_id)
            for group_id in value
        ):
            raise ValueError("group_ids must be lowercase SHA-256 identifiers")
        return value


class IncidentMembersRequest(StrictModel):
    site_id: SiteId
    add_group_ids: list[Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]] = Field(
        default_factory=list, max_length=100
    )
    remove_group_ids: list[Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]] = Field(
        default_factory=list, max_length=100
    )
    expected_work_version: int = Field(ge=1, le=2**31 - 2)


class IncidentAssignRequest(StrictModel):
    site_id: SiteId
    owner_key: str | None = Field(max_length=256)
    expected_work_version: int = Field(ge=1, le=2**31 - 2)


class IncidentStatusRequest(StrictModel):
    site_id: SiteId
    status: WorkStatus
    expected_work_version: int = Field(ge=1, le=2**31 - 2)


class IncidentCommentRequest(StrictModel):
    site_id: SiteId
    body: str = Field(min_length=1, max_length=4000)
    expected_work_version: int = Field(ge=1, le=2**31 - 2)


class IncidentDispositionRequest(StrictModel):
    site_id: SiteId
    label: DispositionLabel
    expected_work_version: int = Field(ge=1, le=2**31 - 2)
    expected_evidence_revision: JsonUUID
    reason_code: str | None = Field(default=None, max_length=64)
    note: str | None = Field(default=None, max_length=2000)
    propagate_to_members: Literal[False] = False


class IncidentPage(StrictModel):
    items: list[IncidentSummaryDTO]
    next_cursor: str | None
    limit: int


class ChainPage(StrictModel):
    items: list[ChainCandidateDTO]
    next_cursor: str | None
    limit: int


class IncidentEvidenceMemberDTO(StrictModel):
    group_id: str
    group_revision: str
    title: str
    first_ts: datetime
    last_ts: datetime
    alert_count: int
    score_version: str | None
    score_digest: str | None
    score: float | None


class MembershipIntervalDTO(StrictModel):
    membership_id: UUID
    group_id: str
    added_by: str
    added_at: datetime
    removed_by: str | None
    removed_at: datetime | None


class IncidentHistoryDTO(StrictModel):
    history_id: UUID
    work_version: int
    actor_key: str
    action: str
    before: Any | None
    after: dict[str, Any]
    at: datetime


class IncidentCommentDTO(StrictModel):
    comment_id: UUID
    evidence_revision: UUID
    work_version: int
    actor_key: str
    body: str
    at: datetime


class IncidentDispositionDTO(StrictModel):
    disposition_id: UUID
    evidence_revision: UUID
    work_version: int
    label: DispositionLabel
    reason_code: str | None
    note: str | None
    actor_key: str
    at: datetime


class IncidentDetailResponse(StrictModel):
    incident: IncidentSnapshotDTO
    members: list[IncidentEvidenceMemberDTO]
    membership_intervals: list[MembershipIntervalDTO]
    history: list[IncidentHistoryDTO]
    comments: list[IncidentCommentDTO]
    dispositions: list[IncidentDispositionDTO]
    next_cursors: dict[str, str | None]


class IncidentActionResponse(StrictModel):
    incident: IncidentSnapshotDTO | None = None
    incident_id: UUID | None = None
    action_id: UUID | None = None
    action: str | None = None
    work_version: int | None = None
    evidence_revision: UUID | None = None
    comment: IncidentCommentDTO | None = None
    disposition: IncidentDispositionDTO | None = None
    members: list[str] | None = None
    added: list[str] | None = None
    removed: list[str] | None = None
    chain_state: Literal["promoted"] | None = None


class ChainDismissResponse(StrictModel):
    chain_id: str
    state: Literal["dismissed"]
    version: int
    updated_at: datetime


class IncidentEventDTO(StrictModel):
    kind: Literal["alert"]
    event_ts: datetime
    event_id: str
    alert_key: str
    group_id: str
    group_revision: str
    rule_id: str | None
    fields: dict[str, Any]
    stages: list[dict[str, Any]]


class IncidentEventsResponse(StrictModel):
    evidence_revision: UUID
    events: list[IncidentEventDTO]
    next_cursor: str | None
    limit: int


class IncidentContextResponse(StrictModel):
    evidence_revision: UUID
    evidence_digest: str | None = None
    entities: list[dict[str, str]]
    from_: datetime | None = Field(alias="from")
    to: datetime | None
    sampled_alerts: list[dict[str, Any]]
    sample_limit: int | None = None
    omitted_count: int
    omitted_count_is_lower_bound: bool = False
    omitted_entity_count: int = 0
    omissions_capped: bool = False
    question_draft: dict[str, Any]


class ChainCandidateDetail(ChainCandidateDTO):
    edges: list[dict[str, Any]]
    weak_edges: list[dict[str, Any]]
    score_pins: list[dict[str, Any]]


class GroupSummary(StrictModel):
    group_id: str
    group_revision: str
    title: str
    score: float | None
    computation_version: str | None
    input_digest: str | None
    components: list[ScoreComponent]
    alert_count: int
    first_ts: datetime
    last_ts: datetime
    rule_id: str | None
    primary_entity: EntityRef | None
    status: str
    owner_key: str | None
    disposition: Disposition | None
    pipeline_version: str


class QueueSummary(StrictModel):
    group: GroupSummary
    queue_reasons: list[str]
    work_state: WorkState


class Enrichment(StrictModel):
    enrichment_id: str
    source: str
    source_version: str
    value: dict[str, Any]
    fetched_at: datetime
    expires_at: datetime | None


class HistoryEntry(StrictModel):
    at: datetime
    actor_key: str
    action: str
    before: Any | None
    after: Any


class GroupDetail(GroupSummary):
    site_id: str
    members: Page[AlertSummary]
    enrichments: list[Enrichment]
    edges: list[Any]
    chain_ids: list[str]
    history: list[HistoryEntry]
    work_state: WorkState


class AssignRequest(StrictModel):
    site_id: str
    owner_key: str | None = Field(max_length=256)


class StatusRequest(StrictModel):
    site_id: str
    status: WorkStatus
    expected_updated_at: datetime = Field(strict=False)

    @field_validator("expected_updated_at")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expected_updated_at must include a timezone offset")
        return value


class DispositionRequest(StrictModel):
    site_id: str
    label: DispositionLabel
    reason_code: str | None = Field(default=None, max_length=64)
    note: str | None = Field(default=None, max_length=2000)
    propagate_to_members: bool = False


class BulkAssignAction(StrictModel):
    kind: Literal["assign"]
    owner_key: str | None = Field(max_length=256)


class BulkStatusAction(StrictModel):
    kind: Literal["status"]
    status: WorkStatus


class BulkDispositionAction(StrictModel):
    kind: Literal["disposition"]
    label: DispositionLabel
    reason_code: str | None = Field(default=None, max_length=64)
    note: str | None = Field(default=None, max_length=2000)
    propagate_to_members: bool = False


BulkAction = Annotated[
    BulkAssignAction | BulkStatusAction | BulkDispositionAction,
    Field(discriminator="kind"),
]


class BulkActionRequest(StrictModel):
    site_id: str
    group_ids: list[str] = Field(min_length=1, max_length=100)
    action: BulkAction


class BulkActionItem(StrictModel):
    group_id: str
    result: dict[str, Any]


class BulkActionResponse(StrictModel):
    updated: int
    items: list[BulkActionItem]


class AssetTag(StrictModel):
    site_id: str
    entity_id: int
    entity_kind: str
    entity_value: str
    criticality: int
    tags: list[str]
    set_by: str | None
    set_at: datetime | None


class AssetTagUpsertRequest(StrictModel):
    site_id: str
    entity_id: int = Field(gt=0)
    criticality: int = Field(ge=0, le=3)
    tags: list[str] = Field(max_length=32)


class MetricStats(StrictModel):
    p50: float | None
    p90: float | None
    p95: float | None
    max: float | None
    sample_count: int


class BacklogStats(StrictModel):
    current: int
    previous: int
    delta: int
    unassigned: int


class OpsMetricsResponse(StrictModel):
    window: Window
    volume: list[HourlyBucket]
    ingest_lag_seconds: MetricStats
    queue_age_seconds: MetricStats
    backlog: BacklogStats
    time_to_ack_seconds: MetricStats
    time_to_triage_seconds: MetricStats
    dead_jobs: int


class LabelCount(StrictModel):
    label: DispositionLabel
    count: int


class RulePrecision(StrictModel):
    rule_id: str
    labelled_count: int
    true_positive_count: int
    false_positive_count: int
    benign_true_positive_count: int
    precision: float | None


class PrecisionAtK(StrictModel):
    k: int
    precision: float | None
    relevant_count: int
    labelled_count: int


class QualityMetricsResponse(StrictModel):
    window: Window
    dispositions: list[LabelCount]
    label_coverage: float | None
    labelled_group_count: int = Field(ge=0)
    group_count: int = Field(ge=0)
    rule_precision: list[RulePrecision]
    precision_at_k: list[PrecisionAtK]


class NarrativeUsage(StrictModel):
    input_tokens: int | None = Field(default=None, ge=0)
    cached_input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)


class NarrativeReadResponse(StrictModel):
    incident_id: UUID
    evidence_revision: UUID
    is_current: bool
    status: Literal["pending", "deferred", "running", "retrying", "available", "unavailable"]
    reason_code: str | None = None
    generation_id: UUID | None = None
    generation_digest: str | None = None
    pack_digest: str | None = None
    call_id: UUID | None = None
    completed_at: datetime | None = None
    usage: NarrativeUsage
    summary: ValidatedNarrative | None = None
    removals: list[RemovedSelection] = Field(default_factory=list[RemovedSelection], max_length=8)
    evidence: FrozenIncidentPack | None = None
