"""Canonical strict wire and internal contract models (freeze revision 1.16)."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from enum import StrEnum
from importlib.resources import files
from typing import Annotated, Any, Literal, Protocol, cast
from urllib.parse import urlsplit
from uuid import UUID
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    PlainSerializer,
    StringConstraints,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic.types import SecretStr

type ContentId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]{0,63}$")]
type TopicId = ContentId | Literal["_records"]
type SHA256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
type PolicyHash = Annotated[
    str,
    StringConstraints(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]*[1-9a-f][0-9a-f]*$",
    ),
]
type GitSHA40 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
type EvidenceId = Annotated[str, StringConstraints(pattern=r"^ev1_[0-9a-f]{64}$")]
type TraceId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
type SpanId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{16}$")]
type StageSlotId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9#:_-]{0,63}$")]


def _validate_zone(value: str) -> str:
    if any(part in ("", ".", "..") for part in value.split("/")):
        raise ValueError("timezone path is invalid")
    try:
        resource = files("tzdata.zoneinfo").joinpath(*value.split("/"))
        with resource.open("rb") as zone_data:
            ZoneInfo.from_file(zone_data, key=value)
    except (ZoneInfoNotFoundError, ModuleNotFoundError, FileNotFoundError) as exc:
        raise ValueError("timezone must be an IANA zone") from exc
    return value


def _utc_string(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _validate_https_url(value: HttpUrl) -> HttpUrl:
    if value.scheme != "https":
        raise ValueError("URL must use HTTPS")
    return value


def _validate_origin(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("origin must be an HTTPS origin")
    if parsed.path or parsed.query or parsed.fragment:
        raise ValueError("origin cannot include path, query, or fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("origin port is invalid") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("port must be in the valid TCP range")
    return value


type IANAZone = Annotated[
    str,
    StringConstraints(
        min_length=1, max_length=64, pattern=r"^[A-Za-z][A-Za-z0-9_+.-]*(?:/[A-Za-z0-9_+.-]+)*$"
    ),
    AfterValidator(_validate_zone),
]
type HTTPSUrl = Annotated[HttpUrl, AfterValidator(_validate_https_url)]
type HTTPSOrigin = Annotated[
    str,
    StringConstraints(pattern=r"^https://[^/?#@\s]+(?::[0-9]{1,5})?$"),
    AfterValidator(_validate_origin),
]
type UTCDateTime = Annotated[
    datetime,
    AfterValidator(
        lambda value: (
            value
            if value.tzinfo is not None and value.utcoffset() is not None
            else (_ for _ in ()).throw(ValueError("timezone offset required"))
        )
    ),
    PlainSerializer(_utc_string, return_type=str, when_used="json"),
]
type FilterValue = str | int | list[str] | None
type EvidenceValue = str | int | bool | None | list[str]
type FiniteFloat = Annotated[float, Field(allow_inf_nan=False)]
type JSONScalar = str | int | FiniteFloat | bool | None
type JSONValue = str | int | FiniteFloat | bool | None | list["JSONValue"] | dict[str, "JSONValue"]


class StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True, use_enum_values=True)


class LocaleText(StrictModel):
    en: str
    es: str


class Effort(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    xhigh = "xhigh"
    max = "max"


class Visibility(StrEnum):
    full = "full"
    filtered = "filtered"
    unknown = "unknown"


class ErrorCode(StrEnum):
    BAD_REQUEST = "BAD_REQUEST"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    AUTH_INVALID = "AUTH_INVALID"
    AUTH_EXPIRED = "AUTH_EXPIRED"
    FORBIDDEN = "FORBIDDEN"
    SITE_DENIED = "SITE_DENIED"
    ORIGIN_DENIED = "ORIGIN_DENIED"
    CSRF_DENIED = "CSRF_DENIED"
    SCOPE_DENIED = "SCOPE_DENIED"
    FOLLOWUP_EXPIRED = "FOLLOWUP_EXPIRED"
    FOLLOWUP_CONFLICT = "FOLLOWUP_CONFLICT"
    QUESTION_ACTIVE = "QUESTION_ACTIVE"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    POLICY_CHANGED = "POLICY_CHANGED"
    CONTENT_CHANGED = "CONTENT_CHANGED"
    BUSY = "BUSY"
    RATE_LIMITED = "RATE_LIMITED"
    UNSUPPORTED_MODEL = "UNSUPPORTED_MODEL"
    UNSUPPORTED_EFFORT = "UNSUPPORTED_EFFORT"
    INVALID_WINDOW = "INVALID_WINDOW"
    INVALID_FILTER = "INVALID_FILTER"
    INVALID_SCHEMA = "INVALID_SCHEMA"
    DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"
    SERVICE_DISABLED = "SERVICE_DISABLED"
    CONFIG_INVALID = "CONFIG_INVALID"
    INTERNAL = "INTERNAL"
    INDEXER_AUTH_REJECTED = "INDEXER_AUTH_REJECTED"
    INDEXER_DENIED = "INDEXER_DENIED"
    INDEXER_UNAVAILABLE = "INDEXER_UNAVAILABLE"
    MAPPING_UNSUPPORTED = "MAPPING_UNSUPPORTED"
    QUERY_INVALID = "QUERY_INVALID"
    CA_UNTRUSTED = "CA_UNTRUSTED"
    TOKEN_BROKER_UNAVAILABLE = "TOKEN_BROKER_UNAVAILABLE"
    CONTEXT_EXCEEDED = "CONTEXT_EXCEEDED"
    TOKEN_COUNT_UNAVAILABLE = "TOKEN_COUNT_UNAVAILABLE"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
    GUARDRAIL_BLOCKED = "GUARDRAIL_BLOCKED"
    INVALID_MODEL_OUTPUT = "INVALID_MODEL_OUTPUT"
    CONTENT_INVALID = "CONTENT_INVALID"
    LEASE_LOST = "LEASE_LOST"
    FEEDBACK_UNAVAILABLE = "FEEDBACK_UNAVAILABLE"
    FEEDBACK_INVALID = "FEEDBACK_INVALID"
    EVIDENCE_INVALID = "EVIDENCE_INVALID"
    EVIDENCE_LIMIT = "EVIDENCE_LIMIT"
    CAPACITY_LIMIT = "CAPACITY_LIMIT"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    AUDIT_UNAVAILABLE = "AUDIT_UNAVAILABLE"
    REQUEST_COMPLETED = "REQUEST_COMPLETED"
    REQUEST_ABANDONED = "REQUEST_ABANDONED"
    INVALID_CONTINUATION = "INVALID_CONTINUATION"
    REQUEST_TOO_LARGE = "REQUEST_TOO_LARGE"
    REQUEST_COMPLEXITY = "REQUEST_COMPLEXITY"
    CURSOR_EXPIRED = "CURSOR_EXPIRED"
    INVALID_MODEL_SELECTION = "INVALID_MODEL_SELECTION"


class TemplateId(StrEnum):
    alerts_rows_v1 = "alerts_rows_v1"
    alerts_count_v1 = "alerts_count_v1"
    alerts_group_v1 = "alerts_group_v1"
    vulnerabilities_rows_v1 = "vulnerabilities_rows_v1"
    vulnerabilities_count_v1 = "vulnerabilities_count_v1"
    vulnerabilities_group_v1 = "vulnerabilities_group_v1"


class FieldId(StrEnum):
    timestamp = "timestamp"
    agent_id = "agent.id"
    agent_name = "agent.name"
    rule_id = "rule.id"
    rule_level = "rule.level"
    rule_groups = "rule.groups"
    data_srcip = "data.srcip"
    data_dstip = "data.dstip"
    vulnerability_id = "vulnerability.id"
    vulnerability_severity = "vulnerability.severity"
    vulnerability_detected_at = "vulnerability.detected_at"
    package_name = "package.name"
    package_version = "package.version"


type EvidenceKey = (
    FieldId
    | Literal[
        "count",
        "outcome",
        "matched_nothing",
        "relation",
        "approximate",
        "bucket_key",
        "operand_ids",
        "expectation_id",
        "expectation_version",
        "kev_cve",
        "kev_lookup",
        "kev_freshness",
        "kev_added_on",
        "kev_coverage",
        "kev_reason",
        "kev_row_n",
        "kev_subject_n",
        "kev_annotated_n",
        "kev_omitted_n",
        "kev_hit_n",
        "kev_not_listed_n",
        "kev_invalid_n",
        "kev_unavailable_n",
        "kev_fresh_n",
        "kev_stale_n",
        "kev_not_yet_valid_n",
        "kev_unknown_n",
    ]
)
_EVIDENCE_KEYS = [
    *(field.value for field in FieldId),
    "count",
    "outcome",
    "matched_nothing",
    "relation",
    "approximate",
    "bucket_key",
    "operand_ids",
    "expectation_id",
    "expectation_version",
    "kev_cve",
    "kev_lookup",
    "kev_freshness",
    "kev_added_on",
    "kev_coverage",
    "kev_reason",
    "kev_row_n",
    "kev_subject_n",
    "kev_annotated_n",
    "kev_omitted_n",
    "kev_hit_n",
    "kev_not_listed_n",
    "kev_invalid_n",
    "kev_unavailable_n",
    "kev_fresh_n",
    "kev_stale_n",
    "kev_not_yet_valid_n",
    "kev_unknown_n",
]
type EvidenceValues = Annotated[
    dict[EvidenceKey, EvidenceValue],
    Field(json_schema_extra=cast(dict[str, Any], {"propertyNames": {"enum": _EVIDENCE_KEYS}})),
]


class IndexFamily(StrEnum):
    alerts = "alerts"
    vulnerabilities = "vulnerabilities"


class GroupField(StrEnum):
    agent_id = "agent.id"
    rule_id = "rule.id"
    rule_level = "rule.level"
    vulnerability_severity = "vulnerability.severity"


class AnswerStatus(StrEnum):
    answered = "answered"
    partial = "partial"
    clarify = "clarify"
    refused = "refused"


class JudgmentState(StrEnum):
    not_requested = "not_requested"
    validated = "validated"
    denial = "denial"
    ingestion_unconfirmed = "ingestion_unconfirmed"
    context_exceeded = "context_exceeded"
    budget_exceeded = "budget_exceeded"
    model_unavailable = "model_unavailable"
    guardrail_blocked = "guardrail_blocked"
    invalid_output = "invalid_output"
    no_findings = "no_findings"
    all_removed = "all_removed"
    evidence_unavailable = "evidence_unavailable"
    token_count_unavailable = "token_count_unavailable"
    deadline_exceeded = "deadline_exceeded"
    capacity_limited = "capacity_limited"


class RemovedReason(StrEnum):
    unknown_evidence = "unknown_evidence"
    cross_topic = "cross_topic"
    bad_binding = "bad_binding"
    unsupported_value = "unsupported_value"
    unknown_template = "unknown_template"
    invalid_schema = "invalid_schema"
    bad_relation = "bad_relation"
    failed_prerequisite = "failed_prerequisite"
    duplicate_id = "duplicate_id"


class LeftOutReason(StrEnum):
    context_exceeded = "context_exceeded"
    budget_exceeded = "budget_exceeded"
    model_unavailable = "model_unavailable"
    guardrail_blocked = "guardrail_blocked"
    invalid_output = "invalid_output"
    all_removed = "all_removed"
    token_count_unavailable = "token_count_unavailable"
    deadline_exceeded = "deadline_exceeded"
    capacity_limited = "capacity_limited"
    evidence_unavailable = "evidence_unavailable"


class CheckOutcome(StrEnum):
    passed = "passed"
    failed = "failed"
    unknown = "unknown"
    denied = "denied"
    not_configured = "not_configured"


class SnapshotKind(StrEnum):
    pit = "pit"
    first_page_only = "first_page_only"


class FetchState(StrEnum):
    rows = "rows"
    empty = "empty"
    filtered = "filtered"
    denied = "denied"
    unavailable = "unavailable"


class Filter(StrictModel):
    field: FieldId
    op: Literal["eq", "in", "gte", "lte", "exists"]
    value: FilterValue

    @field_validator("value", mode="before")
    @classmethod
    def reject_bool_count(cls, value: object) -> FilterValue:
        if isinstance(value, bool):
            raise ValueError("boolean is not a filter integer")
        if isinstance(value, str) and len(value.encode("utf-8")) > 128:
            raise ValueError("filter string exceeds 128 UTF-8 bytes")
        if isinstance(value, list):
            items = cast(list[str], value)
            if len(items) > 16 or len(set(items)) != len(items):
                raise ValueError("in-list must contain at most 16 distinct values")
        if value is not None and not isinstance(value, (str, int, list)):
            raise ValueError("unsupported filter value")
        return cast(FilterValue, value)

    @model_validator(mode="after")
    def validate_field_operator(self) -> Filter:
        if self.field in (FieldId.timestamp, FieldId.vulnerability_detected_at):
            raise ValueError("time fields are supplied only by the resolved window")
        if self.field == FieldId.rule_level:
            if self.op not in ("eq", "gte", "lte", "exists"):
                raise ValueError("rule.level supports eq/gte/lte/exists")
            if self.op != "exists" and not isinstance(self.value, int):
                raise ValueError("rule.level filters require an integer")
        elif self.op in ("gte", "lte"):
            raise ValueError("numeric comparisons are supported only for rule.level")
        if self.op == "exists" and self.value is not None:
            raise ValueError("exists filters have a null value")
        if self.op == "in" and not isinstance(self.value, list):
            raise ValueError("in filters require a string list")
        if self.op != "in" and isinstance(self.value, list):
            raise ValueError("only in filters accept a list")
        if self.op != "exists" and self.value is None:
            raise ValueError("only exists filters may have a null value")
        if (
            self.field == FieldId.rule_level
            and isinstance(self.value, int)
            and not 0 <= self.value <= 16
        ):
            raise ValueError("rule.level must be between 0 and 16")
        if self.field in (FieldId.data_srcip, FieldId.data_dstip):
            values = self.value if isinstance(self.value, list) else [self.value]
            for item in values:
                if not isinstance(item, str):
                    raise ValueError("IP filters require string literals")
                try:
                    address = ipaddress.ip_address(item)
                except ValueError as exc:
                    raise ValueError("IP filter must be a canonical address literal") from exc
                if str(address) != item:
                    raise ValueError("IP filter must use canonical address notation")
        if self.field == FieldId.vulnerability_id:
            values = self.value if isinstance(self.value, list) else [self.value]
            if any(
                not isinstance(item, str) or re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", item) is None
                for item in values
            ):
                raise ValueError("vulnerability IDs must be canonical CVE identifiers")
        return self


class ResolvedWindow(StrictModel):
    start: UTCDateTime
    end: UTCDateTime
    semantics: Literal["rolling", "calendar", "absolute"]
    source_text: Annotated[str, StringConstraints(max_length=128)]
    timezone: IANAZone
    anchor_at: UTCDateTime

    @model_validator(mode="after")
    def validate_interval(self) -> ResolvedWindow:
        start = self.start.astimezone(UTC)
        end = self.end.astimezone(UTC)
        anchor = self.anchor_at.astimezone(UTC)
        if start >= end:
            raise ValueError("window must be a positive [start,end) interval")
        if end > anchor:
            raise ValueError("window end must not exceed anchor")
        if end - start > timedelta(days=90):
            raise ValueError("window cannot exceed 90 days")
        if len(self.source_text.encode("utf-8")) > 128:
            raise ValueError("window descriptor exceeds 128 bytes")
        return self


class MatchedSpan(StrictModel):
    start: int = Field(ge=0)
    end: int = Field(ge=0)
    kind: Literal["cue", "alias"]
    id: ContentId


class PlanProvenance(StrictModel):
    cue_pack_sha: SHA256
    normalized_question_hash: SHA256
    origin: Literal["new", "window_followup", "leftout_followup", "explicit_keep"]
    previous_question_id: UUID | None = None
    matched_spans: list[MatchedSpan]


class FetchSpec(StrictModel):
    fetch_id: ContentId
    template_id: TemplateId
    window: ResolvedWindow
    filters: list[Filter] = Field(max_length=10)
    page_size: int = Field(default=20, ge=1, le=50)
    limit: int | None = Field(default=None, ge=1, le=50)
    order: Literal["latest", "earliest"] = "latest"
    group_by: GroupField | None = None


class TopicPlan(StrictModel):
    topic_id: TopicId
    ordinal: int = Field(ge=0)
    document: bool
    failure: bool
    judgment: bool
    fetches: list[FetchSpec]
    playbook_id: ContentId | None = None
    playbook_window: ResolvedWindow | None = None
    cue_ids: list[ContentId]
    alias_ids: list[ContentId]


class QuestionPlan(StrictModel):
    schema_version: Literal["1"] = "1"
    question_id: UUID
    environment_id: ContentId
    owner_key: SHA256
    content_sha: GitSHA40
    policy_hash: PolicyHash
    language: Literal["en", "es"]
    timezone: IANAZone
    anchor_at: UTCDateTime
    topics: list[TopicPlan]
    model_id: str | None = None
    effort: Effort | None = None
    provenance: PlanProvenance


class AskRequest(StrictModel):
    question: Annotated[str, StringConstraints(min_length=1)]
    environment_id: ContentId
    model_id: str | None = None
    effort: Effort | None = None
    followup_id: UUID | None = None
    followup_revision: int | None = Field(default=None, ge=1)
    continue_topic_ids: list[TopicId] | None = None
    language_hint: Literal["en", "es"] | None = None
    timezone: IANAZone = "UTC"

    @model_validator(mode="after")
    def validate_request(self) -> AskRequest:
        if len(self.question.encode("utf-8")) > 16384:
            raise ValueError("question exceeds 16384 UTF-8 bytes")
        if (self.followup_id is None) != (self.followup_revision is None):
            raise ValueError("follow-up ID and revision must be provided together")
        if self.continue_topic_ids is not None:
            if not self.continue_topic_ids or len(set(self.continue_topic_ids)) != len(
                self.continue_topic_ids
            ):
                raise ValueError("continuation topic IDs must be nonempty and unique")
        return self


class Clarify(StrictModel):
    kind: Literal[
        "missing_slots",
        "ambiguous_scope",
        "missing_subject",
        "semantic_suggestion",
        "model_selection",
    ]
    question: str
    slots: list[str]
    suggested_topic: ContentId | None = None


class Planned(StrictModel):
    kind: Literal["planned"] = "planned"
    plan: QuestionPlan


class Clarified(StrictModel):
    kind: Literal["clarified"] = "clarified"
    clarify: Clarify


class Refused(StrictModel):
    kind: Literal["refused"] = "refused"
    message: str


type PlanningResult = Annotated[Planned | Clarified | Refused, Field(discriminator="kind")]


class DomainError(StrictModel):
    code: ErrorCode
    message: str
    retryable: bool
    trace_id: str
    details: dict[str, str | int | list[str]] = Field(default_factory=dict)


class Count(StrictModel):
    value: int = Field(ge=0)
    relation: Literal["eq", "gte"]
    scope: Literal["matching_visible_records", "bucket_visible_records"]
    computed_by: Literal["indexer"]
    approximate: bool = False


class Column(StrictModel):
    field: FieldId
    label: LocaleText
    kind: Literal["text", "integer", "date", "ip"]


class RecordRef(StrictModel):
    index_alias: str
    record_id: str


class EvidenceRow(StrictModel):
    evidence_id: EvidenceId
    topic_id: TopicId
    fetch_id: ContentId
    record_ref: RecordRef | None = None
    values: dict[FieldId, EvidenceValue]


class SnapshotRef(StrictModel):
    kind: SnapshotKind
    key: SHA256
    at: UTCDateTime
    expires_at: UTCDateTime | None = None


class FetchScope(StrictModel):
    environment_id: ContentId
    template_id: TemplateId
    index_family: IndexFamily
    filters: list[Filter]
    visibility: Visibility
    policy_hash: PolicyHash
    snapshot: SnapshotKind
    displayed_rows: int = Field(ge=0)


class EvidenceCheck(StrictModel):
    name: Literal[
        "policy",
        "mapping",
        "validate_query",
        "execute_as_analyst",
        "exact_count",
        "index_exists",
        "window_data",
        "filter_probe",
        "snapshot",
        "duplicate_source",
    ]
    outcome: Literal["passed", "unknown", "failed"]
    code: ContentId


class FilterProbe(StrictModel):
    filter: Filter
    count: Count | None = None
    outcome: Literal["passed", "unknown"]


class CheckResult(StrictModel):
    check_id: ContentId
    topic_id: TopicId
    label: str
    outcome: CheckOutcome
    evidence_ids: list[EvidenceId]
    message: str
    expectation_id: ContentId | None = None


class EvidenceSourceRow(StrictModel):
    index_alias: str
    record_id: str


class EvidenceSourceBucket(StrictModel):
    group_field: GroupField
    key: str | int


class EvidenceSourceCount(StrictModel):
    template_id: TemplateId
    window: ResolvedWindow
    filters: list[Filter]
    scope: Literal["matching_visible_records"]


class EvidenceSourceProbe(StrictModel):
    probe_kind: Literal["index_exists", "window_data", "filter", "combination"]
    filters: list[Filter]


class EvidenceSourceCheck(StrictModel):
    step_id: ContentId
    operand_ids: list[EvidenceId]


class KevEntry(StrictModel):
    cve: Annotated[str, StringConstraints(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$", max_length=32)]
    added_on: date

    @field_validator("cve")
    @classmethod
    def require_ascii_cve(cls, value: str) -> str:
        if not value.isascii() or len(value.encode("ascii")) > 32:
            raise ValueError("CVE must be ASCII and at most 32 bytes")
        return value


class KevPolicy(StrictModel):
    topic_id: Literal["vuln_review"] = "vuln_review"
    fetch_id: Literal["vuln_rows"] = "vuln_rows"
    template_id: Literal[TemplateId.vulnerabilities_rows_v1] = TemplateId.vulnerabilities_rows_v1
    max_age_seconds: Literal[604800] = 604800
    page_context_items: Literal[256] = 256
    page_context_bytes: Literal[49152] = 49152
    initial_context_items: Literal[512] = 512
    initial_context_bytes: Literal[98304] = 98304
    page_summary_bytes: Literal[16384] = 16384


class KevNotice(StrictModel):
    source_url: Annotated[str, StringConstraints(min_length=1, max_length=512)]
    terms_url: Annotated[str, StringConstraints(min_length=1, max_length=512)]
    attribution: Annotated[str, StringConstraints(min_length=1, max_length=512)]
    terms_text: Annotated[str, StringConstraints(min_length=1)]
    transformations: Annotated[str, StringConstraints(min_length=1, max_length=512)]
    terms_review_record: Annotated[str, StringConstraints(min_length=1, max_length=512)]

    @field_validator("terms_text")
    @classmethod
    def bound_notice_text(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 4096:
            raise ValueError("notice text exceeds 4096 UTF-8 bytes")
        return value

    @field_validator(
        "source_url",
        "terms_url",
        "attribution",
        "transformations",
        "terms_review_record",
    )
    @classmethod
    def bound_notice_fields(cls, value: str, info: ValidationInfo) -> str:
        if len(value.encode("utf-8")) > 512:
            raise ValueError("KEV notice field exceeds 512 UTF-8 bytes")
        if info.field_name in {"source_url", "terms_url"}:
            parsed = urlsplit(value)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
            ):
                raise ValueError("KEV notice URLs must be HTTPS URLs without user information")
        return value


class KevMetadata(StrictModel):
    dataset_id: Literal["cisa-kev"] = "cisa-kev"
    catalog_version: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    record_count: int = Field(ge=1, le=4096)
    published_at: UTCDateTime
    retrieved_at: UTCDateTime
    raw_sha256: SHA256
    normalized_sha256: SHA256
    normalizer_version: Literal["cisa-kev/1"] = "cisa-kev/1"
    policy: KevPolicy
    notice: KevNotice

    @field_validator("catalog_version")
    @classmethod
    def bound_catalog_version(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 128:
            raise ValueError("catalog version exceeds 128 UTF-8 bytes")
        return value


class KevCatalog(StrictModel):
    metadata: KevMetadata
    entries: tuple[KevEntry, ...] = Field(min_length=1, max_length=4096)

    @model_validator(mode="after")
    def validate_entries(self) -> KevCatalog:
        cves = [entry.cve for entry in self.entries]
        if cves != sorted(cves) or len(cves) != len(set(cves)):
            raise ValueError("KEV entries must be uniquely CVE-sorted")
        if len(cves) != self.metadata.record_count:
            raise ValueError("KEV record count does not match entries")
        return self


class KevSnapshot(StrictModel):
    metadata: KevMetadata
    approved_at: UTCDateTime
    approval_key_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    entries: tuple[KevEntry, ...] = Field(min_length=1, max_length=4096)

    @model_validator(mode="after")
    def validate_entries(self) -> KevSnapshot:
        cves = [entry.cve for entry in self.entries]
        if cves != sorted(cves) or len(cves) != len(set(cves)):
            raise ValueError("KEV entries must be uniquely CVE-sorted")
        if len(cves) != self.metadata.record_count:
            raise ValueError("KEV record count does not match entries")
        if self.approved_at < self.metadata.retrieved_at:
            raise ValueError("KEV approval cannot precede retrieval")
        return self


class KevUseRef(StrictModel):
    content_sha: GitSHA40
    pack_sha256: SHA256
    metadata: KevMetadata | None
    approved_at: UTCDateTime | None
    approval_key_id: str | None
    policy_sha256: SHA256
    evaluation_at: UTCDateTime
    valid_from: UTCDateTime | None
    expires_at: UTCDateTime | None

    @model_validator(mode="after")
    def validate_availability(self) -> KevUseRef:
        absent = self.metadata is None
        if absent != (self.approved_at is None) or absent != (self.approval_key_id is None):
            raise ValueError("absent KEV metadata requires absent approval metadata")
        if absent != (self.valid_from is None) or absent != (self.expires_at is None):
            raise ValueError("absent KEV metadata requires absent validity dates")
        if self.metadata is not None:
            valid_from = max(
                self.metadata.published_at,
                self.metadata.retrieved_at,
                cast(datetime, self.approved_at),
            )
            expires_at = self.metadata.published_at + timedelta(
                seconds=self.metadata.policy.max_age_seconds
            )
            if self.valid_from != valid_from or self.expires_at != expires_at:
                raise ValueError("KEV validity dates must be derived from metadata and approval")
        return self


class EvidenceSourceContext(StrictModel):
    role: Literal["page", "subject"]
    kev_use: KevUseRef | None = None
    parent_evidence_id: EvidenceId | None = None
    member_index: int | None = Field(default=None, ge=0, le=63)
    page_evidence_id: EvidenceId | None = None

    @model_validator(mode="after")
    def validate_role(self) -> EvidenceSourceContext:
        if self.role == "page":
            if self.kev_use is None or any(
                value is not None
                for value in (self.parent_evidence_id, self.member_index, self.page_evidence_id)
            ):
                raise ValueError("page context source requires only kev_use")
        elif (
            self.kev_use is not None
            or self.parent_evidence_id is None
            or self.member_index is None
            or self.page_evidence_id is None
        ):
            raise ValueError("subject context source requires row, member and page references")
        return self


type EvidenceSource = (
    EvidenceSourceRow
    | EvidenceSourceBucket
    | EvidenceSourceCount
    | EvidenceSourceProbe
    | EvidenceSourceCheck
    | EvidenceSourceContext
)


class EvidenceItem(StrictModel):
    evidence_id: EvidenceId
    topic_id: TopicId
    fetch_id: ContentId | None = None
    check_id: ContentId | None = None
    kind: Literal["row", "aggregate", "check", "context"]
    source: EvidenceSource
    snapshot: SnapshotRef
    values: EvidenceValues = Field(
        json_schema_extra=cast(
            dict[str, Any],
            {
                "propertyNames": {"enum": _EVIDENCE_KEYS},
                "additionalProperties": {
                    "anyOf": [
                        {"type": "string"},
                        {"type": "integer"},
                        {"type": "boolean"},
                        {"type": "null"},
                        {"type": "array", "items": {"type": "string"}},
                    ]
                },
            },
        )
    )
    visibility: Visibility
    scope_hash: SHA256

    @field_validator("values", mode="before")
    @classmethod
    def validate_value_map(cls, value: object) -> EvidenceValues:
        if not isinstance(value, dict):
            raise ValueError("evidence values must be an object")
        mapping = cast(dict[object, object], value)
        finite = set(_EVIDENCE_KEYS)
        for key, item in mapping.items():
            key_string = key.value if isinstance(key, FieldId) else key
            if not isinstance(key_string, str) or key_string not in finite:
                raise ValueError("evidence values contain an unknown key")
            if not (
                item is None
                or isinstance(item, (str, int, bool))
                or isinstance(item, list)
                and all(isinstance(member, str) for member in cast(list[object], item))
            ):
                raise ValueError("evidence values contain an unsupported value")
        return cast(EvidenceValues, value)

    @model_validator(mode="after")
    def validate_item_binding(self) -> EvidenceItem:
        if (self.fetch_id is None) == (self.check_id is None):
            raise ValueError("evidence item binds to exactly one fetch or check")
        if self.kind == "check" and self.check_id is None:
            raise ValueError("check evidence requires check_id")
        if self.kind != "check" and self.fetch_id is None:
            raise ValueError("row/aggregate evidence requires fetch_id")
        if self.kind == "context":
            if not isinstance(self.source, EvidenceSourceContext):
                raise ValueError("context evidence requires a context source")
            if self.topic_id != "vuln_review" or self.fetch_id != "vuln_rows":
                raise ValueError("context evidence is bound to the KEV vulnerability fetch")
            allowed = (
                {
                    "kev_coverage",
                    "kev_reason",
                    "kev_row_n",
                    "kev_subject_n",
                    "kev_annotated_n",
                    "kev_omitted_n",
                    "kev_hit_n",
                    "kev_not_listed_n",
                    "kev_invalid_n",
                    "kev_unavailable_n",
                    "kev_fresh_n",
                    "kev_stale_n",
                    "kev_not_yet_valid_n",
                    "kev_unknown_n",
                }
                if self.source.role == "page"
                else {"kev_cve", "kev_lookup", "kev_freshness", "kev_added_on"}
            )
            value_keys = {
                key.value if isinstance(key, FieldId) else key
                for key in cast(dict[object, object], self.values)
            }
            if not self.values or value_keys - allowed:
                raise ValueError("context evidence contains keys invalid for its role")
            enum_values = {
                "kev_lookup": {"hit", "not_listed", "invalid_cve", "unavailable"},
                "kev_freshness": {"fresh", "stale", "not_yet_valid", "unknown"},
                "kev_coverage": {"complete", "incomplete", "unavailable"},
                "kev_reason": {"not_configured", "limit", "lookup_error", "not_yet_available"},
            }
            for key, value in self.values.items():
                if key in enum_values and (
                    not isinstance(value, str) or value not in enum_values[key]
                ):
                    raise ValueError("context evidence contains an invalid finite value")
                if key.endswith("_n") and (
                    isinstance(value, bool) or not isinstance(value, int) or value < 0
                ):
                    raise ValueError("context counts must be nonnegative integers")
                if key == "kev_added_on" and value is not None:
                    try:
                        valid_date = (
                            isinstance(value, str)
                            and date.fromisoformat(value).isoformat() == value
                        )
                    except ValueError:
                        valid_date = False
                    if not valid_date:
                        raise ValueError("context added_on must be a calendar date")
                if (
                    key == "kev_cve"
                    and value is not None
                    and (not isinstance(value, str) or len(value.encode("utf-8")) > 32)
                ):
                    raise ValueError("context CVE value is invalid")
            if self.source.role == "page" and "kev_coverage" not in self.values:
                raise ValueError("page context evidence requires coverage")
            if self.source.role == "page":
                summary_counts = {
                    "kev_row_n",
                    "kev_subject_n",
                    "kev_annotated_n",
                    "kev_omitted_n",
                    "kev_hit_n",
                    "kev_not_listed_n",
                    "kev_invalid_n",
                    "kev_unavailable_n",
                    "kev_fresh_n",
                    "kev_stale_n",
                    "kev_not_yet_valid_n",
                    "kev_unknown_n",
                }
                if not summary_counts.issubset(self.values):
                    raise ValueError("page context evidence requires complete summary counts")
                lookup_total = sum(
                    cast(int, self.values[key])
                    for key in (
                        "kev_hit_n",
                        "kev_not_listed_n",
                        "kev_invalid_n",
                        "kev_unavailable_n",
                    )
                )
                freshness_total = sum(
                    cast(int, self.values[key])
                    for key in (
                        "kev_fresh_n",
                        "kev_stale_n",
                        "kev_not_yet_valid_n",
                        "kev_unknown_n",
                    )
                )
                annotated = cast(int, self.values["kev_annotated_n"])
                omitted = cast(int, self.values["kev_omitted_n"])
                if annotated + omitted != self.values["kev_subject_n"]:
                    raise ValueError("page context counts must partition subjects")
                if lookup_total != annotated or freshness_total != annotated:
                    raise ValueError("page lookup and freshness counts must equal annotations")
                coverage = self.values["kev_coverage"]
                reason = self.values.get("kev_reason")
                if coverage == "complete" and (reason is not None or omitted != 0):
                    raise ValueError("complete page coverage cannot have omissions or a reason")
                if coverage == "incomplete" and (reason is None or omitted == 0):
                    raise ValueError("incomplete page coverage requires omissions and a reason")
                if coverage == "unavailable" and (
                    reason is None or omitted != self.values["kev_subject_n"]
                ):
                    raise ValueError("unavailable page coverage must omit every subject")
            if self.source.role == "subject" and not {
                "kev_cve",
                "kev_lookup",
                "kev_freshness",
            }.issubset(self.values):
                raise ValueError("subject context evidence requires lookup identity and states")
            if self.source.role == "subject":
                lookup = self.values["kev_lookup"]
                cve = self.values["kev_cve"]
                canonical_cve = (
                    isinstance(cve, str)
                    and len(cve.encode("ascii", errors="ignore")) <= 32
                    and re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve, re.ASCII) is not None
                )
                if lookup in {"hit", "not_listed"} and not canonical_cve:
                    raise ValueError("KEV hits and misses require a canonical CVE")
                if lookup == "hit" and self.values.get("kev_added_on") is None:
                    raise ValueError("KEV hits require their date-only added_on value")
                if lookup != "hit" and self.values.get("kev_added_on") is not None:
                    raise ValueError("only KEV hits carry added_on")
        else:
            if isinstance(self.source, EvidenceSourceContext) or any(
                key.startswith("kev_") for key in self.values
            ):
                raise ValueError("KEV context fields require context evidence")
        return self


class EmptyProof(StrictModel):
    index_exists: Literal["confirmed", "unknown"]
    window_has_data: Literal["confirmed", "unknown", "empty"]
    window_count: Count | None = None
    filter_probes: list[FilterProbe]
    matched_nothing: list[FieldId]
    visibility: Visibility
    combination_zero: bool = False
    snapshot: SnapshotRef
    consistency: Literal["coherent", "unconfirmed"]
    items: list[EvidenceItem]


class Bucket(StrictModel):
    key: str | int
    count: Count
    evidence_id: EvidenceId


class FetchResult(StrictModel):
    fetch_id: ContentId
    topic_id: TopicId
    state: FetchState
    scope: FetchScope
    window: ResolvedWindow
    columns: list[Column]
    rows: list[EvidenceRow]
    count: Count | None = None
    checks: list[EvidenceCheck]
    empty_proof: EmptyProof | None = None
    next_cursor: str | None = None
    snapshot_at: UTCDateTime | None = None
    snapshot: SnapshotRef
    items: list[EvidenceItem]
    buckets: list[Bucket] = Field(default_factory=lambda: list[Bucket]())
    bucket_completeness: Literal["complete", "partial", "unknown"] = "complete"
    message: str | None = None
    error: DomainError | None = None

    @model_validator(mode="after")
    def validate_fetch_state(self) -> FetchResult:
        if self.state in (FetchState.denied, FetchState.unavailable) and (
            self.rows or self.count is not None
        ):
            raise ValueError("denied or unavailable fetches cannot carry rows or counts")
        if self.state == FetchState.filtered and self.scope.visibility != Visibility.filtered:
            raise ValueError("filtered result requires filtered authorization visibility")
        return self


class RenderedFinding(StrictModel):
    finding_id: ContentId
    kind: Literal["observation", "hypothesis", "recommendation"]
    text: str
    evidence_ids: list[EvidenceId]


class RemovedFinding(StrictModel):
    finding_id: str
    reason: RemovedReason
    candidate_sha256: SHA256


class LeftOut(StrictModel):
    topic_id: TopicId
    stage: Literal["fetch", "checks", "judgment"]
    reason: LeftOutReason
    retryable: bool


class TokenUsage(StrictModel):
    topic_id: TopicId
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    cache_read_input_tokens: int = Field(ge=0)
    cache_write_input_tokens: int = Field(ge=0)
    total_input_tokens: int = Field(ge=0)
    reserved_tokens: int = Field(ge=0)
    reservation_id: UUID


class JudgmentResult(StrictModel):
    state: JudgmentState
    model_id: str | None = None
    effort: Effort | None = None
    sentences: list[RenderedFinding]
    removed: list[RemovedFinding]
    usage: TokenUsage | None = None
    message: str | None = None


class DocPointer(StrictModel):
    document_id: ContentId
    source_path: str
    heading: str
    anchor: str
    url: HTTPSUrl
    content_sha: GitSHA40
    document_sha256: SHA256


class TopicAnswer(StrictModel):
    topic_id: TopicId
    ordinal: int = Field(ge=0)
    document: DocPointer | None = None
    missing: list[Literal["public_document", "playbook"]]
    tables: list[FetchResult]
    checks: list[CheckResult]
    judgment: JudgmentResult


class BuildProvenance(StrictModel):
    service_sha: GitSHA40
    content_repository: str
    content_sha: GitSHA40
    pack_sha256: SHA256
    image_digest: Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
    docs_origin: HTTPSOrigin
    docs_manifest_sha256: SHA256
    contract_version: Literal["1"] = "1"


class Answer(StrictModel):
    schema_version: Literal["1"] = "1"
    question_id: UUID
    environment_id: ContentId
    language: Literal["en", "es"]
    status: AnswerStatus
    blocks: list[TopicAnswer]
    message: str | None = None
    clarify: Clarify | None = None
    followup_id: UUID | None = None
    followup_revision: int | None = None
    left_out: list[LeftOut]
    provenance: BuildProvenance
    trace_id: str
    feedback_receipt: Annotated[str, StringConstraints(max_length=8192)]

    @model_validator(mode="after")
    def validate_answer_state(self) -> Answer:
        if self.status in (AnswerStatus.clarify, AnswerStatus.refused):
            if self.blocks or self.followup_id is not None or self.followup_revision is not None:
                raise ValueError("clarify/refusal cannot carry blocks or follow-up state")
        if (self.followup_id is None) != (self.followup_revision is None):
            raise ValueError("follow-up ID and revision must be paired")
        return self


class PublicLimits(StrictModel):
    question_bytes: int = Field(gt=0)
    page_size: int = Field(gt=0)
    window_days: int = Field(gt=0)
    request_bytes: int = Field(gt=0)
    plan_bytes: int = Field(gt=0)


class ModelCapabilityPublic(StrictModel):
    id: str
    label: str
    efforts: list[Effort]
    context_tokens: int = Field(gt=0)
    max_output_tokens: int = Field(gt=0)


class SitePublic(StrictModel):
    id: ContentId
    label: str


class BootstrapResponse(StrictModel):
    schema_version: Literal["1"] = "1"
    sites: list[SitePublic]
    models: list[ModelCapabilityPublic]
    provenance: BuildProvenance
    mode: Literal["fixture", "live"]
    limits: PublicLimits
    csrf_token: str | None = None


class PageRequest(StrictModel):
    environment_id: ContentId
    cursor: str


class FeedbackRequest(StrictModel):
    question_id: UUID
    environment_id: ContentId
    feedback_receipt: str
    kind: Literal["wrong"]
    note: str | None = None


class FeedbackQueued(StrictModel):
    feedback_id: UUID
    status: Literal["queued"]


class SiteConfig(StrictModel):
    environment_id: ContentId
    label: str
    enabled: bool
    indexer_origin: HTTPSOrigin
    private_network_ref: str
    jwt_issuer: str
    jwt_audience: str
    kms_signing_key_arn: str
    ca_secret_arn: str
    ca_secret_version: str
    ca_sha256: SHA256
    group_role_map: dict[str, tuple[str, ...]]
    role_visibility: dict[str, Visibility]
    allowed_index_patterns: dict[IndexFamily, tuple[str, ...]]
    mapping_profile: str
    policy_version: str
    pit_supported: bool
    allowed_templates: tuple[TemplateId, ...]
    dls_attestation_version: str
    composite_role_visibility: dict[str, Visibility]
    expectations: tuple[ExpectationDefinition, ...] = ()


class VerifiedPrincipal(StrictModel):
    issuer: HTTPSUrl
    sub: str
    owner_key: SHA256
    groups: tuple[str, ...]
    edge: Literal["browser", "mcp", "fixture"]
    authenticated_at: UTCDateTime
    expires_at: UTCDateTime
    assertion_hash: SHA256


class AuthorizedSite(StrictModel):
    config: SiteConfig
    backend_roles: tuple[str, ...]
    visibility: Visibility
    config_hash: SHA256
    policy_hash: PolicyHash


class IndexerCredential(StrictModel):
    bearer_token: SecretStr
    expires_at: UTCDateTime
    key_id: str

    def __repr__(self) -> str:
        return "IndexerCredential(bearer_token=SecretStr('**********'), expires_at=..., key_id=...)"


class ModelCapability(StrictModel):
    id: str
    label: str
    region: str
    resource_arns: tuple[str, ...]
    context_tokens: int = Field(gt=0)
    max_output_tokens: int = Field(gt=0)
    count_tokens_model_id: str
    efforts: tuple[Effort, ...]
    effort_transport: Literal["none", "additionalModelRequestFields"]
    effort_parameters: dict[Effort, dict[str, JSONScalar]]
    output_strategy: Literal["strict_json_messages"]
    count_strategy: Literal["count_tokens_converse"]
    count_contract_sha256: SHA256
    cache_min_tokens: int = Field(ge=0)
    cache_max_checkpoints: int = Field(ge=0)
    cache_ttl: Literal["5m", "1h"]
    validated_at: UTCDateTime
    primary_doc_url: HTTPSUrl


class SemanticSuggestion(StrictModel):
    topic_id: TopicId
    score: FiniteFloat
    margin: Annotated[FiniteFloat, Field(ge=0)]
    model_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    qualifies: bool
    near_threshold: bool

    @model_validator(mode="after")
    def reject_conflicting_classification(self) -> SemanticSuggestion:
        if self.qualifies and self.near_threshold:
            raise ValueError("a qualified suggestion cannot be near-threshold")
        return self


class TopicDefinition(StrictModel):
    schema_version: Literal["1"] = "1"
    topic_id: ContentId
    name: LocaleText
    aliases: list[AliasDefinition]
    public_document: DocumentDefinition | None = None
    playbook_id: ContentId | None = None
    finding_template_ids: list[ContentId]
    fetch_bindings: list[FetchBinding]


class AliasDefinition(StrictModel):
    alias_id: ContentId
    language: Literal["en", "es"]
    text: str
    normalized: str
    boundary: Literal["word", "phrase"]
    topic_id: ContentId


class DocumentDefinition(StrictModel):
    document_id: ContentId
    language: Literal["en", "es"]
    source_path: str
    heading: str
    anchor: str
    sha256: SHA256
    published_path: str


class FetchBinding(StrictModel):
    template_id: TemplateId
    filters: list[Filter]


class CueDefinition(StrictModel):
    cue_id: ContentId
    language: Literal["en", "es"]
    text: str
    normalized: str
    kind: Literal["fetch", "judgment", "failure", "keep", "continue"]
    boundary: Literal["word", "phrase"]
    negation_rule: ContentId | None = None


class CueAmbiguity(StrictModel):
    normalized: str
    topic_ids: list[ContentId]


class CueCatalog(StrictModel):
    version: Literal["1"]
    sha256: SHA256
    cues: list[CueDefinition]
    aliases: list[AliasDefinition]
    ambiguities: list[CueAmbiguity]


class TopicPromptPack(StrictModel):
    schema_version: Literal["1"] = "1"
    topic_id: TopicId
    language: Literal["en", "es"]
    content_sha: GitSHA40
    sha256: SHA256
    document_section: str | None = None
    internal_context: str | None = None
    missing: list[Literal["public_document", "playbook"]]


class GuardrailPin(StrictModel):
    identifier: str
    version: Annotated[str, StringConstraints(pattern=r"^[1-9][0-9]*$")]


class FindingBinding(StrictModel):
    evidence_id: EvidenceId
    field: FieldId | Literal["count", "outcome", "matched_nothing"]


class FindingCandidate(StrictModel):
    finding_id: ContentId
    kind: Literal["observation", "hypothesis", "recommendation"]
    template_id: ContentId
    evidence_ids: list[EvidenceId]
    bindings: dict[ContentId, FindingBinding]


class FindingCandidateSet(StrictModel):
    schema_version: Literal["1"]
    findings: list[FindingCandidate]


class FindingRelationSameRecord(StrictModel):
    kind: Literal["same_record"]
    bindings: list[ContentId]


class FindingRelationSameFetch(StrictModel):
    kind: Literal["same_fetch"]
    bindings: list[ContentId]


class FindingRelationAggregateScope(StrictModel):
    kind: Literal["aggregate_scope"]
    count_binding: ContentId
    entity_bindings: dict[ContentId, FieldId]


type FindingRelation = Annotated[
    FindingRelationSameRecord | FindingRelationSameFetch | FindingRelationAggregateScope,
    Field(discriminator="kind"),
]


class RequiredCheckOutcome(StrictModel):
    check_id: ContentId
    outcome: CheckOutcome


class FindingTemplate(StrictModel):
    template_id: ContentId
    topic_id: TopicId
    kind: Literal["observation", "hypothesis", "recommendation"]
    required_bindings: dict[
        ContentId, tuple[FieldId | Literal["count", "outcome", "matched_nothing"], ...]
    ]
    texts: LocaleText
    required_check_outcomes: list[RequiredCheckOutcome]
    allowed_evidence_kinds: list[Literal["row", "aggregate", "check"]]
    relations: list[
        FindingRelationSameRecord | FindingRelationSameFetch | FindingRelationAggregateScope
    ] = Field(
        default_factory=lambda: list[
            FindingRelationSameRecord | FindingRelationSameFetch | FindingRelationAggregateScope
        ]()
    )


class ExpectationDefinition(StrictModel):
    schema_version: Literal["1"] = "1"
    expectation_id: ContentId
    topic_id: ContentId
    field: FieldId
    op: Literal["eq", "in", "gte", "lte", "exists"]
    value: FilterValue
    source: Literal["content", "site"]
    version: str


class WindowDefault(StrictModel):
    unit: Literal["hours", "days"]
    amount: int = Field(gt=0)


class IntegerOperand(StrictModel):
    kind: Literal["literal"]
    value: int = Field(ge=0)


class FetchCountOperand(StrictModel):
    kind: Literal["fetch_count"]
    fetch_id: ContentId


type CountOperand = Annotated[IntegerOperand | FetchCountOperand, Field(discriminator="kind")]


class FetchStep(StrictModel):
    kind: Literal["fetch"]
    step_id: ContentId
    label: LocaleText
    fetch_id: ContentId
    template_id: TemplateId
    window_default: WindowDefault
    filters: list[Filter]


class CompareCountStep(StrictModel):
    kind: Literal["compare_count"]
    step_id: ContentId
    label: LocaleText
    check_id: ContentId
    left_fetch_id: ContentId
    op: Literal["eq", "gte", "lte"]
    right: CountOperand


class FieldPresentStep(StrictModel):
    kind: Literal["field_present"]
    step_id: ContentId
    label: LocaleText
    check_id: ContentId
    fetch_id: ContentId
    field: FieldId
    quantifier: Literal["all", "any"]


class ExpectationMatchStep(StrictModel):
    kind: Literal["expectation_match"]
    step_id: ContentId
    label: LocaleText
    check_id: ContentId
    fetch_id: ContentId
    field: FieldId
    expectation_id: ContentId
    quantifier: Literal["all", "any"]


class ReportConfigurationMissingStep(StrictModel):
    kind: Literal["report_configuration_missing"]
    step_id: ContentId
    label: LocaleText
    check_id: ContentId
    expectation_id: ContentId


class RecordAgeStep(StrictModel):
    kind: Literal["record_age"]
    step_id: ContentId
    check_id: ContentId
    label: LocaleText
    fetch_id: ContentId
    max_age_seconds: int = Field(gt=0)


type PlaybookStep = Annotated[
    FetchStep
    | CompareCountStep
    | FieldPresentStep
    | ExpectationMatchStep
    | ReportConfigurationMissingStep
    | RecordAgeStep,
    Field(discriminator="kind"),
]


class PlaybookDefinition(StrictModel):
    schema_version: Literal["1"] = "1"
    playbook_id: ContentId
    topic_id: ContentId
    title: LocaleText
    internal_context: str
    steps: list[PlaybookStep] = Field(max_length=10)


class PlaybookRun(StrictModel):
    fetches: list[FetchResult]
    checks: list[CheckResult]
    items: list[EvidenceItem]


class EvidencePack(StrictModel):
    schema_version: Literal["1"] = "1"
    question_id: UUID
    environment_id: ContentId
    topic_id: TopicId
    policy_hash: PolicyHash
    content_sha: GitSHA40
    fetches: list[FetchResult]
    checks: list[CheckResult]
    items: list[EvidenceItem]
    sha256: SHA256


class ValidationContext(StrictModel):
    topic_pack: TopicPromptPack
    templates: tuple[FindingTemplate, ...]
    policy_hash: PolicyHash
    content_sha: GitSHA40
    language: Literal["en", "es"]
    expected_checks: tuple[CheckResult, ...]


class JudgmentRequest(StrictModel):
    question_id: UUID
    topic_id: TopicId
    model: ModelCapability
    effort: Effort | None = None
    language: Literal["en", "es"]
    standing_rules: str
    topic_pack: TopicPromptPack
    evidence: EvidencePack
    question: str
    max_output_tokens: int = Field(gt=0)
    guardrail: GuardrailPin
    finding_templates: tuple[FindingTemplate, ...] = ()
    reservation_id: UUID | None = None
    reserved_tokens: int = Field(default=0, ge=0)


class RawJudgment(StrictModel):
    text: str
    stop_reason: str
    guardrail_intervened: bool
    usage: TokenUsage | None = None
    provider_request_id: str


class Skip(StrictModel):
    kind: Literal["skip"] = "skip"
    result: JudgmentResult
    left_out: LeftOut | None = None


class Ready(StrictModel):
    kind: Literal["ready"] = "ready"
    request: JudgmentRequest


type JudgmentPreparation = Annotated[Skip | Ready, Field(discriminator="kind")]


class FollowupRecord(StrictModel):
    schema_version: Literal["1"] = "1"
    followup_id: UUID
    owner_key: SHA256
    environment_id: ContentId
    revision: Literal[1] = 1
    plan: QuestionPlan
    answered_topic_ids: list[TopicId]
    leftout_topic_ids: list[TopicId]
    leftout_stages: list[LeftOut]
    parent_id: UUID | None = None
    created_at: UTCDateTime
    expires_at: UTCDateTime


class Lease(StrictModel):
    lease_id: UUID
    question_id: UUID
    owner_key: SHA256
    environment_id: ContentId
    holder_id: UUID
    fence: int = Field(ge=1)
    expires_at: UTCDateTime
    last_renewed_at: UTCDateTime


class Reservation(StrictModel):
    reservation_id: UUID
    operation_id: UUID
    question_id: UUID
    topic_id: TopicId
    owner_key: SHA256
    environment_id: ContentId
    lease_id: UUID
    holder_id: UUID
    fence: int = Field(ge=1)
    reserved_tokens: int = Field(ge=0)
    charged_tokens: int | None = None
    state: Literal["reserved", "started", "settled", "released", "unknown_charged"]
    created_at: UTCDateTime
    started_at: UTCDateTime | None = None
    hard_deadline_at: UTCDateTime
    recover_after: UTCDateTime
    daily_token_day_epoch: int = Field(ge=0, default=0)
    version: int = Field(ge=1)


class AdmissionGrant(StrictModel):
    holder_id: UUID
    slot_ids: tuple[str, ...]
    expires_at: UTCDateTime
    fence: int = Field(ge=1)


class ReadOperationGrant(StrictModel):
    """Fenced cross-replica permit for one physical indexer read operation."""

    question_id: UUID
    environment_id: ContentId
    operation_id: UUID
    call: Literal["mapping", "validate", "pit", "search", "probe"]
    holder_id: UUID
    service_slot_id: StageSlotId
    site_slot_id: StageSlotId
    fence: int = Field(ge=1)
    acquired_at: UTCDateTime
    lease_expires_at: UTCDateTime
    hard_deadline_at: UTCDateTime
    recover_after: UTCDateTime

    @model_validator(mode="after")
    def bounded_lifetime(self) -> ReadOperationGrant:
        if not self.acquired_at < self.lease_expires_at <= self.hard_deadline_at:
            raise ValueError("read lease must end by its hard deadline")
        if self.hard_deadline_at != self.acquired_at + timedelta(seconds=10):
            raise ValueError("read hard deadline must be ten seconds")
        if self.recover_after != self.hard_deadline_at + timedelta(seconds=35):
            raise ValueError("read recovery must include the 35 second orphan grace")
        return self


class ModelCountGrant(StrictModel):
    """Fenced permit for one physical Count or Converse transport call."""

    question_id: UUID
    environment_id: ContentId
    operation_id: UUID
    call: Literal["count", "converse"]
    holder_id: UUID
    service_slot_id: StageSlotId
    site_slot_id: StageSlotId
    fence: int = Field(ge=1)
    acquired_at: UTCDateTime
    lease_expires_at: UTCDateTime
    hard_deadline_at: UTCDateTime
    recover_after: UTCDateTime

    @model_validator(mode="after")
    def bounded_lifetime(self) -> ModelCountGrant:
        maximum = 5 if self.call == "count" else 30
        if not self.acquired_at < self.lease_expires_at <= self.hard_deadline_at:
            raise ValueError("model/count lease must end by its hard deadline")
        if self.hard_deadline_at != self.acquired_at + timedelta(seconds=maximum):
            raise ValueError("model/count hard deadline does not match the operation timeout")
        if self.recover_after != self.hard_deadline_at + timedelta(seconds=35):
            raise ValueError("model/count recovery must include the 35 second orphan grace")
        return self


class EmbeddingGrant(StrictModel):
    """Question-scoped fenced permit for a single physical embedding call."""

    question_id: UUID
    environment_id: ContentId
    operation_id: UUID
    call: Literal["embedding"] = "embedding"
    holder_id: UUID
    fence: int = Field(ge=1)
    acquired_at: UTCDateTime
    lease_expires_at: UTCDateTime
    hard_deadline_at: UTCDateTime
    recover_after: UTCDateTime

    @model_validator(mode="after")
    def bounded_lifetime(self) -> EmbeddingGrant:
        if not self.acquired_at < self.lease_expires_at <= self.hard_deadline_at:
            raise ValueError("embedding lease must end by its hard deadline")
        if self.hard_deadline_at != self.acquired_at + timedelta(seconds=10):
            raise ValueError("embedding hard deadline must be ten seconds")
        if self.recover_after != self.hard_deadline_at + timedelta(seconds=35):
            raise ValueError("embedding recovery must include the 35 second orphan grace")
        return self


class StageCapacityRejection(StrictModel):
    """Immediate typed rejection of a physical-stage permit request."""

    question_id: UUID
    operation_id: UUID
    call: Literal["mapping", "validate", "pit", "search", "probe", "count", "converse", "embedding"]
    code: Literal[ErrorCode.CAPACITY_LIMIT] = ErrorCode.CAPACITY_LIMIT
    outcome: Literal["capacity"] = "capacity"


class RecoveryPage(StrictModel):
    after: str | None
    examined: int = Field(ge=0)
    terminalized: int = Field(ge=0)
    errors: list[ErrorCode]


class CompletionCommand(StrictModel):
    question_id: UUID
    owner_key: SHA256
    environment_id: ContentId
    answer_status: AnswerStatus
    followup: FollowupRecord | None
    idempotency: IdempotencyRecord | None
    audit_ack: AuditAck
    metadata_sha256: SHA256


class CompletionReceipt(StrictModel):
    completion_id: UUID
    question_id: UUID
    committed_at: UTCDateTime
    followup_id: UUID | None
    followup_revision: int | None
    answer_metadata_sha256: SHA256


class QuestionRecord(StrictModel):
    question_id: UUID
    owner_key: SHA256
    environment_id: ContentId
    lease_id: UUID
    holder_id: UUID
    fence: int = Field(ge=1)
    request_hash: SHA256
    state: Literal["active", "completed", "cancelled", "abandoned"]
    completion_id: UUID | None = None
    answer_status: AnswerStatus | None = None
    created_at: UTCDateTime
    expires_at: UTCDateTime


class QuestionBudget(StrictModel):
    question_id: UUID
    token_limit: int = Field(ge=0)
    reserved_tokens: int = Field(ge=0)
    charged_tokens: int = Field(ge=0)
    remaining_tokens: int = Field(ge=0)
    version: int = Field(ge=1)
    overflow_tokens: int = Field(ge=0)
    state: Literal["open", "closed"]
    owner_key: SHA256
    environment_id: ContentId
    created_at: UTCDateTime
    expires_at: UTCDateTime | None = None


class IdempotencyRecord(StrictModel):
    owner_key: SHA256
    environment_id: ContentId
    key: UUID
    request_hash: SHA256
    question_id: UUID
    status: Literal["active", "completed", "abandoned"]
    completion_id: UUID | None = None
    expires_at: UTCDateTime


class RecoveryTicket(StrictModel):
    bucket: int = Field(ge=0, lt=128)
    due_at: UTCDateTime
    question_id: UUID
    reservation_id: UUID
    version: int = Field(ge=1)


class OperationRecord(StrictModel):
    operation_id: UUID
    kind: str
    input_hash: SHA256
    terminal_result_hash: SHA256 | None = None
    state: Literal["started", "completed", "failed"]
    expires_at: UTCDateTime


class CancellationToken(Protocol):
    """Small protocol-like contract; implementations must be explicit dependencies."""

    def is_cancelled(self) -> bool: ...

    def raise_if_cancelled(self) -> None: ...

    async def wait(self) -> None: ...


class CallKind(StrEnum):
    identity = "identity"
    kms = "kms"
    mapping = "mapping"
    validate = "validate"
    pit = "pit"
    search = "search"
    probe = "probe"
    COUNT = "count"
    converse = "converse"
    embedding = "embedding"
    state = "state"
    feedback = "feedback"
    audit = "audit"


class AcceptanceId(StrEnum):
    G001 = "G001"
    G002 = "G002"
    G003 = "G003"
    G004 = "G004"
    G005 = "G005"
    G006 = "G006"
    G007 = "G007"
    G008 = "G008"
    G009 = "G009"
    G010 = "G010"
    G011 = "G011"
    G012 = "G012"
    G013 = "G013"
    G014 = "G014"
    G015 = "G015"
    G016 = "G016"
    G017 = "G017"
    G018 = "G018"
    G019 = "G019"
    G020 = "G020"
    G021 = "G021"
    G022 = "G022"
    G023 = "G023"
    G024 = "G024"
    G025 = "G025"
    G026 = "G026"
    G027 = "G027"
    G028 = "G028"
    G029 = "G029"
    G030 = "G030"
    G031 = "G031"
    G032 = "G032"
    G033 = "G033"
    G034 = "G034"
    G035 = "G035"
    G036 = "G036"
    G037 = "G037"
    G038 = "G038"
    G039 = "G039"
    G040 = "G040"
    G041 = "G041"
    G042 = "G042"
    G043 = "G043"
    G044 = "G044"
    G045 = "G045"
    G046 = "G046"
    G047 = "G047"
    G048 = "G048"
    G049 = "G049"
    G050 = "G050"
    G051 = "G051"
    G052 = "G052"
    G053 = "G053"
    G054 = "G054"
    G055 = "G055"
    G056 = "G056"
    G057 = "G057"
    G058 = "G058"
    G059 = "G059"
    G060 = "G060"
    G061 = "G061"
    GP1 = "GP1"
    GP2 = "GP2"
    GP3 = "GP3"
    GP4 = "GP4"
    GUI = "GUI"
    GMCP = "GMCP"
    GN01 = "GN01"
    GN02 = "GN02"
    GN03 = "GN03"
    GN04 = "GN04"


class TaskId(StrEnum):
    B1_T01 = "B1-T01"
    B1_T02 = "B1-T02"
    B1_T03 = "B1-T03"
    B1_T04 = "B1-T04"
    B1_T05 = "B1-T05"
    B2_T01 = "B2-T01"
    B2_T02 = "B2-T02"
    B2_T03 = "B2-T03"
    B2_T04 = "B2-T04"
    B2_T05 = "B2-T05"
    B3_T01 = "B3-T01"
    B3_T02 = "B3-T02"
    B3_T03 = "B3-T03"
    B3_T04 = "B3-T04"
    B3_T05 = "B3-T05"
    B4_T01 = "B4-T01"
    B4_T02 = "B4-T02"
    B4_T03 = "B4-T03"
    B4_T04 = "B4-T04"
    B4_T05 = "B4-T05"
    B5_T01 = "B5-T01"
    B5_T02 = "B5-T02"
    B5_T03 = "B5-T03"
    B5_T04 = "B5-T04"
    B5_T05 = "B5-T05"
    B6_T01 = "B6-T01"
    B6_T02 = "B6-T02"
    B6_T03 = "B6-T03"
    B6_T04 = "B6-T04"
    B6_T05 = "B6-T05"
    B6_T06 = "B6-T06"


class GoldenOperation(StrEnum):
    parser_external_calls = "parser_external_calls"
    identity = "identity"
    kms = "kms"
    mapping = "mapping"
    validate = "validate"
    pit = "pit"
    search = "search"
    probe = "probe"
    COUNT = "count"
    converse = "converse"
    embedding = "embedding"
    state = "state"
    feedback = "feedback"
    audit = "audit"


class CallLedger(Protocol):
    def claim(self, kind: CallKind) -> None: ...


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    question_id: UUID
    operation: Literal["ask", "page", "feedback", "semantic"]
    owner_key: SHA256
    environment_id: ContentId
    deadline_at: UTCDateTime
    cancel: CancellationToken
    calls: CallLedger
    admission: AdmissionGrant
    trace_context: TraceContext


@dataclass(frozen=True, slots=True)
class FeedbackControlContext:
    deadline_monotonic: float
    monotonic: Callable[[], float]
    cancel: CancellationToken
    calls: CallLedger


class FeedbackMetadata(StrictModel):
    schema_version: Literal["1"] = "1"
    feedback_id: UUID
    status: Literal["pending", "queued"]
    created_at: UTCDateTime
    ttl_epoch: int = Field(ge=0, strict=True)


class StageOutcome(StrEnum):
    ok = "ok"
    skipped = "skipped"
    denied = "denied"
    unavailable = "unavailable"
    failed = "failed"
    cancelled = "cancelled"
    deadline = "deadline"
    capacity = "capacity"


class StageName(StrEnum):
    auth = "auth"
    plan = "plan"
    content = "content"
    broker = "broker"
    fetch = "fetch"
    checks = "checks"
    count_stage = "count"
    reserve = "reserve"
    converse = "converse"
    validate = "validate"
    render = "render"
    feedback = "feedback"
    audit = "audit"


class TraceContext(StrictModel):
    trace_id: TraceId
    span_id: SpanId
    trace_flags: int = Field(ge=0, le=255)

    @field_validator("trace_id")
    @classmethod
    def reject_zero_trace_id(cls, value: str) -> str:
        if value == "0" * 32:
            raise ValueError("trace ID cannot be all zeroes")
        return value

    @field_validator("span_id")
    @classmethod
    def reject_zero_span_id(cls, value: str) -> str:
        if value == "0" * 16:
            raise ValueError("span ID cannot be all zeroes")
        return value


class StageAttributes(StrictModel):
    outcome: StageOutcome | None = None
    latency_ms: int | None = Field(default=None, ge=0)
    error_code: ErrorCode | None = None
    visibility: Visibility | None = None
    fetch_state: FetchState | None = None


class StageSpan(Protocol):
    def set_outcome(self, outcome: StageOutcome) -> None: ...

    def record_latency(self, milliseconds: int) -> None: ...

    def record_attributes(self, attributes: StageAttributes) -> None: ...


class AuditAck(StrictModel):
    event_id: UUID
    delivery_id: str
    accepted_at: UTCDateTime


class AuditStageOutcome(StrictModel):
    stage: StageName
    outcome: StageOutcome
    latency_ms: int = Field(ge=0)


class AuditRemovedFinding(StrictModel):
    topic_id: TopicId
    finding_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    reason: RemovedReason
    candidate_sha256: SHA256


class AuditFetchRecord(StrictModel):
    scope_hash: SHA256
    window: ResolvedWindow
    template_id: TemplateId
    query_sha256: SHA256
    result_classification: FetchState
    count: Count | None = None
    count_exact: bool | None = None
    evidence_checks: list[EvidenceCheck] = Field(default_factory=lambda: list[EvidenceCheck]())

    @model_validator(mode="after")
    def validate_count_exactness(self) -> AuditFetchRecord:
        if self.count is None:
            if self.count_exact is not None:
                raise ValueError("count exactness requires an available count")
            return self
        can_be_exact = self.count.relation == "eq" and not self.count.approximate
        if self.count_exact is not can_be_exact:
            raise ValueError("count exactness must agree with count relation and approximation")
        return self


class AuditContextUse(StrictModel):
    topic_id: TopicId
    fetch_id: ContentId
    source_snapshot_key: SHA256
    kev_use: KevUseRef
    activation_at: UTCDateTime | None
    availability_proof: Literal["boot", "cursor"]
    rows_returned: int = Field(ge=0)
    subjects_total: int = Field(ge=0)
    annotated_subjects: int = Field(ge=0)
    omitted_subjects: int = Field(ge=0)
    lookup_counts: dict[Literal["hit", "not_listed", "invalid_cve", "unavailable"], int]
    freshness_counts: dict[Literal["fresh", "stale", "not_yet_valid", "unknown"], int]
    coverage: Literal["complete", "incomplete", "unavailable"]
    reason: Literal["not_configured", "limit", "lookup_error", "not_yet_available"] | None
    annotation_sha256: SHA256

    @model_validator(mode="after")
    def validate_counts(self) -> AuditContextUse:
        if self.topic_id != "vuln_review" or self.fetch_id != "vuln_rows":
            raise ValueError("audit KEV use is bound to vuln_review/vuln_rows")
        if self.annotated_subjects + self.omitted_subjects != self.subjects_total:
            raise ValueError("annotated and omitted subjects must partition the total")
        if sum(self.lookup_counts.values()) != self.annotated_subjects:
            raise ValueError("lookup counts must equal annotated subjects")
        if sum(self.freshness_counts.values()) != self.annotated_subjects:
            raise ValueError("freshness counts must equal annotated subjects")
        if any(
            value < 0 for value in (*self.lookup_counts.values(), *self.freshness_counts.values())
        ):
            raise ValueError("audit context counts must be nonnegative")
        if (self.availability_proof == "boot") != (self.activation_at is not None):
            raise ValueError("boot proof requires activation time and cursor proof forbids it")
        if self.activation_at is not None and self.activation_at > self.kev_use.evaluation_at:
            raise ValueError("boot activation cannot follow KEV evaluation time")
        if self.coverage == "complete" and (self.reason is not None or self.omitted_subjects != 0):
            raise ValueError("complete context coverage cannot have omissions or a reason")
        if self.coverage == "incomplete" and (self.reason is None or self.omitted_subjects == 0):
            raise ValueError("incomplete context coverage requires omissions and a reason")
        if self.coverage == "unavailable" and (
            self.reason is None or self.omitted_subjects != self.subjects_total
        ):
            raise ValueError("unavailable context must omit every subject")
        return self


class AuditPageReturn(StrictModel):
    input_cursor_sha256: SHA256
    next_cursor_sha256: SHA256 | None
    response_sha256: SHA256


class AuditEvent(StrictModel):
    schema_version: Literal["1"] = "1"
    event_id: UUID
    question_id: UUID
    trace_id: TraceId
    owner_key: SHA256
    environment_id: ContentId
    authenticated_issuer: HTTPSUrl
    auth_edge: Literal["browser", "mcp", "fixture"]
    service_sha: GitSHA40
    image_digest: Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
    content_sha: GitSHA40
    pack_sha256: SHA256
    policy_hash: PolicyHash
    cue_ids: list[ContentId]
    topic_ids: list[TopicId]
    model_id: Annotated[str, StringConstraints(min_length=1, max_length=128)] | None = None
    effort: Effort | None = None
    guardrail_id: ContentId | None = None
    guardrail_version: Annotated[str, StringConstraints(min_length=1, max_length=64)] | None = None
    stage_outcomes: list[AuditStageOutcome] = Field(
        default_factory=lambda: list[AuditStageOutcome]()
    )
    removed_findings: list[AuditRemovedFinding] = Field(
        default_factory=lambda: list[AuditRemovedFinding]()
    )
    usage_by_topic: list[TokenUsage] = Field(default_factory=lambda: list[TokenUsage]())
    answer_status: AnswerStatus | None = None
    outcome: Literal["attempted", "completed", "cancelled"]
    completion_id: UUID | None = None
    fetches: list[AuditFetchRecord] = Field(default_factory=lambda: list[AuditFetchRecord]())
    context_uses: list[AuditContextUse] = Field(default_factory=lambda: list[AuditContextUse]())
    page_return: AuditPageReturn | None = None
    created_at: UTCDateTime

    @field_validator("trace_id")
    @classmethod
    def reject_zero_audit_trace_id(cls, value: str) -> str:
        if value == "0" * 32:
            raise ValueError("trace ID cannot be all zeroes")
        return value

    @model_validator(mode="after")
    def validate_terminal_fields(self) -> AuditEvent:
        if self.outcome == "completed" and (
            self.completion_id is None or self.answer_status is None
        ):
            raise ValueError("completed audit events require completion and answer status")
        if self.outcome != "completed" and self.completion_id is not None:
            raise ValueError("only completed audit events may carry a completion ID")
        if self.outcome != "completed" and self.answer_status is not None:
            raise ValueError("only completed audit events may carry answer status")
        if self.page_return is not None and (
            self.outcome != "attempted"
            or self.completion_id is not None
            or self.answer_status is not None
        ):
            raise ValueError("page-return metadata is valid only on an attempted event")
        return self


class FeedbackEvent(StrictModel):
    schema_version: Literal["1"] = "1"
    feedback_id: UUID
    receipt_id: UUID
    question_id: UUID
    owner_key: SHA256
    environment_id: ContentId
    content_sha: GitSHA40
    kind: Literal["wrong"]
    note_redacted: str | None
    created_at: UTCDateTime


class FeedbackReceiptPayload(StrictModel):
    schema_version: Literal["1"] = "1"
    receipt_id: UUID
    question_id: UUID
    owner_key: SHA256
    environment_id: ContentId
    content_sha: GitSHA40
    cue_ids: list[ContentId]
    topic_ids: list[TopicId]
    outcome_code: AnswerStatus
    issued_at: UTCDateTime
    expires_at: UTCDateTime
    key_id: str


class FeedbackReceipt(StrictModel):
    token: Annotated[str, StringConstraints(min_length=1, max_length=8192)]
    status: Literal["issued", "queued"]
    feedback_id: UUID | None = None


class SourceManifest(StrictModel):
    schema_version: Literal["1"] = "1"
    repository: HTTPSUrl
    license: str
    default_language: Literal["en", "es"]
    topics: list[ContentId]
    cue_files: dict[Literal["en", "es"], str]
    docs_origin: HTTPSOrigin
    embedding: EmbeddingManifest | None = None


class SolvedCase(StrictModel):
    schema_version: Literal["1"] = "1"
    case_id: ContentId
    topic_id: ContentId
    synthetic: Literal[True] = True
    description: str
    public_reference: HTTPSUrl | None = None
    promotion_status: Literal["candidate", "approved"]
    review_record: HTTPSUrl | None = None
    anonymization_attestation: AnonymizationAttestation


class AnonymizationAttestation(StrictModel):
    reviewer_id: str
    date: str


class EmbeddingManifest(StrictModel):
    model_id: str
    region: str
    dimensions: int = Field(gt=0)
    purpose: Literal["topic_cards"]
    normalization: Literal["l2"]
    corpus_sha256: SHA256
    vector_sha256: SHA256
    golden_sha256: SHA256
    threshold: float
    minimum_margin: float
    selection_report_path: str


class ManifestFile(StrictModel):
    path: str
    sha256: SHA256
    bytes: int = Field(ge=0)


class PackManifest(StrictModel):
    schema_version: Literal["1"] = "1"
    service_contract_version: Literal["1"] = "1"
    source_repository: HTTPSUrl
    content_sha: GitSHA40
    source_tree_sha256: SHA256
    pack_sha256: SHA256
    docs_manifest_sha256: SHA256
    cue_pack_sha: SHA256
    review_attestation: HTTPSUrl
    files: list[ManifestFile]
    embedding: EmbeddingManifest | None = None


class DetachedApproval(StrictModel):
    schema_version: Literal["1"] = "1"
    repository: HTTPSUrl
    commit: GitSHA40
    tree_sha: str
    reviewer_ids: list[str]
    review_record: HTTPSUrl
    policy_id: str
    approved_at: UTCDateTime
    signature: str
    key_id: str
    mode: Literal["fixture", "live"] = "live"


class PublicModelMetadata(StrictModel):
    id: str
    label: str
    efforts: tuple[Effort, ...]
    context_tokens: int = Field(gt=0)
    max_output_tokens: int = Field(gt=0)


class CursorPayload(StrictModel):
    schema_version: Literal["1"] = "1"
    key_id: str
    owner_key: SHA256
    environment_id: ContentId
    policy_hash: PolicyHash
    content_sha: GitSHA40
    question_id: UUID
    topic_id: TopicId
    fetch_id: ContentId
    template_id: TemplateId
    filters: list[Filter]
    window: ResolvedWindow
    projection_hash: SHA256
    sort_values: list[str | int]
    pit_id: str
    snapshot: SnapshotRef
    page_size: int = Field(ge=1, le=50)
    remaining_top_n: int | None = Field(default=None, ge=0)
    order: Literal["latest", "earliest"] = "latest"
    expires_at: UTCDateTime


class ExpectedCall(StrictModel):
    operation: GoldenOperation
    principal: str
    site: ContentId
    count: int = Field(ge=0)
    request_sha256: SHA256 | None = None


class GoldenExpected(StrictModel):
    kind: Literal["domain_exact", "invariants", "artifact_hashes", "policy"]
    payload: dict[str, JSONValue]


class GoldenInput(StrictModel):
    kind: Literal["request", "plan", "evidence", "content", "state", "infra", "browser"]
    payload: dict[str, JSONValue]


class GoldenCase(StrictModel):
    schema_version: Literal["1"] = "1"
    case_id: str
    requirements: list[AcceptanceId]
    tasks: list[TaskId]
    layer: Literal[
        "contract",
        "unit",
        "security",
        "golden",
        "integration",
        "e2e",
        "infra",
        "reproducibility",
        "live",
    ]
    variant: Literal["positive", "negative", "boundary", "failure"]
    evidence_class: Literal["offline", "local_protocol", "live"]
    fixture_sha256: SHA256
    content_sha: GitSHA40
    input: GoldenInput
    expected: GoldenExpected
    calls: list[ExpectedCall]
    timeout_seconds: int = Field(gt=0)


class ConfigBounds(StrictModel):
    request_bytes: int = 65536
    header_bytes: int = 32768
    auth_token_bytes: int = 16384
    json_depth: int = 16
    json_members: int = 4096
    json_array_items: int = 1024
    question_bytes: int = 16384
    filter_count: int = 10
    filter_string_bytes: int = 128
    filter_in_items: int = 16
    plan_bytes: int = 131072
    cursor_plain_bytes: int = 5500
    cursor_wire_bytes: int = 8192
    backend_wire_bytes: int = 2097152
    backend_decoded_bytes: int = 2097152
    field_bytes: int = 4096
    field_list_items: int = 32
    row_bytes: int = 16384
    fetch_bytes: int = 262144
    pack_bytes: int = 524288
    answer_bytes: int = 1048576
    finding_output_bytes: int = 65536
    finding_count: int = 20
    finding_text_bytes: int = 8192
    content_file_bytes: int = 1048576
    content_total_bytes: int = 33554432
    content_files: int = 1024
    page_size: int = 20
    page_size_max: int = 50
    bucket_count: int = 20
    window_days: int = 90
    owner_daily_token_limit: int = 200_000
    service_daily_token_limit: int = 1_000_000

    @model_validator(mode="after")
    def require_positive_bounds(self) -> ConfigBounds:
        values = cast(dict[str, int], self.__dict__)
        if any(value <= 0 for value in values.values()):
            raise ValueError("resource bounds must be positive")
        return self


class RunnerManifest(StrictModel):
    schema_version: Literal["1"] = "1"
    python: str
    uv: str
    node: str
    npm: str
    typescript: str
    pyright: str
    ruff: str
    pytest: str
    mcp_sdk: str
    tzdata: str
    playwright: str
    browser: str
    terraform: str
    tflint: str
    provider_lock: str
    buildkit: str
    docker_compose: str
    base_image: str
    scan_tool: str
    scan_database: str
    source_registry: str
    prepared_at: UTCDateTime
    python_implementation: str
    cache_identity: str
    lock_sha256: SHA256
    offline_prepare_passed: bool
    missing_preparations: tuple[str, ...]


class ErrorResponse(StrictModel):
    error: DomainError


class AuthClaims(StrictModel):
    issuer: HTTPSUrl
    sub: str
    groups: tuple[str, ...]
    expires_at: UTCDateTime
    assertion_hash: SHA256


class ConfigProfile(StrEnum):
    fixture = "fixture"
    live = "live"


class StageContext(Protocol):
    def __enter__(self) -> StageSpan: ...

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool: ...


class ModelSelection(StrictModel):
    model_id: str | None = None
    effort: Effort | None = None


class IdempotencyReference(StrictModel):
    owner_key: SHA256
    environment_id: ContentId
    key: UUID
    request_hash: SHA256


class CompletionOutcome(StrEnum):
    committed = "committed"
    abandoned = "abandoned"
    cancelled = "cancelled"


class AdmissionOperation(StrEnum):
    ask = "ask"
    page = "page"
    feedback = "feedback"
    semantic = "semantic"


class AskEnvelope(StrictModel):
    request: AskRequest
    idempotency_key: UUID | None = None


class ResponseMode(StrEnum):
    fixture = "fixture"
    live = "live"


class SourceRange(StrictModel):
    source: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)


class ErrorDetailKey(StrEnum):
    retry_after_seconds = "retry_after_seconds"
    question_id = "question_id"
    stage = "stage"
    limit = "limit"
    allowed = "allowed"
    missing_slots = "missing_slots"
