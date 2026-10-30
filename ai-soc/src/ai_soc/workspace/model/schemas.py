"""Strict frozen types for incident narrative packs and controlled output."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Annotated, Literal, cast
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    TypeAdapter,
    field_validator,
    model_validator,
)

type Identifier = Annotated[
    str,
    StringConstraints(
        strict=True, min_length=1, max_length=512, pattern=r"^[^\x00-\x1f\x7f-\x9f]+$"
    ),
]
type BoundedLabel = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=256)]
type FactId = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$")]
type Digest = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$")]


class FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class IncidentReference(FrozenModel):
    site_id: Identifier
    incident_id: UUID
    incident_revision_id: UUID
    reference_id: FactId


class Coverage(FrozenModel):
    membership_count: Annotated[int, Field(strict=True, ge=1, le=100)]
    alert_count: Annotated[int, Field(strict=True, ge=1)]
    score_unknown_count: Annotated[int, Field(strict=True, ge=0, le=100)]
    included_group_facts: Annotated[int, Field(strict=True, ge=0, le=32)]
    omitted_group_facts: Annotated[int, Field(strict=True, ge=0, le=100)]
    included_alert_facts: Annotated[int, Field(strict=True, ge=0, le=32)]
    omitted_alert_facts: Annotated[int, Field(strict=True, ge=0)]

    @model_validator(mode="after")
    def counts_match(self) -> Coverage:
        if self.included_group_facts + self.omitted_group_facts != self.membership_count:
            raise ValueError("group fact coverage does not match membership count")
        if self.included_alert_facts + self.omitted_alert_facts != self.alert_count:
            raise ValueError("alert fact coverage does not match alert count")
        return self


class GroupFact(FrozenModel):
    fact_id: FactId
    membership_id: UUID
    group_id: Identifier
    group_revision: Digest
    alert_count: Annotated[int, Field(strict=True, ge=1)]
    first_event_at: datetime
    last_event_at: datetime
    rule_id: BoundedLabel | None
    agent_id: BoundedLabel | None
    score_version: Identifier | None
    score_digest: Digest | None
    score: Annotated[float, Field(strict=True, ge=0, le=100, allow_inf_nan=False)] | None

    @field_validator("first_event_at", "last_event_at")
    @classmethod
    def aware_event_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("event time must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def reference_is_complete(self) -> GroupFact:
        if (self.score_version is None) != (self.score_digest is None):
            raise ValueError("score version and digest must both be present or absent")
        if (self.score is None) != (self.score_version is None):
            raise ValueError("a score is available exactly when its immutable reference is present")
        if self.first_event_at > self.last_event_at:
            raise ValueError("group event interval is inverted")
        return self


class AlertFact(FrozenModel):
    fact_id: FactId
    group_fact_id: FactId
    group_id: Identifier
    group_revision: Digest
    alert_key: Digest
    source_hash: Digest
    event_at: datetime
    rule_id: BoundedLabel | None
    agent_id: BoundedLabel | None

    @field_validator("event_at")
    @classmethod
    def aware_event_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("event time must be timezone-aware")
        return value.astimezone(UTC)


class FrozenIncidentPack(FrozenModel):
    site_id: Identifier
    incident_id: UUID
    incident_revision_id: UUID
    revision_seq: Annotated[int, Field(strict=True, ge=1)]
    as_of: datetime
    builder_version: Literal["workspace.incident-narrative-pack.v1"]
    incident_reference: IncidentReference
    coverage: Coverage
    group_facts: Annotated[tuple[GroupFact, ...], Field(max_length=32)]
    alert_facts: Annotated[tuple[AlertFact, ...], Field(max_length=32)]
    content_digest: Digest

    @field_validator("as_of")
    @classmethod
    def aware_as_of(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("pack cutoff must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def associations_and_digest_match(self) -> FrozenIncidentPack:
        reference = self.incident_reference
        if (
            reference.site_id != self.site_id
            or reference.incident_id != self.incident_id
            or reference.incident_revision_id != self.incident_revision_id
            or reference.reference_id
            != incident_reference_id(self.site_id, self.incident_id, self.incident_revision_id)
        ):
            raise ValueError("incident reference is outside this pack")
        if len(self.group_facts) != self.coverage.included_group_facts:
            raise ValueError("included group fact count differs from coverage")
        if len(self.alert_facts) != self.coverage.included_alert_facts:
            raise ValueError("included alert fact count differs from coverage")
        group_ids = {fact.fact_id for fact in self.group_facts}
        groups = {(fact.group_id, fact.group_revision) for fact in self.group_facts}
        if len(group_ids) != len(self.group_facts) or len(groups) != len(self.group_facts):
            raise ValueError("group facts must have unique identities")
        for group in self.group_facts:
            expected_group_id = fact_id(
                "group",
                self.site_id,
                self.incident_id,
                self.incident_revision_id,
                group.membership_id,
                group.group_id,
                group.group_revision,
            )
            if group.fact_id != expected_group_id:
                raise ValueError("group fact id does not bind its typed scope")
        alert_ids = {fact.fact_id for fact in self.alert_facts}
        if len(alert_ids) != len(self.alert_facts):
            raise ValueError("alert facts must have unique identities")
        for alert in self.alert_facts:
            expected_alert_id = fact_id(
                "alert",
                self.site_id,
                self.incident_id,
                self.incident_revision_id,
                alert.group_id,
                alert.group_revision,
                alert.alert_key,
            )
            if alert.fact_id != expected_alert_id:
                raise ValueError("alert fact id does not bind its typed scope")
        alerts_per_group: dict[str, set[str]] = {}
        for alert in self.alert_facts:
            group = next(
                (item for item in self.group_facts if item.fact_id == alert.group_fact_id), None
            )
            if (
                alert.group_fact_id not in group_ids
                or group is None
                or (alert.group_id, alert.group_revision) != (group.group_id, group.group_revision)
            ):
                raise ValueError("alert fact references a group outside the pack")
            if not group.first_event_at <= alert.event_at <= group.last_event_at:
                raise ValueError("alert event time is outside its exact group interval")
            keys = alerts_per_group.setdefault(group.fact_id, set())
            if alert.alert_key in keys or len(keys) >= group.alert_count:
                raise ValueError("alert facts exceed unique exact group membership")
            keys.add(alert.alert_key)
        expected = frozen_pack_digest(self)
        if self.content_digest != expected:
            raise ValueError("pack digest does not match its canonical content")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_pack_bytes(self)


def incident_reference_id(site_id: str, incident_id: UUID, revision_id: UUID) -> str:
    import json
    from hashlib import sha256

    payload = ["incident-reference-v1", site_id, str(incident_id), str(revision_id)]
    return sha256(
        json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode()
    ).hexdigest()


def fact_id(kind: str, *parts: object) -> str:
    import json
    from hashlib import sha256

    payload = ["incident-fact-v1", kind, *[str(part) for part in parts]]
    return sha256(
        json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode()
    ).hexdigest()


def _canonical_json_value(value: object) -> object:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("canonical pack timestamps must be timezone-aware")
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Mapping):
        mapping = cast(Mapping[object, object], value)
        return {str(key): _canonical_json_value(item) for key, item in mapping.items()}
    if isinstance(value, (tuple, list)):
        sequence = cast(Sequence[object], value)
        return [_canonical_json_value(item) for item in sequence]
    return value


def canonical_pack_bytes(pack: FrozenIncidentPack) -> bytes:
    import json

    data = _canonical_json_value(pack.model_dump(mode="python", exclude={"content_digest"}))
    return json.dumps(
        data, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def frozen_pack_digest(pack: FrozenIncidentPack) -> str:
    from hashlib import sha256

    return sha256(canonical_pack_bytes(pack)).hexdigest()


class MemberCountSelection(FrozenModel):
    template: Literal["member_count"]
    incident_reference_id: FactId
    count: Annotated[int, Field(strict=True, ge=1, le=100)]


class MemberScoreSelection(FrozenModel):
    template: Literal["member_score"]
    group_fact_id: FactId
    group_id: Identifier
    score: Annotated[float, Field(strict=True, ge=0, le=100, allow_inf_nan=False)]


class RuleObservedSelection(FrozenModel):
    template: Literal["rule_observed"]
    alert_fact_id: FactId
    group_id: Identifier
    rule_id: BoundedLabel
    agent_id: BoundedLabel | None
    event_at: datetime

    @field_validator("event_at")
    @classmethod
    def aware_event_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("event time must be timezone-aware")
        return value.astimezone(UTC)


class MissingScoresSelection(FrozenModel):
    template: Literal["missing_scores"]
    incident_reference_id: FactId
    count: Annotated[int, Field(strict=True, ge=1, le=100)]


class OmittedAlertsSelection(FrozenModel):
    template: Literal["omitted_alerts"]
    incident_reference_id: FactId
    count: Annotated[int, Field(strict=True, ge=1)]


type NarrativeSelection = Annotated[
    MemberCountSelection
    | MemberScoreSelection
    | RuleObservedSelection
    | MissingScoresSelection
    | OmittedAlertsSelection,
    Field(discriminator="template"),
]
NARRATIVE_SELECTION_ADAPTER: TypeAdapter[NarrativeSelection] = TypeAdapter(NarrativeSelection)


class NarrativeOutput(FrozenModel):
    selections: Annotated[tuple[NarrativeSelection, ...], Field(max_length=8)]


class CitationReference(FrozenModel):
    kind: Literal["incident", "group", "alert"]
    fact_id: FactId


class RemovedSelection(FrozenModel):
    reason: Literal[
        "invalid_selection", "unknown_citation", "incorrect_binding", "duplicate_selection"
    ]
    selection_digest: Digest


class ValidatedNarrative(FrozenModel):
    status: Literal["validated", "all_removed", "invalid_structure"]
    pack_digest: Digest
    selections: tuple[NarrativeSelection, ...]
    citations: tuple[CitationReference, ...]
    removals: tuple[RemovedSelection, ...]
    label_en: Literal["Unvalidated AI summary"]
    label_es: Literal["Resumen de IA no validado"]
    rendered_en: str
    rendered_es: str
    static_error: (
        Literal["invalid_json", "invalid_envelope", "pack_identity_mismatch", "output_too_large"]
        | None
    )


def narrative_output_json_schema() -> dict[str, object]:
    schema = NarrativeOutput.model_json_schema(mode="validation")
    return schema
