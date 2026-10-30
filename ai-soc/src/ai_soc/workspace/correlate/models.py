"""Strict immutable inputs and outputs for deterministic correlation."""

from __future__ import annotations

import ipaddress
import math
import re
from datetime import UTC, datetime
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from ai_soc.workspace.triage.grouping import digest

SHA256 = r"^[0-9a-f]{64}$"
MISSING_TEXT = frozenset({"", "unknown", "null", "none", "n/a", "not available"})


class FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False, strict=True)


def utc(value: datetime) -> datetime:
    return value.astimezone(UTC)


class CorrelationObservation(FrozenModel):
    site_id: str = Field(min_length=1, max_length=128)
    group_id: str = Field(pattern=SHA256)
    group_revision: str = Field(pattern=SHA256)
    alert_key: str = Field(min_length=1, max_length=512)
    source_hash: str = Field(pattern=SHA256)
    event_ts: AwareDatetime
    rule_id: str | None = Field(default=None, max_length=128)
    decoder: str | None = Field(default=None, max_length=256)
    agent_id: str | None = Field(default=None, max_length=256)
    src_ip: str | None = Field(default=None, max_length=64)
    dst_ip: str | None = Field(default=None, max_length=64)
    src_user: str | None = Field(default=None, max_length=256)
    dst_user: str | None = Field(default=None, max_length=256)
    rule_groups: tuple[str, ...] = Field(default=(), max_length=64)
    mitre_tactics: tuple[str, ...] = Field(default=(), max_length=32)
    file_path: str | None = Field(default=None, max_length=4096)
    file_event: str | None = Field(default=None, max_length=128)
    hashes: tuple[str, ...] = Field(default=(), max_length=64)

    @field_validator(
        "rule_id",
        "decoder",
        "agent_id",
        "src_ip",
        "dst_ip",
        "src_user",
        "dst_user",
        "file_path",
        "file_event",
    )
    @classmethod
    def missing_text(cls, value: str | None) -> str | None:
        return None if value is not None and value.strip().casefold() in MISSING_TEXT else value

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def valid_ip(cls, value: str | None) -> str | None:
        if value is not None and value.strip().casefold() not in {
            "",
            "unknown",
            "null",
            "none",
            "n/a",
            "not available",
        }:
            try:
                ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValueError("invalid IP address") from exc
        return (
            None
            if value is not None
            and value.strip().casefold() in {"", "unknown", "null", "none", "n/a", "not available"}
            else value
        )

    @field_validator("hashes")
    @classmethod
    def supported_hashes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(
            not re.fullmatch(r"(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", item)
            for item in value
        ):
            raise ValueError("unsupported or malformed file hash")
        return value

    @field_validator("rule_groups", "mitre_tactics", "hashes")
    @classmethod
    def unique_tuple(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("duplicate projected value")
        if any(len(item) > 512 for item in value):
            raise ValueError("projected value exceeds length cap")
        return value


class CorrelationGroup(FrozenModel):
    site_id: str = Field(min_length=1, max_length=128)
    group_id: str = Field(pattern=SHA256)
    revision: str = Field(pattern=SHA256)
    score: float | None = Field(ge=0, le=100)
    computation_version: str | None = Field(default=None, max_length=128)
    input_digest: str | None = Field(default=None, pattern=SHA256)

    @model_validator(mode="after")
    def complete_score_reference(self) -> CorrelationGroup:
        if (self.computation_version is None) != (self.input_digest is None):
            raise ValueError("score computation version and input digest must be supplied together")
        if self.score is not None and self.computation_version is None:
            raise ValueError("a measured score requires its frozen computation reference")
        return self


class CorrelationInput(FrozenModel):
    site_id: str = Field(min_length=1, max_length=128)
    window_start: AwareDatetime
    window_end: AwareDatetime
    as_of: AwareDatetime
    computation_version: str = Field(min_length=1, max_length=128)
    groups: tuple[CorrelationGroup, ...] = Field(max_length=512)
    observations: tuple[CorrelationObservation, ...] = Field(max_length=100_000)

    @model_validator(mode="after")
    def coherent_snapshot(self) -> CorrelationInput:
        start, end, as_of = map(utc, (self.window_start, self.window_end, self.as_of))
        if not start < end <= as_of:
            raise ValueError("window must satisfy start < end <= as_of")
        if (end - start).total_seconds() > 172800:
            raise ValueError("input window exceeds 48 hours")
        if len(self.groups) > 512 or len(self.observations) > 100_000:
            raise ValueError("correlation input work cap exceeded")
        if any(group.site_id != self.site_id for group in self.groups):
            raise ValueError("mixed site groups")
        if any(observation.site_id != self.site_id for observation in self.observations):
            raise ValueError("mixed site observations")
        by_id: dict[str, CorrelationGroup] = {}
        for group in self.groups:
            if group.group_id in by_id:
                raise ValueError("duplicate group revision")
            by_id[group.group_id] = group
        keys: set[str] = set()
        for observation in self.observations:
            if observation.alert_key in keys:
                raise ValueError("duplicate alert key")
            keys.add(observation.alert_key)
            if not start <= utc(observation.event_ts) < end:
                raise ValueError("observation outside half-open correlation window")
            group = by_id.get(observation.group_id)
            if group is None or group.revision != observation.group_revision:
                raise ValueError("observation does not reference the pinned group revision")
        return self

    @property
    def canonical_payload(self) -> dict[str, object]:
        groups = sorted(self.groups, key=lambda group: group.group_id)
        observations = sorted(self.observations, key=lambda item: item.alert_key)

        def observation_manifest(item: CorrelationObservation) -> dict[str, object]:
            values = item.model_dump(mode="json")
            values["event_ts"] = utc(item.event_ts).isoformat()
            values["rule_groups"] = sorted(item.rule_groups)
            values["mitre_tactics"] = sorted(item.mitre_tactics)
            values["hashes"] = sorted(item.hashes)
            return values

        return {
            "site_id": self.site_id,
            "window_start": utc(self.window_start).isoformat(),
            "window_end": utc(self.window_end).isoformat(),
            "as_of": utc(self.as_of).isoformat(),
            "computation_version": self.computation_version,
            "groups": [group.model_dump(mode="json") for group in groups],
            "observations": [observation_manifest(item) for item in observations],
        }

    @property
    def canonical_digest(self) -> str:
        return digest(self.canonical_payload)


EdgeType = Literal["same_src_ip_user", "same_user_host", "same_src_ip", "same_hash", "same_host"]


class EdgeDraft(FrozenModel):
    site_id: str = Field(min_length=1, max_length=128)
    edge_id: str = Field(pattern=SHA256)
    from_group: str = Field(pattern=SHA256)
    from_revision: str = Field(pattern=SHA256)
    to_group: str = Field(pattern=SHA256)
    to_revision: str = Field(pattern=SHA256)
    edge_type: EdgeType
    confidence: float = Field(ge=0, le=1)
    weak: bool
    reason: str = Field(min_length=1)
    time_delta_seconds: float = Field(ge=0, allow_inf_nan=False)
    from_alert_key: str
    to_alert_key: str
    shared_fields: tuple[tuple[str, str], ...]


FieldName = Literal[
    "agent.id",
    "src_ip",
    "dst_ip",
    "src_user",
    "dst_user",
    "rule_id",
    "decoder",
    "syscheck.path",
    "syscheck.event",
    "rule_groups",
]


class Selector(FrozenModel):
    field: FieldName
    values: tuple[str, ...] = Field(min_length=1, max_length=64)


class SelectorAlternative(FrozenModel):
    selectors: tuple[Selector, ...] = Field(min_length=1, max_length=16)


class ChainStage(FrozenModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9_]{0,39}$")
    rule_id: str | None = Field(default=None, min_length=1, max_length=128)
    any_rule_id: tuple[str, ...] = Field(default=(), max_length=64)
    rule_group: str | None = Field(default=None, min_length=1, max_length=128)
    where_any: tuple[Selector, ...] = Field(default=(), max_length=16)
    any_of: tuple[SelectorAlternative, ...] = Field(default=(), max_length=16)
    after: str | None = None
    after_tolerance_ms: int | None = Field(default=None, ge=1, le=10_000)
    max_gap_seconds: int | None = Field(default=None, gt=0, le=86400)
    same_fields: tuple[tuple[FieldName, FieldName], ...] = Field(default=(), max_length=9)
    actor_match: bool = False
    confidence: float = Field(ge=0, le=1)
    maps_to: str = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def exactly_one_rule_selector(self) -> ChainStage:
        count = sum((self.rule_id is not None, bool(self.any_rule_id), self.rule_group is not None))
        rule_alternatives = bool(self.any_of) and all(
            any(selector.field == "rule_id" for selector in item.selectors) for item in self.any_of
        )
        if count != 1 and not (count == 0 and rule_alternatives):
            raise ValueError("stage requires exactly one rule selector")
        if self.after_tolerance_ms is not None and self.after is None:
            raise ValueError("after_tolerance requires an after stage")
        if self.after_tolerance_ms is not None and not any(
            selector.field == "syscheck.path" for selector in self.where_any
        ):
            raise ValueError("after_tolerance requires where_any syscheck.path")
        return self


class ChainRule(FrozenModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9_.]{0,79}$")
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$", max_length=40)
    name: str = Field(min_length=1, max_length=120)
    window_seconds: int = Field(gt=0, le=86400)
    same_agent: bool
    primary: tuple[FieldName, ...] = Field(min_length=1, max_length=9)
    fallback: tuple[FieldName, ...] = Field(default=(), max_length=9)
    fallback_confidence: float = Field(default=0.0, ge=0, le=1)
    stages: tuple[ChainStage, ...] = Field(min_length=1, max_length=8)
    min_required_stages: int = Field(ge=1, le=8)
    require_stages: tuple[str, ...] = Field(default=(), max_length=8)
    promote_score: float = Field(ge=0, le=100)
    confidence_cap_without_actor_fields: float = Field(ge=0, le=1)
    confidence_cap_with_order_tolerance: float | None = Field(default=None, ge=0, le=1)
    content_digest: str = Field(pattern=SHA256)
    source_yaml: str | None = Field(default=None, max_length=65_536)

    @model_validator(mode="after")
    def valid_stage_graph(self) -> ChainRule:
        ids = [stage.id for stage in self.stages]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate stage id")
        if len(self.require_stages) != len(set(self.require_stages)):
            raise ValueError("duplicate required stage")
        if not set(self.require_stages) <= set(ids):
            raise ValueError("required stage does not exist")
        if self.min_required_stages > len(ids):
            raise ValueError("required stage limits are infeasible")
        has_tolerance = any(stage.after_tolerance_ms is not None for stage in self.stages)
        if has_tolerance != (self.confidence_cap_with_order_tolerance is not None):
            raise ValueError("order-tolerance confidence cap must match tolerant stages")
        prior: set[str] = set()
        for stage in self.stages:
            if stage.after is not None and stage.after not in prior:
                raise ValueError("after must reference an earlier stage")
            if stage.max_gap_seconds is not None and stage.after is None:
                raise ValueError("max_gap requires an after stage")
            if stage.max_gap_seconds is not None and stage.max_gap_seconds > self.window_seconds:
                raise ValueError("stage max_gap cannot exceed the chain window")
            prior.add(stage.id)
        return self


class ChainStageEvidence(FrozenModel):
    stage_id: str
    alert_key: str
    group_id: str = Field(pattern=SHA256)
    group_revision: str = Field(pattern=SHA256)
    event_ts: AwareDatetime
    confidence: float = Field(ge=0, le=1)


class ChainMatch(FrozenModel):
    site_id: str
    chain_id: str = Field(pattern=SHA256)
    revision_digest: str = Field(pattern=SHA256)
    rule_id: str
    rule_version: str
    anchor_alert_key: str
    anchor_identity: str
    stages: tuple[ChainStageEvidence, ...]
    missing_stages: tuple[str, ...]
    reasons: tuple[str, ...]
    fallback_used: bool
    order_tolerance_applied: bool
    confidence: float = Field(ge=0, le=1)
    score: float | None = Field(default=None, ge=0, le=100)
    is_candidate: bool
    eligible_for_promotion: bool

    @field_validator("confidence")
    @classmethod
    def finite_confidence(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("confidence must be finite")
        return value
