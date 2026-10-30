"""Reproducible v1 score over frozen inputs; no model or live context reads."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Literal

import yaml
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from .grouping import digest

SCORE_VERSION = "workspace.score.v1"


class FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)


class ScoreWeights(FrozenModel):
    version: str = Field(min_length=1)
    base: float = Field(ge=0)
    asset: float = Field(ge=0)
    privilege: float = Field(ge=0)
    rarity: float = Field(ge=0)
    first_seen: float = Field(ge=0)
    exposure: float = Field(ge=0)
    chain_strength: float = Field(ge=0)
    known_noise: float = Field(le=0)
    composite_overlap: float = Field(le=0)


def load_weights(path: Path) -> ScoreWeights:
    return ScoreWeights.model_validate(yaml.safe_load(path.read_text()))


class FrozenContext(FrozenModel):
    """A retained input snapshot, including unavailable and measured-zero values."""

    source: str = Field(min_length=1)
    source_version: str = Field(min_length=1)
    evidence_id: str = Field(min_length=1)
    fetched_at: AwareDatetime
    expires_at: AwareDatetime | None = None
    availability: Literal["available", "unavailable", "stale"]
    value: float | None = Field(ge=0, le=1)

    @model_validator(mode="after")
    def check_availability(self) -> FrozenContext:
        if (self.availability == "available") != (self.value is not None):
            raise ValueError("only available context has a measured value")
        return self


class ScoreInputs(FrozenModel):
    site_id: str = Field(min_length=1)
    group_id: str = Field(min_length=1)
    group_revision: str = Field(min_length=1)
    as_of: AwareDatetime
    weights: ScoreWeights
    rule_level: int | None = Field(ge=0, le=15)
    rule_evidence_ids: tuple[str, ...]
    # Prevalence is a frozen count cohort, never a query performed by this function.
    rule_on_agent_30d: int | None = Field(ge=0)
    alerts_on_agent_30d: int | None = Field(ge=0)
    prevalence_evidence_ids: tuple[str, ...] = ()
    contexts: tuple[FrozenContext, ...] = ()
    composite_evidence_ids: tuple[str, ...] = ()
    composite_overlap: bool = False

    @model_validator(mode="after")
    def check_inputs(self) -> ScoreInputs:
        if (self.rule_on_agent_30d is None) != (self.alerts_on_agent_30d is None):
            raise ValueError("prevalence counts must share an availability state")
        if (
            self.rule_on_agent_30d is not None
            and self.alerts_on_agent_30d is not None
            and self.rule_on_agent_30d > self.alerts_on_agent_30d
        ):
            raise ValueError("rule count exceeds its alert cohort")
        sources = [context.source for context in self.contexts]
        if len(set(sources)) != len(sources):
            raise ValueError("duplicate context source")
        for context in self.contexts:
            if context.fetched_at > self.as_of:
                raise ValueError("context was fetched after the frozen cutoff")
            if (
                context.availability == "available"
                and context.expires_at is not None
                and context.expires_at <= self.as_of
            ):
                raise ValueError("expired context cannot be available")
        if self.rule_level is not None and not self.rule_evidence_ids:
            raise ValueError("rule level requires evidence")
        if self.rule_on_agent_30d is not None and not self.prevalence_evidence_ids:
            raise ValueError("prevalence requires cohort evidence")
        if self.composite_overlap and not self.composite_evidence_ids:
            raise ValueError("composite overlap requires evidence")
        return self


class ScoreComponent(FrozenModel):
    name: str
    value: float | None
    weight: float
    contribution: float
    available: bool
    evidence_ids: tuple[str, ...]
    explanation: str


class ScoreResult(FrozenModel):
    site_id: str
    group_id: str
    computation_version: str
    input_digest: str
    total: float
    components: tuple[ScoreComponent, ...]
    inputs: ScoreInputs


def score_group(inputs: ScoreInputs, *, computation_version: str) -> ScoreResult:
    components: list[ScoreComponent] = []

    def add(
        name: str,
        value: float | None,
        weight: float,
        evidence_ids: tuple[str, ...],
        description: str,
    ) -> None:
        components.append(
            ScoreComponent(
                name=name,
                value=value,
                weight=weight,
                contribution=0.0 if value is None else round(value * weight, 6),
                available=value is not None,
                evidence_ids=evidence_ids,
                explanation=description if value is not None else f"{description}: unavailable",
            )
        )

    base = None if inputs.rule_level is None else min(35.0, 3.5 * inputs.rule_level) / 35
    weights = inputs.weights
    add("base", base, weights.base, inputs.rule_evidence_ids, "Wazuh rule level")
    contexts = {context.source: context for context in inputs.contexts}
    for name, weight, explanation in (
        ("asset", weights.asset, "Operator asset criticality"),
        ("privilege", weights.privilege, "Observed privileged account or action"),
    ):
        context = contexts.get(name)
        add(
            name,
            None if context is None else context.value,
            weight,
            () if context is None else (context.evidence_id,),
            explanation,
        )
    prevalence = None
    if inputs.rule_on_agent_30d is not None and inputs.alerts_on_agent_30d is not None:
        smoothed = (inputs.rule_on_agent_30d + 1) / (inputs.alerts_on_agent_30d + 10)
        prevalence = max(0.0, min(1.0, -math.log10(smoothed) / 3))
    add(
        "rarity",
        prevalence,
        weights.rarity,
        inputs.prevalence_evidence_ids,
        "Frozen 30-day prevalence",
    )
    first_seen = contexts.get("first_seen")
    add(
        "first_seen",
        None if first_seen is None else first_seen.value,
        weights.first_seen,
        () if first_seen is None else (first_seen.evidence_id,),
        "First observed source and user pair",
    )
    kev, vuln = contexts.get("kev"), contexts.get("vuln")
    # An observed positive remains useful during another source's outage. An all-zero
    # exposure is available only when both sources were actually measured.
    positive_exposure = max(
        0.0 if kev is None or kev.value is None else kev.value,
        0.0 if vuln is None or vuln.value is None else 0.5 * vuln.value,
    )
    exposure = (
        positive_exposure
        if positive_exposure > 0
        or (
            kev is not None
            and kev.value is not None
            and vuln is not None
            and vuln.value is not None
        )
        else None
    )
    add(
        "exposure",
        exposure,
        weights.exposure,
        tuple(context.evidence_id for context in (kev, vuln) if context is not None),
        "KEV or high-severity vulnerability context; affected state remains unknown",
    )
    add("chain_strength", 0.0, weights.chain_strength, (), "Chain scoring starts at M3")
    noise = contexts.get("known_noise")
    add(
        "known_noise",
        None if noise is None else noise.value,
        weights.known_noise,
        () if noise is None else (noise.evidence_id,),
        "Versioned accepted noise content",
    )
    add(
        "composite_overlap",
        float(inputs.composite_overlap),
        weights.composite_overlap,
        inputs.composite_evidence_ids,
        "Base alerts also summarized by a same-bucket Wazuh composite",
    )
    return ScoreResult(
        site_id=inputs.site_id,
        group_id=inputs.group_id,
        computation_version=computation_version,
        input_digest=digest(inputs.model_dump(mode="json")),
        total=round(max(0.0, min(100.0, sum(item.contribution for item in components))), 6),
        components=tuple(components),
        inputs=inputs,
    )


def render_score_reasons(score: ScoreResult, limit: int = 3) -> tuple[ScoreComponent, ...]:
    positive = sorted(
        (item for item in score.components if item.contribution > 0),
        key=lambda item: (-item.contribution, item.name),
    )[:limit]
    negative = sorted(
        (item for item in score.components if item.contribution < 0),
        key=lambda item: (item.contribution, item.name),
    )
    return tuple(positive + negative)
