"""Versioned workspace templates, evidence rules and selection policy."""

from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from ai_soc.contracts.canonical import sha256_hex
from ai_soc.contracts.models import ContentId, FiniteFloat, LocaleText, StrictModel
from ai_soc.validation.findings import parse_finding_json, template_placeholders_match

CATALOG_PATH = Path(__file__).resolve().parents[4] / "content/workspace/assessment/catalog.json"

type EvidenceKind = Literal["row", "aggregate", "check", "context", "history", "knowledge"]
type Stance = Literal["malicious", "benign"]
type Value = str | int | FiniteFloat | bool


class Condition(StrictModel):
    field: ContentId
    op: Literal["eq", "gte", "lte"]
    value: Value

    @model_validator(mode="after")
    def validate_operand(self) -> "Condition":
        if self.op != "eq" and type(self.value) not in (int, float):
            raise ValueError("ordering conditions require a numeric operand")
        return self

    def matches(self, fields: Mapping[str, object]) -> bool:
        actual = fields.get(self.field)
        if self.op == "eq":
            return type(actual) is type(self.value) and actual == self.value
        if not isinstance(actual, (int, float)) or isinstance(actual, bool):
            return False
        if not isinstance(self.value, (int, float)):
            return False
        if self.op == "gte":
            return actual >= self.value
        return actual <= self.value


class Slot(StrictModel):
    fields: tuple[ContentId, ...] = Field(min_length=1, max_length=8)
    precondition: Condition | None = None


class Relation(StrictModel):
    kind: Literal["same_record", "same_fetch", "aggregate_scope"]
    slots: tuple[ContentId, ...] = Field(min_length=2, max_length=8)


class FindingTemplate(StrictModel):
    subjects: tuple[Literal["group"], ...] = Field(min_length=1)
    stance: Stance
    evidence_kinds: tuple[EvidenceKind, ...] = Field(min_length=1)
    slots: dict[ContentId, Slot] = Field(min_length=1, max_length=8)
    relations: tuple[Relation, ...]
    coverage_slot: ContentId | None = None
    text: LocaleText

    @model_validator(mode="after")
    def validate_template(self) -> "FindingTemplate":
        slots = set(self.slots)
        if not all(
            template_placeholders_match(value, slots) for value in (self.text.en, self.text.es)
        ):
            raise ValueError("finding text must match declared slots")
        if any(not set(relation.slots) <= slots for relation in self.relations):
            raise ValueError("finding relation names undeclared slots")
        if len(slots) > 1:
            connected = {next(iter(slots))}
            for _ in slots:
                for relation in self.relations:
                    if connected.intersection(relation.slots):
                        connected.update(relation.slots)
            if connected != slots:
                raise ValueError("every finding slot must be connected by a relation")
        if self.coverage_slot is not None and (
            self.stance != "benign"
            or self.coverage_slot not in self.slots
            or "aggregate" not in self.evidence_kinds
        ):
            raise ValueError("benign coverage requires a declared aggregate slot")
        return self


class StepTemplate(StrictModel):
    subjects: tuple[Literal["group"], ...] = Field(min_length=1)
    evidence_kinds: tuple[EvidenceKind, ...] = Field(min_length=1)
    precondition: Condition
    text: LocaleText

    @model_validator(mode="after")
    def validate_template(self) -> "StepTemplate":
        if not all(
            template_placeholders_match(value, set()) for value in (self.text.en, self.text.es)
        ):
            raise ValueError("step text cannot contain slots")
        return self


class FamilyRequirements(StrictModel):
    required: tuple[ContentId, ...]
    optional: tuple[ContentId, ...]
    member_fields: tuple[ContentId, ...]

    @model_validator(mode="after")
    def validate_categories(self) -> "FamilyRequirements":
        if set(self.required).intersection(self.optional):
            raise ValueError("required and optional evidence categories must be disjoint")
        return self


class AssessmentCatalog(StrictModel):
    version: ContentId
    score_gate: Annotated[FiniteFloat, Field(ge=0, le=100)]
    sample_basis_points: int = Field(ge=0, le=10_000)
    sample_seed: ContentId
    findings: dict[ContentId, FindingTemplate] = Field(min_length=1, max_length=24)
    next_steps: dict[ContentId, StepTemplate] = Field(min_length=1, max_length=24)
    families: dict[ContentId, FamilyRequirements]

    @model_validator(mode="after")
    def validate_families(self) -> "AssessmentCatalog":
        if "default" not in self.families:
            raise ValueError("a default assessment family policy is required")
        return self

    @property
    def digest(self) -> str:
        return sha256_hex(self)


@lru_cache(maxsize=1)
def load_catalog() -> AssessmentCatalog:
    text = CATALOG_PATH.read_text("utf-8")
    parse_finding_json(text)
    return AssessmentCatalog.model_validate_json(text)
