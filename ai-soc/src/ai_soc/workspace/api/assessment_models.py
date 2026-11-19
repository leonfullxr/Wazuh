"""Public read and review contracts for group assessments."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ai_soc.workspace.assessment.validation import Band, Outcome, Verdict

type AssessmentState = Literal[
    "preview",
    "stale",
    "pending",
    "shadow",
    "disabled",
    "not_selected",
    "no_assessment",
    "provider_unavailable",
]


class AssessmentModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class AssessmentSummary(AssessmentModel):
    state: AssessmentState
    verdict: Verdict | None
    band: Band | None


class AssessmentEvidence(AssessmentModel):
    id: str
    kind: str
    fields: dict[str, Any]


class AssessmentProvenance(AssessmentModel):
    provider: str
    model: str
    prompt_digest: str
    pack_digest: str
    catalog_version: str
    catalog_digest: str
    input_tokens: int | None
    output_tokens: int | None
    latency_ms: int | None
    finished_at: datetime


class AssessmentReviewRequest(AssessmentModel):
    site_id: str = Field(min_length=1, max_length=64)
    request_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision: Literal["agree", "override"]
    verdict: Verdict | None = None
    reason: str = Field(default="", max_length=1000)

    @model_validator(mode="after")
    def validate_decision(self) -> "AssessmentReviewRequest":
        if self.decision == "override" and (self.verdict is None or not self.reason.strip()):
            raise ValueError("an override requires a verdict and a reason")
        if self.decision == "agree" and self.verdict is not None:
            raise ValueError("an agreement uses the assessment verdict")
        return self


class AssessmentReview(AssessmentModel):
    review_id: str
    request_id: str
    decision: Literal["agree", "override"]
    verdict: Verdict
    reason: str
    actor_key: str
    at: datetime


class AssessmentDetail(AssessmentModel):
    summary: AssessmentSummary
    request_id: str | None
    revision: str | None
    outcome: Outcome | None
    evidence: list[AssessmentEvidence]
    gaps: dict[str, Literal["present", "empty", "not_configured", "failed", "stale"]]
    missing_fields: list[str]
    provenance: AssessmentProvenance | None
    reviews: list[AssessmentReview]


class ChainAssessmentPreview(AssessmentModel):
    outcome: Outcome
    evidence: list[AssessmentEvidence]
    provenance: AssessmentProvenance
