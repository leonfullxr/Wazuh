"""Nightly golden scoring used by LV-NIGHTLY and offline GP3 tests."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class CaseOutcome(StrEnum):
    completed = "completed"
    no_findings = "no_findings"
    invalid_json = "invalid_json"
    provider_failure = "provider_failure"
    missing = "missing"


@dataclass(frozen=True, slots=True)
class CaseResult:
    case_id: str
    language: str
    outcome: CaseOutcome
    route_matches: bool | None
    valid_candidates: int = 0
    dropped_candidates: int = 0


@dataclass(frozen=True, slots=True)
class ReviewedBaseline:
    sha256: str
    en_cases: int
    es_cases: int
    drop_rate: float
    independently_reviewed: bool

    def validate(self) -> None:
        if len(self.sha256) != 64 or any(char not in "0123456789abcdef" for char in self.sha256):
            raise ValueError("baseline SHA-256 must be lowercase hexadecimal")
        if self.en_cases < 20 or self.es_cases < 20:
            raise ValueError("baseline needs at least 20 reviewed cases per language")
        if not self.independently_reviewed:
            raise ValueError("baseline must be independently reviewed")
        if not 0 <= self.drop_rate <= 1:
            raise ValueError("baseline drop rate must be between zero and one")


@dataclass(frozen=True, slots=True)
class NightlyResult:
    status: str
    required_cases: int
    routed_correctly: int
    router_accuracy: float | None
    missing_cases: tuple[str, ...]
    outcome_counts: dict[str, int]
    candidate_count: int
    dropped_count: int
    empty_cohort: bool
    drop_rate: float | None
    drop_alarm: bool


def evaluate_nightly(
    *,
    required_case_ids: tuple[str, ...],
    results: tuple[CaseResult, ...],
    baseline: ReviewedBaseline,
) -> NightlyResult:
    """Score only completed, schema-valid candidates; missing routes fail closed."""
    baseline.validate()
    if not required_case_ids or len(set(required_case_ids)) != len(required_case_ids):
        raise ValueError("required case IDs must be nonempty and unique")
    result_by_id: dict[str, CaseResult] = {}
    for result in results:
        if result.case_id not in required_case_ids:
            raise ValueError(f"unexpected case result: {result.case_id}")
        if result.case_id in result_by_id:
            raise ValueError(f"duplicate case result: {result.case_id}")
        if result.language not in {"en", "es"}:
            raise ValueError(f"unsupported case language: {result.language}")
        if result.valid_candidates < 0 or result.dropped_candidates < 0:
            raise ValueError("candidate counts cannot be negative")
        if result.dropped_candidates > result.valid_candidates:
            raise ValueError("dropped candidates cannot exceed valid candidates")
        if result.outcome not in {CaseOutcome.completed, CaseOutcome.no_findings} and (
            result.valid_candidates or result.dropped_candidates
        ):
            raise ValueError("incomplete and invalid outcomes cannot contribute candidates")
        result_by_id[result.case_id] = result

    missing = tuple(case_id for case_id in required_case_ids if case_id not in result_by_id)
    routed = sum(result.route_matches is True for result in result_by_id.values())
    route_denominator = len(required_case_ids)
    valid_results = tuple(
        result
        for result in result_by_id.values()
        if result.outcome in {CaseOutcome.completed, CaseOutcome.no_findings}
    )
    candidate_count = sum(result.valid_candidates for result in valid_results)
    dropped_count = sum(result.dropped_candidates for result in valid_results)
    empty_cohort = candidate_count == 0
    drop_rate = None if empty_cohort else dropped_count / candidate_count
    counts = {outcome.value: 0 for outcome in CaseOutcome}
    counts[CaseOutcome.missing.value] = len(missing)
    for result in result_by_id.values():
        counts[result.outcome.value] += 1

    router_accuracy = routed / route_denominator
    execution_failures = (
        counts[CaseOutcome.invalid_json.value]
        + counts[CaseOutcome.provider_failure.value]
        + counts[CaseOutcome.missing.value]
    )
    status = (
        "PASS" if router_accuracy == 1.0 and not missing and execution_failures == 0 else "FAIL"
    )
    drop_alarm = (
        candidate_count >= 20 and drop_rate is not None and drop_rate > baseline.drop_rate + 0.05
    )
    if drop_alarm:
        status = "FAIL"
    return NightlyResult(
        status=status,
        required_cases=route_denominator,
        routed_correctly=routed,
        router_accuracy=router_accuracy,
        missing_cases=missing,
        outcome_counts=counts,
        candidate_count=candidate_count,
        dropped_count=dropped_count,
        empty_cohort=empty_cohort,
        drop_rate=drop_rate,
        drop_alarm=drop_alarm,
    )
