"""Per-topic eligibility and request construction; never performs orchestration."""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from ai_soc.contracts.models import (
    CheckOutcome,
    Effort,
    EvidencePack,
    FetchResult,
    FetchState,
    FetchStep,
    GuardrailPin,
    JudgmentPreparation,
    JudgmentRequest,
    JudgmentResult,
    JudgmentState,
    LeftOut,
    LeftOutReason,
    ModelCapability,
    PlaybookDefinition,
    Ready,
    Skip,
    TopicPlan,
    ValidationContext,
)

from .capabilities import CapabilityError, validate_guardrail, validate_selection


class ModelSelectionRequired(ValueError):
    """The whole question must clarify selection before making backend calls."""


class JudgmentEngine:
    def __init__(
        self,
        *,
        standing_rules: str,
        guardrail_identifier: str,
        guardrail_version: str,
        playbook: Callable[[str], PlaybookDefinition | None],
    ) -> None:
        self._standing_rules = standing_rules
        self._guardrail_identifier = guardrail_identifier
        self._guardrail_version = guardrail_version
        self._playbook = playbook

    def _required_fetch_ids(self, plan: TopicPlan) -> set[str]:
        required = {fetch.fetch_id for fetch in plan.fetches}
        if plan.playbook_id is not None:
            playbook = self._playbook(plan.playbook_id)
            if playbook is None:
                raise CapabilityError("topic plan names an unknown playbook")
            required.update(step.fetch_id for step in playbook.steps if isinstance(step, FetchStep))
        return required

    def prepare(
        self,
        plan: TopicPlan,
        pack: EvidencePack,
        *,
        context: ValidationContext,
        model: ModelCapability | None,
        effort: Effort | None,
    ) -> JudgmentPreparation:
        """Apply the frozen outcome precedence and construct one topic request."""
        if not plan.judgment:
            return Skip(result=_result(JudgmentState.not_requested))
        if model is None or (model.efforts and effort is None):
            raise ModelSelectionRequired(
                "model and any required effort must be selected before backend work"
            )
        selected = validate_selection(model, effort)
        guardrail = validate_guardrail(
            GuardrailPin(identifier=self._guardrail_identifier, version=self._guardrail_version)
        )

        _validate_bindings(plan, pack, context)
        if not pack.items and not pack.fetches and not pack.checks:
            return _skip(
                JudgmentState.evidence_unavailable,
                plan,
                "judgment",
                LeftOutReason.evidence_unavailable,
                True,
            )

        all_fetches = [*pack.fetches]
        if any(fetch.state == FetchState.denied for fetch in all_fetches) or any(
            check.outcome == CheckOutcome.denied for check in pack.checks
        ):
            return Skip(result=_result(JudgmentState.denial))
        required_fetch_ids = self._required_fetch_ids(plan)
        actual_fetch_ids = {fetch.fetch_id for fetch in pack.fetches}
        if not actual_fetch_ids.issubset(required_fetch_ids):
            raise CapabilityError("evidence pack contains an unplanned fetch")
        if not required_fetch_ids.issubset(actual_fetch_ids):
            return _skip(
                JudgmentState.evidence_unavailable,
                plan,
                "judgment",
                LeftOutReason.evidence_unavailable,
                True,
            )
        if any(fetch.state == FetchState.unavailable for fetch in all_fetches):
            return _skip(
                JudgmentState.evidence_unavailable,
                plan,
                "judgment",
                LeftOutReason.evidence_unavailable,
                True,
            )

        if _has_unqualified_empty(all_fetches):
            return Skip(result=_result(JudgmentState.ingestion_unconfirmed))

        request = JudgmentRequest(
            question_id=pack.question_id,
            topic_id=plan.topic_id,
            model=selected,
            effort=effort,
            language=context.language,
            standing_rules=self._standing_rules,
            topic_pack=context.topic_pack,
            evidence=pack,
            question="",  # The application binds the question after deterministic planning.
            max_output_tokens=selected.max_output_tokens,
            guardrail=guardrail,
            finding_templates=context.templates,
        )
        return Ready(request=request)


def _validate_bindings(plan: TopicPlan, pack: EvidencePack, context: ValidationContext) -> None:
    if pack.topic_id != plan.topic_id or context.topic_pack.topic_id != plan.topic_id:
        raise CapabilityError("topic plan, evidence, and prompt pack must agree")
    if (
        context.topic_pack.content_sha != pack.content_sha
        or context.content_sha != pack.content_sha
    ):
        raise CapabilityError("content revision mismatch")
    if context.policy_hash != pack.policy_hash:
        raise CapabilityError("effective policy mismatch")
    if context.language != context.topic_pack.language:
        raise CapabilityError("prompt language mismatch")
    if tuple(context.expected_checks) != tuple(pack.checks):
        raise CapabilityError("expected check outcomes must exactly match this topic evidence")
    if any(item.topic_id != plan.topic_id for item in pack.items):
        raise CapabilityError("evidence pack contains a foreign topic item")
    if any(row.topic_id != plan.topic_id for fetch in pack.fetches for row in fetch.rows):
        raise CapabilityError("fetch evidence contains a foreign topic row")
    fetch_ids = {fetch.fetch_id for fetch in pack.fetches}
    if any(item.fetch_id is not None and item.fetch_id not in fetch_ids for item in pack.items):
        raise CapabilityError("evidence item references an unknown fetch")
    check_ids = {check.check_id for check in pack.checks}
    if any(item.check_id is not None and item.check_id not in check_ids for item in pack.items):
        raise CapabilityError("evidence item references an unknown check")


def _has_unqualified_empty(fetches: list[FetchResult]) -> bool:
    zero_fetches: list[FetchResult] = []
    for candidate in fetches:
        state = candidate.state
        count = candidate.count
        if candidate.rows or (count is not None and count.value > 0):
            return False
        if state not in (FetchState.empty, FetchState.filtered):
            continue
        zero_fetches.append(candidate)
    if not zero_fetches:
        return False
    return any(_empty_fetch_unqualified(candidate) for candidate in zero_fetches)


def _empty_fetch_unqualified(candidate: FetchResult) -> bool:
    count = candidate.count
    proof = candidate.empty_proof
    individual_zero = False
    if proof is not None:
        individual_zero = any(
            probe.outcome == "passed"
            and probe.count is not None
            and not probe.count.approximate
            and probe.count.relation == "eq"
            and probe.count.value == 0
            for probe in proof.filter_probes
        )
    return (
        count is None
        or count.approximate
        or count.relation != "eq"
        or count.scope != "matching_visible_records"
        or proof is None
        or proof.consistency != "coherent"
        or proof.visibility != "full"
        or proof.index_exists != "confirmed"
        or proof.window_has_data != "confirmed"
        or not (proof.combination_zero or individual_zero)
        or proof.window_count is None
        or proof.window_count.approximate
        or proof.window_count.relation != "eq"
        or proof.window_count.value <= 0
    )


def _result(state: JudgmentState) -> JudgmentResult:
    return JudgmentResult(state=state, sentences=[], removed=[])


def _skip(
    state: JudgmentState,
    plan: TopicPlan,
    stage: Literal["fetch", "checks", "judgment"],
    reason: LeftOutReason,
    retryable: bool,
) -> Skip:
    return Skip(
        result=_result(state),
        left_out=LeftOut(
            topic_id=plan.topic_id,
            stage=stage,
            reason=reason,
            retryable=retryable,
        ),
    )
