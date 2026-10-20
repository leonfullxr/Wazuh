"""Exact context fit decisions after the provider's CountTokens call."""

from __future__ import annotations

from ai_soc.contracts.models import (
    JudgmentRequest,
    JudgmentResult,
    JudgmentState,
    LeftOut,
    LeftOutReason,
    Skip,
    TopicId,
)

SAFETY_MARGIN_TOKENS = 256


def fits_context(
    counted_input_tokens: int,
    request: JudgmentRequest,
    *,
    safety_margin_tokens: int = SAFETY_MARGIN_TOKENS,
) -> bool:
    """Return whether exact input + requested output + margin fits the profile."""
    if isinstance(counted_input_tokens, bool) or counted_input_tokens < 0:
        return False
    if isinstance(safety_margin_tokens, bool) or safety_margin_tokens < 0:
        return False
    return (
        counted_input_tokens + request.max_output_tokens + safety_margin_tokens
        <= request.model.context_tokens
    )


def reserved_gross_tokens(
    counted_input_tokens: int,
    request: JudgmentRequest,
    *,
    safety_margin_tokens: int = SAFETY_MARGIN_TOKENS,
) -> int:
    if not fits_context(counted_input_tokens, request, safety_margin_tokens=safety_margin_tokens):
        raise ValueError("judgment request exceeds selected model context")
    return counted_input_tokens + request.max_output_tokens + safety_margin_tokens


def context_outcome(
    counted_input_tokens: int,
    request: JudgmentRequest,
    *,
    safety_margin_tokens: int = SAFETY_MARGIN_TOKENS,
) -> Skip | None:
    """Return the contract context-exceeded result, or None when it fits."""
    if fits_context(counted_input_tokens, request, safety_margin_tokens=safety_margin_tokens):
        return None
    return _skip(
        request.topic_id,
        JudgmentState.context_exceeded,
        LeftOutReason.context_exceeded,
        retryable=True,
    )


def provider_failure_outcome(state: str, topic_id: TopicId) -> Skip:
    """Map provider/count/capacity failures to the finite v1.1 topic outcomes."""
    mapping = {
        "token_count_unavailable": (
            JudgmentState.token_count_unavailable,
            LeftOutReason.token_count_unavailable,
        ),
        "model_unavailable": (JudgmentState.model_unavailable, LeftOutReason.model_unavailable),
        "guardrail_blocked": (JudgmentState.guardrail_blocked, LeftOutReason.guardrail_blocked),
        "invalid_output": (JudgmentState.invalid_output, LeftOutReason.invalid_output),
        "deadline_exceeded": (JudgmentState.deadline_exceeded, LeftOutReason.deadline_exceeded),
        "capacity_limited": (JudgmentState.capacity_limited, LeftOutReason.capacity_limited),
        "budget_exceeded": (JudgmentState.budget_exceeded, LeftOutReason.budget_exceeded),
        "evidence_unavailable": (
            JudgmentState.evidence_unavailable,
            LeftOutReason.evidence_unavailable,
        ),
    }
    pair = mapping.get(state)
    if pair is None:
        raise ValueError("provider failure is outside the finite judgment outcome table")
    return _skip(topic_id, pair[0], pair[1], retryable=state != "guardrail_blocked")


def _skip(
    topic_id: TopicId, state: JudgmentState, reason: LeftOutReason, *, retryable: bool
) -> Skip:
    return Skip(
        result=JudgmentResult(state=state, sentences=[], removed=[]),
        left_out=LeftOut(topic_id=topic_id, stage="judgment", reason=reason, retryable=retryable),
    )
