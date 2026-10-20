"""Conservative daily-ledger charges for paid guardrail evaluations."""

from __future__ import annotations

from ai_soc.contracts.models import JudgmentRequest, RawJudgment


def judgment_settled_tokens(raw: RawJudgment, request: JudgmentRequest) -> int | None:
    if raw.usage is None and not raw.guardrail_intervened:
        return None
    model_tokens = 0
    if raw.usage is not None:
        model_tokens = raw.usage.total_input_tokens + raw.usage.output_tokens
    if raw.guardrail_intervened:
        # The reservation includes counted input, maximum output, and the existing margin.
        # Keep the full bound when a guardrail blocks before model-token usage is reported.
        return max(model_tokens, request.reserved_tokens)
    if raw.usage is None:
        return None
    return model_tokens
