"""Request-scoped stage outcome collection for durable audit events."""

from __future__ import annotations

from contextvars import ContextVar, Token

from ai_soc.contracts.models import AuditStageOutcome

_stage_outcomes: ContextVar[list[AuditStageOutcome] | None] = ContextVar(
    "soc_stage_outcomes", default=None
)


def begin_stage_outcomes() -> Token[list[AuditStageOutcome] | None]:
    return _stage_outcomes.set([])


def reset_stage_outcomes(token: Token[list[AuditStageOutcome] | None]) -> None:
    _stage_outcomes.reset(token)


def append_stage_outcome(outcome: AuditStageOutcome) -> None:
    buffer = _stage_outcomes.get()
    if buffer is not None:
        buffer.append(outcome)


def current_stage_outcomes() -> list[AuditStageOutcome]:
    buffer = _stage_outcomes.get()
    return list(buffer) if buffer else []
