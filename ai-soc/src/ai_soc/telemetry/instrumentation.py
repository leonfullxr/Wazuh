"""Shared stage span helpers for application and adapter call sites."""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING

from ai_soc.contracts.models import (
    FetchState,
    StageAttributes,
    StageName,
    StageOutcome,
    TraceContext,
)

if TYPE_CHECKING:
    from ai_soc.contracts.ports import Telemetry


@contextmanager
def question_stage(telemetry: Telemetry, stage: StageName, trace_context: TraceContext):
    with telemetry.stage(stage, trace_context=trace_context) as span:
        yield span


def fetch_stage_outcome(state: FetchState) -> StageOutcome:
    if state is FetchState.denied:
        return StageOutcome.denied
    if state is FetchState.unavailable:
        return StageOutcome.unavailable
    return StageOutcome.ok


def fetch_stage_attributes(state: FetchState) -> StageAttributes:
    return StageAttributes(outcome=fetch_stage_outcome(state), fetch_state=state)
