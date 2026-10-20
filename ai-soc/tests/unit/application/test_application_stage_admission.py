from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest

from ai_soc.application.composition import _JudgmentProviderAdapter
from ai_soc.application.errors import ServiceFailure
from ai_soc.contracts.models import ExecutionContext, JudgmentRequest, RawJudgment
from ai_soc.contracts.ports import JudgmentProvider
from ai_soc.judgment.bedrock import ProviderFailure


class _CapacityProvider:
    def __init__(self, state: str = "capacity_limited") -> None:
        self.state = state

    async def count(self, request: JudgmentRequest, *, execution: ExecutionContext) -> int:
        raise ProviderFailure(self.state)

    async def converse(
        self, request: JudgmentRequest, *, execution: ExecutionContext
    ) -> RawJudgment:
        raise ProviderFailure(self.state)


@pytest.mark.asyncio
async def test_count_stage_capacity_becomes_a_typed_application_failure() -> None:
    adapter = _JudgmentProviderAdapter(cast(JudgmentProvider, _CapacityProvider()))
    execution = cast(
        ExecutionContext,
        SimpleNamespace(trace_context=SimpleNamespace(trace_id="a" * 32)),
    )

    with pytest.raises(ServiceFailure) as failure:
        await adapter.count(cast(JudgmentRequest, object()), execution=execution)

    assert failure.value.error.code == "CAPACITY_LIMIT"
    assert failure.value.error.details["stage"] == "count"


@pytest.mark.asyncio
async def test_converse_stage_capacity_becomes_a_typed_application_failure() -> None:
    adapter = _JudgmentProviderAdapter(cast(JudgmentProvider, _CapacityProvider()))
    execution = cast(
        ExecutionContext,
        SimpleNamespace(trace_context=SimpleNamespace(trace_id="b" * 32)),
    )

    with pytest.raises(ServiceFailure) as failure:
        await adapter.converse(cast(JudgmentRequest, object()), execution=execution)

    assert failure.value.error.code == "CAPACITY_LIMIT"
    assert failure.value.error.details["stage"] == "converse"


@pytest.mark.asyncio
async def test_provider_unavailability_is_not_relabelled_as_stage_capacity() -> None:
    provider = _CapacityProvider("model_unavailable")
    adapter = _JudgmentProviderAdapter(cast(JudgmentProvider, provider))
    execution = cast(
        ExecutionContext,
        SimpleNamespace(trace_context=SimpleNamespace(trace_id="c" * 32)),
    )

    with pytest.raises(ProviderFailure) as failure:
        await adapter.count(cast(JudgmentRequest, object()), execution=execution)

    assert failure.value.state == "model_unavailable"
