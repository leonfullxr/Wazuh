from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from ai_soc.application.service import ApplicationService
from ai_soc.contracts.models import (
    EvidencePack,
    ExecutionContext,
    JudgmentRequest,
    JudgmentState,
    RawJudgment,
    TokenUsage,
    TraceContext,
)
from ai_soc.state.daily_tokens import utc_day_start_epoch
from ai_soc.state.memory import MemoryState
from tests.unit.application.test_daily_token_judgment import (
    OWNER,
    _Clock,
    _FakeCancellation,
    _judgment_context,
    _judgment_request,
    _model,
)

NOW = datetime(2026, 9, 30, 12, tzinfo=UTC)


class _GuardrailProvider:
    reserved_tokens = 0
    during_count: Callable[[], Awaitable[None]] | None = None
    during_converse: Callable[[], Awaitable[None]] | None = None

    async def count(self, request: JudgmentRequest, *, execution: ExecutionContext) -> int:
        if self.during_count is not None:
            await self.during_count()
        return 100

    async def converse(
        self, request: JudgmentRequest, *, execution: ExecutionContext
    ) -> RawJudgment:
        self.reserved_tokens = request.reserved_tokens
        if self.during_converse is not None:
            await self.during_converse()
        return RawJudgment(
            text="",
            stop_reason="guardrail_intervened",
            guardrail_intervened=True,
            usage=TokenUsage(
                topic_id=request.topic_id,
                input_tokens=0,
                output_tokens=0,
                cache_read_input_tokens=0,
                cache_write_input_tokens=0,
                total_input_tokens=0,
                reserved_tokens=request.reserved_tokens,
                reservation_id=request.reservation_id or uuid4(),
            ),
            provider_request_id="zero-token-guardrail",
        )


class _Validator:
    def validate(self, raw: RawJudgment, pack: EvidencePack, *, context: object) -> object:
        from ai_soc.contracts.models import JudgmentResult

        return JudgmentResult(
            state=JudgmentState.guardrail_blocked,
            sentences=[],
            removed=[],
            message="blocked",
        )


@pytest.mark.asyncio
async def test_zero_token_guardrail_block_retains_daily_allowance_charge() -> None:
    state = MemoryState()
    day = utc_day_start_epoch(NOW)
    lease = await state.acquire(
        owner_key=OWNER,
        environment_id="alpha",
        question_id=uuid4(),
        holder_id=uuid4(),
        now=NOW,
    )
    await state.open_budget(
        question_id=lease.question_id,
        owner_key=OWNER,
        environment_id="alpha",
        token_limit=100_000,
        expires_at=NOW + timedelta(hours=1),
        lease=lease,
        operation_id=uuid4(),
    )
    provider = _GuardrailProvider()
    service = ApplicationService(
        clock=_Clock(),
        catalog=object(),  # type: ignore[arg-type]
        planner=object(),  # type: ignore[arg-type]
        site_policy=object(),  # type: ignore[arg-type]
        plans=object(),  # type: ignore[arg-type]
        admissions=object(),  # type: ignore[arg-type]
        question_admission=object(),  # type: ignore[arg-type]
        leases=object(),  # type: ignore[arg-type]
        budgets=state,
        completions=object(),  # type: ignore[arg-type]
        fetches=object(),  # type: ignore[arg-type]
        playbooks=object(),  # type: ignore[arg-type]
        judgment_engine=object(),  # type: ignore[arg-type]
        judgment_provider=provider,
        finding_validator=_Validator(),
        telemetry=None,
        feedback_sink=object(),  # type: ignore[arg-type]
        feedback_store=state,
        receipts=object(),  # type: ignore[arg-type]
        runtime=object(),  # type: ignore[arg-type]
        models=(_model(),),
    )
    request = _judgment_request(lease.question_id)
    execution = ExecutionContext(
        question_id=lease.question_id,
        operation="ask",
        owner_key=OWNER,
        environment_id="alpha",
        deadline_at=NOW + timedelta(minutes=5),
        cancel=_FakeCancellation(),  # type: ignore[arg-type]
        calls=object(),  # type: ignore[arg-type]
        admission=object(),  # type: ignore[arg-type]
        trace_context=TraceContext(trace_id="1" * 32, span_id="2" * 16, trace_flags=1),
    )
    await service._topic_judgment([lease]).judge_ready(
        request,
        request.evidence,
        _judgment_context(request),
        execution,
    )
    used = state._daily_tokens.get((f"owner:{OWNER}", day), 0)
    assert used == provider.reserved_tokens
    assert used > 0


@pytest.mark.asyncio
async def test_judgment_uses_lease_renewed_during_converse() -> None:
    state = MemoryState()
    question_id = uuid4()
    lease = await state.acquire(
        owner_key=OWNER,
        environment_id="alpha",
        question_id=question_id,
        holder_id=uuid4(),
        now=NOW,
    )
    await state.open_budget(
        question_id=question_id,
        owner_key=OWNER,
        environment_id="alpha",
        token_limit=100_000,
        expires_at=NOW + timedelta(hours=1),
        lease=lease,
        operation_id=uuid4(),
    )
    lease_holder = [lease]
    provider = _GuardrailProvider()
    seen_reserve = []
    seen_mark_started = []
    seen_settle = []
    reserve = state.reserve
    mark_started = state.mark_started
    settle = state.settle

    async def renew_during_count() -> None:
        lease_holder[0] = await state.renew(lease_holder[0], now=NOW + timedelta(seconds=30))

    async def renew_during_converse() -> None:
        lease_holder[0] = await state.renew(lease_holder[0], now=NOW + timedelta(seconds=60))

    async def capture_reserve(
        *,
        question_id,
        topic_id,
        tokens,
        lease,
        operation_id,
        now,
        owner_daily_limit,
        service_daily_limit,
        lease_supplier=None,
    ):
        seen_reserve.append(lease)
        return await reserve(
            question_id=question_id,
            topic_id=topic_id,
            tokens=tokens,
            lease=lease,
            operation_id=operation_id,
            now=now,
            owner_daily_limit=owner_daily_limit,
            service_daily_limit=service_daily_limit,
            lease_supplier=lease_supplier,
        )

    async def capture_mark_started(reservation, *, lease, operation_id, now, lease_supplier=None):
        seen_mark_started.append(lease)
        return await mark_started(
            reservation,
            lease=lease,
            operation_id=operation_id,
            now=now,
            lease_supplier=lease_supplier,
        )

    async def capture_settle(
        reservation,
        *,
        charged_tokens,
        lease,
        operation_id,
        now,
        release=False,
        lease_supplier=None,
    ):
        seen_settle.append(lease)
        return await settle(
            reservation,
            charged_tokens=charged_tokens,
            lease=lease,
            operation_id=operation_id,
            now=now,
            release=release,
            lease_supplier=lease_supplier,
        )

    state.reserve = capture_reserve  # type: ignore[method-assign]
    state.mark_started = capture_mark_started  # type: ignore[method-assign]
    state.settle = capture_settle  # type: ignore[method-assign]
    provider.during_count = renew_during_count
    provider.during_converse = renew_during_converse
    service = ApplicationService(
        clock=_Clock(),
        catalog=object(),  # type: ignore[arg-type]
        planner=object(),  # type: ignore[arg-type]
        site_policy=object(),  # type: ignore[arg-type]
        plans=object(),  # type: ignore[arg-type]
        admissions=object(),  # type: ignore[arg-type]
        question_admission=object(),  # type: ignore[arg-type]
        leases=object(),  # type: ignore[arg-type]
        budgets=state,
        completions=object(),  # type: ignore[arg-type]
        fetches=object(),  # type: ignore[arg-type]
        playbooks=object(),  # type: ignore[arg-type]
        judgment_engine=object(),  # type: ignore[arg-type]
        judgment_provider=provider,
        finding_validator=_Validator(),
        telemetry=None,
        feedback_sink=object(),  # type: ignore[arg-type]
        feedback_store=state,
        receipts=object(),  # type: ignore[arg-type]
        runtime=object(),  # type: ignore[arg-type]
        models=(_model(),),
    )
    request = _judgment_request(question_id)
    execution = ExecutionContext(
        question_id=question_id,
        operation="ask",
        owner_key=OWNER,
        environment_id="alpha",
        deadline_at=NOW + timedelta(minutes=5),
        cancel=_FakeCancellation(),  # type: ignore[arg-type]
        calls=object(),  # type: ignore[arg-type]
        admission=object(),  # type: ignore[arg-type]
        trace_context=TraceContext(trace_id="3" * 32, span_id="4" * 16, trace_flags=1),
    )

    await service._topic_judgment(lease_holder).judge_ready(
        request,
        request.evidence,
        _judgment_context(request),
        execution,
    )

    assert lease_holder[0].last_renewed_at > lease.last_renewed_at
    assert len(seen_reserve) == 1
    assert seen_reserve[0].last_renewed_at == NOW + timedelta(seconds=30)
    assert seen_mark_started == seen_reserve
    assert seen_settle == [lease_holder[0]]
