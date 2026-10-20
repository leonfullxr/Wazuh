from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import uuid4

import pytest

from ai_soc.application.composition import _JudgmentProviderAdapter
from ai_soc.application.errors import ServiceFailure
from ai_soc.application.runtime import RequestCancellation, RequestCancelled
from ai_soc.application.service import ApplicationService
from ai_soc.contracts.models import (
    DomainError,
    ErrorCode,
    ExecutionContext,
    JudgmentRequest,
    JudgmentResult,
    JudgmentState,
    LeftOut,
    LeftOutReason,
    RawJudgment,
    Reservation,
    Skip,
    TokenUsage,
    TopicAnswer,
    TraceContext,
)
from ai_soc.contracts.ports import JudgmentProvider
from ai_soc.judgment.bedrock import ProviderFailure
from ai_soc.state.memory import MemoryState
from ai_soc.validation.findings import FindingValidator
from tests.unit.application.test_daily_token_judgment import (
    NOW as CLOCK_NOW,
)
from tests.unit.application.test_daily_token_judgment import (
    OWNER,
    _Clock,
    _FakeCancellation,
    _judgment_context,
    _judgment_request,
    _model,
)
from tests.unit.application.test_lease_and_selection import _plan

NOW = datetime(2026, 10, 13, 12, tzinfo=UTC)


class _Provider:
    def __init__(self, failure: ProviderFailure | None = None) -> None:
        self.failure = failure
        self.count_calls = 0
        self.converse_calls = 0

    async def count(self, request: JudgmentRequest, *, execution: ExecutionContext) -> int:
        self.count_calls += 1
        return 100

    async def converse(
        self, request: JudgmentRequest, *, execution: ExecutionContext
    ) -> RawJudgment:
        self.converse_calls += 1
        if self.failure is not None:
            raise self.failure
        return RawJudgment(
            text="",
            stop_reason="end_turn",
            guardrail_intervened=False,
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
            provider_request_id="judgment-outcomes",
        )


class _CancelAfterCountProvider:
    def __init__(self, cancellation: RequestCancellation) -> None:
        self.cancellation = cancellation

    async def count(self, request: JudgmentRequest, *, execution: ExecutionContext) -> int:
        self.cancellation.cancel()
        return 100

    async def converse(
        self, request: JudgmentRequest, *, execution: ExecutionContext
    ) -> RawJudgment:
        raise AssertionError("converse must not run after cancellation")


class _Validator:
    def __init__(self, state: JudgmentState) -> None:
        self.state = state

    def validate(self, raw: RawJudgment, pack: object, *, context: object) -> JudgmentResult:
        return JudgmentResult(state=self.state, sentences=[], removed=[])


def _service(
    state: MemoryState, provider: JudgmentProvider, validator: FindingValidator
) -> ApplicationService:
    return ApplicationService(
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
        finding_validator=validator,
        telemetry=None,
        feedback_sink=object(),  # type: ignore[arg-type]
        feedback_store=state,
        receipts=object(),  # type: ignore[arg-type]
        runtime=object(),  # type: ignore[arg-type]
        models=(_model(),),
    )


async def _judge(
    provider: JudgmentProvider,
    validator: FindingValidator,
    *,
    deadline_at: datetime | None = None,
) -> tuple[JudgmentResult, LeftOut | None, MemoryState]:
    state = MemoryState()
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
    service = _service(state, provider, validator)
    request = _judgment_request(lease.question_id)
    execution = ExecutionContext(
        question_id=lease.question_id,
        operation="ask",
        owner_key=OWNER,
        environment_id="alpha",
        deadline_at=deadline_at or CLOCK_NOW + timedelta(minutes=5),
        cancel=_FakeCancellation(),  # type: ignore[arg-type]
        calls=object(),  # type: ignore[arg-type]
        admission=object(),  # type: ignore[arg-type]
        trace_context=TraceContext(trace_id="1" * 32, span_id="2" * 16, trace_flags=1),
    )
    result, left = await service._topic_judgment([lease]).judge_ready(
        request,
        request.evidence,
        _judgment_context(request),
        execution,
    )
    return result, left, state


@pytest.mark.asyncio
async def test_deadline_too_close_for_count_skips_all_calls() -> None:
    provider = _Provider()
    result, left, state = await _judge(
        provider,
        cast(FindingValidator, _Validator(JudgmentState.validated)),
        deadline_at=CLOCK_NOW + timedelta(seconds=24),
    )

    assert result.state == JudgmentState.deadline_exceeded
    assert left is not None
    assert left.reason == LeftOutReason.deadline_exceeded
    assert left.retryable is True
    assert provider.count_calls == 0
    assert provider.converse_calls == 0
    assert (
        sum(tokens for (key, _), tokens in state._daily_tokens.items() if key == f"owner:{OWNER}")
        == 0
    )


@pytest.mark.asyncio
async def test_deadline_too_close_for_converse_reserves_nothing() -> None:
    provider = _Provider()
    result, left, state = await _judge(
        provider,
        cast(FindingValidator, _Validator(JudgmentState.validated)),
        deadline_at=CLOCK_NOW + timedelta(seconds=55),
    )

    assert result.state == JudgmentState.deadline_exceeded
    assert left is not None
    assert left.reason == LeftOutReason.deadline_exceeded
    assert left.retryable is True
    assert provider.count_calls == 1
    assert provider.converse_calls == 0
    assert state.reservations == {}
    assert (
        sum(tokens for (key, _), tokens in state._daily_tokens.items() if key == f"owner:{OWNER}")
        == 0
    )


@pytest.mark.asyncio
async def test_deadline_with_room_still_judges() -> None:
    provider = _Provider()
    result, left, _ = await _judge(
        provider,
        cast(FindingValidator, _Validator(JudgmentState.validated)),
        deadline_at=CLOCK_NOW + timedelta(seconds=60),
    )

    assert result.state == JudgmentState.validated
    assert left is None
    assert provider.count_calls == 1
    assert provider.converse_calls == 1


@pytest.mark.asyncio
async def test_converse_call_cap_releases_reservation() -> None:
    provider = _JudgmentProviderAdapter(
        _Provider(ProviderFailure("capacity_limited", retryable=True))
    )
    result, left, state = await _judge(
        provider, cast(FindingValidator, _Validator(JudgmentState.validated))
    )

    assert result.state == JudgmentState.capacity_limited
    assert left is not None
    assert left.reason == LeftOutReason.capacity_limited
    assert left.retryable is True
    assert (
        sum(tokens for (key, _), tokens in state._daily_tokens.items() if key == f"owner:{OWNER}")
        == 0
    )


@pytest.mark.asyncio
async def test_raised_guardrail_block_is_guardrail_blocked_and_charged() -> None:
    provider = _JudgmentProviderAdapter(
        _Provider(ProviderFailure("guardrail_blocked", retryable=False))
    )
    result, left, state = await _judge(
        provider, cast(FindingValidator, _Validator(JudgmentState.validated))
    )

    assert result.state == JudgmentState.guardrail_blocked
    assert left is not None
    assert left.reason == LeftOutReason.guardrail_blocked
    assert left.retryable is False
    charges = [
        tokens for (key, _), tokens in state._daily_tokens.items() if key == f"owner:{OWNER}"
    ]
    assert sum(charges) > 0


@pytest.mark.asyncio
async def test_cancellation_after_count_does_not_reserve() -> None:
    state = MemoryState()
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
    cancellation = RequestCancellation()
    service = _service(
        state,
        cast(JudgmentProvider, _CancelAfterCountProvider(cancellation)),
        cast(FindingValidator, _Validator(JudgmentState.validated)),
    )
    request = _judgment_request(lease.question_id)
    execution = ExecutionContext(
        question_id=lease.question_id,
        operation="ask",
        owner_key=OWNER,
        environment_id="alpha",
        deadline_at=NOW + timedelta(minutes=5),
        cancel=cancellation,
        calls=object(),  # type: ignore[arg-type]
        admission=object(),  # type: ignore[arg-type]
        trace_context=TraceContext(trace_id="1" * 32, span_id="2" * 16, trace_flags=1),
    )

    with pytest.raises(RequestCancelled):
        await service._topic_judgment([lease]).judge_ready(
            request,
            request.evidence,
            _judgment_context(request),
            execution,
        )

    assert state.reservations == {}
    charges = [
        tokens for (key, _), tokens in state._daily_tokens.items() if key == f"owner:{OWNER}"
    ]
    assert sum(charges) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("judgment_state", "reason", "retryable"),
    [
        (JudgmentState.invalid_output, LeftOutReason.invalid_output, True),
        (JudgmentState.all_removed, LeftOutReason.all_removed, True),
        (JudgmentState.guardrail_blocked, LeftOutReason.guardrail_blocked, False),
    ],
)
async def test_validator_failure_state_returns_left_out(
    judgment_state: JudgmentState, reason: LeftOutReason, retryable: bool
) -> None:
    result, left, _ = await _judge(_Provider(), cast(FindingValidator, _Validator(judgment_state)))

    assert result.state == judgment_state
    assert left is not None
    assert left.stage == "judgment"
    assert left.reason == reason
    assert left.retryable is retryable


@pytest.mark.asyncio
async def test_no_findings_validation_has_no_left_out() -> None:
    result, left, _ = await _judge(
        _Provider(), cast(FindingValidator, _Validator(JudgmentState.no_findings))
    )

    assert result.state == JudgmentState.no_findings
    assert left is None


def _block(topic_id: str, ordinal: int, judgment_state: JudgmentState) -> TopicAnswer:
    return TopicAnswer(
        topic_id=topic_id,
        ordinal=ordinal,
        document=None,
        missing=[],
        tables=[],
        checks=[],
        judgment=JudgmentResult(state=judgment_state, sentences=[], removed=[]),
    )


def test_followup_lists_only_retryable_left_outs() -> None:
    state = MemoryState()
    service = _service(
        state,
        _Provider(),
        cast(FindingValidator, _Validator(JudgmentState.no_findings)),
    )
    retryable = LeftOut(
        topic_id="ldap",
        stage="judgment",
        reason=LeftOutReason.model_unavailable,
        retryable=True,
    )
    blocked = LeftOut(
        topic_id="vpn",
        stage="judgment",
        reason=LeftOutReason.guardrail_blocked,
        retryable=False,
    )
    blocks = [
        _block("ldap", 0, JudgmentState.model_unavailable),
        _block("vpn", 1, JudgmentState.guardrail_blocked),
        _block("dns", 2, JudgmentState.validated),
    ]

    record = service._followup(_plan(), None, blocks, [retryable, blocked])

    assert record is not None
    assert record.leftout_topic_ids == ["ldap"]
    assert record.leftout_stages == [retryable]
    assert record.answered_topic_ids == ["dns"]


class _NoCallProvider:
    def __init__(self) -> None:
        self.calls = 0

    async def count(self, request: JudgmentRequest, *, execution: ExecutionContext) -> int:
        self.calls += 1
        return 100

    async def converse(
        self, request: JudgmentRequest, *, execution: ExecutionContext
    ) -> RawJudgment:
        self.calls += 1
        raise RuntimeError("converse must not run after an engine skip")


_SKIP_LEFT_OUT = LeftOut(
    topic_id="ldap",
    stage="judgment",
    reason=LeftOutReason.evidence_unavailable,
    retryable=True,
)


class _SkipEngine:
    def prepare(
        self, plan: object, pack: object, *, context: object, model: object, effort: object
    ) -> Skip:
        return Skip(
            result=JudgmentResult(
                state=JudgmentState.evidence_unavailable, sentences=[], removed=[]
            ),
            left_out=_SKIP_LEFT_OUT,
        )


@pytest.mark.asyncio
async def test_engine_skip_returns_prepared_result_without_provider_calls() -> None:
    state = MemoryState()
    lease = await state.acquire(
        owner_key=OWNER,
        environment_id="alpha",
        question_id=uuid4(),
        holder_id=uuid4(),
        now=NOW,
    )
    provider = _NoCallProvider()
    service = _service(state, provider, cast(FindingValidator, _Validator(JudgmentState.validated)))
    service.judgment_engine = _SkipEngine()
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

    result, left = await service._topic_judgment([lease]).judge(
        _plan().topics[0],
        request.evidence,
        object(),  # type: ignore[arg-type]
        model=None,
        effort=None,
        question="q",
        execution=execution,
    )

    assert result.state == JudgmentState.evidence_unavailable
    assert left == _SKIP_LEFT_OUT
    assert provider.calls == 0


class _CapacityFailureProvider(_Provider):
    async def converse(
        self, request: JudgmentRequest, *, execution: ExecutionContext
    ) -> RawJudgment:
        raise ServiceFailure(
            DomainError(
                code=ErrorCode.CAPACITY_LIMIT,
                message="capacity",
                retryable=True,
                trace_id="3" * 32,
            )
        )


@pytest.mark.asyncio
async def test_pre_invocation_capacity_failure_releases_reservation() -> None:
    result, left, state = await _judge(
        _CapacityFailureProvider(), cast(FindingValidator, _Validator(JudgmentState.validated))
    )

    assert result.state == JudgmentState.capacity_limited
    assert left is not None
    assert left.reason == LeftOutReason.capacity_limited
    charges = [
        tokens for (key, _), tokens in state._daily_tokens.items() if key == f"owner:{OWNER}"
    ]
    assert sum(charges) == 0


@pytest.mark.asyncio
async def test_cancellation_during_reserve_leaves_reservation_unstarted() -> None:
    cancellation = RequestCancellation()

    class _CancelOnReserve(MemoryState):
        async def reserve(self, *args: object, **kwargs: object) -> Reservation:
            reservation = await super().reserve(*args, **kwargs)  # type: ignore[arg-type]
            cancellation.cancel()
            return reservation

    state = _CancelOnReserve()
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
    service = _service(
        state,
        cast(JudgmentProvider, _Provider()),
        cast(FindingValidator, _Validator(JudgmentState.validated)),
    )
    request = _judgment_request(lease.question_id)
    execution = ExecutionContext(
        question_id=lease.question_id,
        operation="ask",
        owner_key=OWNER,
        environment_id="alpha",
        deadline_at=NOW + timedelta(minutes=5),
        cancel=cancellation,
        calls=object(),  # type: ignore[arg-type]
        admission=object(),  # type: ignore[arg-type]
        trace_context=TraceContext(trace_id="1" * 32, span_id="2" * 16, trace_flags=1),
    )

    with pytest.raises(RequestCancelled):
        await service._topic_judgment([lease]).judge_ready(
            request,
            request.evidence,
            _judgment_context(request),
            execution,
        )

    assert [reservation.state for reservation in state.reservations.values()] == ["reserved"]
