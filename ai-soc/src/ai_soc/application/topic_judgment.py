"""Per-topic judgment sequence: eligibility, budgets, provider call and settlement."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import timedelta
from uuid import uuid4

from ai_soc.application.errors import ServiceFailure
from ai_soc.contracts.models import (
    Effort,
    ErrorCode,
    EvidencePack,
    ExecutionContext,
    JudgmentRequest,
    JudgmentResult,
    JudgmentState,
    Lease,
    LeftOut,
    LeftOutReason,
    ModelCapability,
    RemovedReason,
    Reservation,
    StageName,
    TopicPlan,
    TraceContext,
    ValidationContext,
)
from ai_soc.contracts.ports import (
    BudgetStore,
    Clock,
    FindingValidator,
    JudgmentEngine,
    JudgmentProvider,
)
from ai_soc.judgment.capabilities import CapabilityError
from ai_soc.judgment.catalog import CatalogUnavailable, capture_catalog_snapshot
from ai_soc.judgment.counting import fits_context, reserved_gross_tokens
from ai_soc.judgment.guardrail_accounting import judgment_settled_tokens
from ai_soc.state.errors import StateFailure
from ai_soc.telemetry.metrics import MetricExporter
from ai_soc.telemetry.operational import (
    emit_budget_charged,
    emit_budget_reserved,
    emit_cache_tokens,
    emit_removed_finding,
)

_STOP_NEW_WORK_BEFORE_DEADLINE = timedelta(seconds=10)
# Contract deadline hierarchy: admission acquire 5 s + count 5 s + admission release 5 s.
_COUNT_WORST_CASE = timedelta(seconds=15)
# Reserve, mark-started, admission acquire 5 s each + Converse 30 s + admission release 5 s.
_CONVERSE_PATH_WORST_CASE = timedelta(seconds=50)

_PRE_INVOCATION_SETTLE = frozenset(
    {
        ErrorCode.CAPACITY_LIMIT,
        ErrorCode.CONTEXT_EXCEEDED,
        ErrorCode.TOKEN_COUNT_UNAVAILABLE,
    }
)
_JUDGMENT_FAILURE_STATE: dict[ErrorCode, JudgmentState] = {
    ErrorCode.CONTEXT_EXCEEDED: JudgmentState.context_exceeded,
    ErrorCode.BUDGET_EXCEEDED: JudgmentState.budget_exceeded,
    ErrorCode.CAPACITY_LIMIT: JudgmentState.capacity_limited,
    ErrorCode.DEADLINE_EXCEEDED: JudgmentState.deadline_exceeded,
    ErrorCode.GUARDRAIL_BLOCKED: JudgmentState.guardrail_blocked,
    ErrorCode.INVALID_MODEL_OUTPUT: JudgmentState.invalid_output,
    ErrorCode.MODEL_UNAVAILABLE: JudgmentState.model_unavailable,
    ErrorCode.TOKEN_COUNT_UNAVAILABLE: JudgmentState.token_count_unavailable,
}
_JUDGMENT_LEFT_OUT_REASON: dict[JudgmentState, LeftOutReason] = {
    JudgmentState.context_exceeded: LeftOutReason.context_exceeded,
    JudgmentState.budget_exceeded: LeftOutReason.budget_exceeded,
    JudgmentState.capacity_limited: LeftOutReason.capacity_limited,
    JudgmentState.deadline_exceeded: LeftOutReason.deadline_exceeded,
    JudgmentState.guardrail_blocked: LeftOutReason.guardrail_blocked,
    JudgmentState.invalid_output: LeftOutReason.invalid_output,
    JudgmentState.model_unavailable: LeftOutReason.model_unavailable,
    JudgmentState.token_count_unavailable: LeftOutReason.token_count_unavailable,
    JudgmentState.all_removed: LeftOutReason.all_removed,
}
_NOT_RETRYABLE_JUDGMENT = frozenset({JudgmentState.guardrail_blocked})


def _catalog_unavailable(request: JudgmentRequest) -> tuple[JudgmentResult, LeftOut]:
    """Abstain on an unusable approved catalog before any budget, count or admission work."""
    result = JudgmentResult(
        state=JudgmentState.evidence_unavailable,
        model_id=request.model.id,
        effort=Effort(request.effort) if request.effort is not None else None,
        sentences=[],
        removed=[],
    )
    return result, LeftOut(
        topic_id=request.topic_id,
        stage="judgment",
        reason=LeftOutReason.evidence_unavailable,
        retryable=False,
    )


def judgment_failure(
    request: JudgmentRequest,
    code: ErrorCode,
    *,
    counting: bool,
    retryable: bool | None = None,
) -> tuple[JudgmentResult, LeftOut]:
    chosen = _JUDGMENT_FAILURE_STATE.get(
        code,
        JudgmentState.token_count_unavailable if counting else JudgmentState.model_unavailable,
    )
    result = JudgmentResult(
        state=chosen,
        model_id=request.model.id,
        effort=Effort(request.effort) if request.effort is not None else None,
        sentences=[],
        removed=[],
    )
    return result, LeftOut(
        topic_id=request.topic_id,
        stage="judgment",
        reason=_JUDGMENT_LEFT_OUT_REASON[chosen],
        retryable=chosen not in _NOT_RETRYABLE_JUDGMENT if retryable is None else retryable,
    )


@dataclass(frozen=True, slots=True)
class QuestionBudgetHandle:
    """Per-question view of the budget store, bound to the live lease holder and daily limits."""

    budgets: BudgetStore
    clock: Clock
    lease_holder: list[Lease]
    token_limit: int
    owner_daily_limit: int
    service_daily_limit: int

    async def daily_blocks(self, request: JudgmentRequest, *, tokens: int | None = None) -> bool:
        owner_key = self.lease_holder[0].owner_key
        now = self.clock.now()
        if await self.budgets.daily_judgment_blocked(
            owner_key=owner_key,
            now=now,
            owner_daily_limit=self.owner_daily_limit,
            service_daily_limit=self.service_daily_limit,
        ):
            return True
        if tokens is not None:
            return await self.budgets.daily_cannot_reserve(
                owner_key=owner_key,
                tokens=tokens,
                now=now,
                owner_daily_limit=self.owner_daily_limit,
                service_daily_limit=self.service_daily_limit,
            )
        question_remaining = await self.budgets.question_budget_remaining(request.question_id)
        bound = min(
            self.token_limit,
            request.model.context_tokens,
            question_remaining if question_remaining is not None else self.token_limit,
        )
        return await self.budgets.daily_cannot_reserve(
            owner_key=owner_key,
            tokens=bound,
            now=now,
            owner_daily_limit=self.owner_daily_limit,
            service_daily_limit=self.service_daily_limit,
        )

    async def exceeded_retryable(self, request: JudgmentRequest, tokens: int) -> bool:
        owner_key = self.lease_holder[0].owner_key
        now = self.clock.now()
        if await self.budgets.daily_cannot_reserve(
            owner_key=owner_key,
            tokens=tokens,
            now=now,
            owner_daily_limit=self.owner_daily_limit,
            service_daily_limit=self.service_daily_limit,
        ):
            return False
        remaining = await self.budgets.question_budget_remaining(request.question_id)
        if remaining is None:
            return True
        return remaining < tokens

    async def reserve(self, request: JudgmentRequest, tokens: int) -> Reservation:
        return await self.budgets.reserve(
            question_id=request.question_id,
            topic_id=request.topic_id,
            tokens=tokens,
            lease=self.lease_holder[0],
            operation_id=uuid4(),
            now=self.clock.now(),
            owner_daily_limit=self.owner_daily_limit,
            service_daily_limit=self.service_daily_limit,
            lease_supplier=lambda: self.lease_holder[0],
        )

    async def mark_started(self, reservation: Reservation) -> Reservation:
        return await self.budgets.mark_started(
            reservation=reservation,
            lease=self.lease_holder[0],
            operation_id=uuid4(),
            now=self.clock.now(),
            lease_supplier=lambda: self.lease_holder[0],
        )

    async def release(self, reservation: Reservation) -> None:
        await self.budgets.settle(
            reservation,
            charged_tokens=None,
            lease=self.lease_holder[0],
            operation_id=uuid4(),
            now=self.clock.now(),
            release=True,
            lease_supplier=lambda: self.lease_holder[0],
        )

    async def charge(self, reservation: Reservation, tokens: int | None) -> None:
        await self.budgets.settle(
            reservation,
            charged_tokens=tokens,
            lease=self.lease_holder[0],
            operation_id=uuid4(),
            now=self.clock.now(),
            lease_supplier=lambda: self.lease_holder[0],
        )


@dataclass(frozen=True, slots=True)
class TopicJudgment:
    engine: JudgmentEngine
    provider: JudgmentProvider
    validator: FindingValidator
    budget: QuestionBudgetHandle
    clock: Clock
    stage: Callable[[StageName, TraceContext], AbstractContextManager[object]]
    metrics: MetricExporter | None

    def _fits(self, execution: ExecutionContext, worst_case: timedelta) -> bool:
        latest_start = execution.deadline_at - _STOP_NEW_WORK_BEFORE_DEADLINE
        return self.clock.now() + worst_case <= latest_start

    async def judge(
        self,
        topic: TopicPlan,
        pack: EvidencePack,
        context: ValidationContext,
        *,
        model: ModelCapability | None,
        effort: Effort | None,
        question: str,
        execution: ExecutionContext,
    ) -> tuple[JudgmentResult, LeftOut | None]:
        preparation = self.engine.prepare(
            topic,
            pack,
            context=context,
            model=model,
            effort=effort,
        )
        if preparation.kind == "skip":
            return preparation.result, preparation.left_out
        return await self.judge_ready(
            preparation.request.model_copy(update={"question": question}),
            pack,
            context,
            execution,
        )

    async def judge_ready(
        self,
        request: JudgmentRequest,
        pack: EvidencePack,
        context: ValidationContext,
        execution: ExecutionContext,
    ) -> tuple[JudgmentResult, LeftOut | None]:
        try:
            snapshot = capture_catalog_snapshot(request, pack, context)
        except CatalogUnavailable:
            return _catalog_unavailable(request)
        if await self.budget.daily_blocks(request):
            return judgment_failure(
                request, ErrorCode.BUDGET_EXCEEDED, counting=False, retryable=False
            )
        if not self._fits(execution, _COUNT_WORST_CASE):
            return judgment_failure(request, ErrorCode.DEADLINE_EXCEEDED, counting=True)
        try:
            execution.cancel.raise_if_cancelled()
            with self.stage(StageName.count_stage, execution.trace_context):
                counted = await self.provider.count(
                    snapshot.request_view(request), execution=execution
                )
        except ServiceFailure as error:
            return judgment_failure(request, error.error.code, counting=True)
        except Exception:
            if execution.cancel.is_cancelled():
                raise
            return judgment_failure(request, ErrorCode.TOKEN_COUNT_UNAVAILABLE, counting=True)
        if type(counted) is not int or counted < 0:
            return judgment_failure(request, ErrorCode.TOKEN_COUNT_UNAVAILABLE, counting=True)
        if not fits_context(counted, request):
            return judgment_failure(request, ErrorCode.CONTEXT_EXCEEDED, counting=True)
        reserve_tokens = reserved_gross_tokens(counted, request)
        if await self.budget.daily_blocks(request, tokens=reserve_tokens):
            return judgment_failure(
                request, ErrorCode.BUDGET_EXCEEDED, counting=False, retryable=False
            )
        if not self._fits(execution, _CONVERSE_PATH_WORST_CASE):
            return judgment_failure(request, ErrorCode.DEADLINE_EXCEEDED, counting=False)
        execution.cancel.raise_if_cancelled()
        try:
            with self.stage(StageName.reserve, execution.trace_context):
                reservation = await self.budget.reserve(request, reserve_tokens)
            metrics = self.metrics
            if metrics is not None:
                emit_budget_reserved(metrics, reservation.reserved_tokens)
        except ServiceFailure as error:
            if error.error.code not in {
                ErrorCode.BUDGET_EXCEEDED,
                ErrorCode.CAPACITY_LIMIT,
                ErrorCode.DEADLINE_EXCEEDED,
            }:
                raise
            retryable = True
            if error.error.code == ErrorCode.BUDGET_EXCEEDED:
                retryable = await self.budget.exceeded_retryable(request, reserve_tokens)
            return judgment_failure(request, error.error.code, counting=False, retryable=retryable)
        except StateFailure as error:
            if error.code == ErrorCode.BUDGET_EXCEEDED:
                retryable = await self.budget.exceeded_retryable(request, reserve_tokens)
                return judgment_failure(request, error.code, counting=False, retryable=retryable)
            raise

        execution.cancel.raise_if_cancelled()
        reservation = await self.budget.mark_started(reservation)
        bound_request = snapshot.request_view(request).model_copy(
            update={
                "reservation_id": reservation.reservation_id,
                "reserved_tokens": reservation.reserved_tokens,
            }
        )
        try:
            with self.stage(StageName.converse, execution.trace_context):
                raw = await self.provider.converse(bound_request, execution=execution)
        except CapabilityError:
            await self.budget.release(reservation)
            return judgment_failure(request, ErrorCode.UNSUPPORTED_EFFORT, counting=False)
        except ServiceFailure as error:
            if error.error.code == ErrorCode.LEASE_LOST or execution.cancel.is_cancelled():
                raise
            if error.error.code in _PRE_INVOCATION_SETTLE:
                await self.budget.release(reservation)
            else:
                await self.budget.charge(reservation, None)
            return judgment_failure(request, error.error.code, counting=False)
        except Exception:
            if execution.cancel.is_cancelled():
                raise
            await self.budget.charge(reservation, None)
            return judgment_failure(request, ErrorCode.MODEL_UNAVAILABLE, counting=False)

        with self.stage(StageName.validate, execution.trace_context):
            result = self.validator.validate(
                raw, snapshot.evidence_view(), context=snapshot.validation_context()
            )
        metrics = self.metrics
        if metrics is not None:
            for finding in result.removed:
                emit_removed_finding(metrics, RemovedReason(finding.reason))
        charged = judgment_settled_tokens(raw, bound_request)
        await self.budget.charge(reservation, charged)
        if metrics is not None and charged is not None:
            emit_budget_charged(metrics, charged)
        if raw.usage is not None:
            if metrics is not None:
                cache_total = raw.usage.cache_read_input_tokens + raw.usage.cache_write_input_tokens
                emit_cache_tokens(metrics, cache_total)
            usage = raw.usage.model_copy(
                update={
                    "topic_id": request.topic_id,
                    "reservation_id": reservation.reservation_id,
                    "reserved_tokens": reservation.reserved_tokens,
                }
            )
            result = result.model_copy(
                update={"model_id": request.model.id, "effort": request.effort, "usage": usage}
            )
        reason = _JUDGMENT_LEFT_OUT_REASON.get(result.state)
        if reason is None:
            return result, None
        return result, LeftOut(
            topic_id=request.topic_id,
            stage="judgment",
            reason=reason,
            retryable=result.state not in _NOT_RETRYABLE_JUDGMENT,
        )
