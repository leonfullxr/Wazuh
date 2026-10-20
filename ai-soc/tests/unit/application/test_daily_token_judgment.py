from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import TypeAdapter

from ai_soc.application.service import ApplicationService
from ai_soc.contracts.models import (
    Effort,
    EvidencePack,
    ExecutionContext,
    FieldId,
    FindingTemplate,
    GuardrailPin,
    HTTPSUrl,
    JudgmentRequest,
    JudgmentState,
    LeftOutReason,
    LocaleText,
    ModelCapability,
    TopicPromptPack,
    TraceContext,
    ValidationContext,
)
from ai_soc.state.daily_tokens import utc_day_start_epoch
from ai_soc.state.memory import MemoryState

NOW = datetime(2026, 9, 30, 12, tzinfo=UTC)
OWNER = "a" * 64


def _model(*, context_tokens: int = 4096) -> ModelCapability:
    return ModelCapability(
        id="fixture-model",
        label="Fixture model",
        region="us-east-1",
        resource_arns=("arn:aws:bedrock:us-east-1:123456789012:inference-profile/fixture",),
        context_tokens=context_tokens,
        max_output_tokens=1024,
        count_tokens_model_id="fixture-count-model",
        efforts=(Effort.low,),
        effort_transport="additionalModelRequestFields",
        effort_parameters={Effort.low: {}},
        output_strategy="strict_json_messages",
        count_strategy="count_tokens_converse",
        count_contract_sha256="b" * 64,
        cache_min_tokens=0,
        cache_max_checkpoints=0,
        cache_ttl="5m",
        validated_at=NOW,
        primary_doc_url=TypeAdapter(HTTPSUrl).validate_python("https://docs.example.test/model"),
    )


class _CountingProvider:
    def __init__(self, *, counted: int = 1_000) -> None:
        self.count_calls = 0
        self._counted = counted

    async def count(self, request: JudgmentRequest, *, execution: ExecutionContext) -> int:
        self.count_calls += 1
        return self._counted

    async def converse(self, *args: object, **kwargs: object) -> object:
        raise AssertionError("converse must not run")


class _FakeCancellation:
    def raise_if_cancelled(self) -> None:
        return None

    def is_cancelled(self) -> bool:
        return False


def _ldap_template() -> FindingTemplate:
    return FindingTemplate(
        template_id="ldap_observation",
        topic_id="ldap",
        kind="observation",
        required_bindings={"rule": (FieldId.rule_id,)},
        texts=LocaleText(en="Observed rule: {rule}", es="Regla observada: {rule}"),
        required_check_outcomes=[],
        allowed_evidence_kinds=["row"],
    )


def _judgment_request(question_id: object | None = None) -> JudgmentRequest:
    model = _model()
    qid = question_id or uuid4()
    evidence = EvidencePack(
        question_id=qid,
        environment_id="alpha",
        topic_id="ldap",
        policy_hash="2" * 64,
        content_sha="a" * 40,
        fetches=[],
        checks=[],
        items=[],
        sha256="3" * 64,
    )
    return JudgmentRequest(
        question_id=qid,
        topic_id="ldap",
        model=model,
        effort=Effort.high,
        language="en",
        standing_rules="RULES",
        topic_pack=TopicPromptPack(
            topic_id="ldap",
            language="en",
            content_sha="a" * 40,
            sha256="4" * 64,
            document_section="DOC",
            internal_context="CTX",
            missing=[],
        ),
        evidence=evidence,
        question="Q",
        max_output_tokens=512,
        guardrail=GuardrailPin(identifier="gr-1", version="1"),
        finding_templates=(_ldap_template(),),
    )


def _judgment_context(request: JudgmentRequest) -> ValidationContext:
    return ValidationContext(
        topic_pack=request.topic_pack,
        templates=request.finding_templates,
        policy_hash=request.evidence.policy_hash,
        content_sha=request.evidence.content_sha,
        language=request.language,
        expected_checks=(),
    )


class _Clock:
    def now(self) -> datetime:
        return NOW


def _service(
    budgets: MemoryState, provider: _CountingProvider, *, owner_daily_limit: int = 200_000
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
        budgets=budgets,
        completions=object(),  # type: ignore[arg-type]
        fetches=object(),  # type: ignore[arg-type]
        playbooks=object(),  # type: ignore[arg-type]
        judgment_engine=object(),  # type: ignore[arg-type]
        judgment_provider=provider,
        finding_validator=object(),  # type: ignore[arg-type]
        telemetry=None,
        feedback_sink=object(),  # type: ignore[arg-type]
        feedback_store=budgets,
        receipts=object(),  # type: ignore[arg-type]
        runtime=object(),  # type: ignore[arg-type]
        models=(_model(),),
        owner_daily_token_limit=owner_daily_limit,
        service_daily_token_limit=1_000_000,
    )


@pytest.mark.asyncio
async def test_judgment_refuses_before_count_when_daily_headroom_below_bound() -> None:
    state = MemoryState()
    day = utc_day_start_epoch(NOW)
    state._daily_tokens[(f"owner:{OWNER}", day)] = 196_100
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
    provider = _CountingProvider()
    service = _service(state, provider)
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
    result, left = await service._topic_judgment([lease]).judge_ready(
        request,
        request.evidence,
        _judgment_context(request),
        execution,
    )
    assert provider.count_calls == 0
    assert result.state == JudgmentState.budget_exceeded
    assert left.reason == LeftOutReason.budget_exceeded
    assert left.retryable is False


@pytest.mark.asyncio
async def test_judgment_after_count_daily_shortfall_is_not_retryable() -> None:
    state = MemoryState()
    day = utc_day_start_epoch(NOW)
    state._daily_tokens[(f"owner:{OWNER}", day)] = 195_000
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
        token_limit=5_000,
        expires_at=NOW + timedelta(hours=1),
        lease=lease,
        operation_id=uuid4(),
    )
    provider = _CountingProvider(counted=5_000)
    service = _service(state, provider)
    request = _judgment_request(lease.question_id).model_copy(
        update={"model": _model(context_tokens=200_000)}
    )
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
    result, left = await service._topic_judgment([lease]).judge_ready(
        request,
        request.evidence,
        _judgment_context(request),
        execution,
    )
    assert provider.count_calls == 1
    assert result.state == JudgmentState.budget_exceeded
    assert left.retryable is False
