from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import TypeAdapter

from ai_soc.application.errors import ServiceFailure
from ai_soc.application.service import _LEASE_RENEW_INTERVAL, ApplicationService
from ai_soc.contracts.models import (
    Clarify,
    Effort,
    ErrorCode,
    HTTPSUrl,
    Lease,
    ModelCapability,
    PlanProvenance,
    QuestionPlan,
    TopicPlan,
)
from ai_soc.state.memory import MemoryState

NOW = datetime(2026, 10, 6, 12, tzinfo=UTC)


class _Clock:
    def __init__(self, now: datetime) -> None:
        self._now = now

    def now(self) -> datetime:
        return self._now

    def advance(self, seconds: int) -> None:
        self._now = self._now + timedelta(seconds=seconds)

    def monotonic(self) -> float:
        return float(self._now.timestamp())


class _RecordingLeases:
    def __init__(self, inner: MemoryState) -> None:
        self.inner = inner
        self.renew_calls = 0

    async def renew(self, lease: Lease, *, now: datetime) -> Lease:
        self.renew_calls += 1
        return await self.inner.renew(lease, now=now)

    async def release(self, lease: Lease) -> None:
        await self.inner.release(lease)


def _model(*, efforts: tuple[Effort, ...] = (Effort.low,)) -> ModelCapability:
    return ModelCapability(
        id="fixture-model",
        label="Fixture model",
        region="us-east-1",
        resource_arns=("arn:aws:bedrock:us-east-1:123456789012:inference-profile/fixture",),
        context_tokens=8192,
        max_output_tokens=1024,
        count_tokens_model_id="fixture-count-model",
        efforts=efforts,
        effort_transport="additionalModelRequestFields",
        effort_parameters={effort: {} for effort in efforts},
        output_strategy="strict_json_messages",
        count_strategy="count_tokens_converse",
        count_contract_sha256="b" * 64,
        cache_min_tokens=0,
        cache_max_checkpoints=0,
        cache_ttl="5m",
        validated_at=NOW,
        primary_doc_url=TypeAdapter(HTTPSUrl).validate_python("https://docs.example.test/model"),
    )


def _plan(
    *, model_id: str | None = "fixture-model", effort: Effort | None = Effort.low
) -> QuestionPlan:
    return QuestionPlan(
        question_id=uuid4(),
        environment_id="alpha",
        owner_key="a" * 64,
        content_sha="b" * 40,
        policy_hash="c" * 63 + "1",
        language="en",
        timezone="UTC",
        anchor_at=NOW,
        model_id=model_id,
        effort=effort,
        topics=[
            TopicPlan(
                topic_id="ldap",
                ordinal=0,
                document=False,
                failure=False,
                judgment=True,
                fetches=[],
                cue_ids=[],
                alias_ids=[],
            )
        ],
        provenance=PlanProvenance(
            cue_pack_sha="d" * 64,
            normalized_question_hash="e" * 64,
            origin="new",
            matched_spans=[],
        ),
    )


def _service(
    *,
    leases: object,
    models: tuple[ModelCapability, ...],
    clock: _Clock | None = None,
    feedback_store: MemoryState | None = None,
) -> ApplicationService:
    return ApplicationService(
        clock=clock or _Clock(NOW),
        catalog=object(),  # type: ignore[arg-type]
        planner=object(),  # type: ignore[arg-type]
        site_policy=object(),  # type: ignore[arg-type]
        plans=object(),  # type: ignore[arg-type]
        admissions=object(),  # type: ignore[arg-type]
        question_admission=object(),  # type: ignore[arg-type]
        leases=leases,  # type: ignore[arg-type]
        budgets=object(),  # type: ignore[arg-type]
        completions=object(),  # type: ignore[arg-type]
        fetches=object(),  # type: ignore[arg-type]
        playbooks=object(),  # type: ignore[arg-type]
        judgment_engine=object(),  # type: ignore[arg-type]
        judgment_provider=object(),  # type: ignore[arg-type]
        finding_validator=object(),  # type: ignore[arg-type]
        telemetry=object(),  # type: ignore[arg-type]
        feedback_sink=object(),  # type: ignore[arg-type]
        feedback_store=feedback_store if feedback_store is not None else MemoryState(),
        receipts=object(),  # type: ignore[arg-type]
        runtime=object(),  # type: ignore[arg-type]
        models=models,
    )


@pytest.mark.asyncio
async def test_h1_maybe_renew_lease_calls_store_at_most_every_twenty_seconds() -> None:
    clock = _Clock(NOW)
    state = MemoryState()
    leases = _RecordingLeases(state)
    lease = await state.acquire(
        owner_key="a" * 64,
        environment_id="alpha",
        question_id=uuid4(),
        holder_id=uuid4(),
        now=NOW,
    )
    service = _service(leases=leases, models=(_model(),), clock=clock, feedback_store=state)
    current = lease
    current = await service._maybe_renew_lease(current)
    assert leases.renew_calls == 0
    clock.advance(int(_LEASE_RENEW_INTERVAL.total_seconds()))
    current = await service._maybe_renew_lease(current)
    assert leases.renew_calls == 1
    clock.advance(5)
    current = await service._maybe_renew_lease(current)
    assert leases.renew_calls == 1
    clock.advance(int(_LEASE_RENEW_INTERVAL.total_seconds()))
    await service._maybe_renew_lease(current)
    assert leases.renew_calls == 2


def test_h2_judgment_selection_issue_returns_model_selection_clarify() -> None:
    service = _service(leases=object(), models=(_model(),))
    issue = service._judgment_selection_issue(_plan(model_id=None, effort=None))
    assert isinstance(issue, Clarify)
    assert issue.kind == "model_selection"


def test_h2_judgment_selection_issue_rejects_unknown_model_before_backend() -> None:
    service = _service(leases=object(), models=(_model(),))
    with pytest.raises(ServiceFailure) as error:
        service._judgment_selection_issue(_plan(model_id="missing-model"))
    assert error.value.error.code == ErrorCode.UNSUPPORTED_MODEL
