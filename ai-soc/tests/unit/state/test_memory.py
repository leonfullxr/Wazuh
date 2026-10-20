from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from ai_soc.contracts.models import (
    AnswerStatus,
    AuditAck,
    CompletionCommand,
    FollowupRecord,
    PlanProvenance,
    QuestionPlan,
)
from ai_soc.state.errors import StateFailure
from ai_soc.state.memory import MemoryState

NOW = datetime(2026, 9, 30, 12, tzinfo=UTC)


def followup_record() -> FollowupRecord:
    plan = QuestionPlan(
        question_id=uuid4(),
        environment_id="alpha",
        owner_key="a" * 64,
        content_sha="b" * 40,
        policy_hash="c" * 63 + "1",
        language="en",
        timezone="UTC",
        anchor_at=NOW,
        topics=[],
        provenance=PlanProvenance(
            cue_pack_sha="d" * 64,
            normalized_question_hash="e" * 64,
            origin="new",
            matched_spans=[],
        ),
    )
    return FollowupRecord(
        followup_id=uuid4(),
        owner_key=plan.owner_key,
        environment_id=plan.environment_id,
        plan=plan,
        answered_topic_ids=[],
        leftout_topic_ids=[],
        leftout_stages=[],
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=30),
    )


@pytest.mark.asyncio
async def test_followup_load_binds_all_current_owner_site_policy_and_content_inputs() -> None:
    state = MemoryState()
    record = followup_record()
    state.plans[record.followup_id] = record

    assert (
        await state.load_plan(
            record.followup_id,
            owner_key=record.owner_key,
            environment_id=record.environment_id,
            revision=record.revision,
            policy_hash=record.plan.policy_hash,
            content_sha=record.plan.content_sha,
            now=NOW,
        )
        == record
    )

    async def rejects(
        *,
        owner_key: str,
        environment_id: str,
        revision: int,
        policy_hash: str,
        content_sha: str,
        code: str,
    ) -> None:
        with pytest.raises(StateFailure) as error:
            await state.load_plan(
                record.followup_id,
                owner_key=owner_key,
                environment_id=environment_id,
                revision=revision,
                policy_hash=policy_hash,
                content_sha=content_sha,
                now=NOW,
            )
        assert error.value.code == code

    await rejects(
        owner_key="f" * 64,
        environment_id=record.environment_id,
        revision=record.revision,
        policy_hash=record.plan.policy_hash,
        content_sha=record.plan.content_sha,
        code="FOLLOWUP_EXPIRED",
    )
    await rejects(
        owner_key=record.owner_key,
        environment_id="beta",
        revision=record.revision,
        policy_hash=record.plan.policy_hash,
        content_sha=record.plan.content_sha,
        code="FOLLOWUP_EXPIRED",
    )
    await rejects(
        owner_key=record.owner_key,
        environment_id=record.environment_id,
        revision=record.revision,
        policy_hash="1" * 64,
        content_sha=record.plan.content_sha,
        code="POLICY_CHANGED",
    )
    await rejects(
        owner_key=record.owner_key,
        environment_id=record.environment_id,
        revision=record.revision,
        policy_hash=record.plan.policy_hash,
        content_sha="2" * 40,
        code="CONTENT_CHANGED",
    )
    await rejects(
        owner_key=record.owner_key,
        environment_id=record.environment_id,
        revision=2,
        policy_hash=record.plan.policy_hash,
        content_sha=record.plan.content_sha,
        code="FOLLOWUP_CONFLICT",
    )


@pytest.mark.asyncio
async def test_completion_is_fenced_acknowledged_and_operation_idempotent() -> None:
    state = MemoryState()
    owner = "a" * 64
    question_id = uuid4()
    idempotency_key = uuid4()
    lease = await state.begin_request(
        owner_key=owner,
        environment_id="alpha",
        question_id=question_id,
        request_hash="b" * 64,
        idempotency_key=idempotency_key,
        now=NOW,
    )
    idem = state.idempotency[(owner, "alpha", idempotency_key)]
    command = CompletionCommand(
        question_id=question_id,
        owner_key=owner,
        environment_id="alpha",
        answer_status=AnswerStatus.answered,
        followup=None,
        idempotency=idem,
        audit_ack=AuditAck(event_id=uuid4(), delivery_id="fixture-ack", accepted_at=NOW),
        metadata_sha256="c" * 64,
    )
    operation_id = uuid4()

    first = await state.commit_completion(command, lease=lease, now=NOW, operation_id=operation_id)
    retry = await state.commit_completion(command, lease=lease, now=NOW, operation_id=operation_id)

    assert retry == first
    assert state.questions[question_id].state == "completed"
    assert state.questions[question_id].completion_id == first.completion_id
    assert state.idempotency[(owner, "alpha", idempotency_key)].status == "completed"
    assert state.operations[operation_id].terminal_result_hash is not None

    # The same durable operation can recover a response lost after its commit,
    # even after another holder has fenced this lease. A fresh operation cannot
    # republish the identical answer hash under the stale lease.
    late = NOW + timedelta(seconds=61)
    replacement = await state.acquire(
        owner_key=owner,
        environment_id="alpha",
        question_id=uuid4(),
        holder_id=uuid4(),
        now=late,
    )
    assert replacement.fence == lease.fence + 1
    assert (
        await state.commit_completion(command, lease=lease, now=late, operation_id=operation_id)
        == first
    )
    with pytest.raises(StateFailure) as stale_delivery:
        await state.commit_completion(command, lease=lease, now=late, operation_id=uuid4())
    assert stale_delivery.value.code == "LEASE_LOST"

    with pytest.raises(StateFailure) as reused:
        await state.commit_completion(
            command.model_copy(update={"metadata_sha256": "d" * 64}),
            lease=lease,
            now=NOW,
            operation_id=operation_id,
        )
    assert reused.value.code == "IDEMPOTENCY_CONFLICT"


@pytest.mark.asyncio
async def test_lease_acquisition_is_single_winner_and_fence_survives_release() -> None:
    state = MemoryState()
    calls = [
        state.acquire(
            owner_key="a" * 64,
            environment_id="alpha",
            question_id=uuid4(),
            holder_id=uuid4(),
            now=NOW,
        )
        for _ in range(2)
    ]
    results = await asyncio.gather(*calls, return_exceptions=True)
    leases = [item for item in results if not isinstance(item, BaseException)]
    failures = [item for item in results if isinstance(item, StateFailure)]
    assert len(leases) == 1
    assert len(failures) == 1
    await state.release(leases[0])
    second = await state.acquire(
        owner_key="a" * 64, environment_id="alpha", question_id=uuid4(), holder_id=uuid4(), now=NOW
    )
    assert second.fence == leases[0].fence + 1
    assert second.lease_id != leases[0].lease_id


@pytest.mark.asyncio
async def test_started_reservation_unknown_usage_is_charged_once() -> None:
    state = MemoryState()
    lease = await state.acquire(
        owner_key="a" * 64, environment_id="alpha", question_id=uuid4(), holder_id=uuid4(), now=NOW
    )
    question_id = lease.question_id
    await state.open_budget(
        question_id=question_id,
        owner_key=lease.owner_key,
        environment_id=lease.environment_id,
        token_limit=1000,
        expires_at=NOW + timedelta(hours=1),
        lease=lease,
        operation_id=uuid4(),
    )
    reservation = await state.reserve(
        question_id=question_id,
        topic_id="ldap",
        tokens=400,
        lease=lease,
        operation_id=uuid4(),
        now=NOW,
        owner_daily_limit=1_000_000,
        service_daily_limit=1_000_000,
    )
    assert reservation.hard_deadline_at >= lease.last_renewed_at + timedelta(seconds=120)
    assert reservation.recover_after >= reservation.hard_deadline_at + timedelta(seconds=35)
    started = await state.mark_started(reservation, lease=lease, operation_id=uuid4(), now=NOW)
    await state.settle(started, charged_tokens=None, lease=lease, operation_id=uuid4(), now=NOW)
    await state.settle(started, charged_tokens=None, lease=lease, operation_id=uuid4(), now=NOW)
    budget = state.budgets[question_id].budget
    assert budget.reserved_tokens == 0
    assert budget.charged_tokens == 400
    assert budget.remaining_tokens == 600
    assert state.reservations[reservation.reservation_id].state == "unknown_charged"


@pytest.mark.asyncio
async def test_m4_pre_invocation_settle_releases_reservation_without_charging() -> None:
    state = MemoryState()
    lease = await state.acquire(
        owner_key="a" * 64, environment_id="alpha", question_id=uuid4(), holder_id=uuid4(), now=NOW
    )
    await state.open_budget(
        question_id=lease.question_id,
        owner_key=lease.owner_key,
        environment_id=lease.environment_id,
        token_limit=1000,
        expires_at=NOW + timedelta(hours=1),
        lease=lease,
        operation_id=uuid4(),
    )
    reservation = await state.reserve(
        question_id=lease.question_id,
        topic_id="ldap",
        tokens=400,
        lease=lease,
        operation_id=uuid4(),
        now=NOW,
        owner_daily_limit=1_000_000,
        service_daily_limit=1_000_000,
    )
    started = await state.mark_started(reservation, lease=lease, operation_id=uuid4(), now=NOW)
    await state.settle(
        started,
        charged_tokens=None,
        lease=lease,
        operation_id=uuid4(),
        now=NOW,
        release=True,
    )
    budget = state.budgets[lease.question_id].budget
    assert budget.charged_tokens == 0
    assert budget.remaining_tokens == 1000
    assert state.reservations[reservation.reservation_id].state == "released"


@pytest.mark.asyncio
async def test_overrun_records_full_provider_usage_and_closes_budget() -> None:
    state = MemoryState()
    lease = await state.acquire(
        owner_key="a" * 64, environment_id="alpha", question_id=uuid4(), holder_id=uuid4(), now=NOW
    )
    await state.open_budget(
        question_id=lease.question_id,
        owner_key=lease.owner_key,
        environment_id=lease.environment_id,
        token_limit=1000,
        expires_at=NOW + timedelta(hours=1),
        lease=lease,
        operation_id=uuid4(),
    )
    reservation = await state.reserve(
        question_id=lease.question_id,
        topic_id="dns",
        tokens=100,
        lease=lease,
        operation_id=uuid4(),
        now=NOW,
        owner_daily_limit=1_000_000,
        service_daily_limit=1_000_000,
    )
    started = await state.mark_started(reservation, lease=lease, operation_id=uuid4(), now=NOW)
    await state.settle(started, charged_tokens=140, lease=lease, operation_id=uuid4(), now=NOW)
    budget = state.budgets[lease.question_id].budget
    assert (budget.reserved_tokens, budget.charged_tokens, budget.remaining_tokens) == (0, 140, 0)
    assert budget.overflow_tokens == 40
    assert budget.state == "closed"


@pytest.mark.asyncio
async def test_stale_lease_cannot_release_replacement_or_settle_started_call() -> None:
    state = MemoryState()
    owner = "b" * 64
    old = await state.acquire(
        owner_key=owner, environment_id="alpha", question_id=uuid4(), holder_id=uuid4(), now=NOW
    )
    await state.release(old)
    new = await state.acquire(
        owner_key=owner, environment_id="alpha", question_id=uuid4(), holder_id=uuid4(), now=NOW
    )
    await state.release(old)
    assert state.leases[(owner, "alpha")].active == new
    with pytest.raises(StateFailure) as error:
        await state.renew(old, now=NOW)
    assert error.value.code == "LEASE_LOST"


@pytest.mark.asyncio
async def test_expired_lease_is_reclaimable_without_waiting_for_cleanup() -> None:
    state = MemoryState(lease_seconds=5)
    first = await state.acquire(
        owner_key="c" * 64, environment_id="beta", question_id=uuid4(), holder_id=uuid4(), now=NOW
    )
    second = await state.acquire(
        owner_key=first.owner_key,
        environment_id="beta",
        question_id=uuid4(),
        holder_id=uuid4(),
        now=NOW + timedelta(seconds=5),
    )
    assert second.fence == first.fence + 1
