from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

import pytest
from botocore.client import BaseClient
from conftest import DynamoFixture

from ai_soc.contracts.models import (
    AnswerStatus,
    AuditAck,
    CompletionCommand,
    FollowupRecord,
    IdempotencyRecord,
    PlanProvenance,
    QuestionPlan,
)
from ai_soc.state.dynamodb import DynamoClient, DynamoState
from ai_soc.state.ttl import TTL_ATTRIBUTE


class _Clock:
    def __init__(self, now: datetime) -> None:
        self.current = now

    def now(self) -> datetime:
        return self.current


def _state(fixture: DynamoFixture, clock: _Clock) -> DynamoState:
    return DynamoState(cast(DynamoClient, fixture.clients[0]), fixture.table, clock=clock)


async def _begin_request(
    state: DynamoState,
    *,
    question_id: UUID,
    owner_key: str,
    now: datetime,
    idempotency_key: UUID | None = None,
):
    return await state.begin_request(
        owner_key=owner_key,
        environment_id="alpha",
        question_id=question_id,
        request_hash="a" * 64,
        idempotency_key=idempotency_key,
        now=now,
    )


@pytest.mark.asyncio
async def test_dynamodb_state_transactions_use_valid_expressions_and_terminal_ttls(
    dynamo_fixture: DynamoFixture,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    clock = _Clock(now)
    state = _state(dynamo_fixture, clock)
    owner_key = "a" * 64
    question_id = uuid4()
    idempotency_key = uuid4()
    lease = await _begin_request(
        state,
        question_id=question_id,
        owner_key=owner_key,
        now=now,
        idempotency_key=idempotency_key,
    )
    clock.current = now + timedelta(seconds=2)
    lease = await state.renew_lease(lease, now=clock.now())
    await state.open_budget(
        question_id=question_id,
        owner_key=owner_key,
        environment_id="alpha",
        token_limit=1000,
        expires_at=clock.now() + timedelta(hours=1),
        lease=lease,
        operation_id=(budget_open_operation_id := uuid4()),
    )
    client = cast(BaseClient, dynamo_fixture.clients[0])
    budget_key = {"pk": {"S": f"QUESTION#{question_id}"}, "sk": {"S": "BUDGET"}}
    open_operation_key = {
        "pk": {"S": f"OP#{budget_open_operation_id}"},
        "sk": {"S": "V1"},
    }
    opened_budget = client.get_item(
        TableName=dynamo_fixture.table, Key=budget_key, ConsistentRead=True
    )["Item"]
    opened_operation = client.get_item(
        TableName=dynamo_fixture.table, Key=open_operation_key, ConsistentRead=True
    )["Item"]
    assert TTL_ATTRIBUTE in opened_budget and TTL_ATTRIBUTE in opened_operation
    reservation = await state.reserve(
        question_id=question_id,
        topic_id="ldap",
        tokens=500,
        lease=lease,
        operation_id=(reserve_operation_id := uuid4()),
        now=clock.now(),
        owner_daily_limit=10_000,
        service_daily_limit=10_000,
    )
    reserved_budget = client.get_item(
        TableName=dynamo_fixture.table, Key=budget_key, ConsistentRead=True
    )["Item"]
    reserved_operation = client.get_item(
        TableName=dynamo_fixture.table, Key=open_operation_key, ConsistentRead=True
    )["Item"]
    assert TTL_ATTRIBUTE not in reserved_budget and TTL_ATTRIBUTE not in reserved_operation
    started = await state.mark_started(
        reservation,
        lease=lease,
        operation_id=(started_operation_id := uuid4()),
        now=clock.now(),
    )
    await state.settle(
        started,
        charged_tokens=125,
        lease=lease,
        operation_id=uuid4(),
        now=clock.now(),
    )
    settled_budget = client.get_item(
        TableName=dynamo_fixture.table, Key=budget_key, ConsistentRead=True
    )["Item"]
    settled_operation = client.get_item(
        TableName=dynamo_fixture.table, Key=open_operation_key, ConsistentRead=True
    )["Item"]
    expected_terminal_ttl = str(int(clock.now().timestamp()) + 86400)
    assert settled_budget[TTL_ATTRIBUTE]["N"] == expected_terminal_ttl
    assert settled_operation[TTL_ATTRIBUTE]["N"] == expected_terminal_ttl

    plan = QuestionPlan(
        question_id=question_id,
        environment_id="alpha",
        owner_key=owner_key,
        content_sha="b" * 40,
        policy_hash="c" * 64,
        language="en",
        timezone="UTC",
        anchor_at=clock.now(),
        topics=[],
        provenance=PlanProvenance(
            cue_pack_sha="d" * 64,
            normalized_question_hash="e" * 64,
            origin="new",
            matched_spans=[],
        ),
    )
    followup = FollowupRecord(
        followup_id=uuid4(),
        owner_key=owner_key,
        environment_id="alpha",
        plan=plan,
        answered_topic_ids=[],
        leftout_topic_ids=[],
        leftout_stages=[],
        created_at=clock.now(),
        expires_at=clock.now() + timedelta(minutes=30),
    )
    completion = CompletionCommand(
        question_id=question_id,
        owner_key=owner_key,
        environment_id="alpha",
        answer_status=AnswerStatus.answered,
        followup=followup,
        idempotency=IdempotencyRecord(
            owner_key=owner_key,
            environment_id="alpha",
            key=idempotency_key,
            request_hash="a" * 64,
            question_id=question_id,
            status="active",
            expires_at=now + timedelta(minutes=10),
        ),
        audit_ack=AuditAck(event_id=uuid4(), delivery_id="ddb-local-ack", accepted_at=clock.now()),
        metadata_sha256="f" * 64,
    )
    await state.commit_completion(
        completion,
        lease=lease,
        now=clock.now(),
        operation_id=(completion_operation_id := uuid4()),
    )

    client = cast(BaseClient, dynamo_fixture.clients[0])
    budget = client.get_item(
        TableName=dynamo_fixture.table,
        Key={"pk": {"S": f"QUESTION#{question_id}"}, "sk": {"S": "BUDGET"}},
        ConsistentRead=True,
    )["Item"]
    assert budget[TTL_ATTRIBUTE]["N"] == str(int(clock.now().timestamp()) + 86400)
    status = client.get_item(
        TableName=dynamo_fixture.table,
        Key={"pk": {"S": f"QUESTION#{question_id}"}, "sk": {"S": "STATUS"}},
        ConsistentRead=True,
    )["Item"]
    assert status[TTL_ATTRIBUTE]["N"] == str(int(clock.now().timestamp()) + 86400)
    for operation_id in (
        budget_open_operation_id,
        reserve_operation_id,
        started_operation_id,
        completion_operation_id,
    ):
        row = client.get_item(
            TableName=dynamo_fixture.table,
            Key={"pk": {"S": f"OP#{operation_id}"}, "sk": {"S": "V1"}},
            ConsistentRead=True,
        )["Item"]
        assert TTL_ATTRIBUTE in row
    plan_row = client.get_item(
        TableName=dynamo_fixture.table,
        Key={"pk": {"S": f"PLAN#{followup.followup_id}"}, "sk": {"S": "V1"}},
        ConsistentRead=True,
    )["Item"]
    assert plan_row[TTL_ATTRIBUTE]["N"] == str(int(followup.expires_at.timestamp()))
