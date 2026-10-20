from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

import pytest
from botocore.client import BaseClient
from conftest import DynamoFixture

from ai_soc.contracts.models import Reservation
from ai_soc.state.dynamodb import DynamoClient, DynamoState
from ai_soc.state.ttl import TTL_ATTRIBUTE


class _Clock:
    def __init__(self, now: datetime) -> None:
        self.current = now

    def now(self) -> datetime:
        return self.current


@pytest.mark.asyncio
async def test_recovery_closes_and_expires_abandoned_budget(dynamo_fixture: DynamoFixture) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    clock = _Clock(now)
    state = DynamoState(
        cast(DynamoClient, dynamo_fixture.clients[0]), dynamo_fixture.table, clock=clock
    )
    owner_key = "b" * 64
    question_id = uuid4()
    lease = await state.begin_request(
        owner_key=owner_key,
        environment_id="alpha",
        question_id=question_id,
        request_hash="a" * 64,
        idempotency_key=None,
        now=now,
    )
    await state.open_budget(
        question_id=question_id,
        owner_key=owner_key,
        environment_id="alpha",
        token_limit=1000,
        expires_at=now + timedelta(hours=1),
        lease=lease,
        operation_id=(budget_open_operation_id := uuid4()),
    )
    reservation = await state.reserve(
        question_id=question_id,
        topic_id="ldap",
        tokens=500,
        lease=lease,
        operation_id=(reserve_operation_id := uuid4()),
        now=now,
        owner_daily_limit=10_000,
        service_daily_limit=10_000,
    )
    started = await state.mark_started(
        reservation, lease=lease, operation_id=(started_operation_id := uuid4()), now=now
    )
    ticket = state._ticket(started)
    clock.current = ticket.due_at + timedelta(seconds=1)

    recovery = await state.reconcile(now=clock.now(), bucket=ticket.bucket)

    assert recovery.terminalized == 1
    assert recovery.errors == []
    client = cast(BaseClient, dynamo_fixture.clients[0])
    budget = client.get_item(
        TableName=dynamo_fixture.table,
        Key={"pk": {"S": f"QUESTION#{question_id}"}, "sk": {"S": "BUDGET"}},
        ConsistentRead=True,
    )["Item"]
    assert int(budget["reserved_tokens"]["N"]) == 0
    assert int(budget["charged_tokens"]["N"]) == reservation.reserved_tokens
    assert budget[TTL_ATTRIBUTE]["N"] == str(int(clock.now().timestamp()) + 86400)
    for operation_id in (budget_open_operation_id, reserve_operation_id, started_operation_id):
        operation = client.get_item(
            TableName=dynamo_fixture.table,
            Key={"pk": {"S": f"OP#{operation_id}"}, "sk": {"S": "V1"}},
            ConsistentRead=True,
        )["Item"]
        assert TTL_ATTRIBUTE in operation


@pytest.mark.asyncio
async def test_scoped_recovery_uses_canonical_ticket_key_and_leaves_other_ticket_untouched(
    dynamo_fixture: DynamoFixture,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    state = DynamoState(
        cast(DynamoClient, dynamo_fixture.clients[0]), dynamo_fixture.table, clock=_Clock(now)
    )

    async def reserve_for(owner_suffix: str) -> tuple[UUID, Reservation]:
        question_id = uuid4()
        owner_key = owner_suffix * 64
        lease = await state.begin_request(
            owner_key=owner_key,
            environment_id="alpha",
            question_id=question_id,
            request_hash=owner_suffix * 64,
            idempotency_key=None,
            now=now,
        )
        await state.open_budget(
            question_id=question_id,
            owner_key=owner_key,
            environment_id="alpha",
            token_limit=100,
            expires_at=now + timedelta(hours=1),
            lease=lease,
            operation_id=uuid4(),
        )
        reservation = await state.reserve(
            question_id=question_id,
            topic_id="synthetic-recovery",
            tokens=5,
            lease=lease,
            operation_id=uuid4(),
            now=now,
            owner_daily_limit=1_000,
            service_daily_limit=1_000,
        )
        await state.release_lease(lease)
        return question_id, reservation

    target_question, target = await reserve_for("d")
    unrelated_question, unrelated = await reserve_for("e")
    assert target.reservation_id != unrelated.reservation_id

    recovery_at = target.recover_after + timedelta(seconds=1)
    page = await state.reconcile(
        now=recovery_at,
        bucket=(int(target.recover_after.timestamp()) // 30) % 128,
        question_id=target_question,
        reservation_id=target.reservation_id,
    )

    client = cast(BaseClient, dynamo_fixture.clients[0])
    target_row = client.get_item(
        TableName=dynamo_fixture.table,
        Key={
            "pk": {"S": f"QUESTION#{target_question}"},
            "sk": {"S": f"RESERVATION#{target.reservation_id}"},
        },
        ConsistentRead=True,
    )["Item"]
    unrelated_row = client.get_item(
        TableName=dynamo_fixture.table,
        Key={
            "pk": {"S": f"QUESTION#{unrelated_question}"},
            "sk": {"S": f"RESERVATION#{unrelated.reservation_id}"},
        },
        ConsistentRead=True,
    )["Item"]

    assert page.examined == 1
    assert page.terminalized == 1
    assert json.loads(target_row["payload"]["S"])["state"] == "released"
    assert json.loads(unrelated_row["payload"]["S"])["state"] == "reserved"


@pytest.mark.asyncio
async def test_empty_open_budget_has_cleanup_ttl_after_crash_before_reservation(
    dynamo_fixture: DynamoFixture,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    state = DynamoState(
        cast(DynamoClient, dynamo_fixture.clients[0]), dynamo_fixture.table, clock=_Clock(now)
    )
    owner_key = "c" * 64
    question_id = uuid4()
    lease = await state.begin_request(
        owner_key=owner_key,
        environment_id="alpha",
        question_id=question_id,
        request_hash="d" * 64,
        idempotency_key=None,
        now=now,
    )
    expires_at = now + timedelta(hours=1)
    budget_open_operation_id = uuid4()
    await state.open_budget(
        question_id=question_id,
        owner_key=owner_key,
        environment_id="alpha",
        token_limit=1000,
        expires_at=expires_at,
        lease=lease,
        operation_id=budget_open_operation_id,
    )

    client = cast(BaseClient, dynamo_fixture.clients[0])
    expected_ttl = int(expires_at.timestamp()) + 86400
    budget = client.get_item(
        TableName=dynamo_fixture.table,
        Key={"pk": {"S": f"QUESTION#{question_id}"}, "sk": {"S": "BUDGET"}},
        ConsistentRead=True,
    )["Item"]
    operation = client.get_item(
        TableName=dynamo_fixture.table,
        Key={"pk": {"S": f"OP#{budget_open_operation_id}"}, "sk": {"S": "V1"}},
        ConsistentRead=True,
    )["Item"]
    assert budget[TTL_ATTRIBUTE]["N"] == str(expected_ttl)
    assert operation[TTL_ATTRIBUTE]["N"] == str(expected_ttl)
