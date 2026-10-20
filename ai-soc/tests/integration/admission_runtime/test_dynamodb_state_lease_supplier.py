from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

import pytest
from botocore.client import BaseClient
from conftest import DynamoFixture

from ai_soc.state.dynamodb import DynamoClient, DynamoState


class _Clock:
    def __init__(self, now: datetime) -> None:
        self.current = now

    def now(self) -> datetime:
        return self.current


class _ObservedSemaphore:
    def __init__(self, value: int) -> None:
        self.semaphore = asyncio.Semaphore(value)
        self.waiting = asyncio.Event()

    async def acquire(self) -> bool:
        if self.semaphore.locked():
            self.waiting.set()
        return await self.semaphore.acquire()

    def release(self) -> None:
        self.semaphore.release()

    async def __aenter__(self) -> _ObservedSemaphore:
        await self.acquire()
        return self

    async def __aexit__(self, *_args: object) -> None:
        self.release()


@pytest.mark.asyncio
async def test_open_budget_uses_lease_renewed_while_transaction_waits_for_io(
    dynamo_fixture: DynamoFixture,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    clock = _Clock(now)
    client = cast(DynamoClient, dynamo_fixture.clients[0])
    state = DynamoState(client, dynamo_fixture.table, clock=clock)
    renewal_state = DynamoState(cast(DynamoClient, dynamo_fixture.clients[1]), dynamo_fixture.table)
    question_id = uuid4()
    lease = await state.begin_request(
        owner_key="d" * 64,
        environment_id="alpha",
        question_id=question_id,
        request_hash="a" * 64,
        idempotency_key=None,
        now=now,
    )
    holder = [lease]
    operation_id = uuid4()
    assert await state._get_operation(operation_id) is None

    async def operation_absent(_operation_id: UUID) -> None:
        return None

    state._get_operation = operation_absent  # type: ignore[method-assign]
    observed = _ObservedSemaphore(8)
    state._io = observed  # type: ignore[assignment]
    for _ in range(8):
        await observed.acquire()

    task = asyncio.create_task(
        state.open_budget(
            question_id=question_id,
            owner_key=lease.owner_key,
            environment_id=lease.environment_id,
            token_limit=1000,
            expires_at=now + timedelta(hours=1),
            lease=lease,
            operation_id=operation_id,
            lease_supplier=lambda: holder[0],
        )
    )
    await observed.waiting.wait()
    renewal_time = lease.expires_at - timedelta(seconds=5)
    renewed = await renewal_state.renew_lease(lease, now=renewal_time)
    holder[0] = renewed
    clock.current = lease.expires_at + timedelta(seconds=10)
    for _ in range(8):
        observed.release()
    await task

    budget = cast(BaseClient, dynamo_fixture.clients[0]).get_item(
        TableName=dynamo_fixture.table,
        Key={"pk": {"S": f"QUESTION#{question_id}"}, "sk": {"S": "BUDGET"}},
        ConsistentRead=True,
    )["Item"]
    assert budget["lease_id"]["S"] == str(lease.lease_id)
    assert renewed.expires_at > clock.now()
