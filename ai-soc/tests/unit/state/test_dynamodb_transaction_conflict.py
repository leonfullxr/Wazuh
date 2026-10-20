from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

import pytest
from botocore.exceptions import ClientError

from ai_soc.contracts.models import ErrorCode, Lease
from ai_soc.state.dynamodb import DynamoClient, DynamoState
from ai_soc.state.errors import StateFailure
from tests.unit.state.test_dynamodb import RecordingDynamo

NOW = datetime(2026, 9, 30, 12, tzinfo=UTC)
CONFLICT_REASONS = [
    {"Code": "None"},
    {"Code": "TransactionConflict"},
    {"Code": "None"},
]


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


class _ConflictThenOkDynamo(RecordingDynamo):
    def __init__(self, clock: _Clock, *, always_conflict: bool = False) -> None:
        super().__init__()
        self.clock = clock
        self.always_conflict = always_conflict
        self.transact_attempts = 0

    def transact_write_items(self, **kwargs: object) -> dict[str, object]:
        self.transact_attempts += 1
        assert len(cast(list[object], kwargs["TransactItems"])) == 3
        if self.transact_attempts == 1 or self.always_conflict:
            self.clock.current += timedelta(seconds=2)
            raise ClientError(
                {
                    "Error": {"Code": "TransactionCanceledException"},
                    "CancellationReasons": CONFLICT_REASONS,
                },
                "TransactWriteItems",
            )
        return super().transact_write_items(**kwargs)


@pytest.mark.asyncio
async def test_transact_retries_multi_item_conflict_with_fresh_time() -> None:
    clock = _Clock(NOW)
    client = _ConflictThenOkDynamo(clock)
    state = DynamoState(cast(DynamoClient, client), "soc-state", clock=clock)  # type: ignore[arg-type]
    question_id = uuid4()
    lease = Lease(
        lease_id=uuid4(),
        question_id=question_id,
        holder_id=uuid4(),
        fence=1,
        owner_key="a" * 64,
        environment_id="alpha",
        expires_at=NOW + timedelta(minutes=1),
        last_renewed_at=NOW,
    )
    await state.open_budget(
        question_id=question_id,
        owner_key=lease.owner_key,
        environment_id=lease.environment_id,
        token_limit=1000,
        expires_at=NOW + timedelta(hours=1),
        lease=lease,
        operation_id=uuid4(),
    )

    assert client.transact_attempts == 2
    actual = cast(list[dict[str, object]], client.calls[-1][1]["TransactItems"])
    assert len(actual) == 3
    values = cast(
        dict[str, dict[str, str]],
        actual[2]["ConditionCheck"]["ExpressionAttributeValues"],
    )
    assert values[":now"]["N"] == str(int((NOW + timedelta(seconds=2)).timestamp()))


@pytest.mark.asyncio
async def test_production_transaction_samples_clock_after_waiting_for_io_slot() -> None:
    clock = _Clock(NOW)
    client = RecordingDynamo()
    state = DynamoState(cast(DynamoClient, client), "soc-state", clock=clock)  # type: ignore[arg-type]
    lease = Lease(
        lease_id=uuid4(),
        question_id=uuid4(),
        holder_id=uuid4(),
        fence=1,
        owner_key="c" * 64,
        environment_id="alpha",
        expires_at=NOW + timedelta(minutes=1),
        last_renewed_at=NOW,
    )
    observed = _ObservedSemaphore(8)
    state._io = observed  # type: ignore[assignment]
    get_operation = state._get_operation
    release_task: asyncio.Task[None] | None = None

    async def release_when_transaction_waits() -> None:
        await observed.waiting.wait()
        clock.current += timedelta(seconds=4)
        for _ in range(8):
            observed.release()

    async def hold_io_slot(operation_id: UUID) -> dict[str, object] | None:
        nonlocal release_task
        result = await get_operation(operation_id)
        for _ in range(8):
            await observed.acquire()
        release_task = asyncio.create_task(release_when_transaction_waits())
        return result

    state._get_operation = hold_io_slot  # type: ignore[method-assign]
    task = asyncio.create_task(
        state.open_budget(
            question_id=lease.question_id,
            owner_key=lease.owner_key,
            environment_id=lease.environment_id,
            token_limit=1000,
            expires_at=NOW + timedelta(hours=1),
            lease=lease,
            operation_id=uuid4(),
        )
    )
    await task
    assert release_task is not None
    await release_task
    transaction = next(params for name, params in client.calls if name == "transact_write_items")
    actions = cast(list[dict[str, object]], transaction["TransactItems"])
    values = cast(
        dict[str, dict[str, str]], actions[2]["ConditionCheck"]["ExpressionAttributeValues"]
    )
    assert values[":now"]["N"] == str(int(clock.current.timestamp()))


@pytest.mark.asyncio
async def test_transact_maps_only_conditional_cancellation_to_conflict_code() -> None:
    client = RecordingDynamo()

    def fail_conditional(**kwargs: object) -> dict[str, object]:
        raise ClientError(
            {
                "Error": {"Code": "TransactionCanceledException"},
                "CancellationReasons": [{"Code": "ConditionalCheckFailed"}],
            },
            "TransactWriteItems",
        )

    client.transact_write_items = fail_conditional  # type: ignore[method-assign]
    state = DynamoState(cast(DynamoClient, client), "soc-state")
    with pytest.raises(StateFailure) as failure:
        await state._transact(lambda _now: [], ErrorCode.LEASE_LOST, now=NOW)
    assert failure.value.code == ErrorCode.LEASE_LOST


@pytest.mark.asyncio
async def test_retry_after_lease_margin_fails_without_second_transaction() -> None:
    clock = _Clock(NOW)
    client = _ConflictThenOkDynamo(clock)
    state = DynamoState(cast(DynamoClient, client), "soc-state", clock=clock)  # type: ignore[arg-type]
    lease = Lease(
        lease_id=uuid4(),
        question_id=uuid4(),
        holder_id=uuid4(),
        fence=1,
        owner_key="a" * 64,
        environment_id="alpha",
        expires_at=NOW + timedelta(seconds=9),
        last_renewed_at=NOW,
    )
    built_at: list[datetime] = []

    def build(attempt_now: datetime) -> list[object]:
        built_at.append(attempt_now)
        check = {"ConditionCheck": {"ExpressionAttributeValues": {}}}
        return [check, check, check]

    with pytest.raises(StateFailure) as failure:
        await state._transact(
            build,
            ErrorCode.LEASE_LOST,
            now=NOW,
            lease=lease,
            lease_margin_seconds=8,
        )

    assert failure.value.code == ErrorCode.LEASE_LOST
    assert client.transact_attempts == 1
    assert built_at == [NOW]


@pytest.mark.asyncio
async def test_transaction_conflict_attempts_are_limited_to_two() -> None:
    clock = _Clock(NOW)
    client = _ConflictThenOkDynamo(clock, always_conflict=True)
    state = DynamoState(cast(DynamoClient, client), "soc-state", clock=clock)  # type: ignore[arg-type]
    with pytest.raises(StateFailure) as failure:
        await state._transact(lambda _now: [{}, {}, {}], ErrorCode.LEASE_LOST, now=NOW)

    assert failure.value.code == ErrorCode.DEPENDENCY_UNAVAILABLE
    assert client.transact_attempts == 2
