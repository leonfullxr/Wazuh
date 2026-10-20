from __future__ import annotations

import asyncio
import threading
from dataclasses import replace
from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

import pytest
from botocore.client import BaseClient
from botocore.exceptions import ClientError
from conftest import DynamoFixture

from ai_soc.application.errors import ServiceFailure
from ai_soc.application.runtime import BoundedCallLedger, RequestCancellation
from ai_soc.contracts.canonical import canonical_bytes
from ai_soc.contracts.models import (
    SHA256,
    AnswerStatus,
    ErrorCode,
    ExecutionContext,
    FeedbackControlContext,
    FeedbackEvent,
    FeedbackMetadata,
    FeedbackRequest,
)
from ai_soc.contracts.ports import FeedbackSink, FeedbackStore
from ai_soc.state.dynamodb import DynamoClient, DynamoState
from ai_soc.state.errors import StateFailure
from ai_soc.state.feedback_control import FeedbackControlPool
from tests.unit.application.test_fenced_completion import NOW as FIXTURE_NOW
from tests.unit.application.test_fenced_completion import _ControlledClock, _principal, _runtime


class _CommitThenLoseResponse:
    def __init__(self, client: BaseClient) -> None:
        self._client = client
        self.operation: str | None = None

    def put_item(self, **kwargs: object) -> object:
        result = self._client.put_item(**kwargs)
        if self.operation == "put_item":
            self.operation = None
            raise OSError("response lost after conditional put")
        return result

    def update_item(self, **kwargs: object) -> object:
        result = self._client.update_item(**kwargs)
        if self.operation == "update_item":
            self.operation = None
            raise OSError("response lost after conditional update")
        return result

    def __getattr__(self, name: str) -> object:
        return getattr(self._client, name)


class _ApplicationAmbiguityClient:
    def __init__(self, client: BaseClient, mode: str) -> None:
        self._client = client
        self.mode = mode
        self.reads = 0
        self.puts = 0
        self.updates = 0

    @staticmethod
    def _condition_error(operation: str) -> ClientError:
        return ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "fixture"}},
            operation,
        )

    def get_item(self, **kwargs: object) -> object:
        self.reads += 1
        if self.mode == "initial-read-outage" and self.reads == 1:
            raise OSError("initial read lost")
        if self.mode == "create-commit-read-outage" and self.reads == 2:
            raise OSError("winner read lost")
        if self.mode == "mark-commit-read-outage" and self.reads == 2:
            raise OSError("queued reconciliation lost")
        if self.mode == "enqueue-replaced-queued" and self.reads == 2:
            key = cast(dict[str, object], kwargs["Key"])
            current = cast(
                dict[str, object],
                self._client.get_item(TableName=kwargs["TableName"], Key=key, ConsistentRead=True)[
                    "Item"
                ],
            )
            current["feedback_id"] = {"S": str(uuid4())}
            current["status"] = {"S": "queued"}
            self._client.put_item(TableName=kwargs["TableName"], Item=current)
        return self._client.get_item(**kwargs)

    def put_item(self, **kwargs: object) -> object:
        self.puts += 1
        if self.mode == "create-conflict-disappears" and self.puts == 1:
            item = cast(dict[str, object], kwargs["Item"])
            competitor = dict(item)
            competitor["feedback_id"] = {"S": str(uuid4())}
            self._client.put_item(TableName=kwargs["TableName"], Item=competitor)
            try:
                self._client.put_item(**kwargs)
            except ClientError:
                self._client.delete_item(
                    TableName=kwargs["TableName"],
                    Key={"pk": item["pk"], "sk": item["sk"]},
                )
                raise
            raise AssertionError("conditional create unexpectedly replaced competitor")
        result = self._client.put_item(**kwargs)
        if self.mode in {"create-commit-lost", "create-commit-read-outage"} and self.puts == 1:
            raise OSError("create response lost")
        return result

    def update_item(self, **kwargs: object) -> object:
        self.updates += 1
        if self.mode == "mark-replaced-queued":
            key = cast(dict[str, object], kwargs["Key"])
            current = cast(
                dict[str, object],
                self._client.get_item(TableName=kwargs["TableName"], Key=key, ConsistentRead=True)[
                    "Item"
                ],
            )
            current["feedback_id"] = {"S": str(uuid4())}
            current["status"] = {"S": "queued"}
            self._client.put_item(TableName=kwargs["TableName"], Item=current)
            return self._client.update_item(**kwargs)
        if self.mode in {"mark-pending", "mark-absent", "mark-expired", "mark-replaced"}:
            if self.mode != "mark-pending":
                key = cast(dict[str, object], kwargs["Key"])
                item = self._client.get_item(
                    TableName=kwargs["TableName"], Key=key, ConsistentRead=True
                )["Item"]
                raw = cast(dict[str, object], item)
                if self.mode == "mark-absent":
                    self._client.delete_item(TableName=kwargs["TableName"], Key=key)
                elif self.mode == "mark-expired":
                    raw["ttl_epoch"] = {"N": str(int(FIXTURE_NOW.timestamp()))}
                    self._client.put_item(TableName=kwargs["TableName"], Item=raw)
                else:
                    raw["feedback_id"] = {"S": str(uuid4())}
                    self._client.put_item(TableName=kwargs["TableName"], Item=raw)
            raise self._condition_error("UpdateItem")
        result = self._client.update_item(**kwargs)
        if self.mode in {"mark-commit-lost", "mark-commit-read-outage"} and self.updates == 1:
            raise OSError("mark response lost")
        return result

    def __getattr__(self, name: str) -> object:
        return getattr(self._client, name)


class _CommitThenBlockCreate:
    def __init__(self, client: BaseClient) -> None:
        self._client = client
        self.committed = threading.Event()
        self.release = threading.Event()

    def put_item(self, **kwargs: object) -> object:
        result = self._client.put_item(**kwargs)
        self.committed.set()
        if not self.release.wait(timeout=3.0):
            raise TimeoutError("committed create was not released")
        return result

    def __getattr__(self, name: str) -> object:
        return getattr(self._client, name)


class _InitialReadBarrier:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._count = 0
        self.ready = asyncio.Event()

    async def wait(self) -> None:
        async with self._lock:
            self._count += 1
            if self._count == 2:
                self.ready.set()
        await asyncio.wait_for(self.ready.wait(), timeout=2.0)


class _BarrierFeedbackStore:
    def __init__(
        self, state: DynamoState, barrier: _InitialReadBarrier, queued: asyncio.Event
    ) -> None:
        self._state = state
        self._barrier = barrier
        self._first_read = True
        self.queued = queued

    async def read_feedback(
        self,
        *,
        receipt_id: UUID,
        note_hash: SHA256,
        now: datetime,
        control: FeedbackControlContext,
    ) -> FeedbackMetadata | None:
        record = await self._state.read_feedback(
            receipt_id=receipt_id, note_hash=note_hash, now=now, control=control
        )
        if self._first_read:
            self._first_read = False
            await self._barrier.wait()
        return record

    async def try_create_feedback(
        self,
        *,
        receipt_id: UUID,
        note_hash: SHA256,
        now: datetime,
        control: FeedbackControlContext,
    ) -> FeedbackMetadata | None:
        return await self._state.try_create_feedback(
            receipt_id=receipt_id, note_hash=note_hash, now=now, control=control
        )

    async def mark_feedback_queued(
        self,
        *,
        receipt_id: UUID,
        note_hash: SHA256,
        feedback_id: UUID,
        now: datetime,
        control: FeedbackControlContext,
    ) -> bool:
        marked = await self._state.mark_feedback_queued(
            receipt_id=receipt_id,
            note_hash=note_hash,
            feedback_id=feedback_id,
            now=now,
            control=control,
        )
        if marked:
            self.queued.set()
        return marked


class _SlowFailedFirstSink:
    def __init__(self, *, fail_first: bool) -> None:
        self._lock = asyncio.Lock()
        self._calls = 0
        self.fail_first = fail_first
        self.events: list[FeedbackEvent] = []
        self.first_entered = asyncio.Event()
        self.release_first = asyncio.Event()

    async def enqueue(self, event: FeedbackEvent, *, execution: ExecutionContext) -> UUID:
        self.events.append(event)
        async with self._lock:
            self._calls += 1
            ordinal = self._calls
        if ordinal == 1:
            self.first_entered.set()
            await asyncio.wait_for(self.release_first.wait(), timeout=2.0)
            if self.fail_first:
                raise OSError("queue response was lost")
        return event.feedback_id


def _control() -> FeedbackControlContext:
    import time

    return FeedbackControlContext(
        deadline_monotonic=time.monotonic() + 30.0,
        monotonic=time.monotonic,
        cancel=RequestCancellation(),
        calls=BoundedCallLedger(),
    )


@pytest.mark.asyncio
async def test_dynamodb_state_feedback_conditional_generation_and_privacy(
    dynamo_fixture: DynamoFixture,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    pool = FeedbackControlPool()
    states = tuple(
        DynamoState(
            cast(DynamoClient, client),
            dynamo_fixture.table,
            feedback_control_pool=pool,
        )
        for client in dynamo_fixture.clients
    )
    receipt_id = uuid4()
    note_hash = "a" * 64
    try:
        assert await asyncio.gather(
            *(
                state.read_feedback(
                    receipt_id=receipt_id, note_hash=note_hash, now=now, control=_control()
                )
                for state in states
            )
        ) == [None, None]
        created = await asyncio.gather(
            *(
                state.try_create_feedback(
                    receipt_id=receipt_id, note_hash=note_hash, now=now, control=_control()
                )
                for state in states
            )
        )
        winners = [value for value in created if value is not None]
        assert len(winners) == 1
        winner = winners[0]
        assert winner.status == "pending"
        observed = await states[1].read_feedback(
            receipt_id=receipt_id,
            note_hash=note_hash,
            now=now,
            control=_control(),
        )
        assert observed == winner
        assert await states[0].mark_feedback_queued(
            receipt_id=receipt_id,
            note_hash=note_hash,
            feedback_id=winner.feedback_id,
            now=now,
            control=_control(),
        )
        queued = await states[1].read_feedback(
            receipt_id=receipt_id,
            note_hash=note_hash,
            now=now,
            control=_control(),
        )
        assert queued is not None and queued.status == "queued"
        assert queued.feedback_id == winner.feedback_id

        raw = cast(BaseClient, dynamo_fixture.clients[0]).get_item(
            TableName=dynamo_fixture.table,
            Key={
                "pk": {"S": f"FEEDBACK#{receipt_id}"},
                "sk": {"S": note_hash},
            },
            ConsistentRead=True,
        )["Item"]
        assert set(raw) == {
            "pk",
            "sk",
            "record_type",
            "schema_version",
            "feedback_id",
            "status",
            "created_at",
            "ttl_epoch",
        }
        assert raw["status"]["S"] == "queued"
        feedback_reads = [
            params
            for operation, params in dynamo_fixture.calls
            if operation == "GetItem"
            and params.get("Key", {}).get("pk", {}).get("S", "").startswith("FEEDBACK#")
        ]
        assert all(params.get("ConsistentRead") is True for params in feedback_reads)
    finally:
        pool.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("fail_first", [False, True])
async def test_dynamodb_state_feedback_two_application_replicas_reconcile_slow_failure(
    dynamo_fixture: DynamoFixture,
    fail_first: bool,
) -> None:
    pool = FeedbackControlPool()
    base = _runtime()
    principal = _principal("a" * 64)
    question_id = uuid4()
    now = base.application.clock.now()
    receipt = base.application.receipts.issue(
        question_id=question_id,
        owner_key=principal.owner_key,
        environment_id="alpha",
        content_sha="d" * 40,
        cue_ids=[],
        topic_ids=[],
        outcome_code=AnswerStatus.answered,
        now=now,
    )
    request = FeedbackRequest(
        question_id=question_id,
        environment_id="alpha",
        feedback_receipt=receipt,
        kind="wrong",
        note=None,
    )
    barrier = _InitialReadBarrier()
    queued = asyncio.Event()
    stores = tuple(
        _BarrierFeedbackStore(
            DynamoState(
                cast(DynamoClient, client),
                dynamo_fixture.table,
                feedback_control_pool=pool,
            ),
            barrier,
            queued,
        )
        for client in dynamo_fixture.clients
    )
    sink = _SlowFailedFirstSink(fail_first=fail_first)
    applications = tuple(
        replace(
            base.application,
            feedback_store=cast(FeedbackStore, store),
            feedback_sink=cast(FeedbackSink, sink),
        )
        for store in stores
    )
    try:
        tasks = tuple(
            asyncio.create_task(application.feedback(request, principal))
            for application in applications
        )
        await asyncio.wait_for(sink.first_entered.wait(), timeout=2.0)
        await asyncio.wait_for(queued.wait(), timeout=2.0)
        sink.release_first.set()
        results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=2.0)
        assert results[0].feedback_id == results[1].feedback_id
        assert results[0].status == results[1].status == "queued"
        assert len(sink.events) == 2
        assert {event.feedback_id for event in sink.events} == {results[0].feedback_id}
        assert canonical_bytes(sink.events[0]) == canonical_bytes(sink.events[1])
        record = await stores[0].read_feedback(
            receipt_id=base.application.receipts.open(
                receipt,
                question_id=question_id,
                owner_key=principal.owner_key,
                environment_id="alpha",
                now=now,
            ).receipt_id,
            note_hash="1b2185e00753da9593abf50ce85dc1d94412e2185c978b8b58cd0c3ed8a8fc06",
            now=now,
            control=_control(),
        )
        assert record is not None and record.feedback_id == results[0].feedback_id
        assert record.status == "queued"
    finally:
        sink.release_first.set()
        pool.close()


class _AcknowledgingSink:
    def __init__(self) -> None:
        self.events: list[FeedbackEvent] = []

    async def enqueue(self, event: FeedbackEvent, *, execution: ExecutionContext) -> UUID:
        self.events.append(event)
        return event.feedback_id


class _FailingSink:
    def __init__(self) -> None:
        self.events: list[FeedbackEvent] = []

    async def enqueue(self, event: FeedbackEvent, *, execution: ExecutionContext) -> UUID:
        self.events.append(event)
        raise OSError("queue response was lost")


class _AdvanceClockSink:
    def __init__(self, clock: _ControlledClock, advance_to: datetime) -> None:
        self.clock = clock
        self.advance_to = advance_to
        self.events: list[FeedbackEvent] = []

    async def enqueue(self, event: FeedbackEvent, *, execution: ExecutionContext) -> UUID:
        self.events.append(event)
        self.clock.current = self.advance_to
        return event.feedback_id


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "first_succeeds", "retry_succeeds", "first_sends", "total_sends"),
    [
        ("create-commit-lost", True, False, 1, 1),
        ("mark-commit-lost", True, False, 1, 1),
        ("mark-commit-read-outage", False, True, 1, 1),
        ("initial-read-outage", False, False, 0, 0),
        ("create-commit-read-outage", False, True, 0, 1),
        ("create-conflict-disappears", False, False, 0, 0),
        ("mark-pending", False, False, 1, 1),
        ("mark-absent", False, False, 1, 1),
        ("mark-expired", False, False, 1, 1),
        ("mark-replaced", False, False, 1, 1),
        ("enqueue-replaced-queued", False, False, 1, 1),
        ("mark-replaced-queued", False, False, 1, 1),
    ],
)
async def test_dynamodb_state_feedback_application_reconciles_actual_local_ambiguity(
    dynamo_fixture: DynamoFixture,
    mode: str,
    first_succeeds: bool,
    retry_succeeds: bool,
    first_sends: int,
    total_sends: int,
) -> None:
    pool = FeedbackControlPool(capacity=2, stage_seconds=1.0)
    base = _runtime()
    principal = _principal("a" * 64)
    question_id = uuid4()
    now = base.application.clock.now()
    receipt = base.application.receipts.issue(
        question_id=question_id,
        owner_key=principal.owner_key,
        environment_id="alpha",
        content_sha="e" * 40,
        cue_ids=["old-cue"],
        topic_ids=["old-topic"],
        outcome_code=AnswerStatus.answered,
        now=now,
    )
    request = FeedbackRequest(
        question_id=question_id,
        environment_id="alpha",
        feedback_receipt=receipt,
        kind="wrong",
        note=None,
    )
    proxy = _ApplicationAmbiguityClient(cast(BaseClient, dynamo_fixture.clients[0]), mode)
    state = DynamoState(cast(DynamoClient, proxy), dynamo_fixture.table, feedback_control_pool=pool)
    sink = _FailingSink() if mode == "enqueue-replaced-queued" else _AcknowledgingSink()
    application = replace(
        base.application,
        feedback_store=cast(FeedbackStore, state),
        feedback_sink=cast(FeedbackSink, sink),
    )
    try:
        if first_succeeds:
            result = await application.feedback(request, principal)
            assert result.status == "queued"
        else:
            with pytest.raises(ServiceFailure) as failure:
                await application.feedback(request, principal)
            assert failure.value.error.code == ErrorCode.FEEDBACK_UNAVAILABLE
            if mode in {
                "create-conflict-disappears",
                "mark-pending",
                "mark-absent",
                "mark-expired",
                "enqueue-replaced-queued",
                "mark-replaced-queued",
            }:
                receipt_payload = application.receipts.open(
                    receipt,
                    question_id=question_id,
                    owner_key=principal.owner_key,
                    environment_id="alpha",
                    now=now,
                )
                row = await state.read_feedback(
                    receipt_id=receipt_payload.receipt_id,
                    note_hash="1b2185e00753da9593abf50ce85dc1d94412e2185c978b8b58cd0c3ed8a8fc06",
                    now=now,
                    control=_control(),
                )
                if mode == "mark-pending":
                    assert row is not None and row.status == "pending"
                elif mode in {"enqueue-replaced-queued", "mark-replaced-queued"}:
                    assert row is not None and row.status == "queued"
                    assert row.feedback_id != sink.events[0].feedback_id
                else:
                    assert row is None
        assert len(sink.events) == first_sends

        if retry_succeeds:
            proxy.mode = "normal"
            retry = await application.feedback(request, principal)
            assert retry.status == "queued"
        assert len(sink.events) == total_sends
        if mode in {
            "mark-pending",
            "mark-absent",
            "mark-expired",
            "mark-replaced",
            "mark-replaced-queued",
        }:
            assert len(sink.events) == 1
            assert proxy.updates == 1
    finally:
        pool.close()


@pytest.mark.asyncio
async def test_dynamodb_state_feedback_mark_uses_fresh_expiry_time(
    dynamo_fixture: DynamoFixture,
) -> None:
    clock = _ControlledClock()
    base = _runtime(clock)
    principal = _principal("a" * 64)
    question_id = uuid4()
    now = clock.now()
    receipt = base.application.receipts.issue(
        question_id=question_id,
        owner_key=principal.owner_key,
        environment_id="alpha",
        content_sha="f" * 40,
        cue_ids=["fresh-now-cue"],
        topic_ids=["fresh-now-topic"],
        outcome_code=AnswerStatus.answered,
        now=now,
    )
    request = FeedbackRequest(
        question_id=question_id,
        environment_id="alpha",
        feedback_receipt=receipt,
        kind="wrong",
        note=None,
    )
    receipt_id = base.application.receipts.open(
        receipt,
        question_id=question_id,
        owner_key=principal.owner_key,
        environment_id="alpha",
        now=now,
    ).receipt_id
    ttl_epoch = int(now.timestamp()) + 604800
    clock_at_expiry = datetime.fromtimestamp(ttl_epoch, UTC)
    pool = FeedbackControlPool(capacity=2, stage_seconds=1.0)
    client = cast(BaseClient, dynamo_fixture.clients[0])
    state = DynamoState(
        cast(DynamoClient, client), dynamo_fixture.table, feedback_control_pool=pool
    )
    sink = _AdvanceClockSink(clock, clock_at_expiry)
    application = replace(
        base.application,
        feedback_store=cast(FeedbackStore, state),
        feedback_sink=cast(FeedbackSink, sink),
    )
    try:
        with pytest.raises(ServiceFailure) as failure:
            await application.feedback(request, principal)
        assert failure.value.error.code == ErrorCode.FEEDBACK_UNAVAILABLE
        assert len(sink.events) == 1
        assert clock.monotonic() == 0.0
        item = client.get_item(
            TableName=dynamo_fixture.table,
            Key={
                "pk": {"S": f"FEEDBACK#{receipt_id}"},
                "sk": {"S": "1b2185e00753da9593abf50ce85dc1d94412e2185c978b8b58cd0c3ed8a8fc06"},
            },
            ConsistentRead=True,
        )["Item"]
        raw = cast(dict[str, object], item)
        assert raw["status"] == {"S": "pending"}
        assert raw["feedback_id"] == {"S": str(sink.events[0].feedback_id)}
        assert raw["ttl_epoch"] == {"N": str(ttl_epoch)}
        created_at = datetime.fromisoformat(
            cast(str, raw["created_at"]["S"]).replace("Z", "+00:00")
        )
        assert created_at == sink.events[0].created_at
    finally:
        pool.close()


@pytest.mark.asyncio
async def test_dynamodb_state_feedback_local_committed_create_timeout_keeps_physical_slot(
    dynamo_fixture: DynamoFixture,
) -> None:
    pool = FeedbackControlPool(capacity=2, stage_seconds=0.05)
    proxy = _CommitThenBlockCreate(cast(BaseClient, dynamo_fixture.clients[0]))
    state = DynamoState(cast(DynamoClient, proxy), dynamo_fixture.table, feedback_control_pool=pool)
    base = _runtime()
    principal = _principal("a" * 64)
    question_id = uuid4()
    receipt = base.application.receipts.issue(
        question_id=question_id,
        owner_key=principal.owner_key,
        environment_id="alpha",
        content_sha="f" * 40,
        cue_ids=["committed-cue"],
        topic_ids=["committed-topic"],
        outcome_code=AnswerStatus.answered,
        now=base.application.clock.now(),
    )
    request = FeedbackRequest(
        question_id=question_id,
        environment_id="alpha",
        feedback_receipt=receipt,
        kind="wrong",
        note=None,
    )
    sink = _AcknowledgingSink()
    application = replace(
        base.application,
        feedback_store=cast(FeedbackStore, state),
        feedback_sink=cast(FeedbackSink, sink),
    )
    try:
        task = asyncio.create_task(application.feedback(request, principal))
        assert await asyncio.to_thread(proxy.committed.wait, 2.0)
        result = await asyncio.wait_for(task, timeout=2.0)
        assert result.status == "queued"
        assert len(sink.events) == 1
        assert pool._capacity.acquire(blocking=False)
        assert not pool._capacity.acquire(blocking=False)
        pool._capacity.release()
    finally:
        proxy.release.set()
        pool.close()


@pytest.mark.asyncio
async def test_dynamodb_state_feedback_expiry_replacement_fences_late_sender(
    dynamo_fixture: DynamoFixture,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    pool = FeedbackControlPool()
    state = DynamoState(
        cast(DynamoClient, dynamo_fixture.clients[0]),
        dynamo_fixture.table,
        feedback_control_pool=pool,
    )
    receipt_id = uuid4()
    note_hash = "b" * 64
    try:
        fence_receipt_id = uuid4()
        pending = await state.try_create_feedback(
            receipt_id=fence_receipt_id,
            note_hash=note_hash,
            now=now,
            control=_control(),
        )
        assert pending is not None
        pending_expiry = datetime.fromtimestamp(pending.ttl_epoch, UTC)
        assert (
            await state.read_feedback(
                receipt_id=fence_receipt_id,
                note_hash=note_hash,
                now=pending_expiry,
                control=_control(),
            )
            is None
        )
        assert not await state.mark_feedback_queued(
            receipt_id=fence_receipt_id,
            note_hash=note_hash,
            feedback_id=pending.feedback_id,
            now=pending_expiry,
            control=_control(),
        )
        replacement = await state.try_create_feedback(
            receipt_id=fence_receipt_id,
            note_hash=note_hash,
            now=pending_expiry,
            control=_control(),
        )
        assert replacement is not None and replacement.feedback_id != pending.feedback_id
        assert not await state.mark_feedback_queued(
            receipt_id=fence_receipt_id,
            note_hash=note_hash,
            feedback_id=pending.feedback_id,
            now=pending_expiry,
            control=_control(),
        )

        first = await state.try_create_feedback(
            receipt_id=receipt_id, note_hash=note_hash, now=now, control=_control()
        )
        assert first is not None
        assert first.ttl_epoch == int(now.timestamp()) + 604800
        # Pending-to-queued succeeds once and keeps the original fixed expiry.
        assert await state.mark_feedback_queued(
            receipt_id=receipt_id,
            note_hash=note_hash,
            feedback_id=first.feedback_id,
            now=now,
            control=_control(),
        )
        assert not await state.mark_feedback_queued(
            receipt_id=receipt_id,
            note_hash=note_hash,
            feedback_id=first.feedback_id,
            now=now,
            control=_control(),
        )
        queued_first = await state.read_feedback(
            receipt_id=receipt_id,
            note_hash=note_hash,
            now=now,
            control=_control(),
        )
        assert queued_first is not None and queued_first.ttl_epoch == first.ttl_epoch
        expires = datetime.fromtimestamp(first.ttl_epoch, UTC)
        assert not await state.mark_feedback_queued(
            receipt_id=receipt_id,
            note_hash=note_hash,
            feedback_id=first.feedback_id,
            now=expires,
            control=_control(),
        )
        assert (
            await state.read_feedback(
                receipt_id=receipt_id,
                note_hash=note_hash,
                now=expires,
                control=_control(),
            )
            is None
        )
        second = await state.try_create_feedback(
            receipt_id=receipt_id,
            note_hash=note_hash,
            now=expires,
            control=_control(),
        )
        assert second is not None and second.feedback_id != first.feedback_id
        assert not await state.mark_feedback_queued(
            receipt_id=receipt_id,
            note_hash=note_hash,
            feedback_id=first.feedback_id,
            now=expires,
            control=_control(),
        )
        assert (
            await state.read_feedback(
                receipt_id=receipt_id,
                note_hash=note_hash,
                now=expires,
                control=_control(),
            )
            == second
        )
    finally:
        pool.close()


@pytest.mark.asyncio
async def test_dynamodb_state_feedback_malformed_live_rows_fail_sanitized(
    dynamo_fixture: DynamoFixture,
) -> None:
    client = cast(BaseClient, dynamo_fixture.clients[0])
    pool = FeedbackControlPool()
    state = DynamoState(
        cast(DynamoClient, client),
        dynamo_fixture.table,
        feedback_control_pool=pool,
    )
    now = datetime.now(UTC).replace(microsecond=0)
    templates = [
        {"note": {"S": "private queue body"}},
        {"status": None},
        {"status": {"S": "unknown"}},
        {"schema_version": {"S": "2"}},
        {"feedback_id": {"S": "invalid"}},
        {"created_at": {"S": "invalid"}},
        {"ttl_epoch": {"N": "1.5"}},
        {"ttl_epoch": {"BOOL": True}},
        {"ttl_epoch": {"S": "1800000000"}},
        {"record_type": {"S": "other"}},
        {"ttl_epoch": {"N": "-1"}},
    ]
    try:
        for index, change in enumerate(templates):
            receipt_id = uuid4()
            note_hash = f"{index:064x}"
            item: dict[str, object] = {
                "pk": {"S": f"FEEDBACK#{receipt_id}"},
                "sk": {"S": note_hash},
                "record_type": {"S": "feedback"},
                "schema_version": {"S": "1"},
                "feedback_id": {"S": str(uuid4())},
                "status": {"S": "pending"},
                "created_at": {"S": now.isoformat()},
                "ttl_epoch": {"N": str(int(now.timestamp()) + 100)},
            }
            for name, value in change.items():
                if value is None:
                    item.pop(name)
                else:
                    item[name] = value
            client.put_item(TableName=dynamo_fixture.table, Item=item)
            with pytest.raises(StateFailure) as failure:
                await state.read_feedback(
                    receipt_id=receipt_id,
                    note_hash=note_hash,
                    now=now,
                    control=_control(),
                )
            assert failure.value.code == ErrorCode.FEEDBACK_UNAVAILABLE
            assert "private queue body" not in failure.value.error.message
    finally:
        pool.close()


@pytest.mark.asyncio
async def test_dynamodb_state_feedback_reconciles_lost_create_and_mark_responses(
    dynamo_fixture: DynamoFixture,
) -> None:
    client = cast(BaseClient, dynamo_fixture.clients[0])
    proxy = _CommitThenLoseResponse(client)
    pool = FeedbackControlPool()
    state = DynamoState(
        cast(DynamoClient, proxy),
        dynamo_fixture.table,
        feedback_control_pool=pool,
    )
    reader = DynamoState(
        cast(DynamoClient, client),
        dynamo_fixture.table,
        feedback_control_pool=pool,
    )
    receipt_id = uuid4()
    note_hash = "c" * 64
    now = datetime.now(UTC).replace(microsecond=0)
    try:
        proxy.operation = "put_item"
        with pytest.raises(StateFailure) as create_failure:
            await state.try_create_feedback(
                receipt_id=receipt_id,
                note_hash=note_hash,
                now=now,
                control=_control(),
            )
        assert create_failure.value.code == ErrorCode.FEEDBACK_UNAVAILABLE
        pending = await reader.read_feedback(
            receipt_id=receipt_id,
            note_hash=note_hash,
            now=now,
            control=_control(),
        )
        assert pending is not None and pending.status == "pending"

        proxy.operation = "update_item"
        with pytest.raises(StateFailure) as mark_failure:
            await state.mark_feedback_queued(
                receipt_id=receipt_id,
                note_hash=note_hash,
                feedback_id=pending.feedback_id,
                now=now,
                control=_control(),
            )
        assert mark_failure.value.code == ErrorCode.FEEDBACK_UNAVAILABLE
        queued = await reader.read_feedback(
            receipt_id=receipt_id,
            note_hash=note_hash,
            now=now,
            control=_control(),
        )
        assert queued is not None and queued.status == "queued"
        assert queued.feedback_id == pending.feedback_id
    finally:
        pool.close()
