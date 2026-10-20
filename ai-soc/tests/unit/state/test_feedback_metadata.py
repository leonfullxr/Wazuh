from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import uuid4

import pytest

from ai_soc.application.runtime import BoundedCallLedger, RequestCancellation, RequestCancelled
from ai_soc.contracts.models import CallKind, ErrorCode, FeedbackControlContext
from ai_soc.state.dynamodb import DynamoClient, DynamoState
from ai_soc.state.errors import StateFailure
from ai_soc.state.feedback_control import FeedbackControlPool
from ai_soc.state.memory import MemoryState

NOW = datetime(2026, 10, 3, 12, tzinfo=UTC)


def _control(*, deadline_offset: float = 30.0) -> FeedbackControlContext:
    return FeedbackControlContext(
        deadline_monotonic=time.monotonic() + deadline_offset,
        monotonic=time.monotonic,
        cancel=RequestCancellation(),
        calls=BoundedCallLedger(),
    )


class _EmptyDynamo:
    def __init__(self) -> None:
        self.reads = 0

    def get_item(self, **_kwargs: object) -> dict[str, object]:
        self.reads += 1
        return {}

    def put_item(self, **_kwargs: object) -> dict[str, object]:
        return {}

    def update_item(self, **_kwargs: object) -> dict[str, object]:
        return {}

    def transact_write_items(self, **_kwargs: object) -> dict[str, object]:
        return {}

    def query(self, **_kwargs: object) -> dict[str, object]:
        return {}


class _ControlledFeedbackLock:
    def __init__(self, after_acquire: Callable[[], None]) -> None:
        self._lock = threading.Lock()
        self._after_acquire = after_acquire

    def acquire(self, blocking: bool = True) -> bool:
        acquired = self._lock.acquire(blocking=blocking)
        if acquired:
            self._after_acquire()
        return acquired

    def release(self) -> None:
        self._lock.release()

    def locked(self) -> bool:
        return self._lock.locked()


@pytest.mark.asyncio
async def test_memory_feedback_ttl_fences_pending_and_queued_generations() -> None:
    state = MemoryState()
    receipt_id = uuid4()
    note_hash = "a" * 64
    pending = await state.try_create_feedback(
        receipt_id=receipt_id, note_hash=note_hash, now=NOW, control=_control()
    )
    assert pending is not None
    assert pending.ttl_epoch == int(NOW.timestamp()) + 604800
    assert (
        await state.read_feedback(
            receipt_id=receipt_id,
            note_hash=note_hash,
            now=datetime.fromtimestamp(pending.ttl_epoch - 1, UTC),
            control=_control(),
        )
        == pending
    )
    assert (
        await state.try_create_feedback(
            receipt_id=receipt_id, note_hash=note_hash, now=NOW, control=_control()
        )
        is None
    )
    assert (
        await state.try_create_feedback(
            receipt_id=receipt_id,
            note_hash=note_hash,
            now=datetime.fromtimestamp(pending.ttl_epoch, UTC),
            control=_control(),
        )
        is not None
    )
    replacement = state.feedback_records[(receipt_id, note_hash)]
    assert replacement.feedback_id != pending.feedback_id
    assert not await state.mark_feedback_queued(
        receipt_id=receipt_id,
        note_hash=note_hash,
        feedback_id=pending.feedback_id,
        now=NOW,
        control=_control(),
    )
    assert not await state.mark_feedback_queued(
        receipt_id=receipt_id,
        note_hash=note_hash,
        feedback_id=replacement.feedback_id,
        now=datetime.fromtimestamp(replacement.ttl_epoch, UTC),
        control=_control(),
    )
    assert state.feedback_records[(receipt_id, note_hash)] == replacement
    assert (
        await state.read_feedback(
            receipt_id=receipt_id,
            note_hash=note_hash,
            now=datetime.fromtimestamp(replacement.ttl_epoch, UTC),
            control=_control(),
        )
        is None
    )


@pytest.mark.asyncio
async def test_memory_feedback_mark_is_pending_only_and_never_upserts() -> None:
    state = MemoryState()
    receipt_id = uuid4()
    note_hash = "b" * 64
    control = _control()
    assert not await state.mark_feedback_queued(
        receipt_id=receipt_id,
        note_hash=note_hash,
        feedback_id=uuid4(),
        now=NOW,
        control=control,
    )
    assert state.feedback_records == {}
    pending = await state.try_create_feedback(
        receipt_id=receipt_id, note_hash=note_hash, now=NOW, control=_control()
    )
    assert pending is not None
    assert await state.mark_feedback_queued(
        receipt_id=receipt_id,
        note_hash=note_hash,
        feedback_id=pending.feedback_id,
        now=NOW + timedelta(seconds=1),
        control=_control(),
    )
    queued = state.feedback_records[(receipt_id, note_hash)]
    assert queued.status == "queued"
    assert queued.created_at == pending.created_at
    assert queued.ttl_epoch == pending.ttl_epoch
    assert not await state.try_create_feedback(
        receipt_id=receipt_id,
        note_hash=note_hash,
        now=NOW + timedelta(seconds=2),
        control=_control(),
    )
    assert not await state.mark_feedback_queued(
        receipt_id=receipt_id,
        note_hash=note_hash,
        feedback_id=pending.feedback_id,
        now=NOW + timedelta(seconds=2),
        control=_control(),
    )
    assert state.feedback_records[(receipt_id, note_hash)] == queued


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["read", "create", "mark"])
@pytest.mark.parametrize("rejection", ["cancel", "budget"])
async def test_memory_feedback_rejects_cancel_and_budget_without_mutation(
    operation: str, rejection: str
) -> None:
    state = MemoryState()
    receipt_id = uuid4()
    note_hash = "c" * 64
    metadata = await state.try_create_feedback(
        receipt_id=receipt_id, note_hash=note_hash, now=NOW, control=_control()
    )
    assert metadata is not None
    control = _control(deadline_offset=0.0 if rejection == "budget" else 30.0)
    if rejection == "cancel":
        control.cancel.cancel()
    method = {
        "read": lambda: state.read_feedback(
            receipt_id=receipt_id, note_hash=note_hash, now=NOW, control=control
        ),
        "create": lambda: state.try_create_feedback(
            receipt_id=uuid4(), note_hash=note_hash, now=NOW, control=control
        ),
        "mark": lambda: state.mark_feedback_queued(
            receipt_id=receipt_id,
            note_hash=note_hash,
            feedback_id=metadata.feedback_id,
            now=NOW,
            control=control,
        ),
    }[operation]
    before = dict(state.feedback_records)
    if rejection == "cancel":
        with pytest.raises(RequestCancelled):
            await method()
    else:
        with pytest.raises(StateFailure) as failure:
            await method()
        assert failure.value.code == ErrorCode.FEEDBACK_UNAVAILABLE
    assert state.feedback_records == before
    assert control.calls.attempts(CallKind.state) == 0


@pytest.mark.asyncio
async def test_memory_feedback_nonblocking_lock_contention_fails_and_releases() -> None:
    state = MemoryState()
    receipt_id = uuid4()
    note_hash = "d" * 64
    state._feedback_lock.acquire()

    async def read_under_worker() -> object:
        return await state.read_feedback(
            receipt_id=receipt_id,
            note_hash=note_hash,
            now=NOW,
            control=_control(),
        )

    worker = asyncio.create_task(asyncio.to_thread(lambda: asyncio.run(read_under_worker())))
    try:
        with pytest.raises(StateFailure) as failure:
            await asyncio.wait_for(asyncio.shield(worker), timeout=0.5)
        assert failure.value.code == ErrorCode.FEEDBACK_UNAVAILABLE
        assert state.feedback_records == {}
    except TimeoutError:
        state._feedback_lock.release()
        await asyncio.wait_for(worker, timeout=1.0)
        pytest.fail("feedback lock acquisition blocked instead of failing fast")
    finally:
        if state._feedback_lock.locked():
            state._feedback_lock.release()

    created = await state.try_create_feedback(
        receipt_id=receipt_id, note_hash=note_hash, now=NOW, control=_control()
    )
    assert created is not None


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["read", "create", "mark"])
@pytest.mark.parametrize("rejection", ["cancel", "deadline"])
async def test_memory_feedback_rechecks_control_after_lock_acquisition(
    monkeypatch: pytest.MonkeyPatch, operation: str, rejection: str
) -> None:
    state = MemoryState()
    receipt_id = uuid4()
    note_hash = "f" * 64
    pending = await state.try_create_feedback(
        receipt_id=receipt_id, note_hash=note_hash, now=NOW, control=_control()
    )
    assert pending is not None
    current = [0.0]
    control = FeedbackControlContext(
        deadline_monotonic=20.0,
        monotonic=lambda: current[0],
        cancel=RequestCancellation(),
        calls=BoundedCallLedger(),
    )

    def change_after_acquire() -> None:
        if rejection == "cancel":
            control.cancel.cancel()
        else:
            current[0] = 15.1

    lock = _ControlledFeedbackLock(change_after_acquire)
    monkeypatch.setattr(state, "_feedback_lock", lock)
    before = dict(state.feedback_records)
    if operation == "read":
        invoke = state.read_feedback(
            receipt_id=receipt_id, note_hash=note_hash, now=NOW, control=control
        )
    elif operation == "create":
        invoke = state.try_create_feedback(
            receipt_id=uuid4(), note_hash=note_hash, now=NOW, control=control
        )
    else:
        invoke = state.mark_feedback_queued(
            receipt_id=receipt_id,
            note_hash=note_hash,
            feedback_id=pending.feedback_id,
            now=NOW,
            control=control,
        )
    if rejection == "cancel":
        with pytest.raises(RequestCancelled):
            await invoke
    else:
        with pytest.raises(StateFailure):
            await invoke
    assert state.feedback_records == before
    assert not lock.locked()


@pytest.mark.asyncio
async def test_memory_feedback_pre_cancel_wins_over_busy_lock_contention() -> None:
    state = MemoryState()
    receipt_id = uuid4()
    note_hash = "e" * 64
    before = dict(state.feedback_records)
    state._feedback_lock.acquire()
    control = _control()
    control.cancel.cancel()
    try:
        with pytest.raises(RequestCancelled):
            await state.read_feedback(
                receipt_id=receipt_id, note_hash=note_hash, now=NOW, control=control
            )
        assert state.feedback_records == before
    finally:
        state._feedback_lock.release()


@pytest.mark.asyncio
async def test_dynamodb_feedback_control_bypasses_fully_occupied_legacy_io_semaphore() -> None:
    client = _EmptyDynamo()
    pool = FeedbackControlPool(capacity=1, stage_seconds=1.0)
    state = DynamoState(cast(DynamoClient, client), "feedback-fixture", feedback_control_pool=pool)
    for _ in range(8):
        await state._io.acquire()
    try:
        record = await asyncio.wait_for(
            state.read_feedback(
                receipt_id=uuid4(), note_hash="e" * 64, now=NOW, control=_control()
            ),
            timeout=1.0,
        )
        assert record is None
        assert client.reads == 1
    finally:
        for _ in range(8):
            state._io.release()
        pool.close()
