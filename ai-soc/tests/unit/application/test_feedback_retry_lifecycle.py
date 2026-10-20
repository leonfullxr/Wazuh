from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

import pytest

from ai_soc.application.errors import ServiceFailure
from ai_soc.application.runtime import RequestCancellation, RequestCancelled, RequestRuntime
from ai_soc.content.catalog import ContentCatalog
from ai_soc.contracts.errors import public_error
from ai_soc.contracts.models import (
    SHA256,
    AdmissionGrant,
    AnswerStatus,
    CallKind,
    ErrorCode,
    ExecutionContext,
    FeedbackControlContext,
    FeedbackEvent,
    FeedbackMetadata,
    FeedbackRequest,
    VerifiedPrincipal,
)
from ai_soc.contracts.ports import AdmissionStore, FeedbackSink, FeedbackStore
from ai_soc.state.dynamodb import DynamoClient, DynamoState
from ai_soc.state.errors import StateFailure
from ai_soc.state.feedback_control import FeedbackControlPool
from ai_soc.state.memory import MemoryState
from tests.unit.application.test_fenced_completion import (
    _ControlledClock,
    _principal,
    _runtime,
)

_DIGEST_VECTORS: tuple[tuple[str | None, str], ...] = (
    (None, "1b2185e00753da9593abf50ce85dc1d94412e2185c978b8b58cd0c3ed8a8fc06"),
    ("", "29a5d2510565a89788b589ef3f6617ace8cf90581c152eff9b8980680869dde8"),
    (
        "[redacted email]",
        "6a81b31cccdb1bb03b3a7aeccff760761de7d58c8578cd9e9a286604f591652c",
    ),
    ("note", "61279277e3941c0c57894bbb1147ea8164391317e69899475f364a031b134a3d"),
    (" note", "a2c470829f06f51ca20dfd8157486964af8a722acba0e248d11cdb67c48636d1"),
    ("Note", "a40ec67a41c359693071ef12cbd786a39d1c7139e8bb47f3d34d0f9f2f5a16fd"),
    ("line\nnext", "6af3541c7686ade13418e58bf98f20e7e160080fd9c2088512b3533452e07b28"),
    ("line\r\nnext", "137bfa0f13e82e0e7f84341af9215a9905fa426fd8117e52e9992839658a51db"),
    ("caf\u00e9", "abea72948d639ca1d7e919ea9c725c31d18d1531601fc11c18fed767673d96d7"),
    ("cafe\u0301", "255050c2eb59d57e65aa0d46b3a19ae798a319f3f142b206f32a98c667b382dd"),
)


class _Sink:
    def __init__(self, *, failure: BaseException | None = None) -> None:
        self.events: list[FeedbackEvent] = []
        self.failure = failure
        self.cancel_token = False
        self.before_failure: Callable[[], None] | None = None

    async def enqueue(self, event: FeedbackEvent, *, execution: ExecutionContext) -> UUID:
        self.events.append(event)
        if self.cancel_token:
            execution.cancel.cancel()
            raise RequestCancelled
        if self.failure is not None:
            if self.before_failure is not None:
                self.before_failure()
            raise self.failure
        return event.feedback_id


class _Store:
    def __init__(self, state: MemoryState) -> None:
        self.state = state
        self.reads = 0
        self.creates = 0
        self.marks = 0
        self.fail_read_at: set[int] = set()
        self.read_failure: BaseException | None = None
        self.fail_create = False
        self.fail_mark = False
        self.controls: list[FeedbackControlContext] = []
        self.after_read: Callable[[int], None] | None = None

    async def read_feedback(
        self,
        *,
        receipt_id: UUID,
        note_hash: SHA256,
        now: datetime,
        control: FeedbackControlContext,
    ) -> FeedbackMetadata | None:
        self.reads += 1
        self.controls.append(control)
        if self.read_failure is not None:
            raise self.read_failure
        if self.reads in self.fail_read_at:
            raise OSError("private metadata read failure")
        record = await self.state.read_feedback(
            receipt_id=receipt_id, note_hash=note_hash, now=now, control=control
        )
        if self.after_read is not None:
            self.after_read(self.reads)
        return record

    async def try_create_feedback(
        self,
        *,
        receipt_id: UUID,
        note_hash: SHA256,
        now: datetime,
        control: FeedbackControlContext,
    ) -> FeedbackMetadata | None:
        self.creates += 1
        if self.fail_create:
            raise OSError("private create failure")
        return await self.state.try_create_feedback(
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
        self.marks += 1
        if self.fail_mark:
            raise OSError("private mark failure")
        return await self.state.mark_feedback_queued(
            receipt_id=receipt_id,
            note_hash=note_hash,
            feedback_id=feedback_id,
            now=now,
            control=control,
        )


class _Admissions:
    def __init__(self, delegate: AdmissionStore) -> None:
        self.delegate = delegate
        self.acquired: list[AdmissionGrant] = []
        self.released: list[AdmissionGrant] = []
        self.reject = False
        self.after_acquire: Callable[[], None] | None = None

    async def acquire(
        self,
        owner_key: str,
        environment_id: str,
        operation: str,
        question_id: UUID,
        now: datetime,
    ) -> AdmissionGrant:
        if self.reject:
            raise ServiceFailure(
                public_error(
                    ErrorCode.RATE_LIMITED,
                    "fixture admission rejected",
                    trace_id="a" * 32,
                )
            )
        grant = await self.delegate.acquire(owner_key, environment_id, operation, question_id, now)
        self.acquired.append(grant)
        if self.after_acquire is not None:
            self.after_acquire()
        return grant

    async def renew(self, grant: AdmissionGrant, now: datetime) -> AdmissionGrant:
        return await self.delegate.renew(grant, now)

    async def release(self, grant: AdmissionGrant) -> None:
        self.released.append(grant)
        await self.delegate.release(grant)


def _request(
    application,
    principal: VerifiedPrincipal,
    *,
    note: str | None,
    question_id: UUID | None = None,
    environment_id: str = "alpha",
    lifetime_seconds: int = 1800,
    content_sha: str = "d" * 40,
) -> FeedbackRequest:
    selected_question = question_id or uuid4()
    token = application.receipts.issue(
        question_id=selected_question,
        owner_key=principal.owner_key,
        environment_id=environment_id,
        content_sha=content_sha,
        cue_ids=["cue-original"],
        topic_ids=["topic-original"],
        outcome_code=AnswerStatus.answered,
        now=application.clock.now(),
        lifetime_seconds=lifetime_seconds,
    )
    return FeedbackRequest(
        question_id=selected_question,
        environment_id=environment_id,
        feedback_receipt=token,
        kind="wrong",
        note=note,
    )


def _fixture(*, note: str | None = None):
    clock = _ControlledClock()
    runtime = _runtime(clock)
    principal = _principal("a" * 64)
    request = _request(runtime.application, principal, note=note)
    state = cast(MemoryState, runtime.application.feedback_store)
    store = _Store(state)
    sink = _Sink()
    admissions = _Admissions(cast(AdmissionStore, runtime.application.admissions))
    runtime.application.feedback_store = cast(FeedbackStore, store)
    runtime.application.feedback_sink = cast(FeedbackSink, sink)
    runtime.application.admissions = cast(AdmissionStore, admissions)
    return runtime, principal, request, state, store, sink, admissions, clock


@pytest.mark.asyncio
@pytest.mark.parametrize(("note", "digest"), _DIGEST_VECTORS)
async def test_application_persists_each_independent_note_digest_vector(
    note: str | None, digest: str
) -> None:
    runtime, principal, request, state, _store, sink, _admissions, clock = _fixture(note=note)
    first = await runtime.application.feedback(request, principal)
    assert len(sink.events) == 1
    stored = state.feedback_records
    payload = runtime.application.receipts.open(
        request.feedback_receipt,
        question_id=request.question_id,
        owner_key=principal.owner_key,
        environment_id=request.environment_id,
        now=clock.now(),
    )
    assert (payload.receipt_id, digest) in stored
    assert stored[(payload.receipt_id, digest)].feedback_id == first.feedback_id
    clock.current += timedelta(seconds=3)
    second = await runtime.application.feedback(request, principal)
    assert second.feedback_id == first.feedback_id
    assert len(sink.events) == 1
    assert sink.events[0].created_at == stored[(payload.receipt_id, digest)].created_at


@pytest.mark.asyncio
async def test_application_redacted_email_equivalence_and_receipt_scope() -> None:
    runtime, principal, first_request, state, _store, sink, _admissions, _clock = _fixture(
        note="contact alice@example.test"
    )
    first = await runtime.application.feedback(first_request, principal)
    same_receipt = first_request.model_copy(update={"note": "contact bob@example.test"})
    duplicate = await runtime.application.feedback(same_receipt, principal)
    assert duplicate.feedback_id == first.feedback_id
    assert len(sink.events) == 1
    assert sink.events[0].note_redacted == "contact [redacted email]"

    other_receipt = _request(runtime.application, principal, note="contact carol@example.test")
    other = await runtime.application.feedback(other_receipt, principal)
    assert other.feedback_id != first.feedback_id
    assert len(sink.events) == 2
    assert len(state.feedback_records) == 2


@pytest.mark.asyncio
async def test_application_concurrent_distinct_notes_create_distinct_events() -> None:
    runtime, principal, first_request, state, _store, sink, _admissions, _clock = _fixture(
        note="first note"
    )
    second_request = first_request.model_copy(update={"note": "second note"})
    first, second = await asyncio.gather(
        runtime.application.feedback(first_request, principal),
        runtime.application.feedback(second_request, principal),
    )
    assert first.feedback_id != second.feedback_id
    assert len(sink.events) == 2
    assert {event.note_redacted for event in sink.events} == {"first note", "second note"}
    assert len(state.feedback_records) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [
        "site-denied",
        "foreign",
        "tampered",
        "expired",
        "question-mismatch",
        "site-mismatch",
        "secret",
    ],
)
async def test_forbidden_feedback_requests_never_access_metadata(case: str) -> None:
    runtime, principal, request, _state, store, sink, admissions, clock = _fixture(note="ordinary")
    if case == "site-denied":
        principal = principal.model_copy(update={"groups": ("unmapped",)})
    elif case == "foreign":
        principal = _principal("b" * 64)
    elif case == "tampered":
        request = request.model_copy(
            update={
                "feedback_receipt": request.feedback_receipt[:-1]
                + ("A" if request.feedback_receipt[-1] != "A" else "B")
            }
        )
    elif case == "expired":
        request = _request(runtime.application, principal, note="ordinary", lifetime_seconds=1)
        clock.current += timedelta(seconds=2)
    elif case == "question-mismatch":
        request = request.model_copy(update={"question_id": uuid4()})
    elif case == "site-mismatch":
        request = _request(runtime.application, principal, note="ordinary", environment_id="beta")
        request = request.model_copy(update={"environment_id": "alpha"})
    else:
        request = request.model_copy(update={"note": "password=private"})
    with pytest.raises(ServiceFailure):
        await runtime.application.feedback(request, principal)
    assert (store.reads, store.creates, store.marks) == (0, 0, 0)
    assert sink.events == []
    assert admissions.acquired == []
    assert admissions.released == []


@pytest.mark.asyncio
async def test_admission_rejection_and_queued_retry_still_require_admission() -> None:
    runtime, principal, request, _state, store, sink, admissions, _clock = _fixture(note="note")
    admissions.reject = True
    with pytest.raises(ServiceFailure):
        await runtime.application.feedback(request, principal)
    assert (store.reads, store.creates, store.marks) == (0, 0, 0)
    assert sink.events == []
    assert admissions.acquired == admissions.released == []

    admissions.reject = False
    queued = await runtime.application.feedback(request, principal)
    prior_acquires = len(admissions.acquired)
    duplicate = await runtime.application.feedback(request, principal)
    assert duplicate.feedback_id == queued.feedback_id
    assert len(admissions.acquired) == prior_acquires + 1
    assert len(admissions.released) == len(admissions.acquired)
    assert len(sink.events) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("cancellation", ["external", "token"])
async def test_store_cancellation_preserves_exception_without_recovery_or_send(
    cancellation: str,
) -> None:
    runtime, principal, request, _state, store, sink, admissions, _clock = _fixture(note="note")
    store.read_failure = (
        asyncio.CancelledError() if cancellation == "external" else RequestCancelled()
    )
    expected = asyncio.CancelledError if cancellation == "external" else RequestCancelled
    with pytest.raises(expected):
        await runtime.application.feedback(request, principal)
    assert store.reads == 1
    assert store.creates == store.marks == 0
    assert sink.events == []
    assert admissions.released == admissions.acquired


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        "runtime-create",
        "initial-read",
        "create-reconcile-read",
        "enqueue",
        "enqueue-cancel",
        "enqueue-token-cancel",
        "mark-reconcile-read",
        "budget",
    ],
)
async def test_feedback_grant_releases_on_added_failure_paths(failure: str) -> None:
    runtime, principal, request, _state, store, sink, admissions, _clock = _fixture(note="note")
    if failure == "runtime-create":
        runtime.application.runtime.create = lambda **_kwargs: (_ for _ in ()).throw(
            RuntimeError("runtime creation failed")
        )
    elif failure == "initial-read":
        store.fail_read_at = {1}
    elif failure == "create-reconcile-read":
        store.fail_create = True
        store.fail_read_at = {2}
    elif failure == "enqueue":
        sink.failure = OSError("private queue failure")
    elif failure == "enqueue-cancel":
        sink.failure = asyncio.CancelledError()
    elif failure == "enqueue-token-cancel":
        sink.cancel_token = True
    elif failure == "mark-reconcile-read":
        store.fail_mark = True
        store.fail_read_at = {2}
    else:
        runtime.application.runtime = RequestRuntime(runtime.application.clock, deadline_seconds=10)
    if failure in {"enqueue-cancel", "enqueue-token-cancel"}:
        expected = (asyncio.CancelledError, RequestCancelled)
        with pytest.raises(expected):
            await runtime.application.feedback(request, principal)
    else:
        with pytest.raises(ServiceFailure):
            await runtime.application.feedback(request, principal)
    assert len(admissions.acquired) == 1
    assert admissions.released == admissions.acquired
    if failure in {"enqueue-cancel", "enqueue-token-cancel"}:
        assert store.reads == store.creates == 1
        assert store.marks == 0
        assert len(sink.events) == 1
    if failure in {"initial-read", "create-reconcile-read", "budget", "runtime-create"}:
        assert sink.events == []


@pytest.mark.asyncio
async def test_feedback_preserves_receipt_content_provenance_after_catalog_change() -> None:
    runtime, principal, request, _state, _store, sink, _admissions, _clock = _fixture(note="note")
    original_sha = "d" * 40
    request = _request(
        runtime.application,
        principal,
        note="note",
        question_id=request.question_id,
        content_sha=original_sha,
    )
    runtime.application.catalog = cast(ContentCatalog, object())
    result = await runtime.application.feedback(request, principal)
    assert result.status == "queued"
    assert sink.events[0].content_sha == original_sha


@pytest.mark.parametrize(
    ("runtime_seconds", "wall_shift_seconds", "expected_remaining"),
    [(30, 5, 15.0), (120, -60, 110.0)],
)
@pytest.mark.asyncio
async def test_feedback_service_deadline_uses_runtime_and_entry_caps(
    runtime_seconds: int, wall_shift_seconds: int, expected_remaining: float
) -> None:
    runtime, principal, request, _state, store, _sink, _admissions, clock = _fixture(note="note")
    mono = [40.0]
    clock.monotonic = lambda: mono[0]
    runtime.application.runtime = RequestRuntime(clock, deadline_seconds=runtime_seconds)
    create = runtime.application.runtime.create

    def create_then_shift_wall_clock(**kwargs):
        execution = create(**kwargs)
        clock.current += timedelta(seconds=wall_shift_seconds)
        return execution

    runtime.application.runtime.create = create_then_shift_wall_clock
    result = await runtime.application.feedback(request, principal)
    assert result.status == "queued"
    assert store.controls
    assert store.controls[0].deadline_monotonic - mono[0] == expected_remaining


@pytest.mark.parametrize("remaining_before_sink", [10.0, 9.99])
@pytest.mark.asyncio
async def test_feedback_sink_requires_ten_seconds_and_recovery_does_not_reset_budget(
    remaining_before_sink: float,
) -> None:
    runtime, principal, request, _state, store, sink, admissions, _clock = _fixture(note="note")
    mono = [0.0]
    runtime.application.clock.monotonic = lambda: mono[0]
    sink_time = 100.0 if remaining_before_sink == 10.0 else 100.01
    store.after_read = lambda count: mono.__setitem__(0, sink_time) if count == 1 else None
    sink.before_failure = lambda: mono.__setitem__(0, 100.0 + (10.0 - remaining_before_sink))
    if remaining_before_sink == 9.99:
        with pytest.raises(ServiceFailure):
            await runtime.application.feedback(request, principal)
        assert sink.events == []
        assert store.reads == 1
        assert store.marks == 0
    else:
        result = await runtime.application.feedback(request, principal)
        assert result.status == "queued"
        assert len(sink.events) == 1
        assert store.marks == 1
    assert admissions.released == admissions.acquired
    assert store.controls[0].deadline_monotonic == 110.0


@pytest.mark.asyncio
async def test_feedback_ambiguous_send_recovery_keeps_original_budget() -> None:
    runtime, principal, request, _state, store, sink, admissions, _clock = _fixture(note="note")
    mono = [0.0]
    runtime.application.clock.monotonic = lambda: mono[0]
    store.after_read = lambda count: mono.__setitem__(0, 100.0) if count == 1 else None
    sink.failure = OSError("private queue response")
    sink.before_failure = lambda: mono.__setitem__(0, 106.0)

    with pytest.raises(ServiceFailure):
        await runtime.application.feedback(request, principal)
    assert len(sink.events) == 1
    assert store.reads == 1
    assert store.marks == 0
    assert admissions.released == admissions.acquired
    assert store.controls[0].deadline_monotonic == 110.0


@pytest.mark.asyncio
async def test_feedback_budget_charges_admission_elapsed_before_runtime_creation() -> None:
    runtime, principal, request, _state, store, sink, admissions, clock = _fixture(note="note")
    monotonic = [0.0]
    clock.monotonic = lambda: monotonic[0]

    def consume_admission_budget() -> None:
        monotonic[0] = 106.0
        clock.current += timedelta(seconds=106)

    admissions.after_acquire = consume_admission_budget
    with pytest.raises(ServiceFailure) as failure:
        await runtime.application.feedback(request, principal)
    assert failure.value.error.code == ErrorCode.FEEDBACK_UNAVAILABLE
    assert (store.reads, store.creates, store.marks) == (0, 0, 0)
    assert sink.events == []
    assert admissions.acquired == admissions.released


@pytest.mark.parametrize("failure_kind", ["oserror", "state", "service"])
@pytest.mark.asyncio
async def test_feedback_read_failures_are_sanitized_at_public_service_boundary(
    failure_kind: str,
) -> None:
    runtime, principal, request, _state, store, sink, admissions, _clock = _fixture(note="note")
    private_message = "private dependency diagnostics"
    detail = public_error(
        ErrorCode.FEEDBACK_UNAVAILABLE,
        private_message,
        trace_id="b" * 32,
        retryable=True,
    )
    if failure_kind == "oserror":
        failure: BaseException = OSError(private_message)
    elif failure_kind == "state":
        failure = StateFailure(detail)
    else:
        failure = ServiceFailure(detail)
    store.read_failure = failure

    with pytest.raises(ServiceFailure) as result:
        await runtime.application.feedback(request, principal)
    assert result.value.error.code == ErrorCode.FEEDBACK_UNAVAILABLE
    assert result.value.error.message == "Feedback is temporarily unavailable."
    assert private_message not in result.value.error.message
    assert (store.reads, store.creates, store.marks) == (1, 0, 0)
    assert sink.events == []
    assert admissions.acquired == admissions.released


class _BlockedDynamoRead:
    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.calls = 0

    def get_item(self, **_kwargs: object) -> dict[str, object]:
        self.calls += 1
        self.entered.set()
        if not self.release.wait(timeout=2.0):
            raise TimeoutError("application feedback worker was not released")
        return {}


@pytest.mark.asyncio
async def test_application_external_cancel_keeps_dynamodb_worker_charged_without_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, principal, request, _memory, _store, sink, admissions, _clock = _fixture(note="note")
    pool = FeedbackControlPool(capacity=1, stage_seconds=1.0)
    client = _BlockedDynamoRead()
    state = DynamoState(cast(DynamoClient, client), "feedback-fixture", feedback_control_pool=pool)
    runtime.application.feedback_store = cast(FeedbackStore, state)
    executor_submit = pool._executor.submit
    futures = []

    def capture_submit(function):
        future = executor_submit(function)
        futures.append(future)
        return future

    monkeypatch.setattr(pool._executor, "submit", capture_submit)
    controls: list[FeedbackControlContext] = []
    original_run = pool.run

    async def capture_control(call, *, control):
        controls.append(control)
        return await original_run(call, control=control)

    monkeypatch.setattr(pool, "run", capture_control)
    try:
        task = asyncio.create_task(runtime.application.feedback(request, principal))
        assert await asyncio.to_thread(client.entered.wait, 1.0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert len(admissions.acquired) == len(admissions.released) == 1
        assert controls and not controls[0].cancel.is_cancelled()
        assert client.calls == 1
        assert sink.events == []
        with pytest.raises(ServiceFailure):
            await runtime.application.feedback(request, principal)
        assert client.calls == 1
        assert sink.events == []
        assert len(admissions.acquired) == len(admissions.released) == 2
        client.release.set()
        await asyncio.wait_for(asyncio.wrap_future(futures[0]), timeout=1.0)
    finally:
        client.release.set()
        pool.close()


@pytest.mark.asyncio
async def test_application_token_cancel_preserves_dynamodb_worker_liability_without_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, principal, request, _memory, _store, sink, admissions, _clock = _fixture(note="note")
    pool = FeedbackControlPool(capacity=1, stage_seconds=1.0)
    client = _BlockedDynamoRead()
    state = DynamoState(cast(DynamoClient, client), "feedback-fixture", feedback_control_pool=pool)
    runtime.application.feedback_store = cast(FeedbackStore, state)
    original_submit = pool._executor.submit
    futures = []

    def capture_submit(function):
        future = original_submit(function)
        futures.append(future)
        return future

    monkeypatch.setattr(pool._executor, "submit", capture_submit)
    controls: list[FeedbackControlContext] = []
    original_run = pool.run

    async def capture_control(call, *, control):
        controls.append(control)
        return await original_run(call, control=control)

    monkeypatch.setattr(pool, "run", capture_control)
    try:
        task = asyncio.create_task(runtime.application.feedback(request, principal))
        assert await asyncio.to_thread(client.entered.wait, 1.0)
        assert controls and controls[0].calls.attempts(CallKind.state) == 1
        controls[0].cancel.cancel()
        with pytest.raises(RequestCancelled):
            await task
        assert controls[0].cancel.is_cancelled()
        assert client.calls == 1
        assert sink.events == []
        assert admissions.acquired == admissions.released
        assert not pool._capacity.acquire(blocking=False)
        client.release.set()
        await asyncio.wait_for(asyncio.wrap_future(futures[0]), timeout=1.0)
        assert pool._capacity.acquire(blocking=False)
        pool._capacity.release()
    finally:
        client.release.set()
        pool.close()


class _EmptyDynamoRead:
    def __init__(self) -> None:
        self.reads = 0
        self.puts = 0
        self.updates = 0

    def get_item(self, **_kwargs: object) -> dict[str, object]:
        self.reads += 1
        return {}

    def put_item(self, **_kwargs: object) -> dict[str, object]:
        self.puts += 1
        return {}

    def update_item(self, **_kwargs: object) -> dict[str, object]:
        self.updates += 1
        return {}


@pytest.mark.asyncio
async def test_application_external_cancel_during_watcher_cleanup_stops_feedback_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, principal, request, _memory, _store, sink, admissions, _clock = _fixture(note="note")
    pool = FeedbackControlPool(capacity=1, stage_seconds=1.0)
    client = _EmptyDynamoRead()
    state = DynamoState(cast(DynamoClient, client), "feedback-fixture", feedback_control_pool=pool)
    runtime.application.feedback_store = cast(FeedbackStore, state)
    original_wait = RequestCancellation.wait
    cleanup_entered = asyncio.Event()
    release_cleanup = asyncio.Event()

    async def gated_wait(token: RequestCancellation) -> None:
        try:
            await original_wait(token)
        finally:
            cleanup_entered.set()
            await release_cleanup.wait()

    monkeypatch.setattr(RequestCancellation, "wait", gated_wait)
    controls: list[FeedbackControlContext] = []
    original_run = pool.run

    async def capture_control(call, *, control):
        controls.append(control)
        return await original_run(call, control=control)

    monkeypatch.setattr(pool, "run", capture_control)
    create_calls = 0
    mark_calls = 0
    original_create = state.try_create_feedback
    original_mark = state.mark_feedback_queued

    async def count_create(
        *, receipt_id: UUID, note_hash: SHA256, now: datetime, control: FeedbackControlContext
    ) -> FeedbackMetadata | None:
        nonlocal create_calls
        create_calls += 1
        return await original_create(
            receipt_id=receipt_id, note_hash=note_hash, now=now, control=control
        )

    async def count_mark(
        *,
        receipt_id: UUID,
        note_hash: SHA256,
        feedback_id: UUID,
        now: datetime,
        control: FeedbackControlContext,
    ) -> bool:
        nonlocal mark_calls
        mark_calls += 1
        return await original_mark(
            receipt_id=receipt_id,
            note_hash=note_hash,
            feedback_id=feedback_id,
            now=now,
            control=control,
        )

    state.try_create_feedback = count_create
    state.mark_feedback_queued = count_mark
    task = asyncio.create_task(runtime.application.feedback(request, principal))
    try:
        await asyncio.wait_for(cleanup_entered.wait(), timeout=1.0)
        assert controls and not controls[0].cancel.is_cancelled()
        task.cancel()
        release_cleanup.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=1.0)
        assert not controls[0].cancel.is_cancelled()
        assert client.reads == 1
        assert client.puts == client.updates == 0
        assert create_calls == mark_calls == 0
        assert sink.events == []
        assert admissions.released == admissions.acquired
    finally:
        release_cleanup.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        pool.close()
