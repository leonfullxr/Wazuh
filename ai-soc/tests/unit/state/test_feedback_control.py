from __future__ import annotations

import asyncio
import gc
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future
from typing import cast

import pytest

from ai_soc.application.errors import ServiceFailure
from ai_soc.application.runtime import BoundedCallLedger, RequestCancellation, RequestCancelled
from ai_soc.contracts.models import CallKind, FeedbackControlContext
from ai_soc.state.errors import StateFailure
from ai_soc.state.feedback_control import FeedbackControlPool


def _control(*, seconds: float = 10.0) -> FeedbackControlContext:
    return FeedbackControlContext(
        deadline_monotonic=time.monotonic() + seconds,
        monotonic=time.monotonic,
        cancel=RequestCancellation(),
        calls=BoundedCallLedger(),
    )


@pytest.mark.asyncio
async def test_feedback_pool_rejects_fifth_blocked_physical_call() -> None:
    pool = FeedbackControlPool(capacity=4, stage_seconds=1.0)
    all_started = threading.Event()
    release = threading.Event()
    started: list[int] = []
    started_lock = threading.Lock()

    def call() -> int:
        with started_lock:
            started.append(1)
            if len(started) == 4:
                all_started.set()
        if not release.wait(timeout=2.0):
            raise TimeoutError("test worker was not released")
        return 7

    tasks = [asyncio.create_task(pool.run(call, control=_control())) for _ in range(4)]
    try:
        assert await asyncio.to_thread(all_started.wait, 2.0)
        with pytest.raises(StateFailure):
            await pool.run(lambda: 8, control=_control())
        assert len(started) == 4
        release.set()
        assert await asyncio.gather(*tasks) == [7, 7, 7, 7]
    finally:
        release.set()
        pool.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["external", "token", "timeout"])
async def test_abandonment_before_worker_gate_prevents_dispatch(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    pool = FeedbackControlPool(capacity=1, stage_seconds=0.05 if mode == "timeout" else 1.0)
    executor = pool._executor
    submitted = threading.Event()
    release_gate = threading.Event()
    captured: list[Future[object]] = []
    original_submit = executor.submit

    def delayed_submit(function: Callable[[], object]) -> Future[object]:
        def wait_then_run() -> object:
            submitted.set()
            if not release_gate.wait(timeout=2.0):
                raise TimeoutError("test gate was not released")
            return function()

        future = original_submit(wait_then_run)
        captured.append(future)
        return future

    monkeypatch.setattr(executor, "submit", delayed_submit)
    control = _control()
    calls: list[int] = []
    task = asyncio.create_task(pool.run(lambda: calls.append(1), control=control))
    try:
        assert await asyncio.to_thread(submitted.wait, 1.0)
        if mode == "external":
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert not control.cancel.is_cancelled()
        elif mode == "token":
            cast(RequestCancellation, control.cancel).cancel()
            with pytest.raises(RequestCancelled):
                await task
            assert control.cancel.is_cancelled()
        else:
            with pytest.raises(StateFailure):
                await task
            assert not control.cancel.is_cancelled()
        assert control.calls.attempts(CallKind.state) == 0
        assert calls == []
        with pytest.raises(StateFailure):
            await pool.run(lambda: calls.append(2), control=_control())
        release_gate.set()
        with pytest.raises((StateFailure, RequestCancelled)):
            await asyncio.wrap_future(captured[0])
        assert calls == []
        assert await pool.run(lambda: 3, control=_control()) == 3
    finally:
        release_gate.set()
        pool.close()


@pytest.mark.asyncio
async def test_admitted_token_cancel_retains_physical_capacity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = FeedbackControlPool(capacity=1, stage_seconds=1.0)
    executor = pool._executor
    captured: list[Future[int]] = []
    original_submit = executor.submit

    def capture_submit(function: Callable[[], int]) -> Future[int]:
        future = original_submit(function)
        captured.append(future)
        return future

    monkeypatch.setattr(executor, "submit", capture_submit)
    entered = threading.Event()
    release = threading.Event()
    control = _control()

    def admitted_call() -> int:
        entered.set()
        if not release.wait(timeout=2.0):
            raise TimeoutError("test SDK call was not released")
        return 9

    task = asyncio.create_task(pool.run(admitted_call, control=control))
    try:
        assert await asyncio.to_thread(entered.wait, 1.0)
        assert control.calls.attempts(CallKind.state) == 1
        cast(RequestCancellation, control.cancel).cancel()
        with pytest.raises(RequestCancelled):
            await task
        with pytest.raises(StateFailure):
            await pool.run(lambda: 10, control=_control())
        release.set()
        assert await asyncio.wrap_future(captured[0]) == 9
        assert await pool.run(lambda: 10, control=_control()) == 10
    finally:
        release.set()
        pool.close()


@pytest.mark.asyncio
async def test_close_abandons_registered_submission_before_worker_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = FeedbackControlPool(capacity=1, stage_seconds=1.0)
    executor = pool._executor
    submitted = threading.Event()
    release_gate = threading.Event()
    captured: list[Future[object]] = []
    original_submit = executor.submit

    def delayed_submit(function: Callable[[], object]) -> Future[object]:
        def wait_then_run() -> object:
            submitted.set()
            if not release_gate.wait(timeout=2.0):
                raise TimeoutError("test close gate was not released")
            return function()

        future = original_submit(wait_then_run)
        captured.append(future)
        return future

    monkeypatch.setattr(executor, "submit", delayed_submit)
    control = _control()
    calls: list[int] = []
    task = asyncio.create_task(pool.run(lambda: calls.append(1), control=control))
    try:
        assert await asyncio.to_thread(submitted.wait, 1.0)
        pool.close()
        with pytest.raises(StateFailure):
            await pool.run(lambda: calls.append(2), control=_control())
        release_gate.set()
        with pytest.raises(StateFailure):
            await asyncio.wrap_future(captured[0])
        with pytest.raises(StateFailure):
            await task
        assert calls == []
        assert control.calls.attempts(CallKind.state) == 0
    finally:
        release_gate.set()
        pool.close()


@pytest.mark.asyncio
async def test_close_does_not_abandon_admitted_physical_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = FeedbackControlPool(capacity=1, stage_seconds=1.0)
    executor = pool._executor
    captured: list[Future[int]] = []
    original_submit = executor.submit

    def capture_submit(function: Callable[[], int]) -> Future[int]:
        future = original_submit(function)
        captured.append(future)
        return future

    monkeypatch.setattr(executor, "submit", capture_submit)
    entered = threading.Event()
    release = threading.Event()

    def admitted_call() -> int:
        entered.set()
        if not release.wait(timeout=2.0):
            raise TimeoutError("admitted close test was not released")
        return 11

    control = _control()
    task = asyncio.create_task(pool.run(admitted_call, control=control))
    try:
        assert await asyncio.to_thread(entered.wait, 1.0)
        pool.close()
        assert control.calls.attempts(CallKind.state) == 1
        assert not pool._capacity.acquire(blocking=False)
        release.set()
        assert await asyncio.wrap_future(captured[0]) == 11
        assert await task == 11
        assert pool._capacity.acquire(blocking=False)
        pool._capacity.release()
    finally:
        release.set()
        pool.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("submit_result", ["future", "failure"])
async def test_close_racing_registered_submit_releases_once(
    monkeypatch: pytest.MonkeyPatch, submit_result: str
) -> None:
    pool = FeedbackControlPool(capacity=1, stage_seconds=1.0)
    executor = pool._executor
    original_submit = executor.submit
    submit_entered = threading.Event()
    allow_submit_return = threading.Event()
    worker_entered = threading.Event()
    allow_worker_admission = threading.Event()
    captured: list[Future[object]] = []

    def racing_submit(function: Callable[[], object]) -> Future[object]:
        submit_entered.set()
        if submit_result == "future":

            def wait_before_dispatch() -> object:
                worker_entered.set()
                if not allow_worker_admission.wait(timeout=2.0):
                    raise TimeoutError("worker admission gate was not released")
                return function()

            future = original_submit(wait_before_dispatch)
            captured.append(future)
            if not allow_submit_return.wait(timeout=2.0):
                raise TimeoutError("successful submit gate was not released")
            return future
        if not allow_submit_return.wait(timeout=2.0):
            raise TimeoutError("failed submit gate was not released")
        raise OSError("submit failed")

    monkeypatch.setattr(executor, "submit", racing_submit)
    outcomes: list[BaseException | object] = []

    def run_from_thread() -> None:
        try:
            outcomes.append(asyncio.run(pool.run(lambda: 5, control=_control())))
        except BaseException as error:
            outcomes.append(error)

    runner = threading.Thread(target=run_from_thread)
    runner.start()
    assert await asyncio.to_thread(submit_entered.wait, 1.0)
    if submit_result == "future":
        assert await asyncio.to_thread(worker_entered.wait, 1.0)
    assert len(pool._owned) == 1
    closer = threading.Thread(target=pool.close)
    closer.start()
    closer.join(timeout=1.0)
    assert not closer.is_alive()
    allow_submit_return.set()
    allow_worker_admission.set()
    await asyncio.to_thread(runner.join, 2.0)
    assert not runner.is_alive()
    assert len(outcomes) == 1
    if submit_result == "future":
        assert isinstance(outcomes[0], StateFailure)
        assert len(captured) == 1
        assert captured[0].done()
    else:
        assert isinstance(outcomes[0], OSError)
        assert captured == []
    pool.close()
    acquired = pool._capacity.acquire(blocking=False)
    assert acquired
    assert not pool._capacity.acquire(blocking=False)
    pool._capacity.release()


@pytest.mark.asyncio
async def test_pre_cancelled_and_denied_state_ledger_never_dispatch() -> None:
    pool = FeedbackControlPool(capacity=2, stage_seconds=1.0)
    calls: list[int] = []
    pre_cancelled = _control()
    cast(RequestCancellation, pre_cancelled.cancel).cancel()
    try:
        with pytest.raises(RequestCancelled):
            await pool.run(lambda: calls.append(1), control=pre_cancelled)

        denied = FeedbackControlContext(
            deadline_monotonic=time.monotonic() + 2.0,
            monotonic=time.monotonic,
            cancel=RequestCancellation(),
            calls=BoundedCallLedger({CallKind.state: 0}),
        )
        with pytest.raises(ServiceFailure):
            await pool.run(lambda: calls.append(2), control=denied)
        assert calls == []
        assert pre_cancelled.calls.attempts(CallKind.state) == 0
        assert denied.calls.attempts(CallKind.state) == 0
    finally:
        pool.close()


@pytest.mark.asyncio
async def test_completion_after_stage_deadline_is_rejected() -> None:
    pool = FeedbackControlPool(capacity=1, stage_seconds=1.0)
    entered = threading.Event()
    release = threading.Event()
    current = [0.0]
    control = FeedbackControlContext(
        deadline_monotonic=100.0,
        monotonic=lambda: current[0],
        cancel=RequestCancellation(),
        calls=BoundedCallLedger(),
    )

    def delayed_call() -> int:
        entered.set()
        if not release.wait(timeout=2.0):
            raise TimeoutError("deadline worker was not released")
        return 9

    task = asyncio.create_task(pool.run(delayed_call, control=control))
    try:
        assert await asyncio.to_thread(entered.wait, 1.0)
        current[0] = 1.0
        release.set()
        with pytest.raises(StateFailure):
            await asyncio.wait_for(task, timeout=1.0)
        assert not control.cancel.is_cancelled()
        assert control.calls.attempts(CallKind.state) == 1
    finally:
        release.set()
        pool.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel_kind", ["external", "token"])
async def test_admitted_cancellation_retains_capacity_and_drains_late_error(
    monkeypatch: pytest.MonkeyPatch, cancel_kind: str
) -> None:
    pool = FeedbackControlPool(capacity=1, stage_seconds=1.0)
    executor = pool._executor
    original_submit = executor.submit
    captured: list[Future[int]] = []

    def capture_submit(function: Callable[[], int]) -> Future[int]:
        future = original_submit(function)
        captured.append(future)
        return future

    monkeypatch.setattr(executor, "submit", capture_submit)
    entered = threading.Event()
    release = threading.Event()
    control = _control()

    def late_failure() -> int:
        entered.set()
        if not release.wait(timeout=2.0):
            raise TimeoutError("late failure worker was not released")
        raise OSError("late physical failure")

    task = asyncio.create_task(pool.run(late_failure, control=control))
    try:
        assert await asyncio.to_thread(entered.wait, 1.0)
        if cancel_kind == "external":
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert not control.cancel.is_cancelled()
        else:
            cast(RequestCancellation, control.cancel).cancel()
            with pytest.raises(RequestCancelled):
                await task
        with pytest.raises(StateFailure):
            await pool.run(lambda: 1, control=_control())
        release.set()
        with pytest.raises(OSError, match="late physical failure"):
            await asyncio.wrap_future(captured[0])
        assert await pool.run(lambda: 1, control=_control()) == 1
    finally:
        release.set()
        pool.close()


@pytest.mark.asyncio
async def test_four_timed_out_physical_calls_keep_all_permits_until_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = FeedbackControlPool(capacity=4, stage_seconds=0.05)
    original_submit = pool._executor.submit
    futures: list[Future[int]] = []

    def capture_submit(function: Callable[[], int]) -> Future[int]:
        future = original_submit(function)
        futures.append(future)
        return future

    monkeypatch.setattr(pool._executor, "submit", capture_submit)
    entered_count = 0
    count_lock = threading.Lock()
    all_entered = threading.Event()
    release = threading.Event()

    def blocked_call() -> int:
        nonlocal entered_count
        with count_lock:
            entered_count += 1
            if entered_count == 4:
                all_entered.set()
        if not release.wait(timeout=2.0):
            raise TimeoutError("orphan capacity test was not released")
        return 1

    tasks = [asyncio.create_task(pool.run(blocked_call, control=_control())) for _ in range(4)]
    try:
        assert await asyncio.to_thread(all_entered.wait, 1.0)
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)
        assert all(isinstance(outcome, StateFailure) for outcome in outcomes)
        with pytest.raises(StateFailure):
            await pool.run(lambda: 2, control=_control())
        release.set()
        assert await asyncio.wait_for(
            asyncio.gather(*(asyncio.wrap_future(future) for future in futures)), timeout=1.0
        ) == [1, 1, 1, 1]
        assert await pool.run(lambda: 2, control=_control()) == 2
    finally:
        release.set()
        pool.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("sufficient", [True, False])
async def test_feedback_pool_requires_the_full_stage_budget(sufficient: bool) -> None:
    pool = FeedbackControlPool(capacity=1, stage_seconds=0.5)
    current = [10.0]
    control = FeedbackControlContext(
        deadline_monotonic=10.5 if sufficient else 10.499,
        monotonic=lambda: current[0],
        cancel=RequestCancellation(),
        calls=BoundedCallLedger(),
    )
    calls: list[int] = []
    try:
        if sufficient:
            assert await pool.run(lambda: calls.append(1), control=control) is None
            assert calls == [1]
            assert control.calls.attempts(CallKind.state) == 1
        else:
            with pytest.raises(StateFailure):
                await pool.run(lambda: calls.append(1), control=control)
            assert calls == []
            assert control.calls.attempts(CallKind.state) == 0
    finally:
        pool.close()


@pytest.mark.asyncio
async def test_admitted_worker_terminal_callback_releases_after_event_loop_shutdown() -> None:
    pool = FeedbackControlPool(capacity=1, stage_seconds=1.0)
    entered = threading.Event()
    release = threading.Event()
    loop_closed = threading.Event()
    captured: list[Future[int]] = []
    original_submit = pool._executor.submit

    def capture_submit(function: Callable[[], int]) -> Future[int]:
        future = original_submit(function)
        captured.append(future)
        return future

    pool._executor.submit = capture_submit

    def blocked_call() -> int:
        entered.set()
        if not release.wait(timeout=2.0):
            raise TimeoutError("event-loop shutdown worker was not released")
        return 17

    def run_until_cancelled() -> None:
        async def invoke() -> None:
            task = asyncio.create_task(pool.run(blocked_call, control=_control()))
            assert await asyncio.to_thread(entered.wait, 1.0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        asyncio.run(invoke())
        loop_closed.set()

    runner = threading.Thread(target=run_until_cancelled)
    runner.start()
    try:
        assert await asyncio.to_thread(loop_closed.wait, 1.0)
        assert len(captured) == 1 and not captured[0].done()
        assert not pool._capacity.acquire(blocking=False)
        pool.close()
        release.set()
        assert await asyncio.wait_for(asyncio.to_thread(captured[0].result), timeout=1.0) == 17
        assert pool._capacity.acquire(blocking=False)
        pool._capacity.release()
    finally:
        release.set()
        pool.close()
        await asyncio.to_thread(runner.join, 1.0)
        assert not runner.is_alive()


@pytest.mark.asyncio
async def test_completion_and_cancellation_ready_together_rejects_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = FeedbackControlPool(capacity=1, stage_seconds=1.0)
    original_submit = pool._executor.submit
    captured: list[Future[int]] = []

    def capture_submit(function: Callable[[], int]) -> Future[int]:
        future = original_submit(function)
        captured.append(future)
        return future

    monkeypatch.setattr(pool._executor, "submit", capture_submit)
    entered = threading.Event()
    release = threading.Event()
    control = _control()

    def call() -> int:
        entered.set()
        if not release.wait(timeout=2.0):
            raise TimeoutError("completion race worker was not released")
        return 23

    task = asyncio.create_task(pool.run(call, control=control))
    try:
        assert await asyncio.to_thread(entered.wait, 1.0)
        # Keep the loop from observing either completion callback until both
        # the executor future and cancellation token are ready.
        release.set()
        assert captured[0].result(timeout=1.0) == 23
        cast(RequestCancellation, control.cancel).cancel()
        with pytest.raises(RequestCancelled):
            await asyncio.wait_for(task, timeout=1.0)
        assert control.calls.attempts(CallKind.state) == 1
        assert pool._capacity.acquire(blocking=False)
        pool._capacity.release()
    finally:
        release.set()
        pool.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("work_result", ["success", "error", "timeout"])
async def test_external_cancel_during_private_watcher_cleanup_is_preserved(
    monkeypatch: pytest.MonkeyPatch, work_result: str
) -> None:
    pool = FeedbackControlPool(capacity=1, stage_seconds=0.05 if work_result == "timeout" else 1.0)
    control = _control()
    cleanup_entered = asyncio.Event()
    release_cleanup = asyncio.Event()
    original_wait = control.cancel.wait

    async def gated_wait() -> None:
        try:
            await original_wait()
        finally:
            cleanup_entered.set()
            await release_cleanup.wait()

    monkeypatch.setattr(control.cancel, "wait", gated_wait)
    worker_entered = threading.Event()
    release_worker = threading.Event()
    captured: list[Future[object]] = []
    original_submit = pool._executor.submit

    def capture_submit(function: Callable[[], object]) -> Future[object]:
        future = original_submit(function)
        captured.append(future)
        return future

    monkeypatch.setattr(pool._executor, "submit", capture_submit)

    def call() -> object:
        worker_entered.set()
        if work_result == "timeout":
            if not release_worker.wait(timeout=2.0):
                raise TimeoutError("timed-out cleanup worker was not released")
            return "late"
        if work_result == "error":
            raise OSError("original worker failure")
        return "ready"

    task = asyncio.create_task(pool.run(call, control=control))
    try:
        assert await asyncio.to_thread(worker_entered.wait, 1.0)
        await asyncio.wait_for(cleanup_entered.wait(), timeout=1.0)
        assert not control.cancel.is_cancelled()
        task.cancel()
        release_cleanup.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=1.0)
        assert not control.cancel.is_cancelled()
    finally:
        release_cleanup.set()
        release_worker.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        if captured:
            if work_result == "error":
                failure = await asyncio.wait_for(
                    asyncio.to_thread(captured[0].exception), timeout=1.0
                )
                assert isinstance(failure, OSError)
            else:
                await asyncio.wait_for(asyncio.to_thread(captured[0].exception), timeout=1.0)
        pool.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["token", "deadline"])
async def test_token_or_deadline_change_during_watcher_cleanup_rejects_result(
    monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    pool = FeedbackControlPool(capacity=1, stage_seconds=1.0)
    current = [0.0]
    control = FeedbackControlContext(
        deadline_monotonic=10.0,
        monotonic=lambda: current[0],
        cancel=RequestCancellation(),
        calls=BoundedCallLedger(),
    )
    cleanup_entered = asyncio.Event()
    release_cleanup = asyncio.Event()
    original_wait = control.cancel.wait

    async def gated_wait() -> None:
        try:
            await original_wait()
        finally:
            cleanup_entered.set()
            await release_cleanup.wait()

    monkeypatch.setattr(control.cancel, "wait", gated_wait)
    task = asyncio.create_task(pool.run(lambda: "completed", control=control))
    try:
        await asyncio.wait_for(cleanup_entered.wait(), timeout=1.0)
        if change == "token":
            control.cancel.cancel()
        else:
            current[0] = 1.0
        release_cleanup.set()
        if change == "token":
            with pytest.raises(RequestCancelled):
                await asyncio.wait_for(task, timeout=1.0)
        else:
            with pytest.raises(StateFailure):
                await asyncio.wait_for(task, timeout=1.0)
    finally:
        release_cleanup.set()
        pool.close()


@pytest.mark.asyncio
async def test_private_watcher_cancellation_does_not_delay_success() -> None:
    pool = FeedbackControlPool(capacity=1, stage_seconds=1.0)
    try:
        assert await asyncio.wait_for(pool.run(lambda: "ready", control=_control()), timeout=1.0)
        assert await asyncio.wait_for(pool.run(lambda: "again", control=_control()), timeout=1.0)
    finally:
        pool.close()


@pytest.mark.asyncio
async def test_pool_registry_tracks_only_live_work_across_repeated_results() -> None:
    pool = FeedbackControlPool(capacity=1, stage_seconds=1.0)
    try:
        for index in range(8):
            if index % 2:
                with pytest.raises(ValueError, match="worker result"):
                    await pool.run(
                        lambda: (_ for _ in ()).throw(ValueError("worker result")),
                        control=_control(),
                    )
            else:
                assert await pool.run(lambda value=index: value, control=_control()) == index
            assert pool._owned == set()
        acquired = threading.Event()
        release = threading.Event()

        def blocked_call() -> int:
            acquired.set()
            if not release.wait(timeout=2.0):
                raise TimeoutError("registry worker was not released")
            return 9

        task = asyncio.create_task(pool.run(blocked_call, control=_control()))
        assert await asyncio.to_thread(acquired.wait, 1.0)
        assert len(pool._owned) == 1
        assert all(invocation.admitted for invocation in pool._owned)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert len(pool._owned) == 1
        release.set()
        assert await asyncio.to_thread(pool._capacity.acquire, True, 1.0)
        pool._capacity.release()
        assert pool._owned == set()
    finally:
        pool.close()


@pytest.mark.asyncio
async def test_repeated_close_does_not_repeat_executor_shutdown_with_blocked_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = FeedbackControlPool(capacity=1, stage_seconds=1.0)
    entered = threading.Event()
    release = threading.Event()
    shutdown_calls = 0
    executor = pool._executor
    original_shutdown = executor.shutdown

    def count_shutdown(*, wait: bool = True, cancel_futures: bool = False) -> None:
        nonlocal shutdown_calls
        shutdown_calls += 1
        original_shutdown(wait=wait, cancel_futures=cancel_futures)

    monkeypatch.setattr(executor, "shutdown", count_shutdown)

    def blocked_call() -> int:
        entered.set()
        if not release.wait(timeout=2.0):
            raise TimeoutError("repeated-close worker was not released")
        return 31

    task = asyncio.create_task(pool.run(blocked_call, control=_control()))
    try:
        assert await asyncio.to_thread(entered.wait, 1.0)
        assert len(pool._owned) == 1
        assert all(invocation.admitted for invocation in pool._owned)
        pool.close()
        pool.close()
        pool.close()
        assert shutdown_calls == 1
        assert executor._work_queue.qsize() == 1
        release.set()
        assert await asyncio.wait_for(task, timeout=1.0) == 31
        assert pool._owned == set()
    finally:
        release.set()
        pool.close()


@pytest.mark.asyncio
async def test_abandoned_late_asyncio_exception_is_drained_without_loop_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = FeedbackControlPool(capacity=1, stage_seconds=1.0)
    entered = threading.Event()
    release = threading.Event()
    worker_terminal = threading.Event()
    wrapped_futures: list[asyncio.Future[object]] = []
    original_wrap = asyncio.wrap_future

    def capture_wrap(future, *, loop=None):
        wrapped = original_wrap(future, loop=loop)
        wrapped_futures.append(wrapped)
        return wrapped

    monkeypatch.setattr(asyncio, "wrap_future", capture_wrap)
    loop = asyncio.get_running_loop()
    contexts: list[dict[str, object]] = []
    original_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: contexts.append(context))

    def late_failure() -> object:
        entered.set()
        try:
            if not release.wait(timeout=2.0):
                raise TimeoutError("late-error worker was not released")
            raise OSError("late asyncio-wrapped failure")
        finally:
            worker_terminal.set()

    task = asyncio.create_task(pool.run(late_failure, control=_control()))
    try:
        assert await asyncio.to_thread(entered.wait, 1.0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        release.set()
        assert await asyncio.to_thread(worker_terminal.wait, 1.0)
        wrapped_done = asyncio.Event()
        wrapped_futures[0].add_done_callback(lambda _future: wrapped_done.set())
        await asyncio.wait_for(wrapped_done.wait(), timeout=1.0)
        assert wrapped_futures[0].done()
        del wrapped_futures[:]
        gc.collect()
        loop_tick = asyncio.Event()
        loop.call_soon(loop_tick.set)
        await loop_tick.wait()
        assert not [
            context
            for context in contexts
            if "Future exception was never retrieved" in str(context.get("message"))
        ]
    finally:
        release.set()
        pool.close()
        loop.set_exception_handler(original_handler)


@pytest.mark.parametrize(
    ("capacity", "stage_seconds"),
    [(0, 1.0), (5, 1.0), (1, 0.0), (1, 5.01)],
)
def test_feedback_pool_rejects_out_of_contract_bounds(capacity: int, stage_seconds: float) -> None:
    with pytest.raises(ValueError):
        FeedbackControlPool(capacity=capacity, stage_seconds=stage_seconds)


@pytest.mark.asyncio
async def test_closed_idle_pool_rejects_without_submission_or_capacity_leak() -> None:
    pool = FeedbackControlPool(capacity=1, stage_seconds=1.0)
    control = _control()
    calls: list[int] = []
    pool.close()
    try:
        with pytest.raises(StateFailure):
            await pool.run(lambda: calls.append(1), control=control)
        assert calls == []
        assert control.calls.attempts(CallKind.state) == 0
        assert pool._owned == set()
        assert pool._capacity.acquire(blocking=False)
        pool._capacity.release()
    finally:
        pool.close()


@pytest.mark.asyncio
async def test_final_worker_gate_rejects_elapsed_stage_before_ledger_or_sdk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = FeedbackControlPool(capacity=1, stage_seconds=1.0)
    current = [0.0]
    control = FeedbackControlContext(
        deadline_monotonic=100.0,
        monotonic=lambda: current[0],
        cancel=RequestCancellation(),
        calls=BoundedCallLedger(),
    )
    worker_waiting = threading.Event()
    release_gate = threading.Event()
    sdk_calls: list[int] = []
    executor = pool._executor
    original_submit = executor.submit

    def submit_before_final_gate(function: Callable[[], object]) -> Future[object]:
        def wait_then_invoke() -> object:
            worker_waiting.set()
            if not release_gate.wait(timeout=2.0):
                raise TimeoutError("worker final-gate barrier was not released")
            return function()

        return original_submit(wait_then_invoke)

    monkeypatch.setattr(executor, "submit", submit_before_final_gate)
    task = asyncio.create_task(pool.run(lambda: sdk_calls.append(1), control=control))
    try:
        assert await asyncio.to_thread(worker_waiting.wait, 1.0)
        current[0] = 1.0
        release_gate.set()
        with pytest.raises(StateFailure):
            await asyncio.wait_for(task, timeout=1.0)
        assert control.calls.attempts(CallKind.state) == 0
        assert sdk_calls == []
    finally:
        release_gate.set()
        if not task.done():
            await asyncio.gather(task, return_exceptions=True)
        pool.close()


@pytest.mark.asyncio
async def test_final_worker_gate_rejects_token_after_notification_before_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = FeedbackControlPool(capacity=1, stage_seconds=1.0)
    control = _control()
    worker_waiting = threading.Event()
    release_gate = threading.Event()
    notification_entered = asyncio.Event()
    release_notification = asyncio.Event()
    original_wait = control.cancel.wait
    sdk_calls: list[int] = []

    async def delayed_notification() -> None:
        await original_wait()
        notification_entered.set()
        await release_notification.wait()

    monkeypatch.setattr(control.cancel, "wait", delayed_notification)
    executor = pool._executor
    original_submit = executor.submit
    captured: list[Future[object]] = []

    def submit_before_final_gate(function: Callable[[], object]) -> Future[object]:
        def wait_then_invoke() -> object:
            worker_waiting.set()
            if not release_gate.wait(timeout=2.0):
                raise TimeoutError("token final-gate barrier was not released")
            return function()

        future = original_submit(wait_then_invoke)
        captured.append(future)
        return future

    monkeypatch.setattr(executor, "submit", submit_before_final_gate)
    task = asyncio.create_task(pool.run(lambda: sdk_calls.append(1), control=control))
    try:
        assert await asyncio.to_thread(worker_waiting.wait, 1.0)
        control.cancel.cancel()
        await asyncio.wait_for(notification_entered.wait(), timeout=1.0)
        release_gate.set()
        with pytest.raises(RequestCancelled):
            await asyncio.wait_for(asyncio.wrap_future(captured[0]), timeout=1.0)
        assert not task.done()
        assert control.calls.attempts(CallKind.state) == 0
        assert sdk_calls == []
        release_notification.set()
        with pytest.raises(RequestCancelled):
            await asyncio.wait_for(task, timeout=1.0)
        assert control.calls.attempts(CallKind.state) == 0
        assert sdk_calls == []
    finally:
        release_gate.set()
        release_notification.set()
        if not task.done():
            await asyncio.gather(task, return_exceptions=True)
        pool.close()
