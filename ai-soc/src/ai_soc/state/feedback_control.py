"""Bounded physical control calls for feedback metadata operations."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from typing import TypeVar
from uuid import uuid4

from ai_soc.contracts.errors import public_error
from ai_soc.contracts.models import CallKind, ErrorCode, FeedbackControlContext
from ai_soc.state.errors import StateFailure

T = TypeVar("T")


@dataclass(slots=True, eq=False)
class _Invocation:
    abandoned: bool = False
    admitted: bool = False


class FeedbackControlPool:
    def __init__(self, *, capacity: int = 4, stage_seconds: float = 5.0) -> None:
        if not 1 <= capacity <= 4 or not 0 < stage_seconds <= 5:
            raise ValueError("feedback control bounds exceed contract limits")
        self._capacity = threading.BoundedSemaphore(capacity)
        self._executor = ThreadPoolExecutor(
            max_workers=capacity, thread_name_prefix="feedback-state"
        )
        self._stage_seconds = stage_seconds
        self._gate = threading.Lock()
        self._closed = False
        self._owned: set[_Invocation] = set()

    @staticmethod
    def _failure() -> StateFailure:
        return StateFailure(
            public_error(
                ErrorCode.FEEDBACK_UNAVAILABLE,
                "Feedback is temporarily unavailable.",
                trace_id=uuid4().hex,
                retryable=True,
            )
        )

    @staticmethod
    def _check(control: FeedbackControlContext, stage_deadline: float) -> None:
        control.cancel.raise_if_cancelled()
        current = control.monotonic()
        if current + 0.0 >= stage_deadline or current >= control.deadline_monotonic:
            raise FeedbackControlPool._failure()

    async def run(self, call: Callable[[], T], *, control: FeedbackControlContext) -> T:
        control.cancel.raise_if_cancelled()
        started = control.monotonic()
        stage_deadline = started + self._stage_seconds
        if stage_deadline > control.deadline_monotonic:
            raise self._failure()
        if not self._capacity.acquire(blocking=False):
            raise self._failure()

        invocation = _Invocation()
        with self._gate:
            if self._closed:
                self._capacity.release()
                raise self._failure()
            self._owned.add(invocation)

        try:
            control.cancel.raise_if_cancelled()
            self._check(control, stage_deadline)

            def invoke() -> T:
                with self._gate:
                    if self._closed or invocation.abandoned:
                        raise self._failure()
                    self._check(control, stage_deadline)
                    control.calls.claim(CallKind.state)
                    invocation.admitted = True
                return call()

            future = self._executor.submit(invoke)
        except BaseException:
            with self._gate:
                self._owned.discard(invocation)
            self._capacity.release()
            raise

        def terminal(done: Future[T]) -> None:
            try:
                done.exception()
            except BaseException:
                pass
            with self._gate:
                self._owned.discard(invocation)
            self._capacity.release()

        future.add_done_callback(terminal)
        wrapped = asyncio.wrap_future(future)
        wrapped.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        cancel_waiter = asyncio.create_task(control.cancel.wait())
        try:
            try:
                timeout = max(
                    0.0,
                    min(stage_deadline, control.deadline_monotonic) - control.monotonic(),
                )
                done, _ = await asyncio.wait(
                    {wrapped, cancel_waiter},
                    timeout=timeout,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if cancel_waiter in done:
                    control.cancel.raise_if_cancelled()
                    raise self._failure()
                if wrapped not in done:
                    raise self._failure()
            finally:
                cancel_waiter.cancel()
                await asyncio.gather(cancel_waiter, return_exceptions=True)

            self._check(control, stage_deadline)
            return wrapped.result()
        except BaseException:
            self._abandon(invocation)
            raise

    def _abandon(self, invocation: _Invocation) -> None:
        with self._gate:
            invocation.abandoned = True

    def close(self) -> None:
        with self._gate:
            if self._closed:
                return
            self._closed = True
            for invocation in self._owned:
                if not invocation.admitted:
                    invocation.abandoned = True
        self._executor.shutdown(wait=False, cancel_futures=False)
