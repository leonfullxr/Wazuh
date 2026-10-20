"""Keep request capacity charged while cancellable SDK work still runs."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from contextvars import ContextVar, Token


class _SlotLease:
    def __init__(self, semaphore: asyncio.Semaphore) -> None:
        self._semaphore = semaphore
        self._pending_workers = 0
        self._scope_exited = False
        self._released = False

    def retain_until(self, worker: asyncio.Future[object]) -> None:
        self._pending_workers += 1
        worker.add_done_callback(self._worker_finished)

    def close(self) -> None:
        self._scope_exited = True
        self._release_if_ready()

    def _worker_finished(self, _worker: asyncio.Future[object]) -> None:
        self._pending_workers -= 1
        self._release_if_ready()

    def _release_if_ready(self) -> None:
        if self._scope_exited and self._pending_workers == 0 and not self._released:
            self._released = True
            self._semaphore.release()


_current_slot_lease: ContextVar[_SlotLease | None] = ContextVar(
    "current_document_slot_lease", default=None
)


@asynccontextmanager
async def document_slot(semaphore: asyncio.Semaphore) -> AsyncIterator[None]:
    """Acquire a document slot and defer its release for retained worker calls."""
    await semaphore.acquire()
    lease = _SlotLease(semaphore)
    token: Token[_SlotLease | None] = _current_slot_lease.set(lease)
    try:
        yield
    finally:
        _current_slot_lease.reset(token)
        lease.close()


def retain_document_slot_until(worker: asyncio.Future[object]) -> None:
    """Attach physical worker lifetime to the current document slot, when present."""
    lease = _current_slot_lease.get()
    if lease is not None:
        lease.retain_until(worker)
