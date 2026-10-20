"""Bounded process-local scheduling for durable reservation reconciliation."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from ai_soc.contracts.models import ErrorCode, RecoveryPage
from ai_soc.contracts.ports import Clock, RecoveryStore
from ai_soc.state.errors import StateFailure

RECOVERY_BUCKETS = 128
RECOVERY_WORKERS = 2
RECOVERY_INTERVAL_SECONDS = 30
RECOVERY_PAGE_SIZE = 100


@dataclass(frozen=True, slots=True)
class RecoveryPass:
    examined: int
    terminalized: int
    errors: tuple[str, ...]
    buckets: int


class RecoveryRunner:
    """Walks the durable 128-bucket ring without a table scan or in-memory queue."""

    def __init__(
        self,
        store: RecoveryStore,
        clock: Clock,
        *,
        page_size: int = RECOVERY_PAGE_SIZE,
        interval_seconds: int = RECOVERY_INTERVAL_SECONDS,
    ) -> None:
        if not 1 <= page_size <= 1000:
            raise ValueError("recovery page size must be between 1 and 1000")
        if not 1 <= interval_seconds <= 30:
            raise ValueError("recovery interval must be between 1 and 30 seconds")
        self._store = store
        self._clock = clock
        self._page_size = page_size
        self._interval = interval_seconds
        self._stop = asyncio.Event()
        self._run_lock = asyncio.Lock()

    async def run_once(self) -> RecoveryPass:
        """Examine every ring bucket with at most two active DDB control calls."""
        async with self._run_lock:
            totals = [0, 0]
            errors: list[str] = []
            examined_buckets = 0
            lock = asyncio.Lock()

            async def worker(first_bucket: int) -> None:
                nonlocal examined_buckets
                for bucket in range(first_bucket, RECOVERY_BUCKETS, RECOVERY_WORKERS):
                    cursor: str | None = None
                    while True:
                        try:
                            page: RecoveryPage = await self._store.reconcile(
                                now=self._clock.now(),
                                bucket=bucket,
                                after=cursor,
                                page_size=self._page_size,
                            )
                        except StateFailure as failure:
                            async with lock:
                                errors.append(ErrorCode(failure.code).value)
                            break
                        except Exception:
                            async with lock:
                                errors.append(ErrorCode.DEPENDENCY_UNAVAILABLE.value)
                            break
                        async with lock:
                            totals[0] += page.examined
                            totals[1] += page.terminalized
                            errors.extend(code.value for code in page.errors)
                            if cursor is None:
                                examined_buckets += 1
                        cursor = page.after
                        if cursor is None:
                            break

            await asyncio.gather(*(worker(index) for index in range(RECOVERY_WORKERS)))
            publisher = getattr(self._store, "publish_recovery_gauges", None)
            if publisher is not None:
                try:
                    await publisher(self._clock.now())
                except Exception:
                    pass
            return RecoveryPass(
                examined=totals[0],
                terminalized=totals[1],
                errors=tuple(errors),
                buckets=examined_buckets,
            )

    async def run_forever(self) -> None:
        """Run a recovery pass every 30 seconds until the owning process stops it."""
        self._stop.clear()
        while not self._stop.is_set():
            await self.run_once()
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._interval)
            except TimeoutError:
                continue

    def stop(self) -> None:
        self._stop.set()
