from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from time import monotonic
from uuid import uuid4

import pytest

from ai_soc.contracts.errors import public_error
from ai_soc.contracts.models import ErrorCode, RecoveryPage
from ai_soc.state.errors import StateFailure
from ai_soc.state.memory import MemoryState
from ai_soc.state.recovery import RecoveryRunner
from ai_soc.telemetry.metrics import FixtureMetricExporter, MetricName


class _Clock:
    def now(self) -> datetime:
        return datetime(2026, 10, 3, tzinfo=UTC)

    def monotonic(self) -> float:
        return monotonic()


class _Recovery:
    def __init__(self) -> None:
        self.calls: list[tuple[int, str | None, int]] = []
        self.active = 0
        self.max_active = 0
        self._guard = asyncio.Lock()

    async def reconcile(
        self, *, now: datetime, bucket: int, after: str | None, page_size: int = 100
    ) -> RecoveryPage:
        async with self._guard:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        await asyncio.sleep(0)
        async with self._guard:
            self.active -= 1
        self.calls.append((bucket, after, page_size))
        if after is None:
            return RecoveryPage(after="next", examined=2, terminalized=1, errors=[])
        return RecoveryPage(after=None, examined=1, terminalized=0, errors=[])


@pytest.mark.asyncio
async def test_recovery_runner_resumes_each_bucket_and_bounds_parallel_workers() -> None:
    store = _Recovery()
    runner = RecoveryRunner(store, _Clock(), page_size=17)

    report = await runner.run_once()

    assert report.buckets == 128
    assert report.examined == 384
    assert report.terminalized == 128
    assert report.errors == ()
    assert len(store.calls) == 256
    assert all(page_size == 17 for _, _, page_size in store.calls)
    assert store.max_active <= 2
    assert {(bucket, after) for bucket, after, _ in store.calls} == {
        (bucket, cursor) for bucket in range(128) for cursor in (None, "next")
    }


@pytest.mark.asyncio
async def test_recovery_runner_records_bucket_failure_and_continues_the_ring() -> None:
    class FailingBucket(_Recovery):
        async def reconcile(
            self, *, now: datetime, bucket: int, after: str | None, page_size: int = 100
        ) -> RecoveryPage:
            if bucket == 37:
                raise StateFailure(
                    public_error(
                        ErrorCode.DEPENDENCY_UNAVAILABLE,
                        "recovery state is unavailable",
                        trace_id=uuid4().hex,
                    )
                )
            return await super().reconcile(now=now, bucket=bucket, after=after, page_size=page_size)

    store = FailingBucket()
    report = await RecoveryRunner(store, _Clock()).run_once()

    assert report.buckets == 127
    assert report.examined == 381
    assert report.terminalized == 127
    assert report.errors == (ErrorCode.DEPENDENCY_UNAVAILABLE.value,)
    assert {bucket for bucket, _, _ in store.calls} == set(range(128)) - {37}


class _RecoveryWithGauges(_Recovery):
    async def publish_recovery_gauges(self, now: datetime) -> None:
        raise RuntimeError("recovery gauge telemetry unavailable")


@pytest.mark.asyncio
async def test_recovery_runner_continues_when_gauge_publish_fails() -> None:
    store = _RecoveryWithGauges()
    report = await RecoveryRunner(store, _Clock()).run_once()

    assert report.buckets == 128
    assert report.terminalized == 128


@pytest.mark.asyncio
async def test_recovery_run_forever_continues_when_gauge_publish_fails() -> None:
    store = _RecoveryWithGauges()
    runner = RecoveryRunner(store, _Clock(), interval_seconds=1)
    task = asyncio.create_task(runner.run_forever())
    await asyncio.sleep(0.05)
    runner.stop()
    await asyncio.wait_for(task, timeout=2.0)


@pytest.mark.asyncio
async def test_recovery_runner_invokes_memory_publish_recovery_gauges() -> None:
    metrics = FixtureMetricExporter()
    store = MemoryState(metrics=metrics)
    await RecoveryRunner(store, _Clock()).run_once()

    emitted = {sample.name for sample in metrics.samples}
    assert MetricName.recovery_backlog in emitted
    assert MetricName.recovery_lag_seconds in emitted
