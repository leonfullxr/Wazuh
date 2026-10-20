from __future__ import annotations

import threading
import time

from ai_soc.contracts.models import StageName
from ai_soc.telemetry.metrics import BatchedCloudWatchMetricExporter, MetricName, MetricSample


class BlockingClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.block = threading.Event()

    def put_metric_data(self, *, Namespace: str, MetricData: list[dict[str, object]]) -> object:
        self.block.wait(timeout=5.0)
        self.calls.append({"Namespace": Namespace, "MetricData": MetricData})
        return {}


def test_batched_exporter_does_not_block_emitter_on_network() -> None:
    client = BlockingClient()
    exporter = BatchedCloudWatchMetricExporter(
        client,
        namespace="AISOC/Test",
        flush_interval_seconds=0.05,
        max_queue=8,
    )
    sample = MetricSample(
        name=MetricName.stage_latency,
        value=1.0,
        unit="Milliseconds",
        stage=StageName.fetch,
    )
    start = time.monotonic()
    exporter.emit(sample)
    elapsed = time.monotonic() - start
    assert elapsed < 0.05
    client.block.set()
    exporter.shutdown()
    assert client.calls
