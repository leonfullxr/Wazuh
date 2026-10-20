"""Low-cardinality metrics for fixture and AWS CloudWatch exporters."""

from __future__ import annotations

import math
import queue
import threading
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from ai_soc.contracts.models import FetchState, RemovedReason, StageName, StageOutcome


class MetricName(StrEnum):
    stage_latency = "StageLatency"
    stage_outcome = "StageOutcome"
    audit_delivery = "AuditDelivery"
    fetch_result = "FetchResult"
    removed_finding = "RemovedFinding"
    cache_tokens = "CacheTokens"
    budget_reserved = "BudgetReserved"
    budget_charged = "BudgetCharged"
    content_provenance_failure = "ContentProvenanceFailure"
    feedback_enqueue_failure = "FeedbackEnqueueFailure"
    lease_conflict = "LeaseConflict"
    token_broker_failure = "TokenBrokerFailure"
    recovery_lag_seconds = "RecoveryLagSeconds"
    recovery_backlog = "RecoveryBacklog"
    admission_rejected = "AdmissionRejected"


@dataclass(frozen=True, slots=True)
class MetricSample:
    name: MetricName
    value: float
    unit: str
    stage: StageName | None = None
    outcome: StageOutcome | None = None
    fetch_state: FetchState | None = None
    removed_reason: RemovedReason | None = None

    def __post_init__(self) -> None:
        if not math.isfinite(self.value) or self.value < 0:
            raise ValueError("metric values must be finite and nonnegative")
        if self.name is MetricName.stage_latency:
            valid = self.unit == "Milliseconds" and self.stage is not None and self.outcome is None
        elif self.name is MetricName.stage_outcome:
            valid = self.unit == "Count" and self.stage is not None and self.outcome is not None
        elif self.name is MetricName.audit_delivery:
            valid = (
                self.unit == "Count" and self.stage is StageName.audit and self.outcome is not None
            )
        elif self.name is MetricName.fetch_result:
            valid = (
                self.unit == "Count"
                and self.fetch_state is not None
                and self.stage is None
                and self.outcome is None
                and self.removed_reason is None
            )
        elif self.name is MetricName.removed_finding:
            valid = (
                self.unit == "Count"
                and self.removed_reason is not None
                and self.stage is None
                and self.outcome is None
                and self.fetch_state is None
            )
        elif self.name in (
            MetricName.cache_tokens,
            MetricName.budget_reserved,
            MetricName.budget_charged,
            MetricName.content_provenance_failure,
            MetricName.feedback_enqueue_failure,
            MetricName.lease_conflict,
            MetricName.token_broker_failure,
        ):
            valid = (
                self.unit == "Count"
                and self.stage is None
                and self.outcome is None
                and self.fetch_state is None
                and self.removed_reason is None
            )
        elif self.name is MetricName.recovery_lag_seconds:
            valid = self.unit == "Seconds" and self.stage is None and self.outcome is None
        elif self.name in (MetricName.recovery_backlog, MetricName.admission_rejected):
            valid = self.unit == "Count" and self.stage is None and self.outcome is None
        else:
            valid = False
        if not valid:
            raise ValueError("metric sample does not match the finite SOC metric schema")
        try:
            if self.stage is not None:
                StageName(self.stage)
            if self.outcome is not None:
                StageOutcome(self.outcome)
            if self.fetch_state is not None:
                FetchState(self.fetch_state)
            if self.removed_reason is not None:
                RemovedReason(self.removed_reason)
        except (TypeError, ValueError) as exc:
            raise ValueError("metric dimensions must use frozen finite enums") from exc


class MetricExporter(Protocol):
    def emit(self, sample: MetricSample) -> None: ...


def emit_safe(exporter: MetricExporter, sample: MetricSample) -> None:
    try:
        exporter.emit(sample)
    except Exception:
        return


class CloudWatchClient(Protocol):
    def put_metric_data(self, *, Namespace: str, MetricData: list[dict[str, object]]) -> object: ...


class FixtureMetricExporter:
    """In-memory exporter; samples contain no per-question dimensions."""

    def __init__(self) -> None:
        self.samples: list[MetricSample] = []

    def emit(self, sample: MetricSample) -> None:
        self.samples.append(sample)


def _metric_datum(sample: MetricSample) -> dict[str, object]:
    dimensions: list[dict[str, object]] = []
    if sample.stage is not None:
        dimensions.append({"Name": "Stage", "Value": sample.stage.value})
    if sample.outcome is not None:
        dimensions.append({"Name": "Outcome", "Value": StageOutcome(sample.outcome).value})
    if sample.fetch_state is not None:
        classification = FetchState(sample.fetch_state).value
        dimensions.append({"Name": "Classification", "Value": classification})
    if sample.removed_reason is not None:
        dimensions.append({"Name": "Reason", "Value": RemovedReason(sample.removed_reason).value})
    data: dict[str, object] = {
        "MetricName": sample.name.value,
        "Value": sample.value,
        "Unit": sample.unit,
    }
    if dimensions:
        data["Dimensions"] = dimensions
    return data


class CloudWatchMetricExporter:
    """Publish only fixed metric names and finite stage/outcome dimensions."""

    def __init__(self, client: CloudWatchClient, *, namespace: str) -> None:
        if not namespace or len(namespace) > 255:
            raise ValueError("invalid metric namespace")
        self._client = client
        self._namespace = namespace

    def emit(self, sample: MetricSample) -> None:
        self._client.put_metric_data(
            Namespace=self._namespace,
            MetricData=[_metric_datum(sample)],
        )


class BatchedCloudWatchMetricExporter:
    """Buffer samples and flush from a background thread; never blocks callers on I/O."""

    def __init__(
        self,
        client: CloudWatchClient,
        *,
        namespace: str,
        max_queue: int = 2048,
        batch_size: int = 20,
        flush_interval_seconds: float = 1.0,
    ) -> None:
        if not namespace or len(namespace) > 255:
            raise ValueError("invalid metric namespace")
        if not 1 <= batch_size <= 20:
            raise ValueError("batch size must be between 1 and 20")
        self._client = client
        self._namespace = namespace
        self._batch_size = batch_size
        self._flush_interval = flush_interval_seconds
        self._queue: queue.Queue[MetricSample | None] = queue.Queue(maxsize=max_queue)
        self.dropped_samples = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="cloudwatch-metrics", daemon=True)
        self._thread.start()

    def emit(self, sample: MetricSample) -> None:
        try:
            self._queue.put_nowait(sample)
        except queue.Full:
            self.dropped_samples += 1

    def shutdown(self) -> None:
        self._stop.set()
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        self._thread.join(timeout=10.0)

    def _run(self) -> None:
        pending: list[MetricSample] = []
        last_flush = time.monotonic()
        while not self._stop.is_set() or not self._queue.empty() or pending:
            try:
                sample = self._queue.get(timeout=self._flush_interval)
            except queue.Empty:
                sample = None
            if sample is None:
                if pending:
                    self._flush(pending)
                    pending = []
                if self._stop.is_set():
                    break
                last_flush = time.monotonic()
                continue
            pending.append(sample)
            if len(pending) >= self._batch_size or (
                time.monotonic() - last_flush >= self._flush_interval
            ):
                self._flush(pending)
                pending = []
                last_flush = time.monotonic()
        if pending:
            self._flush(pending)

    def _flush(self, batch: list[MetricSample]) -> None:
        if not batch:
            return
        try:
            self._client.put_metric_data(
                Namespace=self._namespace,
                MetricData=[_metric_datum(sample) for sample in batch],
            )
        except Exception:
            return
