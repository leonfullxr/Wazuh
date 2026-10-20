"""Strict, redacted audit serialization helpers."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import TypeGuard

from ai_soc.contracts.models import (
    AuditAck,
    AuditEvent,
    ExecutionContext,
    StageName,
    StageOutcome,
    TraceContext,
)

from .audit_delivery import AuditTelemetry
from .metrics import MetricExporter, MetricName, MetricSample
from .outcomes import append_stage_outcome
from .tracing import SpanExporter
from .tracing import StageSpan as TracedStageSpan


class TelemetryAdapter:
    """Join durable audit delivery with safe stage metrics and fixture spans."""

    def __init__(
        self,
        *,
        audit: AuditTelemetry,
        spans: SpanExporter,
        metrics: MetricExporter,
    ) -> None:
        self._audit = audit
        self._spans = spans
        self._metrics = metrics

    @property
    def metrics_exporter(self) -> MetricExporter:
        return self._metrics

    async def event(self, event: AuditEvent, *, execution: ExecutionContext) -> AuditAck:
        try:
            ack = await self._audit.event(event, execution=execution)
        except Exception:
            self._delivery_metric(StageOutcome.unavailable)
            raise
        self._delivery_metric(StageOutcome.ok)
        return ack

    def _delivery_metric(self, outcome: StageOutcome) -> None:
        try:
            self._metrics.emit(
                MetricSample(
                    name=MetricName.audit_delivery,
                    value=1.0,
                    unit="Count",
                    stage=StageName.audit,
                    outcome=outcome,
                )
            )
        except Exception:
            # Metrics are best effort; they must not change durable audit semantics.
            return

    @contextmanager
    def stage(self, name: StageName, *, trace_context: TraceContext) -> Iterator[TracedStageSpan]:
        candidate: object = name
        if not _is_stage_name(candidate):
            raise ValueError("unknown telemetry stage")
        span = TracedStageSpan(
            trace_context=trace_context,
            stage=name,
            spans=self._spans,
            metrics=self._metrics,
            on_record=append_stage_outcome,
        )
        with span:
            yield span


def _is_stage_name(value: object) -> TypeGuard[StageName]:
    try:
        StageName(value)
    except (TypeError, ValueError):
        return False
    return True
