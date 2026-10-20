"""Question-stage spans with a safe in-memory fixture exporter."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from dataclasses import dataclass
from time import monotonic
from typing import Protocol

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags

from ai_soc.contracts.models import (
    AuditStageOutcome,
    StageAttributes,
    StageName,
    StageOutcome,
    TraceContext,
)

from .metrics import MetricExporter, MetricName, MetricSample


@dataclass(frozen=True, slots=True)
class TraceSpan:
    trace_context: TraceContext
    stage: StageName
    outcome: StageOutcome
    latency_ms: int
    attributes: StageAttributes


class SpanExporter(Protocol):
    def export(self, span: TraceSpan) -> None: ...


class FixtureSpanExporter:
    def __init__(self) -> None:
        self.spans: list[TraceSpan] = []

    def export(self, span: TraceSpan) -> None:
        self.spans.append(span)


class OtlpTraceExporter:
    """Export bounded spans over OTLP/gRPC to a local ADOT collector."""

    _LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "adot-collector"})

    def __init__(self, endpoint: str, *, service_version: str) -> None:
        from urllib.parse import urlsplit

        parsed = urlsplit(endpoint)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in self._LOCAL_HOSTS
            or parsed.port != 4317
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise ValueError("OTLP endpoint must be the local ADOT gRPC receiver")
        if re.fullmatch(r"[0-9a-f]{40}", service_version) is None:
            raise ValueError("service version must be a committed service SHA")
        provider = TracerProvider(
            resource=Resource(
                attributes={"service.name": "ai-soc", "service.version": service_version}
            )
        )
        self._provider = provider
        self._tracer = provider.get_tracer("ai_soc.telemetry", "1")
        self._endpoint = endpoint.removeprefix("http://")
        provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=self._endpoint, insecure=True))
        )

    def export(self, item: TraceSpan) -> None:
        parent = SpanContext(
            trace_id=int(item.trace_context.trace_id, 16),
            span_id=int(item.trace_context.span_id, 16),
            is_remote=True,
            trace_flags=TraceFlags(item.trace_context.trace_flags),
        )
        parent_context = trace.set_span_in_context(NonRecordingSpan(parent))
        attributes: dict[str, str | int] = {
            "soc.stage": item.stage.value,
            "soc.outcome": item.outcome.value,
            "soc.latency_ms": item.latency_ms,
        }
        for key, value in item.attributes.model_dump(exclude_none=True).items():
            if isinstance(value, str):
                attributes[f"soc.{key}"] = value
            elif hasattr(value, "value"):
                attributes[f"soc.{key}"] = value.value
            else:
                attributes[f"soc.{key}"] = value
        with self._tracer.start_as_current_span(
            item.stage.value,
            context=parent_context,
            attributes=attributes,
            record_exception=False,
            set_status_on_exception=False,
        ):
            pass

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        return self._provider.force_flush(timeout_millis=timeout_millis)

    def shutdown(self) -> None:
        self._provider.shutdown()


class StageSpan:
    def __init__(
        self,
        *,
        stage: StageName,
        trace_context: TraceContext,
        spans: SpanExporter,
        metrics: MetricExporter,
        now: Callable[[], float] = monotonic,
        on_record: Callable[[AuditStageOutcome], None] | None = None,
    ) -> None:
        self._trace_context = trace_context
        self._stage = stage
        self._spans = spans
        self._metrics = metrics
        self._now = now
        self._on_record = on_record
        self._started = now()
        self._outcome = StageOutcome.ok
        self._latency_ms: int | None = None
        self._attributes = StageAttributes()
        self._closed = False
        self._outcome_explicit = False

    def set_outcome(self, outcome: StageOutcome) -> None:
        if self._closed:
            raise RuntimeError("span is already closed")
        self._outcome = outcome
        self._outcome_explicit = True

    def record_latency(self, milliseconds: int) -> None:
        if milliseconds < 0:
            raise ValueError("latency must be nonnegative")
        if self._closed:
            raise RuntimeError("span is already closed")
        self._latency_ms = milliseconds

    def record_attributes(self, attributes: StageAttributes) -> None:
        if self._closed:
            raise RuntimeError("span is already closed")
        self._attributes = attributes
        if attributes.outcome is not None:
            self._outcome = StageOutcome(attributes.outcome)
        if attributes.latency_ms is not None:
            self._latency_ms = attributes.latency_ms

    def _flush(self, *, latency: int) -> None:
        if self._on_record is not None:
            try:
                self._on_record(
                    AuditStageOutcome(
                        stage=self._stage,
                        outcome=self._outcome,
                        latency_ms=latency,
                    )
                )
            except Exception:
                pass
        try:
            self._spans.export(
                TraceSpan(
                    trace_context=self._trace_context,
                    stage=self._stage,
                    outcome=self._outcome,
                    latency_ms=latency,
                    attributes=self._attributes,
                )
            )
        except Exception:
            pass
        try:
            self._metrics.emit(
                MetricSample(
                    name=MetricName.stage_latency,
                    value=float(latency),
                    unit="Milliseconds",
                    stage=self._stage,
                )
            )
            self._metrics.emit(
                MetricSample(
                    name=MetricName.stage_outcome,
                    value=1.0,
                    unit="Count",
                    stage=self._stage,
                    outcome=self._outcome,
                )
            )
        except Exception:
            pass

    def __enter__(self) -> StageSpan:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        if self._closed:
            return False
        if not self._outcome_explicit:
            if isinstance(exc, asyncio.CancelledError):
                self._outcome = StageOutcome.cancelled
            elif isinstance(exc, TimeoutError):
                self._outcome = StageOutcome.deadline
            elif exc_type is not None:
                self._outcome = StageOutcome.failed
        elapsed = max(0, round((self._now() - self._started) * 1000))
        latency = elapsed if self._latency_ms is None else self._latency_ms
        self._flush(latency=latency)
        self._closed = True
        return False
