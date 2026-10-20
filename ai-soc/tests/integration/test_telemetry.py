from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from typing import Literal, TypedDict
from uuid import uuid4

import boto3
import grpc
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber
from opentelemetry.proto.collector.trace.v1 import trace_service_pb2, trace_service_pb2_grpc
from pydantic import TypeAdapter

from ai_soc.contracts.models import (
    AdmissionGrant,
    AnswerStatus,
    AuditEvent,
    CallKind,
    ExecutionContext,
    FeedbackEvent,
    StageAttributes,
    StageName,
    StageOutcome,
    TraceContext,
)
from ai_soc.telemetry.audit_delivery import (
    AuditArchiveConsumer,
    AuditTelemetry,
    AuditUnavailable,
    FeedbackArchiveConsumer,
)
from ai_soc.telemetry.events import TelemetryAdapter
from ai_soc.telemetry.metrics import (
    CloudWatchMetricExporter,
    FixtureMetricExporter,
    MetricName,
    MetricSample,
)
from ai_soc.telemetry.outcomes import (
    append_stage_outcome,
    begin_stage_outcomes,
    current_stage_outcomes,
    reset_stage_outcomes,
)
from ai_soc.telemetry.serialization import audit_json
from ai_soc.telemetry.tracing import FixtureSpanExporter, OtlpTraceExporter, TraceSpan
from ai_soc.telemetry.tracing import StageSpan as TracedStageSpan

SHA = "a" * 64
GIT_SHA = "b" * 40
FM003_FIXTURE = Path(__file__).parent / "data/fm003_audit_ack_cases.json"


class AuditAckCase(TypedDict):
    variant: Literal["positive", "negative", "boundary", "failure"]
    behavior: Literal["ack", "ackless", "redacted", "ambiguous"]


class AuditAckFixture(TypedDict):
    schema_version: Literal["1"]
    case_id: Literal["FM-003.resolution"]
    requirement: Literal["G047"]
    variants: list[AuditAckCase]


def _fm003_cases() -> list[AuditAckCase]:
    adapter: TypeAdapter[AuditAckFixture] = TypeAdapter(AuditAckFixture)
    return adapter.validate_python(json.loads(FM003_FIXTURE.read_text(encoding="utf-8")))[
        "variants"
    ]


class Calls:
    def __init__(self) -> None:
        self.kinds: list[CallKind] = []

    def claim(self, kind: CallKind) -> None:
        self.kinds.append(kind)


class Cancellation:
    def raise_if_cancelled(self) -> None:
        return None

    def is_cancelled(self) -> bool:
        return False

    async def wait(self) -> None:
        return None


class Clock:
    def now(self) -> datetime:
        return datetime(2026, 9, 30, 12, tzinfo=UTC)

    def monotonic(self) -> float:
        return 1.0


def make_event() -> AuditEvent:
    return AuditEvent(
        event_id=uuid4(),
        question_id=uuid4(),
        trace_id="d" * 32,
        owner_key=SHA,
        environment_id="alpha",
        authenticated_issuer="https://issuer.example.test",
        auth_edge="fixture",
        image_digest="sha256:" + "c" * 64,
        outcome="completed",
        completion_id=uuid4(),
        answer_status=AnswerStatus.answered,
        service_sha=GIT_SHA,
        content_sha=GIT_SHA,
        pack_sha256=SHA,
        policy_hash=SHA,
        cue_ids=[],
        topic_ids=[],
        created_at=datetime(2026, 9, 30, 12, tzinfo=UTC),
    )


def make_execution() -> tuple[ExecutionContext, Calls]:
    calls = Calls()
    execution = ExecutionContext(
        question_id=uuid4(),
        operation="ask",
        owner_key=SHA,
        environment_id="alpha",
        deadline_at=datetime(2026, 9, 30, 12, 2, tzinfo=UTC),
        cancel=Cancellation(),
        calls=calls,
        admission=AdmissionGrant(
            holder_id=uuid4(),
            slot_ids=("site-alpha-1",),
            expires_at=datetime(2026, 9, 30, 12, 1, tzinfo=UTC),
            fence=1,
        ),
        trace_context=TraceContext(
            trace_id="a" * 32,
            span_id="b" * 16,
            trace_flags=1,
        ),
    )
    return execution, calls


class Sqs:
    def __init__(self) -> None:
        self.sent: list[dict[str, object]] = []
        self.deleted: list[str] = []
        self.receive_calls: list[dict[str, object]] = []
        self.messages: list[dict[str, str]] = []
        self.order: list[str] = []

    def send_message(self, *, QueueUrl: str, MessageBody: str) -> dict[str, object]:
        self.sent.append({"QueueUrl": QueueUrl, "MessageBody": MessageBody})
        return {"MessageId": "delivery-1"}

    def delete_message(self, *, QueueUrl: str, ReceiptHandle: str) -> None:
        self.order.append("delete")
        self.deleted.append(ReceiptHandle)

    def receive_message(self, **kwargs: object) -> dict[str, object]:
        self.receive_calls.append(kwargs)
        return {"Messages": self.messages}


class S3:
    def __init__(self, order: list[str] | None = None) -> None:
        self.puts: list[dict[str, object]] = []
        self.duplicate = False
        self.duplicate_error_code = "PreconditionFailed"
        self.fail_on_attempt: int | None = None
        self.order = order if order is not None else []

    def put_object(self, **kwargs: object) -> dict[str, object]:
        self.order.append("archive")
        self.puts.append(kwargs)
        if self.fail_on_attempt == len(self.puts):
            raise OSError("archive unavailable")
        if self.duplicate:
            status = 412 if self.duplicate_error_code == "PreconditionFailed" else 409
            raise ClientError(
                {
                    "Error": {
                        "Code": self.duplicate_error_code,
                        "Message": "conditional object write failed",
                    },
                    "ResponseMetadata": {"HTTPStatusCode": status},
                },
                "PutObject",
            )
        return {"ETag": '"fixture"'}


class MetricClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def put_metric_data(self, *, Namespace: str, MetricData: list[dict[str, object]]) -> None:
        self.calls.append({"Namespace": Namespace, "MetricData": MetricData})


@pytest.mark.asyncio
@pytest.mark.parametrize("case", _fm003_cases(), ids=lambda case: case["variant"])
async def test_fm003_durable_audit_ack_variants(
    case: AuditAckCase, record_property: Callable[[str, str], None]
) -> None:
    record_property("acceptance_ids", "G047")
    record_property("case_id", "FM-003.resolution")
    record_property("variant", case["variant"])
    record_property("fixture_sha256", hashlib.sha256(FM003_FIXTURE.read_bytes()).hexdigest())
    event = make_event()
    body = audit_json(event)

    if case["behavior"] == "ack":
        sqs = Sqs()
        execution, calls = make_execution()
        ack = await AuditTelemetry(
            sqs, queue_url="https://sqs.example.test/audit", clock=Clock()
        ).event(event, execution=execution)
        assert ack.event_id == event.event_id
        assert ack.delivery_id == "delivery-1"
        assert len(sqs.sent) == 1
        assert calls.kinds == [CallKind.audit]
    elif case["behavior"] == "ackless":

        class AcklessSqs(Sqs):
            def send_message(self, *, QueueUrl: str, MessageBody: str) -> dict[str, object]:
                self.sent.append({"QueueUrl": QueueUrl, "MessageBody": MessageBody})
                return {}

        sqs = AcklessSqs()
        execution, calls = make_execution()
        with pytest.raises(AuditUnavailable, match="no delivery identifier"):
            await AuditTelemetry(
                sqs, queue_url="https://sqs.example.test/audit", clock=Clock()
            ).event(event, execution=execution)
        assert len(sqs.sent) == 1
        assert calls.kinds == [CallKind.audit]
    elif case["behavior"] == "redacted":
        sqs = Sqs()
        execution, _ = make_execution()
        ack = await AuditTelemetry(
            sqs, queue_url="https://sqs.example.test/audit", clock=Clock()
        ).event(event, execution=execution)
        assert ack.event_id == event.event_id
        assert json.loads(sqs.sent[0]["MessageBody"]) == event.model_dump(mode="json")
        assert all(secret not in body for secret in ("question_text", "prompt", "rows"))
    else:

        class AcceptedThenTimeout(Sqs):
            def send_message(self, *, QueueUrl: str, MessageBody: str) -> dict[str, object]:
                self.sent.append({"QueueUrl": QueueUrl, "MessageBody": MessageBody})
                raise TimeoutError("response channel lost after queue acceptance")

        sqs = AcceptedThenTimeout()
        execution, calls = make_execution()
        with pytest.raises(AuditUnavailable, match="durable audit queue"):
            await AuditTelemetry(
                sqs, queue_url="https://sqs.example.test/audit", clock=Clock()
            ).event(event, execution=execution)
        assert len(sqs.sent) == 1
        assert calls.kinds == [CallKind.audit]


@pytest.mark.asyncio
async def test_sqs_ack_is_durable_contract_and_contains_no_question_or_rows() -> None:
    sqs = Sqs()
    execution, calls = make_execution()
    telemetry = AuditTelemetry(sqs, queue_url="https://sqs.example.test/audit", clock=Clock())
    event = make_event()

    ack = await telemetry.event(event, execution=execution)

    assert ack.event_id == event.event_id
    assert ack.delivery_id == "delivery-1"
    assert calls.kinds == [CallKind.audit]
    assert json.loads(sqs.sent[0]["MessageBody"]) == event.model_dump(mode="json")
    assert "question_text" not in sqs.sent[0]["MessageBody"]
    assert "prompt" not in sqs.sent[0]["MessageBody"]
    assert "rows" not in sqs.sent[0]["MessageBody"]


@pytest.mark.asyncio
async def test_boto_sqs_ack_uses_one_exact_sdk_attempt_and_wire_request() -> None:
    client = boto3.client(
        "sqs",
        region_name="us-east-1",
        endpoint_url="https://sqs.us-east-1.amazonaws.com",
        aws_access_key_id="fixture",
        aws_secret_access_key="fixture",
    )
    queue = "https://sqs.us-east-1.amazonaws.com/123456789012/audit"
    event = make_event()
    with Stubber(client) as stubber:
        stubber.add_response(
            "send_message",
            {"MessageId": "sdk-delivery-1"},
            {"QueueUrl": queue, "MessageBody": audit_json(event)},
        )
        execution, calls = make_execution()
        telemetry = AuditTelemetry(client, queue_url=queue, clock=Clock())

        ack = await telemetry.event(event, execution=execution)

        assert ack.delivery_id == "sdk-delivery-1"
        assert calls.kinds == [CallKind.audit]
        stubber.assert_no_pending_responses()


def test_boto_archive_consumer_uses_exact_receive_archive_delete_attempts() -> None:
    sqs = boto3.client(
        "sqs",
        region_name="us-east-1",
        endpoint_url="https://sqs.us-east-1.amazonaws.com",
        aws_access_key_id="fixture",
        aws_secret_access_key="fixture",
    )
    s3 = boto3.client(
        "s3",
        region_name="us-east-1",
        endpoint_url="https://s3.us-east-1.amazonaws.com",
        aws_access_key_id="fixture",
        aws_secret_access_key="fixture",
    )
    queue = "https://sqs.us-east-1.amazonaws.com/123456789012/audit"
    event = make_event()
    body = audit_json(event)
    with Stubber(sqs) as sqs_stubber, Stubber(s3) as s3_stubber:
        sqs_stubber.add_response(
            "receive_message",
            {"Messages": [{"Body": body, "ReceiptHandle": "sdk-receipt"}]},
            {
                "QueueUrl": queue,
                "MaxNumberOfMessages": 10,
                "WaitTimeSeconds": 1,
                "VisibilityTimeout": 30,
            },
        )
        s3_stubber.add_response(
            "put_object",
            {"ETag": '"fixture"'},
            {
                "Bucket": "audit-archive",
                "Key": f"events/{str(event.event_id)[:2]}/{event.event_id}.json",
                "Body": body.encode("utf-8"),
                "ContentType": "application/json",
                "IfNoneMatch": "*",
            },
        )
        sqs_stubber.add_response(
            "delete_message", {}, {"QueueUrl": queue, "ReceiptHandle": "sdk-receipt"}
        )
        consumer = AuditArchiveConsumer(sqs=sqs, s3=s3, queue_url=queue, bucket="audit-archive")

        result = consumer.run_once()

        assert (result.received, result.archived, result.failed) == (1, 1, 0)
        sqs_stubber.assert_no_pending_responses()
        s3_stubber.assert_no_pending_responses()


@pytest.mark.asyncio
async def test_sqs_failure_is_fail_closed_and_ack_without_id_is_rejected() -> None:
    class FailingSqs(Sqs):
        def send_message(self, *, QueueUrl: str, MessageBody: str) -> dict[str, object]:
            raise OSError("credential sentinel must not escape")

    execution, _ = make_execution()
    telemetry = AuditTelemetry(
        FailingSqs(), queue_url="https://sqs.example.test/audit", clock=Clock()
    )
    with pytest.raises(AuditUnavailable, match="durable audit queue") as failure:
        await telemetry.event(make_event(), execution=execution)
    assert "credential sentinel" not in str(failure.value)

    class AcklessSqs(Sqs):
        def send_message(self, *, QueueUrl: str, MessageBody: str) -> dict[str, object]:
            self.sent.append({"QueueUrl": QueueUrl, "MessageBody": MessageBody})
            return {}

    ackless = AcklessSqs()
    execution, calls = make_execution()
    telemetry = AuditTelemetry(ackless, queue_url="https://sqs.example.test/audit", clock=Clock())
    with pytest.raises(AuditUnavailable, match="no delivery identifier"):
        await telemetry.event(make_event(), execution=execution)
    assert len(ackless.sent) == 1
    assert calls.kinds == [CallKind.audit]


@pytest.mark.asyncio
async def test_ambiguous_sqs_accept_then_timeout_never_returns_a_durable_ack() -> None:
    class AcceptedThenTimeout(Sqs):
        def send_message(self, *, QueueUrl: str, MessageBody: str) -> dict[str, object]:
            self.sent.append({"QueueUrl": QueueUrl, "MessageBody": MessageBody})
            raise TimeoutError("response channel lost after queue acceptance")

    sqs = AcceptedThenTimeout()
    execution, calls = make_execution()
    telemetry = AuditTelemetry(sqs, queue_url="https://sqs.example.test/audit", clock=Clock())

    with pytest.raises(AuditUnavailable, match="durable audit queue") as failure:
        await telemetry.event(make_event(), execution=execution)

    assert "response channel" not in str(failure.value)
    assert len(sqs.sent) == 1
    assert calls.kinds == [CallKind.audit]


def test_archive_consumer_archives_before_delete_and_deduplicates_by_event_id() -> None:
    sqs = Sqs()
    s3 = S3(sqs.order)
    consumer = AuditArchiveConsumer(
        sqs=sqs, s3=s3, queue_url="https://sqs.example.test/audit", bucket="audit-archive"
    )
    body = audit_json(make_event())
    event_id = json.loads(body)["event_id"]

    assert str(consumer.handle(body=body, receipt_handle="receipt-1")) == event_id
    assert s3.puts[0]["IfNoneMatch"] == "*"
    assert s3.puts[0]["Key"] == f"events/{event_id[:2]}/{event_id}.json"
    assert sqs.deleted == ["receipt-1"]
    assert sqs.order == ["archive", "delete"]

    s3.duplicate = True
    consumer.handle(body=body, receipt_handle="receipt-2")
    assert sqs.deleted == ["receipt-1", "receipt-2"]


@pytest.mark.parametrize(
    ("error_code", "expected_result", "expected_deleted"),
    [
        ("ConditionalRequestConflict", (1, 0, 1), []),
        ("PreconditionFailed", (1, 1, 0), ["receipt-duplicate"]),
    ],
)
def test_audit_archive_consumer_handles_botocore_conditional_errors(
    error_code: str,
    expected_result: tuple[int, int, int],
    expected_deleted: list[str],
) -> None:
    sqs = Sqs()
    s3 = S3(sqs.order)
    s3.duplicate = True
    s3.duplicate_error_code = error_code
    sqs.messages = [{"Body": audit_json(make_event()), "ReceiptHandle": "receipt-duplicate"}]
    consumer = AuditArchiveConsumer(
        sqs=sqs, s3=s3, queue_url="https://sqs.example.test/audit", bucket="audit-archive"
    )

    result = consumer.run_once()

    assert (result.received, result.archived, result.failed) == expected_result
    assert sqs.deleted == expected_deleted


def test_archive_consumer_polls_bounded_batch_and_leaves_failures_for_dlq_retry() -> None:
    sqs = Sqs()
    s3 = S3(sqs.order)
    valid = audit_json(make_event())
    sqs.messages = [
        {"Body": valid, "ReceiptHandle": "receipt-ok"},
        {"Body": "not-json", "ReceiptHandle": "receipt-invalid"},
        {"Body": valid, "ReceiptHandle": "receipt-archive-fails"},
    ]
    s3.fail_on_attempt = 2
    consumer = AuditArchiveConsumer(
        sqs=sqs, s3=s3, queue_url="https://sqs.example.test/audit", bucket="audit-archive"
    )

    result = consumer.run_once()

    assert result.received == 3
    assert result.archived == 1
    assert result.failed == 2
    assert sqs.receive_calls == [
        {
            "QueueUrl": "https://sqs.example.test/audit",
            "MaxNumberOfMessages": 10,
            "WaitTimeSeconds": 1,
            "VisibilityTimeout": 30,
        }
    ]
    assert sqs.deleted == ["receipt-ok"]


def test_invalid_archive_message_is_not_deleted() -> None:
    sqs = Sqs()
    s3 = S3()
    consumer = AuditArchiveConsumer(
        sqs=sqs, s3=s3, queue_url="https://sqs.example.test/audit", bucket="audit-archive"
    )
    with pytest.raises(ValueError, match="invalid audit"):
        consumer.handle(body='{"event_id":"not-an-event"}', receipt_handle="receipt")
    assert not sqs.deleted
    assert not s3.puts


def test_feedback_archive_consumer_archives_redacted_feedback_before_delete() -> None:
    sqs = Sqs()
    s3 = S3(sqs.order)
    event = FeedbackEvent(
        feedback_id=uuid4(),
        receipt_id=uuid4(),
        question_id=uuid4(),
        owner_key="a" * 64,
        environment_id="alpha",
        content_sha="b" * 40,
        kind="wrong",
        note_redacted="The result was incomplete",
        created_at=datetime(2026, 10, 1, tzinfo=UTC),
    )
    body = json.dumps(
        event.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    consumer = FeedbackArchiveConsumer(
        sqs=sqs, s3=s3, queue_url="https://sqs.example.test/feedback", bucket="audit-archive"
    )

    assert str(consumer.handle(body=body, receipt_handle="receipt-feedback")) == str(
        event.feedback_id
    )
    assert s3.puts[0]["Key"] == f"feedback/{str(event.feedback_id)[:2]}/{event.feedback_id}.json"
    assert s3.puts[0]["Body"] == body.encode("utf-8")
    assert sqs.order == ["archive", "delete"]


@pytest.mark.parametrize(
    ("error_code", "expected_archived", "expected_failed", "expected_deleted"),
    [
        ("ConditionalRequestConflict", 0, 1, []),
        ("PreconditionFailed", 1, 0, ["receipt-feedback-duplicate"]),
    ],
)
def test_feedback_archive_consumer_handles_botocore_conditional_errors(
    error_code: str,
    expected_archived: int,
    expected_failed: int,
    expected_deleted: list[str],
) -> None:
    sqs = Sqs()
    s3 = S3(sqs.order)
    s3.duplicate = True
    s3.duplicate_error_code = error_code
    event = FeedbackEvent(
        feedback_id=uuid4(),
        receipt_id=uuid4(),
        question_id=uuid4(),
        owner_key="a" * 64,
        environment_id="alpha",
        content_sha="b" * 40,
        kind="wrong",
        note_redacted="The result was incomplete",
        created_at=datetime(2026, 10, 1, tzinfo=UTC),
    )
    body = json.dumps(
        event.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    sqs.messages = [{"Body": body, "ReceiptHandle": "receipt-feedback-duplicate"}]
    consumer = FeedbackArchiveConsumer(
        sqs=sqs, s3=s3, queue_url="https://sqs.example.test/feedback", bucket="audit-archive"
    )

    result = consumer.run_once()

    assert (result.received, result.archived, result.failed) == (
        1,
        expected_archived,
        expected_failed,
    )
    assert sqs.deleted == expected_deleted


def test_stage_tracing_and_metrics_use_only_finite_low_cardinality_dimensions() -> None:
    spans = FixtureSpanExporter()
    metrics = FixtureMetricExporter()
    client = MetricClient()
    cloudwatch = CloudWatchMetricExporter(client, namespace="AISOC/Fixture")
    sqs = Sqs()
    telemetry = TelemetryAdapter(
        audit=AuditTelemetry(sqs, queue_url="https://sqs.example.test/audit", clock=Clock()),
        spans=spans,
        metrics=metrics,
    )
    question_id = uuid4()

    context = TraceContext(trace_id="a" * 32, span_id="b" * 16, trace_flags=1)
    with telemetry.stage(StageName.fetch, trace_context=context) as span:
        span.set_outcome(StageOutcome.unavailable)
        span.record_latency(37)
        span.record_attributes(
            StageAttributes(
                outcome=StageOutcome.unavailable,
                latency_ms=37,
            )
        )

    assert len(spans.spans) == 1
    assert spans.spans[0].trace_context == context
    assert spans.spans[0].latency_ms == 37
    assert [sample.name for sample in metrics.samples] == [
        MetricName.stage_latency,
        MetricName.stage_outcome,
    ]
    for sample in metrics.samples:
        cloudwatch.emit(sample)
    encoded = json.dumps(client.calls)
    assert '"Name": "Stage", "Value": "fetch"' in encoded
    assert '"Name": "Outcome", "Value": "unavailable"' in encoded
    for forbidden in (str(question_id), "alpha", "owner_key", "question_id"):
        assert forbidden not in encoded


def test_m8_stage_span_export_failure_does_not_raise() -> None:
    class FailingSpanExporter:
        def export(self, span: TraceSpan) -> None:
            raise RuntimeError("otlp unavailable")

    class FailingMetricExporter:
        def emit(self, sample: MetricSample) -> None:
            raise RuntimeError("cloudwatch unavailable")

    span = TracedStageSpan(
        trace_context=TraceContext(trace_id="a" * 32, span_id="b" * 16, trace_flags=1),
        stage=StageName.audit,
        spans=FailingSpanExporter(),
        metrics=FailingMetricExporter(),
        on_record=append_stage_outcome,
    )
    token = begin_stage_outcomes()
    with span:
        span.set_outcome(StageOutcome.ok)
    assert span._closed is True
    assert len(current_stage_outcomes()) == 1
    reset_stage_outcomes(token)


@pytest.mark.asyncio
async def test_m8_audit_ack_uses_bounded_async_thread_wrapper() -> None:
    import time

    class SlowSqs(Sqs):
        def send_message(self, *, QueueUrl: str, MessageBody: str) -> dict[str, object]:
            time.sleep(0.05)
            return super().send_message(QueueUrl=QueueUrl, MessageBody=MessageBody)

    started = time.monotonic()
    execution, _ = make_execution()
    ack = await AuditTelemetry(
        SlowSqs(), queue_url="https://sqs.example.test/audit", clock=Clock()
    ).event(make_event(), execution=execution)
    assert ack.delivery_id == "delivery-1"
    assert time.monotonic() - started < 4.0


def test_m16_operational_metric_schema_accepts_recovery_and_admission_gauges() -> None:
    MetricSample(name=MetricName.recovery_lag_seconds, value=12.0, unit="Seconds")
    MetricSample(name=MetricName.recovery_backlog, value=3.0, unit="Count")
    MetricSample(name=MetricName.admission_rejected, value=1.0, unit="Count")


def test_invalid_stage_name_cannot_create_unbounded_metric_series() -> None:
    from ai_soc.telemetry.events import TelemetryAdapter

    telemetry = TelemetryAdapter(
        audit=AuditTelemetry(Sqs(), queue_url="https://sqs.example.test/audit", clock=Clock()),
        spans=FixtureSpanExporter(),
        metrics=FixtureMetricExporter(),
    )
    with pytest.raises(ValueError, match="unknown telemetry stage"):
        with telemetry.stage(
            "customer-42",
            trace_context=TraceContext(trace_id="a" * 32, span_id="b" * 16, trace_flags=0),
        ):
            pass


@pytest.mark.asyncio
async def test_audit_delivery_metric_is_finite_and_does_not_mask_ack_result() -> None:
    metrics = FixtureMetricExporter()
    telemetry = TelemetryAdapter(
        audit=AuditTelemetry(Sqs(), queue_url="https://sqs.example.test/audit", clock=Clock()),
        spans=FixtureSpanExporter(),
        metrics=metrics,
    )
    execution, _ = make_execution()

    ack = await telemetry.event(make_event(), execution=execution)

    assert ack.delivery_id == "delivery-1"
    assert metrics.samples == [
        MetricSample(
            name=MetricName.audit_delivery,
            value=1.0,
            unit="Count",
            stage=StageName.audit,
            outcome=StageOutcome.ok,
        )
    ]


def test_metric_samples_reject_nonfinite_values_and_unbounded_dimensions() -> None:
    with pytest.raises(ValueError, match="finite and nonnegative"):
        MetricSample(
            name=MetricName.stage_latency,
            value=float("nan"),
            unit="Milliseconds",
            stage=StageName.fetch,
        )
    with pytest.raises(ValueError, match="finite enums"):
        MetricSample(
            name=MetricName.stage_latency,
            value=1.0,
            unit="Milliseconds",
            stage="customer-42",
        )


def test_boto_cloudwatch_exporter_uses_one_exact_metric_attempt() -> None:
    client = boto3.client(
        "cloudwatch",
        region_name="us-east-1",
        endpoint_url="https://monitoring.us-east-1.amazonaws.com",
        aws_access_key_id="fixture",
        aws_secret_access_key="fixture",
    )
    with Stubber(client) as stubber:
        stubber.add_response(
            "put_metric_data",
            {},
            {
                "Namespace": "AISOC/Service",
                "MetricData": [
                    {
                        "MetricName": "StageOutcome",
                        "Value": 1.0,
                        "Unit": "Count",
                        "Dimensions": [
                            {"Name": "Stage", "Value": "audit"},
                            {"Name": "Outcome", "Value": "ok"},
                        ],
                    }
                ],
            },
        )
        CloudWatchMetricExporter(client, namespace="AISOC/Service").emit(
            MetricSample(
                name=MetricName.stage_outcome,
                value=1.0,
                unit="Count",
                stage=StageName.audit,
                outcome=StageOutcome.ok,
            )
        )
        stubber.assert_no_pending_responses()


class TraceReceiver(trace_service_pb2_grpc.TraceServiceServicer):
    def __init__(self) -> None:
        self.received = Event()
        self.requests: list[trace_service_pb2.ExportTraceServiceRequest] = []

    def Export(self, request, context):
        self.requests.append(request)
        self.received.set()
        return trace_service_pb2.ExportTraceServiceResponse()


def test_otlp_export_reaches_local_receiver_with_parent_and_only_bounded_attributes() -> None:
    receiver = TraceReceiver()
    server = grpc.server(ThreadPoolExecutor(max_workers=2))
    trace_service_pb2_grpc.add_TraceServiceServicer_to_server(receiver, server)
    port = server.add_insecure_port("127.0.0.1:4317")
    assert port == 4317
    server.start()
    exporter = OtlpTraceExporter("http://127.0.0.1:4317", service_version="a" * 40)
    try:
        exporter.export(
            TraceSpan(
                trace_context=TraceContext(
                    trace_id="a" * 32,
                    span_id="b" * 16,
                    trace_flags=1,
                ),
                stage=StageName.fetch,
                outcome=StageOutcome.unavailable,
                latency_ms=37,
                attributes=StageAttributes(
                    outcome=StageOutcome.unavailable,
                    latency_ms=37,
                ),
            )
        )
        assert exporter.force_flush()
        assert receiver.received.wait(timeout=5)
        resource_spans = receiver.requests[0].resource_spans
        assert len(resource_spans) == 1
        resource_attrs = {
            item.key: item.value.string_value for item in resource_spans[0].resource.attributes
        }
        assert resource_attrs == {"service.name": "ai-soc", "service.version": "a" * 40}
        span = resource_spans[0].scope_spans[0].spans[0]
        assert span.trace_id.hex() == "a" * 32
        assert span.parent_span_id.hex() == "b" * 16
        attrs = {item.key: item.value for item in span.attributes}
        assert attrs["soc.stage"].string_value == "fetch"
        assert attrs["soc.outcome"].string_value == "unavailable"
        assert attrs["soc.latency_ms"].int_value == 37
        assert not ({"question_id", "environment_id", "owner_key"} & attrs.keys())
    finally:
        exporter.shutdown()
        server.stop(0).wait()


def test_otlp_exporter_rejects_nonlocal_and_noncanonical_destinations() -> None:
    for endpoint in (
        "https://collector.example.test:4317",
        "http://169.254.169.254:4317",
        "http://localhost:4318",
        "http://user@localhost:4317",
    ):
        with pytest.raises(ValueError, match="local ADOT"):
            OtlpTraceExporter(endpoint, service_version="a" * 40)


def test_compose_adot_receiver_is_digest_pinned_and_offline_fixture_only() -> None:
    from pathlib import Path

    import yaml

    config = yaml.safe_load(Path("dev/adot-collector-fixture.yaml").read_text())
    assert config["receivers"]["otlp"]["protocols"]["grpc"]["endpoint"] == "0.0.0.0:4317"
    assert config["service"]["pipelines"]["traces"]["exporters"] == ["debug"]
    compose = yaml.safe_load(Path("compose.yaml").read_text())
    collector = compose["services"]["adot-collector"]
    assert collector["image"].endswith(
        "@sha256:bb72328152c72fb9662056759b275f7cc85e115db12bbb114fbea9f68dc4816c"
    )
    assert not collector.get("ports")
    fixture_network = compose["networks"]["soc-fixture"]
    assert fixture_network["driver"] == "bridge"
    assert fixture_network["internal"] is False
    assert fixture_network["driver_opts"] == {
        "com.docker.network.bridge.enable_ip_masquerade": "false"
    }
