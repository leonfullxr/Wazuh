"""Durable SQS audit acknowledgment and idempotent S3 archive consumer."""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import partial
from typing import Protocol, cast
from uuid import UUID

from pydantic import ValidationError

from ai_soc.contracts.models import AuditAck, AuditEvent, CallKind, ExecutionContext, FeedbackEvent
from ai_soc.contracts.ports import Clock

from .serialization import audit_json
from .worker_capacity import retain_document_slot_until

AUDIT_SEND_TIMEOUT_SECONDS = 5.0


class SqsClient(Protocol):
    def send_message(self, *, QueueUrl: str, MessageBody: str) -> Mapping[str, object]: ...

    def receive_message(
        self,
        *,
        QueueUrl: str,
        MaxNumberOfMessages: int,
        WaitTimeSeconds: int,
        VisibilityTimeout: int,
    ) -> Mapping[str, object]: ...

    def delete_message(self, *, QueueUrl: str, ReceiptHandle: str) -> object: ...


class S3Client(Protocol):
    def put_object(
        self, *, Bucket: str, Key: str, Body: bytes, ContentType: str, IfNoneMatch: str
    ) -> Mapping[str, object]: ...


class AuditUnavailable(RuntimeError):
    """Queue acknowledgment failed; caller must fail closed."""


@dataclass(frozen=True, slots=True)
class ArchiveBatchResult:
    received: int
    archived: int
    failed: int


class AuditTelemetry:
    def __init__(self, client: SqsClient, *, queue_url: str, clock: Clock) -> None:
        if not queue_url.startswith("https://"):
            raise ValueError("audit queue URL must be HTTPS")
        self._client = client
        self._queue_url = queue_url
        self._clock = clock

    async def event(self, event: AuditEvent, *, execution: ExecutionContext) -> AuditAck:
        execution.cancel.raise_if_cancelled()
        execution.calls.claim(CallKind.audit)
        try:
            worker = asyncio.get_running_loop().run_in_executor(
                None,
                partial(
                    self._client.send_message,
                    QueueUrl=self._queue_url,
                    MessageBody=audit_json(event),
                ),
            )
            retain_document_slot_until(cast(asyncio.Future[object], worker))
            response = await asyncio.wait_for(
                asyncio.shield(worker),
                timeout=AUDIT_SEND_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            raise AuditUnavailable("durable audit queue did not acknowledge the event") from exc
        delivery_id = response.get("MessageId")
        if not isinstance(delivery_id, str) or not delivery_id:
            raise AuditUnavailable("durable audit queue returned no delivery identifier")
        now = self._clock.now()
        return AuditAck(event_id=event.event_id, delivery_id=delivery_id, accepted_at=now)


class AuditArchiveConsumer:
    """Archive before deleting; S3 conditional write makes retries idempotent."""

    def __init__(
        self,
        *,
        sqs: SqsClient,
        s3: S3Client,
        queue_url: str,
        bucket: str,
    ) -> None:
        if not queue_url.startswith("https://") or not bucket:
            raise ValueError("archive consumer requires queue URL and bucket")
        self._sqs = sqs
        self._s3 = s3
        self._queue_url = queue_url
        self._bucket = bucket

    def handle(self, *, body: str, receipt_handle: str) -> UUID:
        try:
            raw = json.loads(body)
            if not isinstance(raw, dict):
                raise ValueError("audit event must be a JSON object")
            event = AuditEvent.model_validate_json(body)
            encoded = audit_json(event).encode("utf-8")
        except (json.JSONDecodeError, ValidationError, TypeError, ValueError) as exc:
            raise ValueError("invalid audit queue message") from exc

        key = f"events/{str(event.event_id)[:2]}/{event.event_id}.json"
        try:
            self._s3.put_object(
                Bucket=self._bucket,
                Key=key,
                Body=encoded,
                ContentType="application/json",
                IfNoneMatch="*",
            )
        except Exception as exc:
            if _is_duplicate_object(exc):
                pass
            else:
                raise
        self._sqs.delete_message(QueueUrl=self._queue_url, ReceiptHandle=receipt_handle)
        return event.event_id

    def run_once(self) -> ArchiveBatchResult:
        """Receive a bounded batch; failed records remain visible for retry/DLQ."""
        response = self._sqs.receive_message(
            QueueUrl=self._queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=1,
            VisibilityTimeout=30,
        )
        raw_messages = response.get("Messages", [])
        if not isinstance(raw_messages, list):
            raise RuntimeError("SQS returned an invalid message batch")
        messages = cast(list[object], raw_messages)
        archived = 0
        failed = 0
        for raw in messages:
            if not isinstance(raw, Mapping):
                failed += 1
                continue
            message = cast(Mapping[str, object], raw)
            body, receipt = message.get("Body"), message.get("ReceiptHandle")
            if not isinstance(body, str) or not isinstance(receipt, str) or not receipt:
                failed += 1
                continue
            try:
                self.handle(body=body, receipt_handle=receipt)
            except Exception:
                failed += 1
            else:
                archived += 1
        return ArchiveBatchResult(len(messages), archived, failed)


class FeedbackArchiveConsumer:
    """Archive redacted feedback before acknowledging its retained queue message."""

    def __init__(
        self,
        *,
        sqs: SqsClient,
        s3: S3Client,
        queue_url: str,
        bucket: str,
    ) -> None:
        if not queue_url.startswith("https://") or not bucket:
            raise ValueError("feedback archive consumer requires queue URL and bucket")
        self._sqs = sqs
        self._s3 = s3
        self._queue_url = queue_url
        self._bucket = bucket

    def handle(self, *, body: str, receipt_handle: str) -> UUID:
        try:
            event = FeedbackEvent.model_validate_json(body)
            encoded = json.dumps(
                event.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        except (json.JSONDecodeError, ValidationError, TypeError, ValueError) as exc:
            raise ValueError("invalid feedback queue message") from exc

        feedback_id = event.feedback_id
        key = f"feedback/{str(feedback_id)[:2]}/{feedback_id}.json"
        try:
            self._s3.put_object(
                Bucket=self._bucket,
                Key=key,
                Body=encoded,
                ContentType="application/json",
                IfNoneMatch="*",
            )
        except Exception as exc:
            if not _is_duplicate_object(exc):
                raise
        self._sqs.delete_message(QueueUrl=self._queue_url, ReceiptHandle=receipt_handle)
        return feedback_id

    def run_once(self) -> ArchiveBatchResult:
        response = self._sqs.receive_message(
            QueueUrl=self._queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=1,
            VisibilityTimeout=30,
        )
        raw_messages = response.get("Messages", [])
        if not isinstance(raw_messages, list):
            raise RuntimeError("SQS returned an invalid feedback batch")
        messages = cast(list[object], raw_messages)
        archived = 0
        failed = 0
        for raw in messages:
            if not isinstance(raw, Mapping):
                failed += 1
                continue
            message = cast(Mapping[str, object], raw)
            body, receipt = message.get("Body"), message.get("ReceiptHandle")
            if not isinstance(body, str) or not isinstance(receipt, str) or not receipt:
                failed += 1
                continue
            try:
                self.handle(body=body, receipt_handle=receipt)
            except Exception:
                failed += 1
            else:
                archived += 1
        return ArchiveBatchResult(len(messages), archived, failed)


def _is_duplicate_object(exc: Exception) -> bool:
    response = getattr(exc, "response", None)
    if not isinstance(response, Mapping):
        return False
    response_map = cast(Mapping[str, object], response)
    error = response_map.get("Error")
    if not isinstance(error, Mapping):
        return False
    error_map = cast(Mapping[str, object], error)
    code = error_map.get("Code")
    # Only a 412 proves that the create-only write found an existing object.
    # A 409 is a transient concurrent-write conflict and must be retried.
    return code == "PreconditionFailed"


def main() -> int:
    """One bounded poll for EventBridge/ECS scheduled task invocations."""
    import boto3

    queue_url = os.environ.get("AUDIT_QUEUE_URL", "")
    feedback_queue_url = os.environ.get("FEEDBACK_QUEUE_URL", "")
    bucket = os.environ.get("AUDIT_ARCHIVE_BUCKET", "")
    region = os.environ.get("AWS_REGION", "")
    if (
        not queue_url.startswith("https://")
        or not feedback_queue_url.startswith("https://")
        or not bucket
        or not region
    ):
        raise SystemExit(
            "AUDIT_QUEUE_URL, FEEDBACK_QUEUE_URL, AUDIT_ARCHIVE_BUCKET, and AWS_REGION are required"
        )
    create_client = cast(Callable[..., object], vars(boto3).get("client"))
    consumer = AuditArchiveConsumer(
        # boto3 exposes dynamically generated service clients without precise
        # static types. Keep the cast at this SDK boundary; botocore Stubber
        # integration tests assert the real calls and parameter shapes.
        sqs=cast(SqsClient, create_client("sqs", region_name=region)),
        s3=cast(S3Client, create_client("s3", region_name=region)),
        queue_url=queue_url,
        bucket=bucket,
    )
    result = consumer.run_once()
    feedback_consumer = FeedbackArchiveConsumer(
        sqs=cast(SqsClient, create_client("sqs", region_name=region)),
        s3=cast(S3Client, create_client("s3", region_name=region)),
        queue_url=feedback_queue_url,
        bucket=bucket,
    )
    feedback_result = feedback_consumer.run_once()
    # Emit fixed fields only; never log a message body, event ID, or provider error.
    print(
        json.dumps(
            {
                "audit": {
                    "received": result.received,
                    "archived": result.archived,
                    "failed": result.failed,
                },
                "feedback": {
                    "received": feedback_result.received,
                    "archived": feedback_result.archived,
                    "failed": feedback_result.failed,
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 1 if result.failed or feedback_result.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
