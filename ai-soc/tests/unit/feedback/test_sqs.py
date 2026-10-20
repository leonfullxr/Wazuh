from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import pytest

from ai_soc.application.errors import ServiceFailure
from ai_soc.contracts.models import (
    AdmissionGrant,
    CallKind,
    ExecutionContext,
    FeedbackEvent,
    TraceContext,
)
from ai_soc.feedback.sqs import SqsFeedbackSink

_FEEDBACK_CASE_FIXTURE = Path(__file__).parent / "data" / "feedback_receipt_cases.json"
_FEEDBACK_CASE_SHA256 = hashlib.sha256(_FEEDBACK_CASE_FIXTURE.read_bytes()).hexdigest()


class FakeLedger:
    def __init__(self) -> None:
        self.calls: list[CallKind] = []

    def claim(self, kind: CallKind) -> None:
        self.calls.append(kind)


class FakeCancel:
    def is_cancelled(self) -> bool:
        return False

    def raise_if_cancelled(self) -> None:
        return None

    async def wait(self) -> None:
        await asyncio.Event().wait()


class FakeSqs:
    def __init__(self, *, fail: bool = False) -> None:
        self.params: dict[str, object] = {}
        self.fail = fail
        self.calls = 0

    def send_message(self, **kwargs: object) -> dict[str, object]:
        self.calls += 1
        self.params = kwargs
        if self.fail:
            raise OSError("private queue detail")
        return {"MessageId": "msg-1"}


class BlockingSqs:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()
        self.calls = 0

    def send_message(self, **kwargs: object) -> dict[str, object]:
        self.calls += 1
        if self.calls == 1:
            self.started.set()
            self.release.wait()
        return {"MessageId": f"msg-{self.calls}"}


def event() -> FeedbackEvent:
    return FeedbackEvent(
        feedback_id=uuid4(),
        receipt_id=uuid4(),
        question_id=uuid4(),
        owner_key="a" * 64,
        environment_id="alpha",
        content_sha="b" * 40,
        kind="wrong",
        note_redacted=None,
        created_at=datetime(2026, 9, 30, tzinfo=UTC),
    )


def execution(ledger: FakeLedger) -> ExecutionContext:
    now = datetime(2026, 9, 30, tzinfo=UTC)
    return ExecutionContext(
        question_id=uuid4(),
        operation="feedback",
        owner_key="a" * 64,
        environment_id="alpha",
        deadline_at=now + timedelta(seconds=5),
        cancel=FakeCancel(),
        calls=ledger,
        admission=AdmissionGrant(
            holder_id=uuid4(),
            slot_ids=("SLOT#0000",),
            expires_at=now + timedelta(seconds=60),
            fence=1,
        ),
        trace_context=TraceContext(trace_id="a" * 32, span_id="b" * 16, trace_flags=1),
    )


@pytest.mark.asyncio
async def test_sqs_sink_claims_one_attempt_and_sends_only_redacted_event() -> None:
    client = FakeSqs()
    ledger = FakeLedger()
    sink = SqsFeedbackSink(client, "https://sqs.us-east-1.amazonaws.com/123/review")
    submitted = event()
    identifier = await sink.enqueue(submitted, execution=execution(ledger))
    assert identifier == submitted.feedback_id
    assert event_id(client.params) == submitted.feedback_id
    assert ledger.calls == [CallKind.feedback]
    assert set(client.params) == {"QueueUrl", "MessageBody"}


@pytest.mark.asyncio
@pytest.mark.acceptance()
@pytest.mark.case_id("B5-feedback.receipt-component")
@pytest.mark.variant("failure")
@pytest.mark.fixture_sha256(_FEEDBACK_CASE_SHA256)
async def test_queue_failure_is_sanitized() -> None:
    fixture = cast(
        dict[str, object],
        json.loads(_FEEDBACK_CASE_FIXTURE.read_text(encoding="utf-8")),
    )
    expected = cast(dict[str, object], fixture["failure"])
    client = FakeSqs(fail=True)
    ledger = FakeLedger()
    sink = SqsFeedbackSink(client, "https://sqs.us-east-1.amazonaws.com/123/review")
    with pytest.raises(ServiceFailure) as error:
        await sink.enqueue(event(), execution=execution(ledger))
    assert error.value.error.code == expected["queue_error"]
    assert ("private queue" in error.value.error.message) is expected["private_detail_exposed"]
    assert client.calls == expected["attempts"]
    assert ledger.calls == [CallKind.feedback]


@pytest.mark.asyncio
async def test_timed_out_physical_send_keeps_its_bounded_slot_until_thread_finishes() -> None:
    client = BlockingSqs()
    ledger = FakeLedger()
    sink = SqsFeedbackSink(
        client,
        "https://sqs.us-east-1.amazonaws.com/123/review",
        timeout_seconds=0.01,
        max_concurrency=1,
    )
    pending = asyncio.create_task(sink.enqueue(event(), execution=execution(ledger)))
    assert await asyncio.to_thread(client.started.wait, 1)
    with pytest.raises(ServiceFailure) as timeout:
        await pending
    assert timeout.value.error.code == "FEEDBACK_UNAVAILABLE"

    with pytest.raises(ServiceFailure) as capacity:
        await sink.enqueue(event(), execution=execution(ledger))
    assert capacity.value.error.code == "FEEDBACK_UNAVAILABLE"
    assert client.calls == 1

    client.release.set()
    await asyncio.wait_for(sink._slots.acquire(), timeout=1)
    sink._slots.release()
    assert client.calls == 1


def event_id(params: dict[str, object]) -> UUID:

    from ai_soc.contracts.models import FeedbackEvent

    return FeedbackEvent.model_validate_json(str(params["MessageBody"])).feedback_id
