from __future__ import annotations

import asyncio
import threading
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest

from ai_soc.application.service import ApplicationService
from ai_soc.contracts.models import (
    AnswerStatus,
    AskRequest,
    AuditEvent,
    Clarify,
    Planned,
    PlanProvenance,
    QuestionPlan,
    TopicPlan,
)
from ai_soc.state.admission import MemoryAdmissionStore
from ai_soc.telemetry.audit_delivery import AuditTelemetry, AuditUnavailable

NOW = datetime(2026, 9, 30, 12, tzinfo=UTC)
OWNER = "a" * 64


class _Clock:
    def now(self) -> datetime:
        return NOW

    def monotonic(self) -> float:
        return 0.0


def _document_service(monkeypatch: pytest.MonkeyPatch, *, authorized: bool = True):
    plan = QuestionPlan(
        question_id=uuid4(),
        environment_id="alpha",
        owner_key=OWNER,
        content_sha="b" * 40,
        policy_hash="c" * 63 + "1",
        language="en",
        timezone="UTC",
        anchor_at=NOW,
        topics=[
            TopicPlan(
                topic_id="ldap",
                ordinal=0,
                document=True,
                failure=False,
                judgment=False,
                fetches=[],
                cue_ids=[],
                alias_ids=[],
            )
        ],
        provenance=PlanProvenance(
            cue_pack_sha="d" * 64,
            normalized_question_hash="e" * 64,
            origin="new",
            matched_spans=[],
        ),
    )
    admissions = MemoryAdmissionStore()

    def authorize(*_args: object) -> object:
        if not authorized:
            raise RuntimeError("site is unauthorized")
        return SimpleNamespace(
            policy_hash=plan.policy_hash,
            config=SimpleNamespace(allowed_templates=()),
        )

    service = object.__new__(ApplicationService)
    service.clock = _Clock()
    service.catalog = SimpleNamespace(
        manifest=lambda: SimpleNamespace(content_sha=plan.content_sha),
        topic=lambda _topic_id: SimpleNamespace(public_document=None, playbook_id=None),
    )
    service.site_policy = SimpleNamespace(authorize=authorize)
    service.planner = SimpleNamespace(plan=lambda *_args, **_kwargs: Planned(plan=plan))
    service.admissions = admissions
    service.telemetry = None
    service._document_slots = asyncio.Semaphore(16)

    async def answer_without_backend(*_args: object, **_kwargs: object) -> str:
        return "document answer"

    monkeypatch.setattr(ApplicationService, "_answer_without_state", answer_without_backend)
    return service, admissions


@pytest.mark.asyncio
async def test_document_request_uses_ingress_without_backend_question_slots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, admissions = _document_service(monkeypatch)
    running_backend = await admissions.acquire(OWNER, "alpha", "ask", uuid4(), NOW)
    before_slots = dict(admissions._slots)
    before_ask_rate = admissions._rates[("owner", OWNER, "ask", int(NOW.timestamp()) // 60)]

    answer = await service.ask(
        AskRequest(question="Explain LDAP", environment_id="alpha"),
        SimpleNamespace(owner_key=OWNER),  # type: ignore[arg-type]
    )

    assert answer == "document answer"
    assert admissions._slots == before_slots
    assert admissions._rates[("owner", OWNER, "ask", int(NOW.timestamp()) // 60)] == before_ask_rate
    assert admissions._rates[("ingress", OWNER, "all", int(NOW.timestamp()) // 60)] == 1
    assert running_backend.slot_ids


@pytest.mark.asyncio
async def test_unauthorized_site_does_not_increment_admission_counters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, admissions = _document_service(monkeypatch, authorized=False)

    with pytest.raises(RuntimeError, match="site is unauthorized"):
        await service.ask(
            AskRequest(question="Explain LDAP", environment_id="alpha"),
            SimpleNamespace(owner_key=OWNER),  # type: ignore[arg-type]
        )

    assert admissions._rates == {}
    assert admissions._slots == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["planned", "clarification"])
async def test_document_slot_stays_held_until_timed_out_audit_send_finishes(
    monkeypatch: pytest.MonkeyPatch,
    path: str,
) -> None:
    entered_send = threading.Event()
    finish_send = threading.Event()

    class _BlockedSqs:
        def send_message(self, *, QueueUrl: str, MessageBody: str) -> dict[str, object]:
            entered_send.set()
            finish_send.wait(timeout=3)
            return {"MessageId": "fixture-ack"}

    class _Clock:
        def now(self) -> datetime:
            return NOW

    from ai_soc.telemetry import audit_delivery

    monkeypatch.setattr(audit_delivery, "AUDIT_SEND_TIMEOUT_SECONDS", 0.02)
    audit = AuditTelemetry(
        _BlockedSqs(), queue_url="https://sqs.example.test/audit", clock=_Clock()
    )
    event = AuditEvent(
        event_id=uuid4(),
        question_id=uuid4(),
        trace_id="1" * 32,
        owner_key=OWNER,
        environment_id="alpha",
        authenticated_issuer="https://id.example.test/",
        auth_edge="fixture",
        service_sha="2" * 40,
        image_digest="sha256:" + "3" * 64,
        content_sha="4" * 40,
        pack_sha256="5" * 64,
        policy_hash="6" * 64,
        cue_ids=[],
        topic_ids=[],
        outcome="attempted",
        created_at=NOW,
    )
    execution = SimpleNamespace(
        cancel=SimpleNamespace(raise_if_cancelled=lambda: None),
        calls=SimpleNamespace(claim=lambda _kind: None),
    )
    service = object.__new__(ApplicationService)
    service._document_slots = asyncio.Semaphore(1)
    impl_calls = 0

    async def emit_audit(*_args: object, **_kwargs: object) -> str:
        nonlocal impl_calls
        impl_calls += 1
        await audit.event(event, execution=execution)  # type: ignore[arg-type]
        return "complete"

    impl_method = (
        "_unplanned_answer_impl" if path == "clarification" else "_answer_without_state_impl"
    )
    monkeypatch.setattr(ApplicationService, impl_method, emit_audit)
    args = (
        AskRequest(question="explain LDAP", environment_id="alpha"),
        SimpleNamespace(owner_key=OWNER),
        None,
        "6" * 64,
        None,
        [],
        [],
        None,
    )
    kwargs = {"trace_context": None}

    async def invoke() -> str:
        if path == "clarification":
            return await service._unplanned_answer(
                args[0],
                args[1],
                args[3],
                args[4],
                status=AnswerStatus.clarify,
                message=None,
                clarify=Clarify(
                    kind="missing_subject", question="Which subject?", slots=["subject"]
                ),
                topic_ids=[],
                cue_ids=[],
                trace_context=None,  # type: ignore[arg-type]
            )  # type: ignore[return-value]
        return await service._answer_without_state(*args, **kwargs)  # type: ignore[arg-type]

    with pytest.raises(AuditUnavailable):
        await invoke()
    assert await asyncio.to_thread(entered_send.wait, 1)

    waiting_request = asyncio.create_task(invoke())
    await asyncio.sleep(0.05)
    try:
        slot_remained_occupied = not waiting_request.done() and impl_calls == 1
    finally:
        finish_send.set()
    result = await asyncio.gather(waiting_request, return_exceptions=True)
    assert slot_remained_occupied
    assert result == ["complete"]
