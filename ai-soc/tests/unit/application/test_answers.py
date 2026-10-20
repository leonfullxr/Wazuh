from __future__ import annotations

import importlib.util
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast
from uuid import uuid4

import pytest

from ai_soc.application.answers import AnswerAssembly
from ai_soc.application.errors import ServiceFailure
from ai_soc.contracts.models import (
    AnswerStatus,
    AskRequest,
    BuildProvenance,
    ErrorCode,
    FollowupRecord,
    Planned,
)
from ai_soc.contracts.ports import ContentCatalog, Planner
from ai_soc.feedback.receipts import FeedbackReceiptCodec
from ai_soc.planning.followups import InvalidContinuation
from ai_soc.planning.parser import DeterministicPlanner

_support_spec = importlib.util.spec_from_file_location(
    "_answers_planning_support", Path(__file__).parent.parent / "planning/support.py"
)
assert _support_spec is not None and _support_spec.loader is not None
_support = importlib.util.module_from_spec(_support_spec)
_support_spec.loader.exec_module(_support)
FixedClock = _support.FixedClock
make_catalog = _support.make_catalog
make_principal = _support.make_principal


class _Receipts:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def issue(self, **kwargs: object) -> str:
        self.calls.append(kwargs)
        return "receipt-token"


def _manifest() -> BuildProvenance:
    return BuildProvenance(
        service_sha="a" * 40,
        content_repository="https://example.test/content",
        content_sha="b" * 40,
        pack_sha256="c" * 64,
        image_digest="sha256:" + "d" * 64,
        docs_origin="https://docs.example.test",
        docs_manifest_sha256="e" * 64,
    )


def _assembly(receipts: _Receipts) -> AnswerAssembly:
    return AnswerAssembly(
        catalog=cast(ContentCatalog, object()),
        receipts=cast(FeedbackReceiptCodec, receipts),
        clock=FixedClock(),
        guardrail_identifier="",
        guardrail_version="",
    )


def _answer(assembly: AnswerAssembly):
    return assembly.answer(
        question_id=uuid4(),
        environment_id="alpha",
        language="en",
        owner_key="a" * 64,
        content_sha="b" * 40,
        cue_ids=["cue-one"],
        topic_ids=["ldap"],
        status=AnswerStatus.partial,
        manifest=_manifest(),
        trace_id="1" * 32,
    )


def test_answer_issues_receipt_with_status_and_matching_identifiers() -> None:
    receipts = _Receipts()
    answer = _answer(_assembly(receipts))

    assert answer.feedback_receipt == "receipt-token"
    assert receipts.calls == [
        {
            "question_id": answer.question_id,
            "owner_key": "a" * 64,
            "environment_id": "alpha",
            "content_sha": "b" * 40,
            "cue_ids": ["cue-one"],
            "topic_ids": ["ldap"],
            "outcome_code": AnswerStatus.partial,
            "now": FixedClock().now(),
        }
    ]


def test_unplanned_audit_event_has_empty_plan_fields_and_answer_identifiers() -> None:
    assembly = _assembly(_Receipts())
    principal = make_principal()
    answer = _answer(assembly)

    event = assembly.audit_event(
        answer,
        principal,
        _manifest(),
        "f" * 63 + "1",
        "attempted",
        plan=None,
        cue_ids=["cue-one"],
        topic_ids=["ldap"],
    )

    assert event.fetches == []
    assert event.removed_findings == []
    assert event.usage_by_topic == []
    assert event.model_id is None
    assert event.effort is None
    assert event.answer_status is None
    assert event.question_id == answer.question_id
    assert event.trace_id == answer.trace_id
    assert event.environment_id == answer.environment_id


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [("attempted", None), ("completed", AnswerStatus.partial)],
)
def test_audit_answer_status_is_present_only_for_completed_outcomes(
    outcome: str, expected: AnswerStatus | None
) -> None:
    assembly = _assembly(_Receipts())
    answer = _answer(assembly)
    event = assembly.audit_event(
        answer,
        make_principal(),
        _manifest(),
        "f" * 63 + "1",
        cast(Literal["attempted", "completed", "cancelled"], outcome),
        plan=None,
        cue_ids=[],
        topic_ids=[],
        completion_id=uuid4() if outcome == "completed" else None,
    )

    assert event.answer_status == expected


def test_parser_raises_invalid_continuation_for_disallowed_selection() -> None:
    principal = make_principal()
    catalog = make_catalog(("ldap", "dns"))
    planner = DeterministicPlanner(catalog)
    planned = planner.plan(
        AskRequest(question="LDAP is failing", environment_id="alpha", timezone="UTC"),
        principal,
        None,
        policy_hash="f" * 63 + "1",
        clock=FixedClock(),
    )
    assert isinstance(planned, Planned)
    previous = FollowupRecord(
        followup_id=uuid4(),
        owner_key=principal.owner_key,
        environment_id="alpha",
        revision=1,
        plan=planned.plan,
        answered_topic_ids=[],
        leftout_topic_ids=[],
        leftout_stages=[],
        created_at=datetime(2026, 9, 30, 12, tzinfo=UTC),
        expires_at=datetime(2026, 10, 1, 12, tzinfo=UTC),
    )
    request = AskRequest(
        question="continue the left-out judgments",
        environment_id="alpha",
        followup_id=previous.followup_id,
        followup_revision=previous.revision,
        continue_topic_ids=["ldap"],
        timezone="UTC",
    )

    with pytest.raises(InvalidContinuation):
        planner.plan(
            request,
            principal,
            previous,
            policy_hash="f" * 63 + "1",
            clock=FixedClock(),
        )


@pytest.mark.asyncio
async def test_service_translates_invalid_continuation_with_public_error() -> None:
    _fixture_spec = importlib.util.spec_from_file_location(
        "_answers_fenced_completion",
        Path(__file__).with_name("test_fenced_completion.py"),
    )
    assert _fixture_spec is not None and _fixture_spec.loader is not None
    fixture = importlib.util.module_from_spec(_fixture_spec)
    _fixture_spec.loader.exec_module(fixture)

    class _Planner:
        def plan(self, *args: object, **kwargs: object) -> object:
            raise InvalidContinuation

    service = fixture._runtime().application
    service.planner = cast(Planner, _Planner())

    with pytest.raises(ServiceFailure) as failure:
        await service.ask(
            AskRequest(question="LDAP is failing", environment_id="alpha"),
            fixture._principal("a" * 64),
        )

    assert failure.value.error.code == ErrorCode.INVALID_CONTINUATION
    assert failure.value.error.message == "The continuation selection is invalid."
