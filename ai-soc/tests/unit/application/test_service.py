from __future__ import annotations

import asyncio
import json
from pathlib import Path
from uuid import UUID

import pytest

from ai_soc.application.answers import audit_removed
from ai_soc.application.service import (
    derive_answer_status,
    order_topic_answers,
)
from ai_soc.contracts.models import (
    Answer,
    AnswerStatus,
    BuildProvenance,
    JudgmentResult,
    JudgmentState,
    LeftOut,
    LeftOutReason,
    RemovedFinding,
    RemovedReason,
    TopicAnswer,
)

_TOPIC_ORDER_FIXTURE = Path(__file__).parent / "data" / "topic_order_cases.json"
_TOPIC_ORDER_CASES = json.loads(_TOPIC_ORDER_FIXTURE.read_text(encoding="utf-8"))["cases"]
_TOPIC_ORDER_FIXTURE_SHA256 = "5976eb5f8b84fe347349e9e206577aa0ef50be5c93b46f158ea0639b61866a95"


def test_audit_removed_findings_preserve_only_typed_hash_provenance() -> None:
    provenance = BuildProvenance(
        service_sha="a" * 40,
        content_repository="https://example.test/content",
        content_sha="b" * 40,
        pack_sha256="c" * 64,
        image_digest="sha256:" + "d" * 64,
        docs_origin="https://docs.example.test",
        docs_manifest_sha256="e" * 64,
    )
    removed = RemovedFinding(
        finding_id="finding-1",
        reason=RemovedReason.unknown_evidence,
        candidate_sha256="f" * 64,
    )
    answer = Answer(
        question_id=UUID("11111111-1111-4111-8111-111111111111"),
        environment_id="alpha",
        language="en",
        status=AnswerStatus.partial,
        blocks=[
            TopicAnswer(
                topic_id="ldap",
                ordinal=0,
                document=None,
                missing=[],
                tables=[],
                checks=[],
                judgment=JudgmentResult(
                    state=JudgmentState.all_removed,
                    model_id="fixture-model",
                    sentences=[],
                    removed=[removed],
                ),
            )
        ],
        message=None,
        clarify=None,
        followup_id=None,
        followup_revision=None,
        left_out=[
            LeftOut(
                topic_id="ldap",
                stage="judgment",
                reason=LeftOutReason.all_removed,
                retryable=True,
            )
        ],
        provenance=provenance,
        trace_id="1" * 32,
        feedback_receipt="opaque-receipt",
    )

    audited = audit_removed(answer)

    assert len(audited) == 1
    assert audited[0].topic_id == "ldap"
    assert audited[0].finding_id == "finding-1"
    assert audited[0].reason == "unknown_evidence"
    assert audited[0].candidate_sha256 == "f" * 64


@pytest.mark.parametrize(
    ("judgment_state", "left_out", "expected"),
    [
        (JudgmentState.no_findings, [], AnswerStatus.answered),
        (JudgmentState.model_unavailable, [], AnswerStatus.partial),
        (
            JudgmentState.no_findings,
            [
                LeftOut(
                    topic_id="ldap",
                    stage="judgment",
                    reason=LeftOutReason.capacity_limited,
                    retryable=True,
                )
            ],
            AnswerStatus.partial,
        ),
    ],
)
def test_answer_status_handles_pydantic_enum_values(
    judgment_state: JudgmentState,
    left_out: list[LeftOut],
    expected: AnswerStatus,
) -> None:
    block = TopicAnswer(
        topic_id="ldap",
        ordinal=0,
        document=None,
        missing=[],
        tables=[],
        checks=[],
        judgment=JudgmentResult(state=judgment_state, sentences=[], removed=[]),
    )

    assert derive_answer_status([block], left_out) == expected


@pytest.mark.parametrize(
    "variant",
    [
        pytest.param(
            variant,
            marks=[
                pytest.mark.acceptance("G030"),
                pytest.mark.case_id("QA-016.resolution"),
                pytest.mark.variant(variant),
                pytest.mark.fixture_sha256(_TOPIC_ORDER_FIXTURE_SHA256),
            ],
        )
        for variant in ("positive", "negative", "boundary", "failure")
    ],
)
@pytest.mark.asyncio
async def test_topic_answers_preserve_plan_order_after_out_of_order_completion(
    variant: str,
) -> None:
    case = _TOPIC_ORDER_CASES[variant]

    async def completed_answer(item: dict[str, object]) -> TopicAnswer:
        await asyncio.sleep(item["completion_delay_ms"] / 1000)
        return TopicAnswer(
            topic_id=item["topic_id"],
            ordinal=item["ordinal"],
            document=None,
            missing=[],
            tables=[],
            checks=[],
            judgment=JudgmentResult(
                state=JudgmentState(item["judgment_state"]), sentences=[], removed=[]
            ),
        )

    tasks = [asyncio.create_task(completed_answer(item)) for item in case["topics"]]
    completed = [await task for task in asyncio.as_completed(tasks)]

    assert [block.topic_id for block in completed] == case["completion_order"]
    ordered = order_topic_answers(completed)

    assert [block.topic_id for block in ordered] == case["expected_order"]
    assert derive_answer_status(ordered, []) == AnswerStatus(case["expected_status"])
