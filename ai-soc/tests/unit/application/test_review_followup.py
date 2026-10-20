from __future__ import annotations

import importlib.util
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import cast
from uuid import uuid4

import pytest

from ai_soc.application.answers import audit_fetch_record
from ai_soc.application.service import ApplicationService
from ai_soc.application.topic_evidence import evidence_pack
from ai_soc.contracts.canonical import canonical_bytes
from ai_soc.contracts.models import (
    AnswerStatus,
    AskRequest,
    CheckOutcome,
    CheckResult,
    Effort,
    FetchSpec,
    FetchState,
    FetchStep,
    LocaleText,
    PlanProvenance,
    PlaybookDefinition,
    PlaybookRun,
    QuestionPlan,
    ResolvedWindow,
    TemplateId,
    TopicPlan,
)
from ai_soc.contracts.ports import FetchExecutor, JudgmentProvider, PlaybookExecutor
from ai_soc.judgment.engine import JudgmentEngine
from ai_soc.state.memory import MemoryState

_fc = importlib.util.module_from_spec(
    importlib.util.spec_from_file_location(
        "_fenced_completion_fixture",
        __import__("pathlib").Path(__file__).with_name("test_fenced_completion.py"),
    )
)
assert _fc.__spec__ is not None and _fc.__spec__.loader is not None
_fc.__spec__.loader.exec_module(_fc)
NOW = _fc.NOW
_plan = _fc._plan
_mixed_fetch_result = _fc._mixed_fetch_result


class _Clock:
    def now(self) -> datetime:
        return datetime(2026, 10, 6, 12, tzinfo=UTC)


def test_m1_pack_keeps_playbook_check_items_without_duplicating_fetch_evidence() -> None:
    policy_hash = "c" * 63 + "1"
    plan = _plan("model", owner="a" * 64, question_id=uuid4(), policy_hash=policy_hash)
    topic = plan.topics[0]
    table = _mixed_fetch_result(
        topic.topic_id,
        FetchState.rows,
        question_id=plan.question_id,
        policy_hash=policy_hash,
    )
    row_item = table.items[0]
    check_evidence_id = f"ev1_{sha256(b'playbook-check').hexdigest()}"
    check_item = row_item.model_copy(
        update={
            "evidence_id": check_evidence_id,
            "kind": "check",
            "check_id": "pb-check",
            "fetch_id": None,
        }
    )
    checks = [
        CheckResult(
            check_id="pb-check",
            topic_id=topic.topic_id,
            label="check",
            outcome=CheckOutcome.passed,
            evidence_ids=[check_evidence_id],
            message="ok",
        )
    ]
    pack = evidence_pack(plan, topic, [table], checks, [row_item, check_item])
    assert {item.evidence_id for item in pack.items} == {row_item.evidence_id, check_evidence_id}
    assert pack.checks[0].outcome == CheckOutcome.passed


def test_m5_playbook_fetch_audit_hashes_full_fetch_spec() -> None:
    from ai_soc.contracts.models import FetchStep, LocaleText, PlaybookDefinition, TopicDefinition

    label = LocaleText(en="alerts", es="alerts")

    class _Catalog:
        def topic(self, topic_id: str) -> TopicDefinition:
            return TopicDefinition(
                schema_version="1",
                topic_id=topic_id,
                name={"en": "ldap", "es": "ldap"},
                aliases=[],
                public_document=None,
                playbook_id="pb-1",
                finding_template_ids=[],
                fetch_bindings=[],
            )

        def playbook(self, playbook_id: str) -> PlaybookDefinition:
            return PlaybookDefinition(
                playbook_id=playbook_id,
                topic_id="ldap",
                title=label,
                internal_context="fixture",
                steps=[
                    FetchStep(
                        kind="fetch",
                        step_id="step-1",
                        label=label,
                        fetch_id="pb-fetch",
                        template_id=TemplateId.alerts_rows_v1,
                        window_default={"unit": "hours", "amount": 1},
                        filters=[],
                    )
                ],
            )

    service = ApplicationService(
        clock=_Clock(),
        catalog=_Catalog(),
        planner=object(),  # type: ignore[arg-type]
        site_policy=object(),  # type: ignore[arg-type]
        plans=object(),  # type: ignore[arg-type]
        admissions=object(),  # type: ignore[arg-type]
        question_admission=object(),  # type: ignore[arg-type]
        leases=object(),  # type: ignore[arg-type]
        budgets=object(),  # type: ignore[arg-type]
        completions=object(),  # type: ignore[arg-type]
        fetches=object(),  # type: ignore[arg-type]
        playbooks=object(),  # type: ignore[arg-type]
        judgment_engine=object(),  # type: ignore[arg-type]
        judgment_provider=object(),  # type: ignore[arg-type]
        finding_validator=object(),  # type: ignore[arg-type]
        telemetry=object(),  # type: ignore[arg-type]
        feedback_sink=object(),  # type: ignore[arg-type]
        feedback_store=MemoryState(),
        receipts=object(),  # type: ignore[arg-type]
        runtime=object(),  # type: ignore[arg-type]
        models=(),
    )
    window = ResolvedWindow(
        start=NOW - timedelta(hours=1),
        end=NOW,
        semantics="absolute",
        source_text="fixture",
        timezone="UTC",
        anchor_at=NOW,
    )
    spec = FetchSpec(
        fetch_id="pb-fetch",
        template_id=TemplateId.alerts_rows_v1,
        window=window,
        filters=[],
    )
    result = _mixed_fetch_result(
        "ldap", FetchState.rows, question_id=uuid4(), policy_hash="c" * 63 + "1"
    ).model_copy(update={"fetch_id": "pb-fetch", "window": window})

    planned = audit_fetch_record(service.catalog, result, spec)
    playbook = audit_fetch_record(service.catalog, result, None)
    assert planned is not None and playbook is not None
    digest = sha256(canonical_bytes(spec)).hexdigest()
    assert planned.query_sha256 == digest
    assert playbook.query_sha256 == digest


@pytest.mark.asyncio
async def test_m1_ask_judgment_keeps_playbook_check_items_without_duplicate_fetch_rows() -> None:
    owner = "a" * 64
    runtime = _fc._runtime(_fc._Clock())
    _fc._catalog_for_plan(runtime.application, with_prompt=True)
    site = runtime.application.site_policy.authorize(_fc._principal(owner), "alpha")
    policy_hash = site.policy_hash
    question_id = uuid4()
    window = ResolvedWindow(
        start=NOW - timedelta(hours=1),
        end=NOW,
        semantics="absolute",
        source_text="fixture",
        timezone="UTC",
        anchor_at=NOW,
    )
    planned_fetch = FetchSpec(
        fetch_id="alerts",
        template_id=TemplateId.alerts_rows_v1,
        window=window,
        filters=[],
    )
    topic = TopicPlan(
        topic_id="ldap",
        ordinal=0,
        document=False,
        failure=True,
        judgment=True,
        fetches=[planned_fetch],
        playbook_id="pb-1",
        cue_ids=[],
        alias_ids=[],
    )
    plan = QuestionPlan(
        question_id=question_id,
        environment_id="alpha",
        owner_key=owner,
        content_sha=_fc._provenance().content_sha,
        policy_hash=policy_hash,
        language="en",
        timezone="UTC",
        anchor_at=NOW,
        topics=[topic],
        model_id="fixture-model",
        effort=Effort.low,
        provenance=PlanProvenance(
            cue_pack_sha="f" * 64,
            normalized_question_hash="1" * 64,
            origin="new",
            matched_spans=[],
        ),
    )
    table = _mixed_fetch_result(
        "ldap", FetchState.rows, question_id=question_id, policy_hash=policy_hash
    )
    check_evidence_id = f"ev1_{sha256(b'playbook-check-ask').hexdigest()}"
    check_item = table.items[0].model_copy(
        update={
            "evidence_id": check_evidence_id,
            "kind": "check",
            "check_id": "pb-check",
            "fetch_id": None,
        }
    )
    check = CheckResult(
        check_id="pb-check",
        topic_id="ldap",
        label="check",
        outcome=CheckOutcome.passed,
        evidence_ids=[check_evidence_id],
        message="ok",
    )

    class _Playbooks:
        async def run(self, *_args: object, **_kwargs: object) -> PlaybookRun:
            return PlaybookRun(
                fetches=[table],
                checks=[check],
                items=[*table.items, check_item],
            )

    provider = _fc._FixedCountProvider(8)
    runtime.application.playbooks = cast(PlaybookExecutor, _Playbooks())
    runtime.application.fetches = cast(FetchExecutor, _fc._MixedFetches({"ldap": table}))
    runtime.application.planner = _fc._FixedPlanner(plan)
    runtime.application.judgment_provider = cast(JudgmentProvider, provider)
    engine = runtime.application.judgment_engine
    pinned = PlaybookDefinition(
        playbook_id="pb-1",
        topic_id="ldap",
        title=LocaleText(en="alerts", es="alerts"),
        internal_context="fixture",
        steps=[
            FetchStep(
                kind="fetch",
                step_id="step-1",
                label=LocaleText(en="alerts", es="alerts"),
                fetch_id="alerts",
                template_id=TemplateId.alerts_rows_v1,
                window_default={"unit": "hours", "amount": 1},
                filters=[],
            )
        ],
    )
    runtime.application.judgment_engine = JudgmentEngine(
        standing_rules=engine._standing_rules,
        guardrail_identifier=engine._guardrail_identifier,
        guardrail_version=engine._guardrail_version,
        playbook={"pb-1": pinned}.get,
    )

    answer = await runtime.application.ask(
        AskRequest(question="investigate ldap failure", environment_id="alpha"),
        _fc._principal(owner),
    )

    assert answer.status == AnswerStatus.answered
    assert len(provider.converse_requests) == 1
    pack_ids = {item.evidence_id for item in provider.converse_requests[0].evidence.items}
    assert check_evidence_id in pack_ids
    assert table.items[0].evidence_id in pack_ids
    assert len(pack_ids) == 2
