from __future__ import annotations

import hashlib
import importlib.util
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, NotRequired, TypedDict, cast
from uuid import UUID

import pytest
from pydantic import TypeAdapter

from ai_soc.content.catalog import ContentCatalog
from ai_soc.contracts.canonical import canonical_bytes
from ai_soc.contracts.models import (
    AnswerStatus,
    AskRequest,
    AuthorizedSite,
    DocumentDefinition,
    Effort,
    EmbeddingManifest,
    ExecutionContext,
    FetchResult,
    FetchSpec,
    FetchState,
    FetchStep,
    FieldId,
    FindingTemplate,
    JudgmentRequest,
    JudgmentState,
    LocaleText,
    Planned,
    PlaybookDefinition,
    PlaybookRun,
    RawJudgment,
    TemplateId,
    TopicPlan,
    TopicPromptPack,
    VerifiedPrincipal,
)
from ai_soc.contracts.ports import PlaybookExecutor
from ai_soc.judgment.embeddings import AdmittedSemanticSuggester
from ai_soc.judgment.engine import JudgmentEngine
from ai_soc.planning.parser import DeterministicPlanner
from ai_soc.planning.semantic import (
    EmbeddingSemanticSuggester,
    SemanticIndex,
    SemanticProviderBinding,
)
from ai_soc.state.stage_admission import MemoryEmbeddingAdmissionStore

_unit_support_path = (
    Path(__file__).resolve().parents[2] / "unit/application/test_fenced_completion.py"
)
_unit_support_spec = importlib.util.spec_from_file_location(
    "_b2_application_runtime_support", _unit_support_path
)
if _unit_support_spec is None or _unit_support_spec.loader is None:
    raise RuntimeError("application runtime fixture could not be loaded")
_unit_support = importlib.util.module_from_spec(_unit_support_spec)
_unit_support_spec.loader.exec_module(_unit_support)
_mixed_fetch_result = _unit_support._mixed_fetch_result
_principal = _unit_support._principal
_runtime = _unit_support._runtime

_planning_support_path = Path(__file__).resolve().parents[2] / "unit/planning/support.py"
_planning_support_spec = importlib.util.spec_from_file_location(
    "_b2_planning_support", _planning_support_path
)
if _planning_support_spec is None or _planning_support_spec.loader is None:
    raise RuntimeError("planning fixture could not be loaded")
_planning_support = importlib.util.module_from_spec(_planning_support_spec)
_planning_support_spec.loader.exec_module(_planning_support)
make_catalog = _planning_support.make_catalog
FIXTURE = Path(__file__).parent / "data/planning_runtime_cases.json"


class _LocalizedQuestions(TypedDict):
    en: str
    es: str


class _G020Expected(TypedDict):
    topic_ids: list[str]
    fetch_topics: list[str]
    template_ids: list[str]
    window_start: NotRequired[str]
    window_end: NotRequired[str]
    languages: list[Literal["en", "es"]]
    statuses: list[Literal["answered", "refused"]]
    playbook_topics: NotRequired[list[str]]


class _G020Case(TypedDict):
    variant: Literal["positive", "negative", "boundary", "failure"]
    questions: _LocalizedQuestions
    language_hints: NotRequired[_LocalizedQuestions]
    expected: _G020Expected


class _RuntimeTopicExpectation(TypedDict):
    topic_id: str
    document: bool
    direct_fetches: int
    playbook: bool
    judgment_state: str
    table_counts: list[int]


class _G009Expected(TypedDict):
    language: Literal["en", "es"]
    status: Literal["answered", "partial", "refused"]
    topics: list[_RuntimeTopicExpectation]
    fetch_calls: list[str]
    playbook_calls: list[str]
    judgment_calls: list[str]


class _G009Case(TypedDict):
    variant: Literal["positive", "negative", "boundary", "failure"]
    question: str
    model_id: NotRequired[str]
    effort: NotRequired[Literal["low"]]
    provider_outcome: NotRequired[Literal["success", "invalid_output", "unavailable"]]
    expected: _G009Expected


class _G001Case(TypedDict):
    variant: Literal["positive", "negative", "boundary", "failure"]
    question: str
    model_id: str
    effort: Literal["low"]
    provider_outcome: Literal["success", "invalid_output", "unavailable"]
    expected: _G009Expected


class _G031Case(TypedDict):
    variant: Literal["positive", "negative", "boundary", "failure"]
    question: str
    language_hint: NotRequired[Literal["en", "es"]]
    expected: _G009Expected


class _PlanningRuntimeFixture(TypedDict):
    schema_version: Literal["1"]
    timezone: str
    anchor_at: str
    g001: list[_G001Case]
    g009: list[_G009Case]
    g020: list[_G020Case]
    g031: list[_G031Case]


_FIXTURE_ADAPTER: TypeAdapter[_PlanningRuntimeFixture] = TypeAdapter(_PlanningRuntimeFixture)


def _fixture() -> _PlanningRuntimeFixture:
    raw: object = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return _FIXTURE_ADAPTER.validate_python(raw)


def _record_case(
    record_property: Callable[[str, str], None], *, requirement: str, case_id: str, variant: str
) -> None:
    record_property("acceptance_ids", requirement)
    record_property("case_id", case_id)
    record_property("variant", variant)
    record_property("fixture_sha256", hashlib.sha256(FIXTURE.read_bytes()).hexdigest())


class _FixtureClock:
    def __init__(self, now: datetime) -> None:
        self._now = now

    def now(self) -> datetime:
        return self._now

    def monotonic(self) -> float:
        return 0.0


class _FixedEmbedding:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], str, str]] = []

    async def embed(
        self,
        texts: tuple[str, ...],
        *,
        purpose: str,
        execution: ExecutionContext,
    ) -> tuple[tuple[float, ...], ...]:
        self.calls.append((texts, purpose, execution.operation))
        return ((1.0, 0.0, 0.0),)


class _RecordingFetches:
    def __init__(self, *, row_count: int = 1) -> None:
        self.topics: list[str] = []
        self.requests: list[FetchSpec] = []
        self.row_count = row_count

    async def execute(
        self,
        fetch: FetchSpec,
        *,
        topic_id: str,
        question_id: UUID,
        principal: VerifiedPrincipal,
        site: AuthorizedSite,
        execution: ExecutionContext,
    ) -> FetchResult:
        assert principal.owner_key
        assert site.config.environment_id == "alpha"
        assert execution.question_id == question_id
        self.topics.append(topic_id)
        self.requests.append(fetch)
        result = _mixed_fetch_result(
            topic_id,
            FetchState.rows,
            question_id=question_id,
            policy_hash=site.policy_hash,
        )
        count = result.count
        if count is not None and self.row_count != count.value:
            count = count.model_copy(update={"value": self.row_count})
        return result.model_copy(
            update={
                "fetch_id": fetch.fetch_id,
                "rows": [
                    row.model_copy(update={"fetch_id": fetch.fetch_id}) for row in result.rows
                ],
                "items": [
                    item.model_copy(update={"fetch_id": fetch.fetch_id}) for item in result.items
                ],
                "count": count,
            }
        )

    async def page(
        self,
        cursor: str,
        *,
        principal: VerifiedPrincipal,
        site: AuthorizedSite,
        execution: ExecutionContext,
    ) -> FetchResult:
        raise AssertionError("the planning runtime scenario does not page")


class _RecordingPlaybooks:
    def __init__(self) -> None:
        self.topics: list[str] = []

    async def run(
        self,
        plan: TopicPlan,
        *,
        principal: VerifiedPrincipal,
        site: AuthorizedSite,
        question_id: UUID,
        execution: ExecutionContext,
    ) -> PlaybookRun:
        assert principal.owner_key
        assert site.config.environment_id == "alpha"
        assert execution.question_id == question_id
        self.topics.append(plan.topic_id)
        result = _mixed_fetch_result(
            plan.topic_id,
            FetchState.rows,
            question_id=question_id,
            policy_hash=site.policy_hash,
        )
        return PlaybookRun(fetches=[result], checks=[], items=result.items)


class _ScriptedJudgment:
    def __init__(self, outcome: Literal["success", "invalid_output", "unavailable"]) -> None:
        self.outcome = outcome
        self.requests: list[JudgmentRequest] = []

    async def count(self, request: JudgmentRequest, *, execution: ExecutionContext) -> int:
        self.requests.append(request)
        return 80

    async def converse(
        self, request: JudgmentRequest, *, execution: ExecutionContext
    ) -> RawJudgment:
        self.requests.append(request)
        if self.outcome == "unavailable":
            raise TimeoutError("fixture judgment transport unavailable")
        text = '{"schema_version":"1","findings":[]}' if self.outcome == "success" else "not-json"
        return RawJudgment(
            text=text,
            stop_reason="end_turn",
            guardrail_intervened=False,
            provider_request_id="fixture-judgment",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("case", _fixture()["g031"])
async def test_failure_and_configuration_clauses_keep_independent_topic_order(
    case: _G031Case,
    record_property: Callable[[str, str], None],
) -> None:
    _record_case(
        record_property,
        requirement="G031",
        case_id="B2-G031.planning-component",
        variant=case["variant"],
    )
    runtime = _runtime()
    catalog = _catalog_with_documents()
    application = runtime.application
    application.catalog = catalog
    application.planner = DeterministicPlanner(catalog)
    application.semantic_suggester = None
    playbooks = _RecordingPlaybooks()
    application.playbooks = playbooks

    answer = await application.ask(
        AskRequest(
            question=case["question"],
            environment_id="alpha",
            language_hint=case.get("language_hint"),
        ),
        _principal("d" * 64),
    )

    expected = case["expected"]
    assert answer.status == AnswerStatus(expected["status"])
    assert answer.language == expected["language"]
    assert [block.topic_id for block in answer.blocks] == [
        topic["topic_id"] for topic in expected["topics"]
    ]
    assert playbooks.topics == expected["playbook_calls"]
    for block, wanted in zip(answer.blocks, expected["topics"], strict=True):
        assert (block.document is not None) is wanted["document"]
        assert bool(block.checks or wanted["playbook"]) is wanted["playbook"]


def _catalog_with_documents() -> ContentCatalog:
    original = make_catalog()
    topics = tuple(
        topic.model_copy(
            update={
                "public_document": DocumentDefinition(
                    document_id=f"{topic.topic_id}_guide",
                    language="en",
                    source_path=f"docs/{topic.topic_id}.md",
                    heading=topic.name.en,
                    anchor=topic.topic_id,
                    sha256="8" * 64,
                    published_path=f"{topic.topic_id}.html",
                )
            }
        )
        for topic in original.topics()
    )
    prompt_packs = tuple(
        TopicPromptPack(
            topic_id=topic.topic_id,
            language=language,
            content_sha=original.provenance.content_sha,
            sha256="9" * 64,
            document_section=f"Reviewed {language} context for {topic.topic_id}.",
            internal_context=f"Use only bounded {language} evidence for {topic.topic_id}.",
            missing=[],
        )
        for topic in topics
        for language in ("en", "es")
    )
    templates = tuple(
        FindingTemplate(
            template_id=f"{topic.topic_id}_observation",
            topic_id=topic.topic_id,
            kind="observation",
            required_bindings={"rule": (FieldId.rule_id,)},
            texts=LocaleText(
                en=f"Observed {topic.topic_id} rule: {{rule}}",
                es=f"Regla observada de {topic.topic_id}: {{rule}}",
            ),
            required_check_outcomes=[],
            allowed_evidence_kinds=["row"],
        )
        for topic in topics
    )
    return ContentCatalog(
        original.provenance,
        original.cues(),
        topics,
        prompt_packs,
        original.playbook_records,
        original.expectations,
        templates,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("case", _fixture()["g001"])
async def test_planner_and_application_preserve_judgment_outcomes_and_question(
    case: _G001Case,
    record_property: Callable[[str, str], None],
) -> None:
    _record_case(
        record_property,
        requirement="G001",
        case_id="B2-G001.planning-component",
        variant=case["variant"],
    )
    runtime = _runtime()
    catalog = _catalog_with_documents()
    application = runtime.application
    application.catalog = catalog
    application.planner = DeterministicPlanner(catalog)
    expected = case["expected"]
    fetches = _RecordingFetches(row_count=expected["topics"][0]["table_counts"][0])
    provider = _ScriptedJudgment(case["provider_outcome"])
    application.fetches = fetches
    application.judgment_provider = provider
    principal = _principal("d" * 64)

    answer = await application.ask(
        AskRequest(
            question=case["question"],
            environment_id="alpha",
            model_id=case["model_id"],
            effort=Effort(case["effort"]),
        ),
        principal,
    )

    assert answer.status == AnswerStatus(expected["status"])
    assert answer.language == expected["language"]
    assert [block.topic_id for block in answer.blocks] == [
        topic["topic_id"] for topic in expected["topics"]
    ]
    assert fetches.topics == expected["fetch_calls"]
    assert [request.topic_id for request in provider.requests if request.topic_id] == [
        "ldap",
        "ldap",
    ]
    assert provider.requests[-1].question == case["question"]
    block = answer.blocks[0]
    assert block.document is not None
    assert len(block.tables) == expected["topics"][0]["direct_fetches"]
    assert [table.count.value for table in block.tables if table.count is not None] == expected[
        "topics"
    ][0]["table_counts"]
    assert block.judgment.state == expected["topics"][0]["judgment_state"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case", [case for case in _fixture()["g020"] if case["variant"] == "positive"]
)
async def test_actual_planner_and_application_preserve_localized_fetch_scope(
    case: _G020Case, record_property: Callable[[str, str], None]
) -> None:
    _record_case(
        record_property,
        requirement="G020",
        case_id="B2-G020.planning-component",
        variant=case["variant"],
    )
    fixture = _fixture()
    expected = case["expected"]
    for expected_index, language in enumerate(("en", "es")):
        question = case["questions"][language]
        anchor = datetime.fromisoformat(fixture["anchor_at"].replace("Z", "+00:00"))
        runtime = _runtime(_FixtureClock(anchor))
        catalog = _catalog_with_documents()
        application = runtime.application
        application.catalog = catalog
        application.planner = DeterministicPlanner(catalog)
        fetches = _RecordingFetches()
        application.fetches = fetches
        principal = _principal("d" * 64)

        planned = application.planner.plan(
            AskRequest(question=question, environment_id="alpha", timezone="Europe/Madrid"),
            principal,
            None,
            policy_hash=application.site_policy.authorize(principal, "alpha").policy_hash,
            clock=application.clock,
        )
        assert isinstance(planned, Planned)
        assert planned.plan.language == language
        assert [topic.topic_id for topic in planned.plan.topics] == ["ldap"]
        assert len(planned.plan.topics[0].fetches) == 1

        answer = await application.ask(
            AskRequest(
                question=question,
                environment_id="alpha",
                timezone="Europe/Madrid",
                language_hint=language,
            ),
            principal,
        )

        assert answer.status == AnswerStatus(expected["statuses"][expected_index])
        assert [block.topic_id for block in answer.blocks] == expected["topic_ids"]
        assert fetches.topics == expected["fetch_topics"]
        assert len(fetches.requests) == 1
        assert [str(request.template_id) for request in fetches.requests] == expected[
            "template_ids"
        ]
        window = fetches.requests[0].window
        expected_start = expected.get("window_start")
        expected_end = expected.get("window_end")
        assert expected_start is not None and expected_end is not None
        assert window.start.astimezone(UTC).isoformat().replace("+00:00", "Z") == expected_start
        assert window.end.astimezone(UTC).isoformat().replace("+00:00", "Z") == expected_end
        assert window.timezone == fixture["timezone"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [case for case in _fixture()["g020"] if case["variant"] != "positive"],
)
async def test_localized_failure_absolute_window_and_refusal_runtime_variants(
    case: _G020Case,
    record_property: Callable[[str, str], None],
) -> None:
    _record_case(
        record_property,
        requirement="G020",
        case_id="B2-G020.planning-component",
        variant=case["variant"],
    )
    fixture = _fixture()
    expected = case["expected"]
    for language_index, language in enumerate(("en", "es")):
        question = case["questions"][language]
        anchor = datetime.fromisoformat(fixture["anchor_at"].replace("Z", "+00:00"))
        runtime = _runtime(_FixtureClock(anchor))
        catalog = _catalog_with_documents()
        application = runtime.application
        application.catalog = catalog
        application.planner = DeterministicPlanner(catalog)
        application.semantic_suggester = None
        fetches = _RecordingFetches()
        playbooks = _RecordingPlaybooks()
        application.fetches = fetches
        application.playbooks = playbooks

        answer = await application.ask(
            AskRequest(
                question=question,
                environment_id="alpha",
                timezone=fixture["timezone"],
                language_hint=language,
            ),
            _principal("d" * 64),
        )

        assert answer.status == AnswerStatus(expected["statuses"][language_index])
        assert answer.language == expected["languages"][language_index]
        assert [block.topic_id for block in answer.blocks] == expected["topic_ids"]
        assert fetches.topics == expected["fetch_topics"]
        assert [str(request.template_id) for request in fetches.requests] == expected[
            "template_ids"
        ]
        assert playbooks.topics == expected.get("playbook_topics", [])
        expected_start = expected.get("window_start")
        expected_end = expected.get("window_end")
        if expected_start is not None and expected_end is not None:
            assert len(fetches.requests) == 1
            window = fetches.requests[0].window
            assert window.start.astimezone(UTC).isoformat().replace("+00:00", "Z") == expected_start
            assert window.end.astimezone(UTC).isoformat().replace("+00:00", "Z") == expected_end


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    _fixture()["g009"],
)
async def test_document_generic_fetch_and_refusal_runtime_cases(
    case: _G009Case, record_property: Callable[[str, str], None]
) -> None:
    _record_case(
        record_property,
        requirement="G009",
        case_id="B2-G009.planning-component",
        variant=case["variant"],
    )
    runtime = _runtime()
    catalog = _catalog_with_documents()
    application = runtime.application
    application.catalog = catalog
    application.planner = DeterministicPlanner(catalog)
    application.semantic_suggester = None
    expected = case["expected"]
    fetches = _RecordingFetches(row_count=2)
    provider = _ScriptedJudgment(case.get("provider_outcome", "success"))
    effort = case.get("effort")
    application.fetches = fetches
    application.judgment_provider = provider

    answer = await application.ask(
        AskRequest(
            question=case["question"],
            environment_id="alpha",
            model_id=case.get("model_id"),
            effort=Effort(effort) if effort is not None else None,
        ),
        _principal("d" * 64),
    )

    assert answer.status == AnswerStatus(expected["status"])
    assert answer.language == expected["language"]
    assert [block.topic_id for block in answer.blocks] == [
        topic["topic_id"] for topic in expected["topics"]
    ]
    assert fetches.topics == expected["fetch_calls"]
    assert [request.topic_id for request in provider.requests[::2]] == expected["judgment_calls"]
    for block, wanted in zip(answer.blocks, expected["topics"], strict=True):
        assert (block.document is not None) is wanted["document"]
        assert len(block.tables) == wanted["direct_fetches"]
        assert [table.count.value for table in block.tables if table.count is not None] == wanted[
            "table_counts"
        ]


@pytest.mark.asyncio
async def test_semantic_suggestion_flows_through_embedding_port_and_stays_a_clarification() -> None:
    runtime = _runtime()
    catalog = _catalog_with_documents()
    application = runtime.application
    application.catalog = catalog
    application.planner = DeterministicPlanner(catalog)
    vectors = {
        "ldap": (1.0, 0.0, 0.0),
        "dns": (0.0, 1.0, 0.0),
        "tls": (0.0, 0.0, 1.0),
    }
    vector_sha256 = hashlib.sha256(
        canonical_bytes({topic_id: list(vectors[topic_id]) for topic_id in sorted(vectors)})
    ).hexdigest()
    manifest = EmbeddingManifest(
        model_id="fixture-embedding",
        region="us-east-1",
        dimensions=3,
        purpose="topic_cards",
        normalization="l2",
        corpus_sha256="a" * 64,
        vector_sha256=vector_sha256,
        golden_sha256="b" * 64,
        threshold=0.8,
        minimum_margin=0.1,
        selection_report_path="fixture/selection.json",
    )
    embedding = _FixedEmbedding()
    suggester = EmbeddingSemanticSuggester(
        SemanticIndex(manifest, vectors, "query", "document"),
        embedding,
        provider_binding=SemanticProviderBinding(
            model_id="fixture-embedding",
            dimensions=3,
            purpose="topic_cards",
            normalization="l2",
            query_mode="single_text",
            document_mode="single_text",
        ),
    )
    application.semantic_suggester = AdmittedSemanticSuggester(
        suggester, admission_store=MemoryEmbeddingAdmissionStore()
    )

    answer = await application.ask(
        AskRequest(
            question="Tell me about an unfamiliar directory login concept",
            environment_id="alpha",
            language_hint="es",
        ),
        _principal("d" * 64),
    )

    assert answer.status == AnswerStatus.clarify
    assert answer.clarify is not None
    assert answer.clarify.kind == "semantic_suggestion"
    assert answer.clarify.suggested_topic == "ldap"
    assert answer.clarify.question == "¿Te refieres a LDAP?"
    assert answer.blocks == []
    assert embedding.calls == [
        (("Tell me about an unfamiliar directory login concept",), "query", "semantic")
    ]


PLAYBOOK_FETCH_ID = "ldap_recent_alert_count"
QUESTION = "LDAP on 636 is failing, what should I fix?"


class _PinnedPlaybooks:
    def __init__(self) -> None:
        self.topics: list[str] = []

    async def run(
        self,
        plan: TopicPlan,
        *,
        principal: VerifiedPrincipal,
        site: AuthorizedSite,
        question_id: UUID,
        execution: ExecutionContext,
    ) -> PlaybookRun:
        assert principal.owner_key
        assert execution.question_id == question_id
        self.topics.append(plan.topic_id)
        result = _mixed_fetch_result(
            plan.topic_id,
            FetchState.rows,
            question_id=question_id,
            policy_hash=site.policy_hash,
        )
        fetch = _with_fetch_id(result)
        return PlaybookRun(fetches=[fetch], checks=[], items=fetch.items)


def _with_fetch_id(result: FetchResult) -> FetchResult:
    return result.model_copy(
        update={
            "fetch_id": PLAYBOOK_FETCH_ID,
            "rows": [row.model_copy(update={"fetch_id": PLAYBOOK_FETCH_ID}) for row in result.rows],
            "items": [
                item.model_copy(update={"fetch_id": PLAYBOOK_FETCH_ID}) for item in result.items
            ],
        }
    )


def _pinned_playbook(playbook_id: str) -> PlaybookDefinition:
    label = LocaleText(en="recent alerts", es="recent alerts")
    return PlaybookDefinition(
        playbook_id=playbook_id,
        topic_id="ldap",
        title=label,
        internal_context="fixture",
        steps=[
            FetchStep(
                kind="fetch",
                step_id="ldap_alert_count_step",
                label=label,
                fetch_id=PLAYBOOK_FETCH_ID,
                template_id=TemplateId.alerts_rows_v1,
                window_default={"unit": "hours", "amount": 24},
                filters=[],
            )
        ],
    )


@pytest.mark.asyncio
async def test_failure_topic_with_pinned_playbook_is_judged_on_its_playbook_fetch() -> None:
    runtime = _runtime()
    catalog = _catalog_with_documents()
    application = runtime.application
    application.catalog = catalog
    application.planner = DeterministicPlanner(catalog)
    playbook_id = catalog.topic("ldap").playbook_id
    assert playbook_id is not None
    pinned = _pinned_playbook(playbook_id)
    engine = application.judgment_engine
    application.judgment_engine = JudgmentEngine(
        standing_rules=engine._standing_rules,
        guardrail_identifier=engine._guardrail_identifier,
        guardrail_version=engine._guardrail_version,
        playbook={playbook_id: pinned}.get,
    )
    playbooks = _PinnedPlaybooks()
    provider = _ScriptedJudgment("success")
    application.playbooks = cast(PlaybookExecutor, playbooks)
    application.judgment_provider = provider

    answer = await application.ask(
        AskRequest(
            question=QUESTION,
            environment_id="alpha",
            model_id="fixture-model",
            effort=Effort("low"),
        ),
        _principal("d" * 64),
    )

    assert answer.status == AnswerStatus.answered
    assert answer.left_out == []
    assert [block.topic_id for block in answer.blocks] == ["ldap"]
    assert playbooks.topics == ["ldap"]
    assert answer.blocks[0].judgment.state == JudgmentState.no_findings
    assert [request.topic_id for request in provider.requests] == ["ldap", "ldap"]
