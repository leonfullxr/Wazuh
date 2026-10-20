from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Literal, TypedDict

import pytest
from pydantic import TypeAdapter, ValidationError
from support import FixedClock, make_catalog, make_principal

from ai_soc.contracts.coverage import case_fixture_bindings, validate_case_fixture_bindings
from ai_soc.contracts.models import AskRequest, Clarified, Planned, Refused
from ai_soc.planning.parser import DeterministicPlanner

FIXTURE = Path(__file__).parent / "data/b2_d12_d13_runtime_variants.json"
ROOT = Path(__file__).resolve().parents[3]
CASE_CATALOG = ROOT / "docs/case_catalog.json"
CONTRACT_FREEZE = ROOT / "contracts/v1/freeze.json"
POLICY_HASH = "a" * 64


class D12Positive(TypedDict):
    question: str
    language_hint: Literal["en", "es"]
    expected_language: str
    expected_question: str


class D12Negative(TypedDict):
    question: str
    language_hint: Literal["en", "es"]
    expected_kind: str


class D12Boundary(TypedDict):
    question: str
    language_hint: Literal["en", "es"]
    expected_language: str
    expected_question: str


class D12Failure(TypedDict):
    question_prefix: str
    repeat_count: int
    expected_error: str


class D12(TypedDict):
    positive: list[D12Positive]
    negative: D12Negative
    boundary: D12Boundary
    failure: D12Failure


class D13Positive(TypedDict):
    question: str
    expected_topic_ids: list[str]
    expected_failure: bool
    expected_judgment: bool
    expected_document: bool
    expected_playbook: str
    expected_fetch_templates: list[str]


class D13Negative(TypedDict):
    question: str
    expected_topic_ids: list[str]
    expected_fetch_topics: list[str]
    expected_judgment_topics: list[str]
    expected_playbook_topics: list[str]


class D13Boundary(TypedDict):
    question: str
    language_hint: Literal["en", "es"]
    expected_language: str
    expected_fetch_templates: list[str]


class D13Failure(TypedDict):
    question: str
    expected_clarify_kind: str
    expected_slots: list[str]


class D13(TypedDict):
    positive: D13Positive
    negative: D13Negative
    boundary: list[D13Boundary]
    failure: D13Failure


class RuntimeFixture(TypedDict):
    schema_version: Literal["1"]
    d12: D12
    d13: D13


FIXTURE_ADAPTER: TypeAdapter[RuntimeFixture] = TypeAdapter(RuntimeFixture)


def _fixture() -> RuntimeFixture:
    return FIXTURE_ADAPTER.validate_python(json.loads(FIXTURE.read_text(encoding="utf-8")))


def _record_variant(
    record_property: Callable[[str, str], None],
    *,
    acceptance_id: str,
    case_id: str,
    variant: str,
) -> None:
    catalog = json.loads(CASE_CATALOG.read_text(encoding="utf-8"))
    freeze = json.loads(CONTRACT_FREEZE.read_text(encoding="utf-8"))
    validate_case_fixture_bindings(catalog, freeze["case_fixture_bindings_sha256"])
    approved_hashes = case_fixture_bindings(catalog)[case_id][variant]
    actual_hash = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    assert approved_hashes == [actual_hash]
    record_property("acceptance_ids", acceptance_id)
    record_property("case_id", case_id)
    record_property("variant", variant)
    record_property("fixture_sha256", approved_hashes[0])


def _plan(
    question: str,
    language_hint: Literal["en", "es"] | None = None,
) -> Planned | Clarified | Refused:
    request = AskRequest(
        question=question,
        environment_id="alpha",
        language_hint=language_hint,
        timezone="UTC",
    )
    return DeterministicPlanner(make_catalog()).plan(
        request,
        make_principal(),
        None,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )


def test_d12_bare_judgment_clarifies_in_both_reviewed_languages(
    record_property: Callable[[str, str], None],
) -> None:
    _record_variant(
        record_property,
        acceptance_id="G012",
        case_id="B2-G012.parser",
        variant="positive",
    )
    for case in _fixture()["d12"]["positive"]:
        result = _plan(case["question"], case["language_hint"])
        assert isinstance(result, Clarified)
        assert result.clarify.kind == "missing_subject"
        assert result.clarify.question == case["expected_question"]
        assert result.clarify.slots == ["topic", "evidence_scope"]


def test_d12_judgment_inside_untrusted_quotes_does_not_create_a_plan(
    record_property: Callable[[str, str], None],
) -> None:
    _record_variant(
        record_property,
        acceptance_id="G012",
        case_id="B2-G012.parser",
        variant="negative",
    )
    case = _fixture()["d12"]["negative"]
    result = _plan(case["question"], case["language_hint"])
    assert isinstance(result, Refused)


def test_d12_tied_bilingual_judgment_uses_the_requested_language(
    record_property: Callable[[str, str], None],
) -> None:
    _record_variant(
        record_property,
        acceptance_id="G012",
        case_id="B2-G012.parser",
        variant="boundary",
    )
    case = _fixture()["d12"]["boundary"]
    result = _plan(case["question"], case["language_hint"])
    assert isinstance(result, Clarified)
    assert result.clarify.kind == "missing_subject"
    assert result.clarify.question == case["expected_question"]
    assert result.clarify.slots == ["topic", "evidence_scope"]


def test_d12_over_limit_input_fails_before_planner_execution(
    record_property: Callable[[str, str], None],
) -> None:
    _record_variant(
        record_property,
        acceptance_id="G012",
        case_id="B2-G012.parser",
        variant="failure",
    )
    case = _fixture()["d12"]["failure"]
    question = case["question_prefix"] * case["repeat_count"]
    with pytest.raises(ValidationError, match=case["expected_error"]):
        AskRequest(question=question, environment_id="alpha", timezone="UTC")


def test_d13_ldap_failure_judgment_is_bound_to_its_only_topic_evidence(
    record_property: Callable[[str, str], None],
) -> None:
    _record_variant(
        record_property,
        acceptance_id="G013",
        case_id="B2-G013.parser",
        variant="positive",
    )
    case = _fixture()["d13"]["positive"]
    result = _plan(case["question"])
    assert isinstance(result, Planned)
    assert [topic.topic_id for topic in result.plan.topics] == case["expected_topic_ids"]
    topic = result.plan.topics[0]
    assert topic.failure is case["expected_failure"]
    assert topic.judgment is case["expected_judgment"]
    assert topic.document is case["expected_document"]
    assert topic.playbook_id == case["expected_playbook"]
    assert [str(fetch.template_id) for fetch in topic.fetches] == case["expected_fetch_templates"]


def test_d13_distinct_setup_topic_cannot_inherit_ldap_evidence(
    record_property: Callable[[str, str], None],
) -> None:
    _record_variant(
        record_property,
        acceptance_id="G013",
        case_id="B2-G013.parser",
        variant="negative",
    )
    case = _fixture()["d13"]["negative"]
    result = _plan(case["question"])
    assert isinstance(result, Planned)
    assert [topic.topic_id for topic in result.plan.topics] == case["expected_topic_ids"]
    fetch_topics = [topic.topic_id for topic in result.plan.topics if topic.fetches]
    judgment_topics = [topic.topic_id for topic in result.plan.topics if topic.judgment]
    playbook_topics = [topic.topic_id for topic in result.plan.topics if topic.playbook_id]
    assert fetch_topics == case["expected_fetch_topics"]
    assert judgment_topics == case["expected_judgment_topics"]
    assert playbook_topics == case["expected_playbook_topics"]


def test_d13_bilingual_failure_and_judgment_keep_equivalent_ldap_jobs(
    record_property: Callable[[str, str], None],
) -> None:
    _record_variant(
        record_property,
        acceptance_id="G013",
        case_id="B2-G013.parser",
        variant="boundary",
    )
    plans: list[Planned] = []
    cases = _fixture()["d13"]["boundary"]
    for case in cases:
        result = _plan(case["question"], case["language_hint"])
        assert isinstance(result, Planned)
        assert result.plan.language == case["expected_language"]
        plans.append(result)
    english, spanish = plans
    assert [topic.topic_id for topic in english.plan.topics] == ["ldap"]
    assert [topic.topic_id for topic in spanish.plan.topics] == ["ldap"]
    for plan, case in zip(plans, cases, strict=True):
        topic = plan.plan.topics[0]
        assert topic.failure and topic.judgment and topic.document
        assert topic.playbook_id == "ldap_checks"
        assert [str(fetch.template_id) for fetch in topic.fetches] == case[
            "expected_fetch_templates"
        ]


def test_d13_invalid_filter_clarifies_without_partial_evidence_plan(
    record_property: Callable[[str, str], None],
) -> None:
    _record_variant(
        record_property,
        acceptance_id="G013",
        case_id="B2-G013.parser",
        variant="failure",
    )
    case = _fixture()["d13"]["failure"]
    result = _plan(case["question"])
    assert isinstance(result, Clarified)
    assert result.clarify.kind == case["expected_clarify_kind"]
    assert result.clarify.slots == case["expected_slots"]
