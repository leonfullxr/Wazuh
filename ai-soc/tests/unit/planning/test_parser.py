# pyright: reportPrivateUsage=false

import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Literal, TypedDict

import pytest
from pydantic import TypeAdapter
from support import FixedClock, make_catalog, make_principal, record_case

from ai_soc.content.builder import ContentBuildError, _validate_cross_references, cue_catalog_digest
from ai_soc.content.catalog import ContentCatalog
from ai_soc.content.pointers import document_pointer
from ai_soc.contracts.models import (
    AliasDefinition,
    AskRequest,
    Clarified,
    CueCatalog,
    CueDefinition,
    DocumentDefinition,
    FieldId,
    GroupField,
    Planned,
    Refused,
    TemplateId,
    TopicDefinition,
)
from ai_soc.planning.parser import DeterministicPlanner

POLICY_HASH = "a" * 64
ROOT = Path(__file__).resolve().parents[3]
QA004_FIXTURE = Path(__file__).parent / "data/qa004_variants.json"
QA001_FIXTURE = Path(__file__).parent / "data/qa001_variants.json"
G023_FIXTURE = Path(__file__).parent / "data/b2_g023_refusal_variants.json"
G008_FIXTURE = Path(__file__).parent / "data/b2_g008_alias_variants.json"
G036_FIXTURE = Path(__file__).parent / "data/b2_g036_static_cues.json"
G026_FIXTURE = Path(__file__).parent / "data/b2_g026_alias_variants.json"
G041_FIXTURE = Path(__file__).parent / "data/b2_g041_parser_cases.json"
GOLDEN_FIXTURE = ROOT / "docs/golden_examples.json"


class G041TopicExpectation(TypedDict):
    topic_id: str
    ordinal: int
    document: bool
    failure: bool
    judgment: bool
    playbook_id: str | None
    fetch_templates: list[str]


class G041PlannedExpectation(TypedDict):
    language: Literal["en", "es"]
    topics: list[G041TopicExpectation]


class G041PlannedCase(TypedDict):
    question: str
    expected: G041PlannedExpectation


class G041ClarifiedExpectation(TypedDict):
    kind: Literal["clarified"]
    clarify_kind: Literal["missing_subject", "missing_slots"]
    suggested_topic: str | None


class G041ClarifiedCase(TypedDict):
    question: str
    expected: G041ClarifiedExpectation


class G041Fixture(TypedDict):
    schema_version: Literal["1"]
    positive: G041PlannedCase
    negative: G041PlannedCase
    failure: list[G041ClarifiedCase]


G041_FIXTURE_ADAPTER: TypeAdapter[G041Fixture] = TypeAdapter(G041Fixture)


def _g041_fixture() -> G041Fixture:
    value: object = json.loads(G041_FIXTURE.read_text(encoding="utf-8"))
    return G041_FIXTURE_ADAPTER.validate_python(value)


def _assert_g041_plan(case: G041PlannedCase) -> None:
    result = parse(case["question"])
    assert isinstance(result, Planned)
    expected = case["expected"]
    assert result.plan.language == expected["language"]
    assert len(result.plan.topics) == len(expected["topics"])
    for actual, wanted in zip(result.plan.topics, expected["topics"], strict=True):
        assert actual.topic_id == wanted["topic_id"]
        assert actual.ordinal == wanted["ordinal"]
        assert actual.document is wanted["document"]
        assert actual.failure is wanted["failure"]
        assert actual.judgment is wanted["judgment"]
        assert actual.playbook_id == wanted["playbook_id"]
        assert [str(fetch.template_id) for fetch in actual.fetches] == wanted["fetch_templates"]


def _assert_g041_clarification(case: G041ClarifiedCase) -> None:
    result = parse(case["question"])
    assert isinstance(result, Clarified)
    assert result.kind == case["expected"]["kind"]
    assert result.clarify.kind == case["expected"]["clarify_kind"]
    assert result.clarify.suggested_topic == case["expected"]["suggested_topic"]


def ask(question: str, language_hint: Literal["en", "es"] | None = None) -> AskRequest:
    return AskRequest(
        question=question,
        environment_id="alpha",
        language_hint=language_hint,
        timezone="UTC",
    )


def parse(
    question: str,
    language_hint: Literal["en", "es"] | None = None,
    catalog: ContentCatalog | None = None,
) -> Planned | Clarified | Refused:
    planner = DeterministicPlanner(catalog or make_catalog())
    return planner.plan(
        ask(question, language_hint),
        make_principal(),
        None,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )


def _catalog_with_reviewed_ldap_synonyms() -> ContentCatalog:
    catalog = make_catalog()
    ldap = catalog.topic("ldap")
    assert ldap is not None
    reviewed_aliases = [
        AliasDefinition(
            alias_id="ldap_ldaps",
            language="en",
            text="LDAPS",
            normalized="ldaps",
            boundary="word",
            topic_id="ldap",
        ),
        AliasDefinition(
            alias_id="ldap_ad_auth",
            language="en",
            text="AD authentication",
            normalized="ad authentication",
            boundary="phrase",
            topic_id="ldap",
        ),
        AliasDefinition(
            alias_id="ldap_port_636",
            language="en",
            text="port 636",
            normalized="port 636",
            boundary="phrase",
            topic_id="ldap",
        ),
        AliasDefinition(
            alias_id="ldap_authentication",
            language="en",
            text="LDAP authentication",
            normalized="ldap authentication",
            boundary="phrase",
            topic_id="ldap",
        ),
    ]
    topics = tuple(
        topic.model_copy(
            update={
                "aliases": [*topic.aliases, *reviewed_aliases],
                "public_document": DocumentDefinition(
                    document_id="ldap_guide",
                    language="en",
                    source_path="public-docs/en/ldap.md",
                    heading="LDAP directory guide",
                    anchor="ldap-directory-guide",
                    sha256="a" * 64,
                    published_path="en/ldap.html",
                ),
            }
        )
        if topic.topic_id == "ldap"
        else topic
        for topic in catalog.topic_records
    )
    return replace(catalog, topic_records=topics)


def _reviewed_cues(fixture: dict[str, str]) -> CueCatalog:
    cues = CueCatalog(
        version="1",
        sha256="0" * 64,
        cues=[
            CueDefinition(
                cue_id=fixture["english_cue_id"],
                language="en",
                text=fixture["english_text"],
                normalized=fixture["english_text"],
                kind="failure",
                boundary="phrase",
            ),
            CueDefinition(
                cue_id=fixture["spanish_cue_id"],
                language="es",
                text=fixture["spanish_text"],
                normalized=fixture["spanish_text"],
                kind="failure",
                boundary="phrase",
            ),
        ],
        aliases=[],
        ambiguities=[],
    )
    return cues.model_copy(update={"sha256": cue_catalog_digest(cues)})


def _content_topics_without_playbooks() -> tuple[TopicDefinition, ...]:
    return tuple(
        topic.model_copy(update={"playbook_id": None}) for topic in make_catalog().topic_records
    )


def test_en_es_failure_and_judgment_are_bound_to_alias() -> None:
    english = parse("LDAP is failing, what should I fix?")
    spanish = parse("LDAP falla, ¿qué debería corregir?")
    assert isinstance(english, Planned)
    assert english.plan.language == "en"
    assert english.plan.topics[0].failure and english.plan.topics[0].judgment
    assert english.plan.topics[0].playbook_id == "ldap_checks"
    assert isinstance(spanish, Planned)
    assert spanish.plan.language == "es"
    assert spanish.plan.topics[0].failure and spanish.plan.topics[0].judgment


def test_shared_terminal_judgment_applies_to_all_ordered_failure_topics() -> None:
    result = parse("LDAP is failing; DNS is failing; TLS is failing; recommend fixes")
    assert isinstance(result, Planned)
    assert [topic.topic_id for topic in result.plan.topics] == ["ldap", "dns", "tls"]
    assert all(topic.failure and topic.judgment for topic in result.plan.topics)


def test_registered_mixed_failure_setup_clause_isolated_to_failure_topic(
    record_property: Callable[[str, str], None],
) -> None:
    case = next(
        item
        for item in json.loads(GOLDEN_FIXTURE.read_text(encoding="utf-8"))["cases"]
        if item["case_id"] == "G031.en.mixed"
    )
    record_case(
        record_property,
        requirements=("G031",),
        case_id="G031.en.mixed",
        variant="positive",
        fixture_sha256=case["fixture_sha256"],
    )
    result = parse(case["input"]["payload"]["question"])
    assert isinstance(result, Planned)
    assert [topic.topic_id for topic in result.plan.topics] == ["ldap", "dns"]
    assert (result.plan.topics[0].failure, result.plan.topics[0].judgment) == (True, False)
    assert result.plan.topics[0].playbook_id == "ldap_checks"
    assert result.plan.topics[1].document
    assert not result.plan.topics[1].failure and not result.plan.topics[1].judgment
    assert not result.plan.topics[1].fetches and result.plan.topics[1].playbook_id is None


def test_registered_spanish_bare_judgment_clarifies_without_a_subject(
    record_property: Callable[[str, str], None],
) -> None:
    case = next(
        item
        for item in json.loads(GOLDEN_FIXTURE.read_text(encoding="utf-8"))["cases"]
        if item["case_id"] == "G012.es.bare"
    )
    record_case(
        record_property,
        requirements=("G012",),
        case_id="G012.es.bare",
        variant="positive",
        fixture_sha256=case["fixture_sha256"],
    )
    result = parse(case["input"]["payload"]["question"], language_hint="es")
    assert isinstance(result, Clarified)
    assert result.clarify.kind == "missing_subject"
    assert result.clarify.question == "¿Sobre qué tema?"


def test_ldap_failure_binds_pointer_playbook_and_judgment() -> None:
    fixture = json.loads(QA001_FIXTURE.read_text(encoding="utf-8"))["positive"]
    result = parse(fixture["question"])
    assert isinstance(result, Planned)
    topic = result.plan.topics[0]
    assert topic.topic_id == fixture["expected_topic"]
    assert topic.document is fixture["expected_document"]
    assert topic.failure is fixture["expected_failure"]
    assert topic.judgment is fixture["expected_judgment"]
    assert topic.playbook_id == fixture["expected_playbook"]


def test_registered_bilingual_generic_and_shared_terminal_cases(
    record_property: Callable[[str, str], None],
) -> None:
    golden_cases = json.loads(GOLDEN_FIXTURE.read_text(encoding="utf-8"))["cases"]
    cases = [
        case
        for case in golden_cases
        if case["case_id"]
        in {
            "QA-004.en.generic",
            "QA-004.es.generic",
            "QA-004.en.shared",
            "QA-004.es.shared",
        }
    ]
    assert len(cases) == 4
    record_case(
        record_property,
        requirements=("G009", "G020"),
        case_id="QA-004.resolution",
        variant="positive",
        fixture=GOLDEN_FIXTURE,
    )
    for case in cases:
        question = case["input"]["payload"]["question"]
        result = parse(question)
        expected_topics = case["expected"]["payload"]["topic_plans"]
        assert isinstance(result, Planned)
        assert [topic.topic_id for topic in result.plan.topics] == [
            expected["topic_id"] for expected in expected_topics
        ]
        for topic, expected in zip(result.plan.topics, expected_topics, strict=True):
            assert topic.document is expected["document"]
            assert topic.failure is expected["failure"]
            assert topic.judgment is expected["judgment"] is True
            if expected["failure"]:
                assert topic.playbook_id is not None
                assert topic.fetches == []
            else:
                assert [fetch.template_id for fetch in topic.fetches] == expected["fetch_templates"]
            assert all(fetch.window.end == result.plan.anchor_at for fetch in topic.fetches)


def test_registered_quote_negation_and_clause_scope_cases(
    record_property: Callable[[str, str], None],
) -> None:
    record_case(
        record_property,
        requirements=("G009", "G031"),
        case_id="QA-004.resolution",
        variant="negative",
        fixture=QA004_FIXTURE,
    )
    fixture = json.loads(QA004_FIXTURE.read_text(encoding="utf-8"))
    quoted, negated = fixture["negative"]
    assert isinstance(parse(quoted["question"]), Refused)
    assert negated["expected"] == "planned_failure_without_judgment"
    negated_result = parse(negated["question"])
    assert isinstance(negated_result, Planned)
    assert negated_result.plan.topics[0].failure
    assert not negated_result.plan.topics[0].judgment
    spanish_negated = parse("LDAP falla; no recomiendes una solución", language_hint="es")
    assert isinstance(spanish_negated, Planned)
    assert spanish_negated.plan.language == "es"
    assert spanish_negated.plan.topics[0].failure
    assert not spanish_negated.plan.topics[0].judgment
    scoped = parse("LDAP is failing; how do I configure DNS?")
    assert isinstance(scoped, Planned)
    assert [(topic.topic_id, topic.failure, topic.judgment) for topic in scoped.plan.topics] == [
        ("ldap", True, False),
        ("dns", False, False),
    ]


def test_qa004_missing_subject_and_invalid_filter_cases() -> None:
    fixture = json.loads(QA004_FIXTURE.read_text(encoding="utf-8"))
    for case in fixture["failure"]:
        assert case["expected"] == "clarified"
        assert isinstance(parse(case["question"]), Clarified)
    assert isinstance(parse("Show alerts for the last 24 hours; DNS is failing"), Clarified)
    spanish = parse("¿Qué debería corregir?", language_hint="es")
    assert isinstance(spanish, Clarified)
    assert spanish.clarify.kind == "missing_subject"


def test_leading_zero_agent_filter_stays_a_string() -> None:
    result = parse("Show LDAP alerts for the last 24 hours for agent id 007")
    assert isinstance(result, Planned)
    assert result.plan.topics[0].fetches[0].filters[0].value == "007"


def test_registered_topic_count_boundary_is_bounded_by_plan_bytes(
    record_property: Callable[[str, str], None],
) -> None:
    record_case(
        record_property,
        requirements=("G009", "G020"),
        case_id="QA-004.resolution",
        variant="boundary",
        fixture=QA004_FIXTURE,
    )
    fixture = json.loads(QA004_FIXTURE.read_text(encoding="utf-8"))["boundary"]
    names = tuple(fixture["topic_ids"])
    result = parse(
        "; ".join(
            f"{name} is failing" if index % 2 == 0 else f"how do I configure {name}"
            for index, name in enumerate(names)
        ),
        catalog=make_catalog(names),
    )
    assert isinstance(result, Planned)
    assert len(result.plan.topics) == fixture["expected_topic_count"]
    assert [topic.topic_id for topic in result.plan.topics] == list(names)
    assert all(topic.document for topic in result.plan.topics)
    assert [topic.failure for topic in result.plan.topics] == [
        index % 2 == 0 for index in range(len(names))
    ]
    assert all(not topic.judgment for topic in result.plan.topics)
    english = parse("Show LDAP alerts for the last 24 hours")
    spanish = parse("Muestra alertas LDAP de las últimas 24 horas", language_hint="es")
    assert isinstance(english, Planned) and isinstance(spanish, Planned)
    assert english.plan.language == "en" and spanish.plan.language == "es"
    assert english.plan.topics[0].fetches == spanish.plan.topics[0].fetches


def test_finite_fetch_options_select_group_template_and_preserve_limit_order() -> None:
    result = parse("Show LDAP alerts for the last 24 hours, top 5 earliest by agent")
    assert isinstance(result, Planned)
    fetch = result.plan.topics[0].fetches[0]
    assert fetch.template_id == TemplateId.alerts_group_v1
    assert fetch.limit == 5
    assert fetch.order == "earliest"
    assert fetch.group_by == GroupField.agent_id


def test_generic_bilingual_vulnerability_fetch_keeps_id_string_and_selects_count() -> None:
    result = parse("Muestra cuántas vulnerabilidades hubo en los últimos 3 días para agente id 007")
    assert isinstance(result, Planned)
    fetch = result.plan.topics[0].fetches[0]
    assert result.plan.language == "es"
    assert result.plan.topics[0].topic_id == "_records"
    assert fetch.template_id == TemplateId.vulnerabilities_count_v1
    assert fetch.filters[0].field == FieldId.agent_id
    assert fetch.filters[0].value == "007"


def test_invalid_filter_literals_clarify_instead_of_being_dropped() -> None:
    bad_address = parse("Show LDAP alerts for the last 24 hours source IP 999.1.1.1")
    unsupported_group = parse("Show LDAP alerts for the last 24 hours group unreviewed_group")
    assert isinstance(bad_address, Clarified)
    assert isinstance(unsupported_group, Clarified)


@pytest.mark.parametrize("variant", ["positive", "negative", "boundary", "failure"])
def test_registered_unmatched_queries_refuse_without_guessing(
    record_property: Callable[[str, str], None], variant: str
) -> None:
    fixture = json.loads(G023_FIXTURE.read_text(encoding="utf-8"))
    record_case(
        record_property,
        requirements=("G023",),
        case_id="B2-G023.refusal",
        variant=variant,
        fixture=G023_FIXTURE,
    )
    case = fixture[variant]
    assert case["expected"] == "refused"
    result = parse(case["question"], language_hint="en")
    assert isinstance(result, Refused)


def test_parser_keeps_failure_and_document_intents_topic_local(
    record_property: Callable[[str, str], None],
) -> None:
    record_case(
        record_property,
        requirements=("G041",),
        case_id="B2-G041.parser",
        variant="positive",
        fixture=G041_FIXTURE,
    )
    _assert_g041_plan(_g041_fixture()["positive"])


def test_parser_does_not_merge_fetches_into_failure_topics(
    record_property: Callable[[str, str], None],
) -> None:
    record_case(
        record_property,
        requirements=("G041",),
        case_id="B2-G041.parser",
        variant="negative",
        fixture=G041_FIXTURE,
    )
    _assert_g041_plan(_g041_fixture()["negative"])


def test_registered_parser_preserves_order_for_more_than_thirty_two_topics(
    record_property: Callable[[str, str], None],
) -> None:
    record_case(
        record_property,
        requirements=("G041",),
        case_id="B2-G041.parser",
        variant="boundary",
        fixture=QA004_FIXTURE,
    )
    fixture = json.loads(QA004_FIXTURE.read_text(encoding="utf-8"))["boundary"]
    names = tuple(fixture["topic_ids"])
    question = "; ".join(f"how do I configure {name}" for name in names)
    result = parse(question, catalog=make_catalog(names))
    assert isinstance(result, Planned)
    assert len(result.plan.topics) == fixture["expected_topic_count"] > 32
    assert [topic.topic_id for topic in result.plan.topics] == list(names)


def test_parser_clarifies_when_required_slots_are_missing(
    record_property: Callable[[str, str], None],
) -> None:
    record_case(
        record_property,
        requirements=("G041",),
        case_id="B2-G041.parser",
        variant="failure",
        fixture=G041_FIXTURE,
    )
    for case in _g041_fixture()["failure"]:
        _assert_g041_clarification(case)


def test_registered_reviewed_aliases_resolve_only_to_their_canonical_topic(
    record_property: Callable[[str, str], None],
) -> None:
    record_case(
        record_property,
        requirements=("G008",),
        case_id="B2-G008.content",
        variant="positive",
        fixture=G008_FIXTURE,
    )
    fixture = json.loads(G008_FIXTURE.read_text(encoding="utf-8"))["positive"]
    catalog = _catalog_with_reviewed_ldap_synonyms()
    ldap = catalog.topic("ldap")
    assert ldap is not None
    pointer = document_pointer(
        ldap,
        language="en",
        content_sha=catalog.provenance.content_sha,
        docs_origin=catalog.provenance.docs_origin,
    )
    assert pointer is not None
    assert pointer.source_path == "public-docs/en/ldap.md"
    assert str(pointer.url).startswith("https://docs.example.test/commits/")
    for question in fixture["questions"]:
        result = parse(question, catalog=catalog)
        assert isinstance(result, Planned)
        assert len(result.plan.topics) == 1
        assert result.plan.topics[0].topic_id == fixture["expected_topic"]
        assert result.plan.topics[0].failure is fixture["expected_failure"]


def test_registered_unreviewed_synonym_does_not_resolve_a_topic(
    record_property: Callable[[str, str], None],
) -> None:
    record_case(
        record_property,
        requirements=("G008",),
        case_id="B2-G008.content",
        variant="negative",
        fixture=G008_FIXTURE,
    )
    fixture = json.loads(G008_FIXTURE.read_text(encoding="utf-8"))["negative"]
    result = parse(fixture["question"], catalog=_catalog_with_reviewed_ldap_synonyms())
    assert fixture["expected"] == "refused"
    assert isinstance(result, Refused)


def test_registered_alias_normalization_handles_case_and_spacing_only(
    record_property: Callable[[str, str], None],
) -> None:
    record_case(
        record_property,
        requirements=("G008",),
        case_id="B2-G008.content",
        variant="boundary",
        fixture=G008_FIXTURE,
    )
    fixture = json.loads(G008_FIXTURE.read_text(encoding="utf-8"))["boundary"]
    result = parse(fixture["question"], catalog=_catalog_with_reviewed_ldap_synonyms())
    assert isinstance(result, Planned)
    assert result.plan.topics[0].topic_id == fixture["expected_topic"]
    assert result.plan.topics[0].failure is fixture["expected_failure"]


def test_registered_unsupported_alias_refuses_without_guessed_topic(
    record_property: Callable[[str, str], None],
) -> None:
    record_case(
        record_property,
        requirements=("G008",),
        case_id="B2-G008.content",
        variant="failure",
        fixture=G008_FIXTURE,
    )
    fixture = json.loads(G008_FIXTURE.read_text(encoding="utf-8"))["failure"]
    result = parse(fixture["question"], catalog=_catalog_with_reviewed_ldap_synonyms())
    assert fixture["expected"] == "refused"
    assert isinstance(result, Refused)


def test_registered_reviewed_static_cues_drive_parser_failure_classification(
    record_property: Callable[[str, str], None],
) -> None:
    record_case(
        record_property,
        requirements=("G036",),
        case_id="B2-G036.static-cues",
        variant="positive",
        fixture=G036_FIXTURE,
    )
    fixture = json.loads(G036_FIXTURE.read_text(encoding="utf-8"))["positive"]
    cues = _reviewed_cues(fixture)
    catalog = replace(make_catalog(), cue_catalog=cues)
    result = parse(fixture["question"], catalog=catalog)
    assert isinstance(result, Planned)
    topic = result.plan.topics[0]
    assert topic.topic_id == "ldap"
    assert topic.failure is fixture["expected_failure"]
    assert "fixture_failure_en" in topic.cue_ids


def test_unreviewed_external_cue_text_has_no_parser_effect(
    record_property: Callable[[str, str], None],
) -> None:
    record_case(
        record_property,
        requirements=("G036",),
        case_id="B2-G036.static-cues",
        variant="negative",
        fixture=G036_FIXTURE,
    )
    fixture = json.loads(G036_FIXTURE.read_text(encoding="utf-8"))["negative"]
    result = parse(fixture["question"], catalog=make_catalog())
    assert isinstance(result, Planned)
    assert result.plan.topics[0].failure is fixture["expected_failure"]
    assert all(not cue_id.startswith("fixture_failure") for cue_id in result.plan.topics[0].cue_ids)


def test_registered_cue_bytes_require_the_matching_digest(
    record_property: Callable[[str, str], None],
) -> None:
    record_case(
        record_property,
        requirements=("G036",),
        case_id="B2-G036.static-cues",
        variant="boundary",
        fixture=G036_FIXTURE,
    )
    fixture = json.loads(G036_FIXTURE.read_text(encoding="utf-8"))["boundary"]
    cues = _reviewed_cues(fixture)
    topics = _content_topics_without_playbooks()
    _validate_cross_references({}, topics, (cues,), (), (), (), (), ())
    changed = cues.model_copy(
        update={
            "cues": [
                cues.cues[0].model_copy(update={"text": fixture["changed_text"]}),
                cues.cues[1],
            ]
        }
    )
    with pytest.raises(ContentBuildError, match="cue catalog digest"):
        _validate_cross_references({}, topics, (changed,), (), (), (), (), ())


def test_registered_duplicate_static_cues_fail_pack_validation(
    record_property: Callable[[str, str], None],
) -> None:
    record_case(
        record_property,
        requirements=("G036",),
        case_id="B2-G036.static-cues",
        variant="failure",
        fixture=G036_FIXTURE,
    )
    fixture = json.loads(G036_FIXTURE.read_text(encoding="utf-8"))["failure"]
    cues = _reviewed_cues(
        {
            "english_cue_id": fixture["duplicate_cue_id"],
            "english_text": fixture["english_text"],
            "spanish_cue_id": fixture["spanish_cue_id"],
            "spanish_text": fixture["spanish_text"],
        }
    )
    duplicate = cues.model_copy(update={"cues": [*cues.cues, cues.cues[0]]})
    duplicate = duplicate.model_copy(update={"sha256": cue_catalog_digest(duplicate)})
    with pytest.raises(ContentBuildError, match="duplicate cue ID"):
        _validate_cross_references(
            {}, _content_topics_without_playbooks(), (duplicate,), (), (), (), (), ()
        )


def test_registered_bilingual_alias_inventory_resolves_only_reviewed_names(
    record_property: Callable[[str, str], None],
) -> None:
    record_case(
        record_property,
        requirements=("G026",),
        case_id="B2-G026.aliases",
        variant="positive",
        fixture=G026_FIXTURE,
    )
    fixture = json.loads(G026_FIXTURE.read_text(encoding="utf-8"))["positive"]
    catalog = _catalog_with_reviewed_ldap_synonyms()
    english = parse(fixture["english_question"], catalog=catalog)
    spanish = parse(fixture["spanish_question"], language_hint="es", catalog=catalog)
    assert isinstance(english, Planned) and isinstance(spanish, Planned)
    assert english.plan.topics[0].topic_id == fixture["expected_topic"]
    assert spanish.plan.topics[0].topic_id == fixture["expected_topic"]
    assert english.plan.language == "en" and spanish.plan.language == "es"


def test_unreviewed_alias_has_no_routing_effect(
    record_property: Callable[[str, str], None],
) -> None:
    record_case(
        record_property,
        requirements=("G026",),
        case_id="B2-G026.aliases",
        variant="negative",
        fixture=G026_FIXTURE,
    )
    fixture = json.loads(G026_FIXTURE.read_text(encoding="utf-8"))["negative"]
    result = parse(fixture["question"], catalog=_catalog_with_reviewed_ldap_synonyms())
    assert fixture["expected"] == "refused"
    assert isinstance(result, Refused)


def test_longest_reviewed_alias_wins_an_overlapping_match(
    record_property: Callable[[str, str], None],
) -> None:
    record_case(
        record_property,
        requirements=("G026",),
        case_id="B2-G026.aliases",
        variant="boundary",
        fixture=G026_FIXTURE,
    )
    fixture = json.loads(G026_FIXTURE.read_text(encoding="utf-8"))["boundary"]
    result = parse(fixture["question"], catalog=_catalog_with_reviewed_ldap_synonyms())
    assert isinstance(result, Planned)
    aliases = result.plan.topics[0].alias_ids
    assert fixture["long_alias_id"] in aliases
    assert fixture["short_alias_id"] not in aliases


def test_cross_topic_alias_collision_requires_content_ambiguity_rule(
    record_property: Callable[[str, str], None],
) -> None:
    record_case(
        record_property,
        requirements=("G026",),
        case_id="B2-G026.aliases",
        variant="failure",
        fixture=G026_FIXTURE,
    )
    fixture = json.loads(G026_FIXTURE.read_text(encoding="utf-8"))["failure"]
    aliases = {
        "ldap": fixture["first_alias_id"],
        "dns": fixture["second_alias_id"],
    }
    topics = tuple(
        topic.model_copy(
            update={
                "aliases": [
                    *topic.aliases,
                    AliasDefinition(
                        alias_id=aliases[topic.topic_id],
                        language="en",
                        text=fixture["shared_alias"],
                        normalized=fixture["shared_alias"],
                        boundary="phrase",
                        topic_id=topic.topic_id,
                    ),
                ]
            }
        )
        if topic.topic_id in aliases
        else topic
        for topic in _content_topics_without_playbooks()
    )
    cues = _reviewed_cues(json.loads(G036_FIXTURE.read_text(encoding="utf-8"))["positive"])
    with pytest.raises(ContentBuildError, match="unreviewed cross-topic alias collision"):
        _validate_cross_references({}, topics, (cues,), (), (), (), (), ())


def test_window_only_followup_without_anchor_clarifies_prior_plan() -> None:
    result = parse("and for the last 7 days?", catalog=make_catalog())
    assert isinstance(result, Clarified)
    assert result.clarify.slots == ["prior_plan"]


def test_and_for_agent_filter_on_first_question_still_plans() -> None:
    question = "Show LDAP alerts for the last 24 hours and for agent id 007"
    result = parse(question, catalog=make_catalog(("ldap",)))
    assert isinstance(result, Planned)
    filters = result.plan.topics[0].fetches[0].filters
    assert any(filter.field == FieldId.agent_id and filter.value == "007" for filter in filters)


def test_quoted_agent_name_filter_survives_quote_protection() -> None:
    question = 'Show LDAP alerts for the last 24 hours for agent name "alice"'
    result = parse(question, catalog=make_catalog(("ldap",)))
    assert isinstance(result, Planned)
    filters = result.plan.topics[0].fetches[0].filters
    assert any(filter.field == FieldId.agent_name and filter.value == "alice" for filter in filters)


def test_quoted_log_payload_does_not_become_fetch_filter() -> None:
    question = 'Show LDAP alerts for the last 24 hours, log line "rule id 9999"'
    result = parse(question, catalog=make_catalog(("ldap",)))
    assert isinstance(result, Planned)
    filters = result.plan.topics[0].fetches[0].filters
    assert not any(filter.field == FieldId.rule_id for filter in filters)


def test_terminal_judgment_clarifies_when_clauses_have_distinct_windows() -> None:
    question = (
        "Show LDAP alerts for the last 24 hours; "
        "show DNS alerts for the last 7 days; recommend fixes"
    )
    result = parse(question, catalog=make_catalog(("ldap", "dns")))
    assert isinstance(result, Clarified)
    assert "judgment_scope" in result.clarify.slots


def test_terminal_judgment_clarifies_when_failure_clause_has_calendar_window() -> None:
    question = "Show LDAP alerts for the last 24 hours; DNS is failing yesterday; recommend fixes"
    result = parse(question, catalog=make_catalog(("ldap", "dns")))
    assert isinstance(result, Clarified)
    assert "judgment_scope" in result.clarify.slots


def test_terminal_judgment_binds_windowless_failure_with_one_fetch_window() -> None:
    question = "Show LDAP alerts for the last 24 hours; DNS is failing; recommend fixes"
    result = parse(question, catalog=make_catalog(("ldap", "dns")))
    assert isinstance(result, Planned)
    topics = {topic.topic_id: topic for topic in result.plan.topics}
    assert topics["ldap"].judgment
    assert topics["dns"].judgment


def test_quoted_agent_id_payload_does_not_become_filter() -> None:
    question = 'Show LDAP alerts for the last 24 hours, log line "agent id 007"'
    result = parse(question, catalog=make_catalog(("ldap",)))
    assert isinstance(result, Planned)
    filters = result.plan.topics[0].fetches[0].filters
    assert not any(filter.field == FieldId.agent_id for filter in filters)
