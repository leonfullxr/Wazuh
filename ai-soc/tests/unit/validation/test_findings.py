from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import UUID

import pytest
from case_binding import (
    assert_fixture_matches_all_variants,
    canonical_acceptance_ids,
    canonical_fixture_sha256,
    registered_case_variants,
)

from ai_soc.contracts.models import (
    CheckOutcome,
    CheckResult,
    Count,
    EvidenceItem,
    EvidencePack,
    EvidenceSourceCheck,
    FetchSpec,
    FieldId,
    Filter,
    FindingRelationAggregateScope,
    FindingRelationSameRecord,
    FindingTemplate,
    JudgmentState,
    LocaleText,
    RawJudgment,
    RemovedReason,
    RequiredCheckOutcome,
    ResolvedWindow,
    SnapshotKind,
    SnapshotRef,
    TemplateId,
    TopicPromptPack,
    ValidationContext,
    Visibility,
)
from ai_soc.query.evidence import count_item, row_item
from ai_soc.validation.findings import FindingValidator

NOW = datetime(2026, 1, 1, tzinfo=UTC)
POLICY = "1" * 64
CONTENT = "a" * 40
EVIDENCE_ID = "ev1_" + "2" * 64
G022_BINDING_FIXTURE = Path(__file__).parent / "data" / "g022_binding_cases.json"
RENDERER_FIXTURE = Path(__file__).parent / "data" / "g021_g039_renderer.json"
G021_FIXTURE = Path(__file__).parent / "data" / "g021_approved_template_boundary.json"
G039_FIXTURE = Path(__file__).parent / "data" / "g039_spanish_renderer.json"
G025_FIXTURE = Path(__file__).parent / "data" / "g025_denied_evidence_boundary.json"
G005_FIXTURE = Path(__file__).parents[1] / "judgment" / "data" / "g005_empty_fetch_eligibility.json"


def _fixture(*, topic: str = "ldap", relation: bool = False):
    check = CheckResult(
        check_id="tls_check",
        topic_id=topic,
        label="TLS check",
        outcome=CheckOutcome.passed,
        evidence_ids=[EVIDENCE_ID],
        message="passed",
    )
    snapshot = SnapshotRef(kind=SnapshotKind.pit, key="3" * 64, at=NOW)
    source = EvidenceSourceCheck(step_id="tls_check", operand_ids=[])
    item = EvidenceItem(
        evidence_id=EVIDENCE_ID,
        topic_id=topic,
        fetch_id=None,
        check_id="tls_check",
        kind="check",
        source=source,
        snapshot=snapshot,
        values={"outcome": "passed"},
        visibility=Visibility.full,
        scope_hash="4" * 64,
    )
    pack = EvidencePack(
        question_id=UUID("a650f780-5e2c-4cf3-a234-1ebd59c22b05"),
        environment_id="alpha",
        topic_id=topic,
        policy_hash=POLICY,
        content_sha=CONTENT,
        fetches=[],
        checks=[check],
        items=[item],
        sha256="5" * 64,
    )
    required = {"result": ("outcome",)}
    relations = []
    if relation:
        required["same"] = ("outcome",)
        relations = [FindingRelationSameRecord(kind="same_record", bindings=["result", "same"])]
    template = FindingTemplate(
        template_id="tls_ok",
        topic_id=topic,
        kind="observation",
        required_bindings=required,
        texts=LocaleText(
            en="TLS check: {result}" + (" for {same}" if relation else ""),
            es="Verificación TLS: {result}" + (" para {same}" if relation else ""),
        ),
        required_check_outcomes=[
            RequiredCheckOutcome(check_id="tls_check", outcome=CheckOutcome.passed)
        ],
        allowed_evidence_kinds=["check", "row"],
        relations=relations,
    )
    context = ValidationContext(
        topic_pack=TopicPromptPack(
            topic_id=topic,
            language="es",
            content_sha=CONTENT,
            sha256="6" * 64,
            missing=[],
        ),
        templates=(template,),
        policy_hash=POLICY,
        content_sha=CONTENT,
        language="es",
        expected_checks=(check,),
    )
    return pack, context, item


def _raw(candidate: dict[str, object]) -> RawJudgment:
    return RawJudgment(
        usage=None,
        text=json.dumps({"schema_version": "1", "findings": [candidate]}),
        stop_reason="end_turn",
        guardrail_intervened=False,
        provider_request_id="fixture-request",
    )


def _candidate(*, evidence_id: str = EVIDENCE_ID, evidence_ids: list[str] | None = None):
    return {
        "finding_id": "tls_observation",
        "kind": "observation",
        "template_id": "tls_ok",
        "evidence_ids": evidence_ids or [evidence_id],
        "bindings": {"result": {"evidence_id": evidence_id, "field": "outcome"}},
    }


def _g022_case(variant: str) -> tuple[dict[str, object], dict[str, object]]:
    assert_fixture_matches_all_variants(
        "B4-G022.topic-evidence-binding.private", G022_BINDING_FIXTURE
    )
    parsed: object = json.loads(G022_BINDING_FIXTURE.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise AssertionError("G022 binding fixture must be a JSON object")
    fixture = cast(dict[str, object], parsed)
    variants = fixture.get("variants")
    if not isinstance(variants, dict) or not isinstance(variants.get(variant), dict):
        raise AssertionError(f"G022 binding fixture has no {variant} vector")
    return fixture, cast(dict[str, object], variants[variant])


def _renderer_case(variant: str) -> dict[str, object]:
    parsed: object = json.loads(RENDERER_FIXTURE.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise AssertionError("renderer fixture must be a JSON object")
    variants = parsed.get("variants")
    if not isinstance(variants, dict) or not isinstance(variants.get(variant), dict):
        raise AssertionError(f"renderer fixture has no {variant} variant")
    return cast(dict[str, object], variants[variant])


def _independent_renderer_case(path: Path, variant: str) -> dict[str, object]:
    parsed: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise AssertionError(f"{path.name} must be a JSON object")
    variants = parsed.get("variants")
    if not isinstance(variants, dict) or not isinstance(variants.get(variant), dict):
        raise AssertionError(f"{path.name} has no {variant} variant")
    return cast(dict[str, object], variants[variant])


def _g025_case(variant: str) -> dict[str, object]:
    assert_fixture_matches_all_variants("B4-G025.denied-evidence-boundary.private", G025_FIXTURE)
    return _independent_renderer_case(G025_FIXTURE, variant)


@pytest.mark.case_id("B4-G022.topic-evidence-binding.private")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G022.topic-evidence-binding.private"))
@pytest.mark.variant("positive")
@pytest.mark.fixture_sha256(
    canonical_fixture_sha256("B4-G022.topic-evidence-binding.private", "positive")
)
def test_b4_g022_valid_topic_bound_evidence_is_rendered_from_its_citation() -> None:
    fixture, expected = _g022_case("positive")
    pack, context, _ = _fixture(topic=str(fixture["primary_topic"]))
    evidence_id = str(fixture["evidence_id"])
    candidate = _candidate(evidence_id=evidence_id)
    candidate["finding_id"] = "tls_observation"

    result = FindingValidator().validate(_raw(candidate), pack, context=context)

    assert result.state == expected["expected_state"]
    assert len(result.removed) == expected["expected_removed"]
    assert result.sentences[0].evidence_ids == [evidence_id]


@pytest.mark.case_id("B4-G022.topic-evidence-binding.private")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G022.topic-evidence-binding.private"))
@pytest.mark.variant("negative")
@pytest.mark.fixture_sha256(
    canonical_fixture_sha256("B4-G022.topic-evidence-binding.private", "negative")
)
def test_b4_g022_foreign_topic_evidence_is_removed_without_leaking_topic() -> None:
    fixture, expected = _g022_case("negative")
    pack, context, item = _fixture(topic=str(fixture["primary_topic"]))
    foreign = item.model_copy(update={"topic_id": fixture["foreign_topic"]})
    pack = pack.model_copy(update={"items": [foreign]})
    candidate = _candidate(evidence_id=str(fixture["evidence_id"]))

    result = FindingValidator().validate(_raw(candidate), pack, context=context)

    assert result.state == expected["expected_state"]
    assert len(result.removed) == expected["expected_removed"]
    assert result.removed[0].reason == RemovedReason.cross_topic
    assert str(fixture["foreign_topic"]) not in result.model_dump_json()


@pytest.mark.case_id("B4-G022.topic-evidence-binding.private")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G022.topic-evidence-binding.private"))
@pytest.mark.variant("boundary")
@pytest.mark.fixture_sha256(
    canonical_fixture_sha256("B4-G022.topic-evidence-binding.private", "boundary")
)
def test_b4_g022_mixed_topic_boundary_keeps_only_the_cited_local_candidate() -> None:
    fixture, expected = _g022_case("boundary")
    pack, context, item = _fixture(topic=str(fixture["primary_topic"]))
    foreign = item.model_copy(
        update={
            "evidence_id": fixture["foreign_evidence_id"],
            "topic_id": fixture["foreign_topic"],
        }
    )
    pack = pack.model_copy(update={"items": [item, foreign]})
    local_id = str(fixture["evidence_id"])
    foreign_id = str(fixture["foreign_evidence_id"])
    local = _candidate(evidence_id=local_id)
    cross_topic = _candidate(evidence_id=foreign_id)
    cross_topic["finding_id"] = "foreign_finding"
    raw = RawJudgment(
        text=json.dumps({"schema_version": "1", "findings": [local, cross_topic]}),
        stop_reason="end_turn",
        guardrail_intervened=False,
        provider_request_id="fixture-request",
    )

    result = FindingValidator().validate(raw, pack, context=context)

    assert result.state == expected["expected_state"]
    assert len(result.removed) == expected["expected_removed"]
    assert len(result.sentences) == expected["retained_candidates"]
    assert result.sentences[0].evidence_ids == [local_id]
    assert foreign_id not in result.model_dump_json()


@pytest.mark.case_id("B4-G022.topic-evidence-binding.private")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G022.topic-evidence-binding.private"))
@pytest.mark.variant("failure")
@pytest.mark.fixture_sha256(
    canonical_fixture_sha256("B4-G022.topic-evidence-binding.private", "failure")
)
def test_b4_g022_cross_topic_context_binding_fails_closed() -> None:
    fixture, expected = _g022_case("failure")
    pack, context, _ = _fixture(topic=str(fixture["primary_topic"]))
    foreign_context = context.model_copy(
        update={
            "topic_pack": context.topic_pack.model_copy(
                update={"topic_id": fixture["foreign_topic"]}
            )
        }
    )
    candidate = _candidate(evidence_id=str(fixture["evidence_id"]))

    result = FindingValidator().validate(_raw(candidate), pack, context=foreign_context)

    assert result.state == expected["expected_state"]
    assert len(result.removed) == expected["expected_removed"]
    assert str(fixture["foreign_topic"]) not in result.model_dump_json()


def test_bilingual_renderer_uses_cited_value_and_escapes_hostile_value() -> None:
    pack, context, item = _fixture()
    hostile = item.model_copy(
        update={"values": {"outcome": "passed", "agent.name": "<script>alert(1)</script>"}}
    )
    pack = pack.model_copy(update={"items": [hostile]})
    template = context.templates[0].model_copy(
        update={"required_bindings": {"result": ("agent.name",)}}
    )
    context = context.model_copy(update={"templates": (template,)})
    candidate = _candidate()
    candidate["bindings"] = {"result": {"evidence_id": EVIDENCE_ID, "field": "agent.name"}}

    result = FindingValidator().validate(_raw(candidate), pack, context=context)

    assert result.state == JudgmentState.validated
    assert result.sentences[0].text == "Verificación TLS: ⟦&lt;script&gt;alert(1)&lt;/script&gt;⟧"
    assert "<script>" not in result.model_dump_json()


def test_g021_g039_approved_spanish_template_owns_rendered_finding_text() -> None:
    case = _renderer_case("positive")
    pack, context, _ = _fixture()

    result = FindingValidator().validate(_raw(_candidate()), pack, context=context)

    assert result.state == case["expected_state"]
    assert result.sentences[0].text == case["expected_text"]


def test_g021_missing_approved_template_cannot_be_replaced_by_model_text() -> None:
    case = _renderer_case("negative")
    pack, context, _ = _fixture()
    context = context.model_copy(
        update={
            "topic_pack": context.topic_pack.model_copy(
                update={"document_section": None, "missing": [str(case["missing_item"])]}
            ),
            "templates": (),
        }
    )

    result = FindingValidator().validate(_raw(_candidate()), pack, context=context)

    assert result.state == case["expected_state"]
    assert result.sentences == []
    assert len(result.removed) == case["removed_candidates"]


def test_g039_hostile_cited_value_is_escaped_in_spanish_template_boundary() -> None:
    case = _renderer_case("boundary")
    pack, context, item = _fixture()
    hostile = item.model_copy(
        update={"values": {"outcome": "passed", "agent.name": str(case["hostile_value"])}}
    )
    pack = pack.model_copy(update={"items": [hostile]})
    template = context.templates[0].model_copy(
        update={"required_bindings": {"result": ("agent.name",)}}
    )
    context = context.model_copy(update={"templates": (template,)})
    candidate = _candidate()
    candidate["bindings"] = {"result": {"evidence_id": EVIDENCE_ID, "field": "agent.name"}}

    result = FindingValidator().validate(_raw(candidate), pack, context=context)

    assert result.state == case["expected_state"]
    assert result.sentences[0].text == case["expected_text"]
    assert str(case["hostile_value"]) not in result.model_dump_json()


def test_g039_invalid_json_is_a_finite_failure_without_rendered_prose() -> None:
    case = _renderer_case("failure")
    pack, context, _ = _fixture()
    malformed = RawJudgment(
        text=str(case["raw_text"]),
        stop_reason="end_turn",
        guardrail_intervened=False,
        provider_request_id="fixture-request",
    )

    result = FindingValidator().validate(malformed, pack, context=context)

    assert result.state == case["expected_state"]
    assert result.sentences == []


@pytest.mark.parametrize(
    "variant", registered_case_variants("B4-G021.approved-template-boundary.private")
)
def test_g021_approved_template_never_comes_from_model(variant: str) -> None:
    assert_fixture_matches_all_variants("B4-G021.approved-template-boundary.private", G021_FIXTURE)
    case = _independent_renderer_case(G021_FIXTURE, variant)
    pack, context, item = _fixture()
    candidate = _candidate()
    raw = _raw(candidate)
    if variant == "negative":
        context = context.model_copy(
            update={
                "topic_pack": context.topic_pack.model_copy(
                    update={"document_section": None, "missing": [str(case["missing_item"])]}
                ),
                "templates": (),
            }
        )
    elif variant == "boundary":
        candidate["bindings"] = {}
        raw = _raw(candidate)
    elif variant == "failure":
        raw = RawJudgment(
            text=str(case["raw_text"]),
            stop_reason="end_turn",
            guardrail_intervened=False,
            provider_request_id="g021-failure",
        )

    result = FindingValidator().validate(raw, pack, context=context)

    assert result.state == case["expected_state"]
    if variant in ("negative", "boundary", "failure"):
        assert result.sentences == []
    else:
        assert result.sentences[0].text == case["expected_text"]


@pytest.mark.parametrize("variant", registered_case_variants("B4-G039.spanish-renderer.private"))
def test_g039_spanish_renderer_uses_only_approved_localized_text(variant: str) -> None:
    assert_fixture_matches_all_variants("B4-G039.spanish-renderer.private", G039_FIXTURE)
    case = _independent_renderer_case(G039_FIXTURE, variant)
    pack, context, item = _fixture()
    raw = _raw(_candidate())
    if variant == "negative":
        context = context.model_copy(update={"templates": ()})
    elif variant == "boundary":
        hostile = item.model_copy(
            update={"values": {"outcome": "passed", "agent.name": str(case["hostile_value"])}}
        )
        pack = pack.model_copy(update={"items": [hostile]})
        template = context.templates[0].model_copy(
            update={"required_bindings": {"result": ("agent.name",)}}
        )
        context = context.model_copy(update={"templates": (template,)})
        candidate = _candidate()
        candidate["bindings"] = {"result": {"evidence_id": EVIDENCE_ID, "field": "agent.name"}}
        raw = _raw(candidate)
    elif variant == "failure":
        raw = RawJudgment(
            text=str(case["raw_text"]),
            stop_reason="end_turn",
            guardrail_intervened=False,
            provider_request_id="g039-failure",
        )

    result = FindingValidator().validate(raw, pack, context=context)

    assert context.language == case["language"]
    assert result.state == case["expected_state"]
    if variant in ("negative", "failure"):
        assert result.sentences == []
    else:
        rendered = result.sentences[0].text
        assert rendered == case["expected_text"]
        assert "<script>" not in result.model_dump_json()


@pytest.mark.parametrize(
    "variant", registered_case_variants("B4-G025.denied-evidence-boundary.private")
)
def test_g025_denied_evidence_never_becomes_a_false_clear(variant: str) -> None:
    case = _g025_case(variant)
    pack, context, item = _fixture()
    denied_check = pack.checks[0].model_copy(update={"outcome": CheckOutcome.denied})
    denied_item = item.model_copy(update={"values": {"outcome": "denied"}})
    pack = pack.model_copy(update={"checks": [denied_check], "items": [denied_item]})

    if variant == "failure":
        raw = RawJudgment(
            text=str(case["raw_text"]),
            stop_reason="end_turn",
            guardrail_intervened=False,
            provider_request_id="g025-failure",
        )
    elif variant == "boundary":
        passed_id = "ev1_" + "7" * 64
        passed_check = denied_check.model_copy(
            update={"check_id": "tls_check_passed", "outcome": CheckOutcome.passed}
        )
        passed_item = denied_item.model_copy(
            update={
                "evidence_id": passed_id,
                "check_id": "tls_check_passed",
                "values": {"outcome": "passed"},
            }
        )
        pack = pack.model_copy(
            update={
                "checks": [denied_check, passed_check],
                "items": [denied_item, passed_item],
            }
        )
        base = context.templates[0]
        denied_template = base.model_copy(
            update={
                "template_id": "tls_denied",
                "required_check_outcomes": [
                    RequiredCheckOutcome(check_id="tls_check", outcome=CheckOutcome.denied)
                ],
            }
        )
        passed_template = base.model_copy(
            update={
                "template_id": "tls_passed",
                "required_check_outcomes": [
                    RequiredCheckOutcome(check_id="tls_check_passed", outcome=CheckOutcome.passed)
                ],
            }
        )
        context = context.model_copy(
            update={
                "templates": (denied_template, passed_template),
                "expected_checks": (denied_check, passed_check),
            }
        )
        denied_candidate = _candidate()
        denied_candidate["finding_id"] = "denied_tls_observation"
        denied_candidate["template_id"] = "tls_denied"
        passed_candidate = _candidate(evidence_id=passed_id)
        passed_candidate["finding_id"] = "passed_tls_observation"
        passed_candidate["template_id"] = "tls_passed"
        raw = RawJudgment(
            text=json.dumps(
                {"schema_version": "1", "findings": [denied_candidate, passed_candidate]}
            ),
            stop_reason="end_turn",
            guardrail_intervened=False,
            provider_request_id="g025-boundary",
        )
    else:
        requirement = RequiredCheckOutcome(
            check_id="tls_check", outcome=CheckOutcome(str(case["required_outcome"]))
        )
        template = context.templates[0].model_copy(
            update={"required_check_outcomes": [requirement]}
        )
        context = context.model_copy(
            update={"templates": (template,), "expected_checks": (denied_check,)}
        )
        raw = _raw(_candidate())

    result = FindingValidator().validate(raw, pack, context=context)

    if variant == "boundary":
        assert len(result.sentences) == case["expected_rendered"]
        assert len(result.removed) == case["expected_removed"]
        texts = [sentence.text for sentence in result.sentences]
        assert "Verificación TLS: denied" in texts
        assert "Everything is healthy" not in texts
    else:
        assert result.state == case["expected_state"]
        if variant == "positive":
            assert result.sentences[0].text == case["expected_text"]
        else:
            assert result.sentences == []
            if variant == "negative":
                assert result.removed[0].reason == case["removed_reason"]


@pytest.mark.case_id("B4-G005.empty-fetch-eligibility.private")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G005.empty-fetch-eligibility.private"))
@pytest.mark.variant("failure")
@pytest.mark.fixture_sha256(
    canonical_fixture_sha256("B4-G005.empty-fetch-eligibility.private", "failure")
)
def test_g005_malicious_alert_finding_cannot_be_invented_from_empty_evidence() -> None:
    assert_fixture_matches_all_variants("B4-G005.empty-fetch-eligibility.private", G005_FIXTURE)
    case = _independent_renderer_case(G005_FIXTURE, "failure")
    pack, context, _ = _fixture()
    empty_pack = pack.model_copy(update={"checks": [], "items": []})
    empty_context = context.model_copy(update={"expected_checks": ()})

    result = FindingValidator().validate(_raw(_candidate()), empty_pack, context=empty_context)

    assert result.state == case["expected_state"]
    assert result.sentences == []
    assert result.removed[0].reason == case["expected_removed_reason"]


def test_aggregate_outcome_and_reviewed_enum_values_are_strict() -> None:
    pack, context, item = _fixture()
    malformed = item.model_copy(update={"values": {"outcome": "possibly"}})
    result = FindingValidator().validate(
        _raw(_candidate()), pack.model_copy(update={"items": [malformed]}), context=context
    )
    assert result.state == JudgmentState.all_removed
    assert result.removed[0].reason == RemovedReason.unsupported_value


def test_duplicate_candidate_ids_remove_every_copy() -> None:
    pack, context, _ = _fixture()
    candidate = _candidate()
    raw = RawJudgment(
        text=json.dumps({"schema_version": "1", "findings": [candidate, candidate]}),
        stop_reason="end_turn",
        guardrail_intervened=False,
        provider_request_id="fixture-request",
    )

    result = FindingValidator().validate(raw, pack, context=context)

    assert result.state == JudgmentState.all_removed
    assert len(result.removed) == 2
    assert all(removed.reason == RemovedReason.duplicate_id for removed in result.removed)


def test_cross_topic_and_unknown_evidence_are_removed_without_candidate_text() -> None:
    pack, context, item = _fixture()
    cross_topic = item.model_copy(update={"topic_id": "dns"})
    bad_pack = pack.model_copy(update={"items": [cross_topic]})

    result = FindingValidator().validate(_raw(_candidate()), bad_pack, context=context)

    assert result.state == JudgmentState.all_removed
    assert result.removed[0].reason == RemovedReason.cross_topic
    assert "dns" not in result.model_dump_json()
    unknown = FindingValidator().validate(
        _raw(_candidate(evidence_id="ev1_" + "9" * 64)), pack, context=context
    )
    assert unknown.removed[0].reason == RemovedReason.unknown_evidence


def test_binding_mismatch_and_false_same_record_relation_are_removed() -> None:
    pack, context, item = _fixture(relation=True)
    result = FindingValidator().validate(
        _raw(
            {
                "finding_id": "tls_observation",
                "kind": "observation",
                "template_id": "tls_ok",
                "evidence_ids": [EVIDENCE_ID],
                "bindings": {"result": {"evidence_id": EVIDENCE_ID, "field": "outcome"}},
            }
        ),
        pack,
        context=context,
    )
    assert result.state == JudgmentState.all_removed
    assert result.removed[0].reason == RemovedReason.bad_binding

    candidate = _candidate()
    candidate["bindings"] = {
        "result": {"evidence_id": EVIDENCE_ID, "field": "outcome"},
        "same": {"evidence_id": EVIDENCE_ID, "field": "outcome"},
    }
    candidate["evidence_ids"] = [EVIDENCE_ID]
    result = FindingValidator().validate(_raw(candidate), pack, context=context)
    assert result.state == JudgmentState.all_removed
    assert result.removed[0].reason == RemovedReason.bad_relation


def test_prerequisite_and_context_scope_mismatch_fail_closed() -> None:
    pack, context, _ = _fixture()
    from ai_soc.contracts.models import RequiredCheckOutcome

    template = context.templates[0].model_copy(
        update={
            "required_check_outcomes": [
                RequiredCheckOutcome(check_id="tls_check", outcome=CheckOutcome.failed)
            ]
        }
    )
    context = context.model_copy(update={"templates": (template,)})
    result = FindingValidator().validate(_raw(_candidate()), pack, context=context)
    assert result.removed[0].reason == RemovedReason.failed_prerequisite

    foreign = context.model_copy(update={"policy_hash": "8" * 64})
    assert (
        FindingValidator().validate(_raw(_candidate()), pack, context=foreign).state
        == JudgmentState.invalid_output
    )


def test_check_binding_must_match_required_check_outcome() -> None:
    pack, context, item = _fixture()
    required = RequiredCheckOutcome(check_id="tls_check", outcome=CheckOutcome.passed)
    template = context.templates[0].model_copy(update={"required_check_outcomes": [required]})
    context = context.model_copy(update={"templates": (template,)})
    unrelated_id = "ev1_" + "7" * 64
    unrelated_check = pack.checks[0].model_copy(update={"check_id": "other_check"})
    unrelated_item = item.model_copy(
        update={
            "evidence_id": unrelated_id,
            "check_id": "other_check",
            "values": {"outcome": "passed"},
        }
    )
    pack = pack.model_copy(
        update={"checks": [*pack.checks, unrelated_check], "items": [item, unrelated_item]}
    )
    context = context.model_copy(update={"expected_checks": (pack.checks[0], unrelated_check)})

    mismatch = _candidate(evidence_id=unrelated_id)
    result = FindingValidator().validate(_raw(mismatch), pack, context=context)

    assert result.state == JudgmentState.all_removed
    assert result.removed[0].reason == RemovedReason.bad_binding

    matching = _candidate()
    accepted = FindingValidator().validate(_raw(matching), pack, context=context)

    assert accepted.state == JudgmentState.validated
    assert accepted.sentences[0].text == "Verificación TLS: passed"


def test_no_findings_and_invalid_or_oversize_outputs_have_finite_states() -> None:
    pack, context, _ = _fixture()
    empty = RawJudgment(
        text='{"schema_version":"1","findings":[]}',
        stop_reason="end_turn",
        guardrail_intervened=False,
        provider_request_id="x",
    )
    assert (
        FindingValidator().validate(empty, pack, context=context).state == JudgmentState.no_findings
    )
    malformed = empty.model_copy(update={"text": "not JSON"})
    assert (
        FindingValidator().validate(malformed, pack, context=context).state
        == JudgmentState.invalid_output
    )
    large = empty.model_copy(update={"text": " " * 65_537})
    assert (
        FindingValidator().validate(large, pack, context=context).state
        == JudgmentState.invalid_output
    )
    nested = empty.model_copy(
        update={"text": '{"schema_version":"1","findings":' + "[" * 17 + "]" * 17 + "}"}
    )
    assert (
        FindingValidator().validate(nested, pack, context=context).state
        == JudgmentState.invalid_output
    )
    duplicate_key = empty.model_copy(
        update={"text": '{"schema_version":"1","schema_version":"1","findings":[]}'}
    )
    assert (
        FindingValidator().validate(duplicate_key, pack, context=context).state
        == JudgmentState.invalid_output
    )


def test_h3_aggregate_scope_rejects_all_agent_count_bound_to_single_row() -> None:
    question_id = UUID("a650f780-5e2c-4cf3-a234-1ebd59c22b05")
    window = ResolvedWindow(
        start=NOW - timedelta(days=1),
        end=NOW,
        semantics="rolling",
        source_text="last 24 hours",
        timezone="UTC",
        anchor_at=NOW,
    )
    fetch = FetchSpec(
        fetch_id="alerts_rows",
        template_id=TemplateId.alerts_rows_v1,
        window=window,
        filters=[],
        page_size=20,
    )
    snapshot = SnapshotRef(kind=SnapshotKind.pit, key="9" * 64, at=NOW)
    policy = POLICY
    _, row = row_item(
        question_id=question_id,
        environment_id="alpha",
        topic_id="ldap",
        fetch=fetch,
        snapshot=snapshot,
        visibility=Visibility.full,
        policy_hash=policy,
        index_alias="alerts",
        record_id="alpha-ldap-007",
        values={FieldId.agent_id: "007"},
    )
    total = Count(
        value=250,
        relation="eq",
        scope="matching_visible_records",
        computed_by="indexer",
        approximate=False,
    )
    count_evidence = count_item(
        question_id=question_id,
        environment_id="alpha",
        topic_id="ldap",
        fetch=fetch,
        snapshot=snapshot,
        visibility=Visibility.full,
        policy_hash=policy,
        count=total,
    )
    pack = EvidencePack(
        question_id=question_id,
        environment_id="alpha",
        topic_id="ldap",
        policy_hash=policy,
        content_sha=CONTENT,
        fetches=[],
        checks=[],
        items=[row, count_evidence],
        sha256="5" * 64,
    )
    template = FindingTemplate(
        template_id="agent_alert_count",
        topic_id="ldap",
        kind="observation",
        required_bindings={"count": ("count",), "agent": (FieldId.agent_id,)},
        texts=LocaleText(
            en="Agent {agent} has {count} alerts",
            es="Agente {agent} tiene {count} alertas",
        ),
        required_check_outcomes=[],
        allowed_evidence_kinds=["row", "aggregate"],
        relations=[
            FindingRelationAggregateScope(
                kind="aggregate_scope",
                count_binding="count",
                entity_bindings={"agent": FieldId.agent_id},
            )
        ],
    )
    context = ValidationContext(
        topic_pack=TopicPromptPack(
            topic_id="ldap",
            language="en",
            content_sha=CONTENT,
            sha256="6" * 64,
            missing=[],
        ),
        templates=(template,),
        policy_hash=policy,
        content_sha=CONTENT,
        language="en",
        expected_checks=(),
    )
    candidate = {
        "finding_id": "agent_count",
        "kind": "observation",
        "template_id": "agent_alert_count",
        "evidence_ids": [row.evidence_id, count_evidence.evidence_id],
        "bindings": {
            "count": {"evidence_id": count_evidence.evidence_id, "field": "count"},
            "agent": {"evidence_id": row.evidence_id, "field": FieldId.agent_id},
        },
    }
    result = FindingValidator().validate(_raw(candidate), pack, context=context)
    assert result.state == JudgmentState.all_removed
    assert result.removed[0].reason == RemovedReason.bad_relation


def test_h3_aggregate_scope_accepts_count_when_entity_filter_matches_row() -> None:
    question_id = UUID("b650f780-5e2c-4cf3-a234-1ebd59c22b05")
    window = ResolvedWindow(
        start=NOW - timedelta(days=1),
        end=NOW,
        semantics="rolling",
        source_text="last 24 hours",
        timezone="UTC",
        anchor_at=NOW,
    )
    agent_filter = FieldId.agent_id

    fetch = FetchSpec(
        fetch_id="alerts_rows",
        template_id=TemplateId.alerts_rows_v1,
        window=window,
        filters=[Filter(field=agent_filter, op="eq", value="007")],
        page_size=20,
    )
    snapshot = SnapshotRef(kind=SnapshotKind.pit, key="9" * 64, at=NOW)
    policy = POLICY
    _, row = row_item(
        question_id=question_id,
        environment_id="alpha",
        topic_id="ldap",
        fetch=fetch,
        snapshot=snapshot,
        visibility=Visibility.full,
        policy_hash=policy,
        index_alias="alerts",
        record_id="alpha-ldap-007",
        values={FieldId.agent_id: "007"},
    )
    scoped = Count(
        value=3,
        relation="eq",
        scope="matching_visible_records",
        computed_by="indexer",
        approximate=False,
    )
    count_evidence = count_item(
        question_id=question_id,
        environment_id="alpha",
        topic_id="ldap",
        fetch=fetch,
        snapshot=snapshot,
        visibility=Visibility.full,
        policy_hash=policy,
        count=scoped,
    )
    pack = EvidencePack(
        question_id=question_id,
        environment_id="alpha",
        topic_id="ldap",
        policy_hash=policy,
        content_sha=CONTENT,
        fetches=[],
        checks=[],
        items=[row, count_evidence],
        sha256="5" * 64,
    )
    template = FindingTemplate(
        template_id="agent_alert_count",
        topic_id="ldap",
        kind="observation",
        required_bindings={"count": ("count",), "agent": (FieldId.agent_id,)},
        texts=LocaleText(
            en="Agent {agent} has {count} alerts",
            es="Agente {agent} tiene {count} alertas",
        ),
        required_check_outcomes=[],
        allowed_evidence_kinds=["row", "aggregate"],
        relations=[
            FindingRelationAggregateScope(
                kind="aggregate_scope",
                count_binding="count",
                entity_bindings={"agent": FieldId.agent_id},
            )
        ],
    )
    context = ValidationContext(
        topic_pack=TopicPromptPack(
            topic_id="ldap",
            language="en",
            content_sha=CONTENT,
            sha256="6" * 64,
            missing=[],
        ),
        templates=(template,),
        policy_hash=policy,
        content_sha=CONTENT,
        language="en",
        expected_checks=(),
    )
    candidate = {
        "finding_id": "agent_count",
        "kind": "observation",
        "template_id": "agent_alert_count",
        "evidence_ids": [row.evidence_id, count_evidence.evidence_id],
        "bindings": {
            "count": {"evidence_id": count_evidence.evidence_id, "field": "count"},
            "agent": {"evidence_id": row.evidence_id, "field": FieldId.agent_id},
        },
    }
    result = FindingValidator().validate(_raw(candidate), pack, context=context)
    assert result.state == JudgmentState.validated
    assert result.sentences[0].text == "Agent 007 has 3 alerts"


def test_stop_reason_content_filtered_maps_to_guardrail_blocked() -> None:
    pack, context, _ = _fixture()
    raw = RawJudgment(
        text='{"schema_version":"1","findings":[]}',
        stop_reason="content_filtered",
        guardrail_intervened=False,
        provider_request_id="x",
    )
    assert (
        FindingValidator().validate(raw, pack, context=context).state
        == JudgmentState.guardrail_blocked
    )


def test_unknown_stop_reason_maps_to_model_unavailable() -> None:
    pack, context, _ = _fixture()
    raw = RawJudgment(
        text='{"schema_version":"1","findings":[]}',
        stop_reason="garbage_reason",
        guardrail_intervened=False,
        provider_request_id="x",
    )
    assert (
        FindingValidator().validate(raw, pack, context=context).state
        == JudgmentState.model_unavailable
    )


def test_guardrail_intervention_never_parses_or_returns_provider_text() -> None:
    pack, context, _ = _fixture()
    raw = RawJudgment(
        text="first-token-secret",
        stop_reason="guardrail_intervened",
        guardrail_intervened=True,
        provider_request_id="x",
    )
    result = FindingValidator().validate(raw, pack, context=context)
    assert result.state == JudgmentState.guardrail_blocked
    assert "first-token-secret" not in result.model_dump_json()


def test_duplicate_catalog_template_ids_reject_even_with_empty_findings() -> None:
    pack, context, _ = _fixture()
    duplicated = context.model_copy(
        update={"templates": (*context.templates, context.templates[0])}
    )
    raw = RawJudgment(
        text='{"schema_version":"1","findings":[]}',
        stop_reason="end_turn",
        guardrail_intervened=False,
        provider_request_id="x",
    )
    result = FindingValidator().validate(raw, pack, context=duplicated)
    assert result.state == JudgmentState.invalid_output
    assert result.sentences == []
    assert result.removed == []


@pytest.mark.parametrize(
    "observed", [None, CheckOutcome.unknown, CheckOutcome.not_configured, CheckOutcome.failed]
)
def test_unmet_prerequisite_keeps_catalog_and_allows_unrelated_supported_finding(
    observed: CheckOutcome | None,
) -> None:
    pack, context, item = _fixture()
    base = context.templates[0]
    dependent = base.model_copy(
        update={
            "template_id": "tls_dependent",
            "required_check_outcomes": [
                RequiredCheckOutcome(check_id="tls_check", outcome=CheckOutcome.passed)
            ],
        }
    )
    independent = base.model_copy(
        update={
            "template_id": "tls_independent",
            "required_check_outcomes": [],
            "allowed_evidence_kinds": ["row"],
            "required_bindings": {"result": (FieldId.agent_id,)},
        }
    )
    if observed is None:
        pack = pack.model_copy(update={"checks": []})
        context = context.model_copy(
            update={"templates": (dependent, independent), "expected_checks": ()}
        )
    else:
        check = pack.checks[0].model_copy(update={"outcome": observed})
        changed_item = item.model_copy(update={"values": {"outcome": observed.value}})
        pack = pack.model_copy(update={"checks": [check], "items": [changed_item]})
        context = context.model_copy(
            update={"templates": (dependent, independent), "expected_checks": (check,)}
        )

    row_window = ResolvedWindow(
        start=NOW - timedelta(days=1),
        end=NOW,
        semantics="rolling",
        source_text="last 24 hours",
        timezone="UTC",
        anchor_at=NOW,
    )
    row_fetch = FetchSpec(
        fetch_id="alerts_rows",
        template_id=TemplateId.alerts_rows_v1,
        window=row_window,
        filters=[],
        page_size=20,
    )
    _, row_evidence = row_item(
        question_id=pack.question_id,
        environment_id="alpha",
        topic_id="ldap",
        fetch=row_fetch,
        snapshot=SnapshotRef(kind=SnapshotKind.pit, key="9" * 64, at=NOW),
        visibility=Visibility.full,
        policy_hash=POLICY,
        index_alias="alerts",
        record_id="alpha-ldap-007",
        values={FieldId.agent_id: "007"},
    )
    pack = pack.model_copy(update={"items": [*pack.items, row_evidence]})
    dependent_candidate = _candidate()
    dependent_candidate.update(finding_id="dependent_candidate", template_id="tls_dependent")
    independent_candidate = {
        "finding_id": "independent_candidate",
        "kind": "observation",
        "template_id": "tls_independent",
        "evidence_ids": [row_evidence.evidence_id],
        "bindings": {"result": {"evidence_id": row_evidence.evidence_id, "field": "agent.id"}},
    }
    raw = RawJudgment(
        text=json.dumps(
            {"schema_version": "1", "findings": [dependent_candidate, independent_candidate]}
        ),
        stop_reason="end_turn",
        guardrail_intervened=False,
        provider_request_id="prerequisite-observation-fixture",
    )

    result = FindingValidator().validate(raw, pack, context=context)

    assert len(context.templates) == 2
    assert len(pack.checks) == (0 if observed is None else 1)
    assert len(result.sentences) == 1
    assert result.sentences[0].finding_id == "independent_candidate"
    assert len(result.removed) == 1
    assert result.removed[0].finding_id == "dependent_candidate"
    assert result.removed[0].reason == RemovedReason.failed_prerequisite


@pytest.mark.parametrize(
    "other_prerequisite", [False, True], ids=["no-prerequisites", "other-prerequisite"]
)
def test_check_citation_outside_declared_prerequisites_is_removed(
    other_prerequisite: bool,
) -> None:
    pack, context, _ = _fixture()
    requirements = (
        [RequiredCheckOutcome(check_id="tls_other", outcome=CheckOutcome.passed)]
        if other_prerequisite
        else []
    )
    template = context.templates[0].model_copy(
        update={"template_id": "tls_undeclared", "required_check_outcomes": requirements}
    )
    context = context.model_copy(update={"templates": (template,)})
    candidate = _candidate()
    candidate["template_id"] = "tls_undeclared"

    result = FindingValidator().validate(_raw(candidate), pack, context=context)

    assert result.state == JudgmentState.all_removed
    assert result.removed[0].reason == RemovedReason.bad_binding
