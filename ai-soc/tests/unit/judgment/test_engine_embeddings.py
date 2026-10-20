from __future__ import annotations

import asyncio
import io
import json
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest
from case_binding import (
    assert_fixture_matches_all_variants,
    canonical_acceptance_ids,
    canonical_fixture_sha256,
    registered_case_variants,
)

from ai_soc.contracts.models import (
    AdmissionGrant,
    CallKind,
    CheckOutcome,
    CheckResult,
    Count,
    Effort,
    EmptyProof,
    EvidenceItem,
    EvidencePack,
    EvidenceSourceCheck,
    ExecutionContext,
    FetchResult,
    FetchScope,
    FetchSpec,
    FetchState,
    FetchStep,
    FieldId,
    Filter,
    FilterProbe,
    GuardrailPin,
    IndexFamily,
    JudgmentState,
    LocaleText,
    ModelCapability,
    PlaybookDefinition,
    Ready,
    ResolvedWindow,
    SnapshotKind,
    SnapshotRef,
    TemplateId,
    TopicPlan,
    TopicPromptPack,
    TraceContext,
    ValidationContext,
    Visibility,
)
from ai_soc.judgment.bedrock import ProviderFailure
from ai_soc.judgment.capabilities import CapabilityError, EmbeddingCapability
from ai_soc.judgment.embeddings import BedrockEmbeddingProvider
from ai_soc.judgment.engine import JudgmentEngine, ModelSelectionRequired

NOW = datetime(2026, 1, 1, tzinfo=UTC)
EMPTY_OUTCOME_FIXTURE = Path(__file__).parent / "data" / "g005_g050_empty_outcomes.json"
ELIGIBILITY_FIXTURE = Path(__file__).parent / "data" / "g018_g024_g025_topic_eligibility.json"
G018_FIXTURE = Path(__file__).parent / "data" / "g018_topic_isolation.json"
G024_FIXTURE = Path(__file__).parent / "data" / "g024_denial_precedence.json"
G005_FIXTURE = Path(__file__).parent / "data" / "g005_empty_fetch_eligibility.json"
EVIDENCE_ID = "ev1_" + "2" * 64


class NeverCancelled:
    def is_cancelled(self) -> bool:
        return False

    def raise_if_cancelled(self) -> None:
        return None

    async def wait(self) -> None:
        await asyncio.Future()


class Ledger:
    def __init__(self) -> None:
        self.attempts: list[str] = []

    def claim(self, kind: object) -> None:
        self.attempts.append(str(kind))


def _execution(ledger: Ledger) -> ExecutionContext:
    return ExecutionContext(
        question_id=uuid4(),
        operation="semantic",
        owner_key="5" * 64,
        environment_id="alpha",
        deadline_at=NOW,
        cancel=NeverCancelled(),
        calls=ledger,  # type: ignore[arg-type]
        admission=AdmissionGrant(
            holder_id=uuid4(), slot_ids=("semantic",), expires_at=NOW, fence=1
        ),
        trace_context=TraceContext(trace_id="1" * 32, span_id="2" * 16, trace_flags=1),
    )


def _model() -> ModelCapability:
    return ModelCapability(
        id="fixture-claude",
        label="Fixture Claude",
        region="us-east-1",
        resource_arns=("arn:aws:bedrock:us-east-1:123456789012:foundation-model/fake",),
        context_tokens=4096,
        max_output_tokens=512,
        count_tokens_model_id="fixture-claude",
        efforts=(Effort.low,),
        effort_transport="additionalModelRequestFields",
        effort_parameters={Effort.low: {"reasoning_effort": "low"}},
        output_strategy="strict_json_messages",
        count_strategy="count_tokens_converse",
        count_contract_sha256="1" * 64,
        cache_min_tokens=0,
        cache_max_checkpoints=0,
        cache_ttl="5m",
        validated_at=NOW,
        primary_doc_url="https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html",
    )


def _engine_fixture(*, denied: bool = False, plan_judgment: bool = True):
    check = CheckResult(
        check_id="playbook_check",
        topic_id="ldap",
        label="check",
        outcome=CheckOutcome.denied if denied else CheckOutcome.passed,
        evidence_ids=[EVIDENCE_ID],
        message="fixed",
    )
    item = EvidenceItem(
        evidence_id=EVIDENCE_ID,
        topic_id="ldap",
        fetch_id=None,
        check_id="playbook_check",
        kind="check",
        source=EvidenceSourceCheck(step_id="playbook_check", operand_ids=[]),
        snapshot=SnapshotRef(kind=SnapshotKind.pit, key="3" * 64, at=NOW),
        values={"outcome": "denied" if denied else "passed"},
        visibility=Visibility.full,
        scope_hash="4" * 64,
    )
    pack = EvidencePack(
        question_id=uuid4(),
        environment_id="alpha",
        topic_id="ldap",
        policy_hash="5" * 64,
        content_sha="a" * 40,
        fetches=[],
        checks=[check],
        items=[item],
        sha256="6" * 64,
    )
    context = ValidationContext(
        topic_pack=TopicPromptPack(
            topic_id="ldap",
            language="en",
            content_sha="a" * 40,
            sha256="7" * 64,
            missing=[],
        ),
        templates=(),
        policy_hash="5" * 64,
        content_sha="a" * 40,
        language="en",
        expected_checks=(check,),
    )
    plan = TopicPlan(
        topic_id="ldap",
        ordinal=0,
        document=True,
        failure=False,
        judgment=plan_judgment,
        fetches=[],
        cue_ids=[],
        alias_ids=[],
    )
    engine = JudgmentEngine(
        standing_rules="fixed system rules",
        guardrail_identifier="numbered-gr-1",
        guardrail_version="3",
        playbook=lambda _playbook_id: None,
    )
    return engine, plan, pack, context


def _retopic_engine_fixture(topic: str, *, denied: bool = False, required_fetch: bool = False):
    engine, plan, pack, context = _engine_fixture(denied=denied)
    check = pack.checks[0].model_copy(update={"topic_id": topic})
    item = pack.items[0].model_copy(update={"topic_id": topic})
    pack = pack.model_copy(update={"topic_id": topic, "checks": [check], "items": [item]})
    context = context.model_copy(
        update={
            "topic_pack": context.topic_pack.model_copy(update={"topic_id": topic}),
            "expected_checks": (check,),
        }
    )
    plan = plan.model_copy(update={"topic_id": topic})
    if required_fetch:
        plan = _with_required_fetch(plan)
    return engine, plan, pack, context


def _eligibility_case(variant: str) -> dict[str, object]:
    parsed: object = json.loads(ELIGIBILITY_FIXTURE.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise AssertionError("topic-eligibility fixture must be a JSON object")
    variants = parsed.get("variants")
    if not isinstance(variants, dict) or not isinstance(variants.get(variant), dict):
        raise AssertionError(f"topic-eligibility fixture has no {variant} variant")
    return cast(dict[str, object], variants[variant])


def _g018_case(variant: str) -> dict[str, object]:
    assert_fixture_matches_all_variants("B4-G018.topic-isolation.private", G018_FIXTURE)
    parsed: object = json.loads(G018_FIXTURE.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise AssertionError("G018 fixture must be a JSON object")
    variants = parsed.get("variants")
    if not isinstance(variants, dict) or not isinstance(variants.get(variant), dict):
        raise AssertionError(f"G018 fixture has no {variant} variant")
    return cast(dict[str, object], variants[variant])


def _g024_case(variant: str) -> dict[str, object]:
    assert_fixture_matches_all_variants("B4-G024.denial-precedence.private", G024_FIXTURE)
    parsed: object = json.loads(G024_FIXTURE.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise AssertionError("G024 fixture must be a JSON object")
    variants = parsed.get("variants")
    if not isinstance(variants, dict) or not isinstance(variants.get(variant), dict):
        raise AssertionError(f"G024 fixture has no {variant} variant")
    return cast(dict[str, object], variants[variant])


def _g005_case(variant: str) -> dict[str, object]:
    assert_fixture_matches_all_variants("B4-G005.empty-fetch-eligibility.private", G005_FIXTURE)
    parsed: object = json.loads(G005_FIXTURE.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise AssertionError("G005 fixture must be a JSON object")
    variants = parsed.get("variants")
    if not isinstance(variants, dict) or not isinstance(variants.get(variant), dict):
        raise AssertionError(f"G005 fixture has no {variant} variant")
    return cast(dict[str, object], variants[variant])


def _with_required_fetch(plan: TopicPlan) -> TopicPlan:
    window = ResolvedWindow(
        start=datetime(2025, 12, 31, tzinfo=UTC),
        end=NOW,
        semantics="rolling",
        source_text="last 24 hours",
        timezone="UTC",
        anchor_at=NOW,
    )
    fetch = FetchSpec(
        fetch_id="ldap_rows",
        template_id=TemplateId.alerts_rows_v1,
        window=window,
        filters=[],
    )
    return plan.model_copy(update={"fetches": [fetch]})


def test_selection_eligibility_skips_nonjudgment_and_denied_topics_before_counts() -> None:
    engine, plan, pack, context = _engine_fixture(plan_judgment=False)
    assert (
        engine.prepare(plan, pack, context=context, model=None, effort=None).result.state
        == JudgmentState.not_requested
    )

    engine, plan, pack, context = _engine_fixture(denied=True)
    plan = _with_required_fetch(plan)
    result = engine.prepare(plan, pack, context=context, model=_model(), effort=Effort.low)
    assert result.result.state == JudgmentState.denial

    engine, plan, pack, context = _engine_fixture()
    plan = _with_required_fetch(plan)
    missing = engine.prepare(plan, pack, context=context, model=_model(), effort=Effort.low)
    assert missing.result.state == JudgmentState.evidence_unavailable
    assert missing.left_out is not None
    assert missing.left_out.reason == "evidence_unavailable"
    with pytest.raises(ModelSelectionRequired):
        engine.prepare(plan, pack, context=context, model=None, effort=None)


def test_g018_two_topic_preparations_keep_their_evidence_and_judgments_separate() -> None:
    case = _eligibility_case("positive")
    prepared = []
    for topic in cast(list[str], case["topics"]):
        engine, plan, pack, context = _retopic_engine_fixture(topic)
        prepared.append(
            engine.prepare(plan, pack, context=context, model=_model(), effort=Effort.low)
        )

    assert all(isinstance(result, Ready) for result in prepared)
    assert len(prepared) == case["expected_preparations"]
    assert [result.request.topic_id for result in prepared if isinstance(result, Ready)] == case[
        "topics"
    ]
    assert [
        result.request.evidence.topic_id for result in prepared if isinstance(result, Ready)
    ] == case["topics"]


def test_g018_cross_topic_evidence_is_rejected_from_a_single_topic_request() -> None:
    case = _eligibility_case("negative")
    engine, plan, pack, context = _retopic_engine_fixture(str(case["topic"]))
    foreign = pack.items[0].model_copy(update={"topic_id": case["foreign_topic"]})
    pack = pack.model_copy(update={"items": [*pack.items, foreign]})

    with pytest.raises(CapabilityError, match="foreign topic item"):
        engine.prepare(plan, pack, context=context, model=_model(), effort=Effort.low)


def test_g024_denial_precedes_an_unavailable_required_fetch_for_its_topic() -> None:
    case = _eligibility_case("boundary")
    engine, plan, pack, context = _retopic_engine_fixture(
        str(case["topic"]), denied=True, required_fetch=True
    )

    result = engine.prepare(plan, pack, context=context, model=_model(), effort=Effort.low)

    assert result.result.state == case["expected_state"]
    assert result.left_out is None


def test_g025_unavailable_fetch_is_a_typed_topic_left_out() -> None:
    case = _eligibility_case("failure")
    engine, plan, pack, context = _retopic_engine_fixture(str(case["topic"]), required_fetch=True)

    result = engine.prepare(plan, pack, context=context, model=_model(), effort=Effort.low)

    assert result.result.state == case["expected_state"]
    assert result.left_out is not None
    assert result.left_out.reason == case["expected_reason"]
    assert result.left_out.retryable is case["retryable"]


@pytest.mark.parametrize("variant", registered_case_variants("B4-G018.topic-isolation.private"))
def test_g018_topic_preparations_never_merge_evidence_or_outcomes(variant: str) -> None:
    case = _g018_case(variant)
    if variant == "negative":
        engine, plan, pack, context = _retopic_engine_fixture(str(case["topic"]))
        foreign = pack.items[0].model_copy(update={"topic_id": case["foreign_topic"]})
        pack = pack.model_copy(update={"items": [*pack.items, foreign]})
        with pytest.raises(CapabilityError, match=str(case["expected_error"])):
            engine.prepare(plan, pack, context=context, model=_model(), effort=Effort.low)
        return

    topics = cast(list[str], case["topics"])
    results = []
    for topic in topics:
        denied = topic == case.get("denied_topic")
        unavailable = topic == case.get("unavailable_topic")
        engine, plan, pack, context = _retopic_engine_fixture(
            topic, denied=denied, required_fetch=unavailable
        )
        results.append(
            engine.prepare(plan, pack, context=context, model=_model(), effort=Effort.low)
        )

    states = ["ready" if isinstance(result, Ready) else result.result.state for result in results]
    assert states == case["expected_states"]
    assert [result.request.topic_id for result in results if isinstance(result, Ready)] == [
        topic for topic, state in zip(topics, states, strict=True) if state == "ready"
    ]


@pytest.mark.parametrize("variant", registered_case_variants("B4-G024.denial-precedence.private"))
def test_g024_denial_precedes_fetch_model_and_empty_proof_failures(variant: str) -> None:
    case = _g024_case(variant)
    if variant in ("boundary", "failure"):
        proof_variant = "qualified" if variant == "boundary" else "unknown_visibility"
        engine, plan, pack, context = _empty_fetch_inputs(proof_variant=proof_variant)
        denied = pack.checks[0].model_copy(update={"outcome": CheckOutcome.denied})
        denied_item = pack.items[0].model_copy(update={"values": {"outcome": "denied"}})
        pack = pack.model_copy(update={"checks": [denied], "items": [denied_item]})
        context = context.model_copy(update={"expected_checks": (denied,)})
    elif variant == "negative":
        engine, plan, pack, context = _engine_fixture(denied=True)
        plan = _with_required_fetch(plan)
    else:
        engine, plan, pack, context = _engine_fixture(denied=True)

    result = engine.prepare(plan, pack, context=context, model=_model(), effort=Effort.low)

    assert result.result.state == case["expected_state"]
    assert result.left_out is None


@pytest.mark.parametrize(
    "variant",
    registered_case_variants("B4-G005.empty-fetch-eligibility.private")[:3],
)
def test_g005_empty_fetch_eligibility_requires_qualified_proof(variant: str) -> None:
    case = _g005_case(variant)
    engine, plan, pack, context = _empty_fetch_inputs(proof_variant=str(case["proof_variant"]))
    proof = pack.fetches[0].empty_proof
    assert proof is not None and proof.window_count is not None
    assert proof.window_count.value == case.get("expected_window_count", 1)
    assert pack.fetches[0].count is not None
    assert pack.fetches[0].count.value == case.get("expected_count", 0)
    assert proof.filter_probes[0].count is not None
    assert proof.filter_probes[0].count.value == case.get("expected_filter_count", 0)

    result = engine.prepare(plan, pack, context=context, model=_model(), effort=Effort.low)

    if isinstance(result, Ready):
        assert case["expected_state"] == "ready"
    else:
        assert result.result.state == case["expected_state"]


@pytest.mark.case_id("B4-G002.model-selection.private")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G002.model-selection.private"))
@pytest.mark.variant("boundary")
@pytest.mark.fixture_sha256(canonical_fixture_sha256("B4-G002.model-selection.private", "boundary"))
def test_b4_missing_selection_requires_clarification_before_provider_work() -> None:
    fixture_path = Path(__file__).parent / "data" / "model_selection_cases.json"
    assert_fixture_matches_all_variants("B4-G002.model-selection.private", fixture_path)
    parsed: object = json.loads(fixture_path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise AssertionError("model-selection fixture must be a JSON object")
    fixture = cast(dict[str, object], parsed)
    engine, plan, pack, context = _engine_fixture()

    with pytest.raises(ModelSelectionRequired):
        engine.prepare(plan, pack, context=context, model=None, effort=None)

    assert fixture["missing_selection_calls"] == 0


@pytest.mark.case_id("B4-G016.prompt-safety")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G016.prompt-safety"))
@pytest.mark.variant("boundary")
@pytest.mark.fixture_sha256(canonical_fixture_sha256("B4-G016.prompt-safety", "boundary"))
def test_b4_nonjudgment_plan_skips_selection_count_and_converse() -> None:
    fixture_path = Path(__file__).parent / "data" / "prompt_transport_cases.json"
    assert_fixture_matches_all_variants("B4-G016.prompt-safety", fixture_path)
    parsed: object = json.loads(fixture_path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise AssertionError("prompt-transport fixture must be a JSON object")
    fixture = cast(dict[str, object], parsed)
    engine, plan, pack, context = _engine_fixture(plan_judgment=False)

    result = engine.prepare(plan, pack, context=context, model=None, effort=None)

    assert result.result.state == JudgmentState.not_requested
    assert fixture["non_judgment_calls"] == 0


def _empty_outcome_case(variant: str) -> dict[str, object]:
    parsed: object = json.loads(EMPTY_OUTCOME_FIXTURE.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise AssertionError("empty-outcome fixture must be a JSON object")
    cases = parsed.get("variants")
    if not isinstance(cases, dict) or not isinstance(cases.get(variant), dict):
        raise AssertionError(f"empty-outcome fixture has no {variant} case")
    return cast(dict[str, object], cases[variant])


def _empty_fetch_inputs(*, proof_variant: str):
    engine, plan, pack, context = _engine_fixture()
    plan = _with_required_fetch(plan)
    spec = plan.fetches[0]
    snapshot = SnapshotRef(kind=SnapshotKind.pit, key="8" * 64, at=NOW)
    exact_zero = Count(
        value=0,
        relation="eq",
        scope="matching_visible_records",
        computed_by="indexer",
        approximate=False,
    )
    probe_filter = Filter(field=FieldId.agent_id, op="eq", value="007")
    spec = spec.model_copy(update={"filters": [probe_filter]})
    plan = plan.model_copy(update={"fetches": [spec]})
    proof = EmptyProof(
        index_exists="confirmed",
        window_has_data="confirmed",
        window_count=Count(
            value=1,
            relation="eq",
            scope="matching_visible_records",
            computed_by="indexer",
        ),
        filter_probes=[FilterProbe(filter=probe_filter, count=exact_zero, outcome="passed")],
        matched_nothing=[FieldId.agent_id],
        visibility=Visibility.full,
        combination_zero=True,
        snapshot=snapshot,
        consistency="coherent",
        items=[],
    )
    fetch_count: Count | None = exact_zero
    fetch_state = FetchState.empty
    if proof_variant == "unknown_visibility":
        proof = proof.model_copy(update={"visibility": Visibility.unknown})
    elif proof_variant == "unconfirmed":
        proof = proof.model_copy(update={"consistency": "unconfirmed"})
    elif proof_variant == "missing_filter_probe":
        proof = proof.model_copy(update={"filter_probes": [], "combination_zero": False})
    elif proof_variant == "missing_index_confirmation":
        proof = proof.model_copy(update={"index_exists": "unknown"})
    elif proof_variant == "missing_window_confirmation":
        proof = proof.model_copy(update={"window_has_data": "unknown"})
    elif proof_variant == "empty_window":
        proof = proof.model_copy(
            update={
                "window_has_data": "empty",
                "window_count": exact_zero,
            }
        )
    elif proof_variant == "missing_combination_zero":
        proof = proof.model_copy(update={"combination_zero": False})
    elif proof_variant == "missing_proof":
        proof = None
    fetch = FetchResult(
        fetch_id=spec.fetch_id,
        topic_id="ldap",
        state=fetch_state,
        scope=FetchScope(
            environment_id="alpha",
            template_id=TemplateId.alerts_rows_v1,
            index_family=IndexFamily.alerts,
            filters=[probe_filter],
            visibility=Visibility.full,
            policy_hash="5" * 64,
            snapshot=SnapshotKind.pit,
            displayed_rows=0,
        ),
        window=spec.window,
        columns=[],
        rows=[],
        count=fetch_count,
        checks=[],
        empty_proof=proof,
        snapshot=snapshot,
        items=[],
    )
    return engine, plan, pack.model_copy(update={"fetches": [fetch]}), context


def test_g050_qualified_empty_with_coherent_zero_proof_remains_judgment_eligible() -> None:
    case = _empty_outcome_case("positive")
    engine, plan, pack, context = _empty_fetch_inputs(proof_variant=str(case["proof_variant"]))

    result = engine.prepare(plan, pack, context=context, model=_model(), effort=Effort.low)

    assert isinstance(result, Ready) is (case["expected_state"] == "ready")
    assert result.request.evidence.fetches[0].count is not None
    assert result.request.evidence.fetches[0].count.value == 0


def test_g050_unknown_visibility_empty_is_fixed_unconfirmed_outcome() -> None:
    case = _empty_outcome_case("negative")
    engine, plan, pack, context = _empty_fetch_inputs(proof_variant=str(case["proof_variant"]))

    result = engine.prepare(plan, pack, context=context, model=_model(), effort=Effort.low)

    assert result.result.state == case["expected_state"]
    assert (result.left_out is not None) is case["expected_left_out"]


def test_g005_exact_zero_boundary_requires_coherent_window_and_filter_probes() -> None:
    case = _empty_outcome_case("boundary")
    engine, plan, pack, context = _empty_fetch_inputs(proof_variant=str(case["proof_variant"]))
    proof = pack.fetches[0].empty_proof
    assert proof is not None and proof.window_count is not None
    assert proof.window_count.value == case["window_count"]
    assert pack.fetches[0].count is not None and pack.fetches[0].count.value == case["count"]
    assert proof.filter_probes[0].count is not None
    assert proof.filter_probes[0].count.value == case["filter_probe_count"]

    result = engine.prepare(plan, pack, context=context, model=_model(), effort=Effort.low)

    assert isinstance(result, Ready) is (case["expected_state"] == "ready")


def test_g005_incomplete_empty_proof_fails_closed_without_retry_left_out() -> None:
    case = _empty_outcome_case("failure")
    engine, plan, pack, context = _empty_fetch_inputs(proof_variant=str(case["proof_variant"]))

    result = engine.prepare(plan, pack, context=context, model=_model(), effort=Effort.low)

    assert result.result.state == case["expected_state"]
    assert (result.left_out is not None) is case["expected_left_out"]


def test_m2_combination_only_zero_proof_remains_judgment_eligible() -> None:
    engine, plan, pack, context = _empty_fetch_inputs(proof_variant="missing_combination_zero")
    proof = pack.fetches[0].empty_proof
    assert proof is not None
    proof = proof.model_copy(
        update={
            "combination_zero": True,
            "filter_probes": [
                FilterProbe(
                    filter=Filter(field=FieldId.agent_id, op="eq", value="007"),
                    count=Count(
                        value=5,
                        relation="eq",
                        scope="matching_visible_records",
                        computed_by="indexer",
                        approximate=False,
                    ),
                    outcome="passed",
                )
            ],
        }
    )
    fetch = pack.fetches[0].model_copy(update={"empty_proof": proof})
    pack = pack.model_copy(update={"fetches": [fetch]})

    result = engine.prepare(plan, pack, context=context, model=_model(), effort=Effort.low)

    assert isinstance(result, Ready)


def test_m2_positive_fetch_is_not_blocked_by_unqualified_empty_sibling() -> None:
    engine, plan, pack, context = _empty_fetch_inputs(proof_variant="missing_proof")
    empty_fetch = pack.fetches[0]
    positive_fetch = empty_fetch.model_copy(
        update={
            "fetch_id": "positive_fetch",
            "state": FetchState.filtered,
            "count": Count(
                value=2,
                relation="eq",
                scope="matching_visible_records",
                computed_by="indexer",
                approximate=False,
            ),
            "empty_proof": None,
        }
    )
    plan = plan.model_copy(
        update={
            "fetches": [
                plan.fetches[0],
                plan.fetches[0].model_copy(update={"fetch_id": "positive_fetch", "filters": []}),
            ]
        }
    )
    pack = pack.model_copy(update={"fetches": [empty_fetch, positive_fetch]})

    result = engine.prepare(plan, pack, context=context, model=_model(), effort=Effort.low)

    assert isinstance(result, Ready)


@pytest.mark.parametrize(
    "proof_variant",
    (
        "missing_index_confirmation",
        "missing_window_confirmation",
    ),
)
def test_g050_missing_scope_proof_never_treats_empty_as_confirmed(
    proof_variant: str,
) -> None:
    engine, plan, pack, context = _empty_fetch_inputs(proof_variant=proof_variant)

    result = engine.prepare(plan, pack, context=context, model=_model(), effort=Effort.low)

    assert result.result.state == JudgmentState.ingestion_unconfirmed
    assert result.left_out is None


def _g050_scope_case(variant: str) -> dict[str, object]:
    fixture_path = Path(__file__).parent / "data" / "g050_empty_scope_proof.json"
    parsed: object = json.loads(fixture_path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise AssertionError("G050 fixture must be a JSON object")
    variants = parsed.get("variants")
    if not isinstance(variants, dict) or not isinstance(variants.get(variant), dict):
        raise AssertionError(f"G050 fixture has no {variant} variant")
    return cast(dict[str, object], variants[variant])


@pytest.mark.parametrize("variant", registered_case_variants("B4-G050.empty-scope-proof.private"))
def test_g050_scope_qualification_case(variant: str) -> None:
    fixture_path = Path(__file__).parent / "data" / "g050_empty_scope_proof.json"
    assert_fixture_matches_all_variants("B4-G050.empty-scope-proof.private", fixture_path)
    case = _g050_scope_case(variant)
    engine, plan, pack, context = _empty_fetch_inputs(proof_variant=str(case["proof_variant"]))

    result = engine.prepare(plan, pack, context=context, model=_model(), effort=Effort.low)

    if isinstance(result, Ready):
        assert case["expected_state"] == "ready"
    else:
        assert result.result.state == case["expected_state"]
    if variant == "positive":
        assert isinstance(result, Ready)
        assert result.request.evidence.fetches[0].count is not None
        assert result.request.evidence.fetches[0].count.value == 0
    else:
        assert result.left_out is None


def test_engine_rejects_policy_content_and_foreign_topic_bindings() -> None:
    engine, plan, pack, context = _engine_fixture()
    foreign = pack.model_copy(update={"policy_hash": "9" * 64})
    with pytest.raises(CapabilityError, match="policy"):
        engine.prepare(plan, foreign, context=context, model=_model(), effort=Effort.low)
    cross = pack.model_copy(update={"topic_id": "dns"})
    with pytest.raises(CapabilityError, match="topic"):
        engine.prepare(plan, cross, context=context, model=_model(), effort=Effort.low)


class EmbedClient:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload
        self.requests: list[dict[str, object]] = []

    def invoke_model(self, **kwargs: object) -> dict[str, object]:
        self.requests.append(kwargs)
        return {"body": io.BytesIO(json.dumps(self.payload).encode())}


def _embedding_capability(mode: str) -> EmbeddingCapability:
    model_id = (
        "amazon.titan-embed-text-v2:0" if mode == "titan_v2" else "cohere.embed-multilingual-v3"
    )
    return EmbeddingCapability(
        model_id=model_id,
        region="us-east-1",
        resource_arns=(f"arn:aws:bedrock:us-east-1:123456789012:foundation-model/{model_id}",),
        dimensions=3,
        purpose="topic_cards",
        normalization="l2",
        provider_mode=mode,
        query_mode="single_text" if mode == "titan_v2" else "search_query",
        document_mode="single_text" if mode == "titan_v2" else "search_document",
        guardrail=GuardrailPin(identifier="embed-gr", version="2"),
        source_vpce="vpce-0123456789abcdef0",
        request_bytes=65_536,
        max_tokens=512,
        max_calls_per_question=1,
        requests_per_minute=30,
        validated_at=NOW,
        primary_doc_url="https://docs.aws.amazon.com/bedrock/latest/userguide/titan-embedding-models.html",
        validated=True,
    )


@pytest.mark.asyncio
async def test_titan_query_embedding_has_separate_guardrail_request_and_normalized_dimension() -> (
    None
):
    client = EmbedClient({"embedding": [3, 4, 0]})
    ledger = Ledger()
    provider = BedrockEmbeddingProvider(client, _embedding_capability("titan_v2"))
    vectors = await provider.embed(("ldap timeout",), purpose="query", execution=_execution(ledger))

    request = client.requests[0]
    assert request["modelId"] == "amazon.titan-embed-text-v2:0"
    assert request["contentType"] == request["accept"] == "application/json"
    assert request["guardrailIdentifier"] == "embed-gr"
    assert request["guardrailVersion"] == "2"
    assert json.loads(request["body"]) == {
        "inputText": "ldap timeout",
        "dimensions": 3,
        "normalize": True,
    }
    assert vectors[0] == pytest.approx((0.6, 0.8, 0.0))
    assert ledger.attempts == ["embedding"]


@pytest.mark.asyncio
async def test_cohere_query_and_document_modes_are_explicit_and_never_truncate() -> None:
    capability = _embedding_capability("cohere_v3")
    client = EmbedClient({"embeddings": {"float": [[1, 2, 2]]}})
    provider = BedrockEmbeddingProvider(client, capability)
    await provider.embed(("question",), purpose="query", execution=_execution(Ledger()))
    args = json.loads(client.requests[0]["body"])
    assert args == {"texts": ["question"], "input_type": "search_query", "truncate": "NONE"}

    client = EmbedClient({"embeddings": {"float": [[1, 0, 0], [0, 1, 0]]}})
    await BedrockEmbeddingProvider(client, capability).embed(
        ("LDAP", "Directorio ligero"), purpose="document", execution=_execution(Ledger())
    )
    args = json.loads(client.requests[0]["body"])
    assert args == {
        "texts": ["LDAP", "Directorio ligero"],
        "input_type": "search_document",
        "truncate": "NONE",
    }


@pytest.mark.asyncio
async def test_embedding_unvalidated_model_wrong_vector_and_telemetry_text_fail_closed() -> None:
    capability = _embedding_capability("titan_v2")
    disabled = replace(capability, validated=False)
    with pytest.raises(CapabilityError, match="not passed live validation"):
        await BedrockEmbeddingProvider(
            EmbedClient({"embedding": [1, 0, 0]}),
            disabled,
        ).embed(("question",), purpose="query", execution=_execution(Ledger()))
    bad_vector = BedrockEmbeddingProvider(EmbedClient({"embedding": [1, 0]}), capability)
    with pytest.raises(ProviderFailure, match="invalid_output"):
        await bad_vector.embed(("question",), purpose="query", execution=_execution(Ledger()))
    with pytest.raises(CapabilityError, match="purpose"):
        await BedrockEmbeddingProvider(EmbedClient({}), capability).embed(
            ("private customer alert text",), purpose="telemetry", execution=_execution(Ledger())
        )
    invalid_vpce = replace(capability, source_vpce="")
    with pytest.raises(CapabilityError, match="VPCE"):
        await BedrockEmbeddingProvider(EmbedClient({}), invalid_vpce).embed(
            ("question",), purpose="query", execution=_execution(Ledger())
        )
    too_small = replace(capability, request_bytes=1)
    with pytest.raises(CapabilityError, match="byte bound"):
        await BedrockEmbeddingProvider(EmbedClient({}), too_small).embed(
            ("question",), purpose="query", execution=_execution(Ledger())
        )
    assert CallKind.embedding.value == "embedding"


PLAYBOOK_ID = "ldap_read_checks"
PLAYBOOK_FETCH_ID = "ldap_recent_alert_count"


def _pinned_playbook() -> PlaybookDefinition:
    label = LocaleText(en="recent alerts", es="recent alerts")
    return PlaybookDefinition(
        playbook_id=PLAYBOOK_ID,
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


def _playbook_engine(lookup: Callable[[str], PlaybookDefinition | None]) -> JudgmentEngine:
    return JudgmentEngine(
        standing_rules="fixed system rules",
        guardrail_identifier="numbered-gr-1",
        guardrail_version="3",
        playbook=lookup,
    )


def _playbook_inputs(
    fetch_ids: tuple[str, ...],
) -> tuple[TopicPlan, EvidencePack, ValidationContext]:
    _, _, pack, context = _empty_fetch_inputs(proof_variant="coherent")
    plan = _engine_fixture()[1].model_copy(
        update={"failure": True, "fetches": [], "playbook_id": PLAYBOOK_ID}
    )
    fetch = pack.fetches[0]
    pack = pack.model_copy(
        update={
            "fetches": [fetch.model_copy(update={"fetch_id": fetch_id}) for fetch_id in fetch_ids]
        }
    )
    return plan, pack, context


def test_playbook_fetch_is_a_required_input_for_a_failure_plan() -> None:
    engine = _playbook_engine({PLAYBOOK_ID: _pinned_playbook()}.get)
    plan, pack, context = _playbook_inputs((PLAYBOOK_FETCH_ID,))

    result = engine.prepare(plan, pack, context=context, model=_model(), effort=Effort.low)

    assert isinstance(result, Ready)


def test_missing_playbook_fetch_is_evidence_unavailable() -> None:
    engine = _playbook_engine({PLAYBOOK_ID: _pinned_playbook()}.get)
    plan, pack, context = _playbook_inputs(())

    missing = engine.prepare(plan, pack, context=context, model=_model(), effort=Effort.low)

    assert missing.result.state == JudgmentState.evidence_unavailable
    assert missing.left_out is not None
    assert missing.left_out.reason == "evidence_unavailable"


def test_fetch_declared_nowhere_is_an_unplanned_fetch() -> None:
    engine = _playbook_engine({PLAYBOOK_ID: _pinned_playbook()}.get)
    plan, pack, context = _playbook_inputs((PLAYBOOK_FETCH_ID, "undeclared_fetch"))

    with pytest.raises(CapabilityError, match="unplanned fetch"):
        engine.prepare(plan, pack, context=context, model=_model(), effort=Effort.low)


def test_plan_naming_an_unknown_playbook_raises() -> None:
    engine = _playbook_engine(lambda _playbook_id: None)
    plan, pack, context = _playbook_inputs((PLAYBOOK_FETCH_ID,))

    with pytest.raises(CapabilityError, match="unknown playbook"):
        engine.prepare(plan, pack, context=context, model=_model(), effort=Effort.low)
