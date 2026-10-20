from __future__ import annotations

import asyncio
import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import boto3
import pytest
from admission_fakes import FakeStageAdmissionStore
from botocore.stub import Stubber
from case_binding import (
    assert_fixture_matches_all_variants,
    canonical_acceptance_ids,
    canonical_fixture_sha256,
    registered_case_variants,
)

from ai_soc.application.runtime import BoundedCallLedger
from ai_soc.contracts.models import (
    AdmissionGrant,
    CallKind,
    Effort,
    EmbeddingGrant,
    EvidencePack,
    ExecutionContext,
    FieldId,
    FindingRelationAggregateScope,
    FindingRelationSameFetch,
    FindingRelationSameRecord,
    FindingTemplate,
    GuardrailPin,
    JudgmentRequest,
    JudgmentState,
    LeftOutReason,
    LocaleText,
    ModelCapability,
    ModelCountGrant,
    TopicPromptPack,
    TraceContext,
    ValidationContext,
)
from ai_soc.judgment.bedrock import BedrockJudgmentProvider, PhysicalCallPool, ProviderFailure
from ai_soc.judgment.capabilities import (
    CapabilityError,
    finite_models,
    validate_guardrail,
    validate_selection,
)
from ai_soc.judgment.counting import (
    context_outcome,
    fits_context,
    provider_failure_outcome,
    reserved_gross_tokens,
)
from ai_soc.state.stage_admission import MemoryModelCountAdmissionStore
from ai_soc.validation.findings import FindingValidator

NOW = datetime(2026, 1, 1, tzinfo=UTC)
CONTEXT_BUDGET_FIXTURE = Path(__file__).parent / "data" / "g029_context_budget_cases.json"
MODEL_GUARDRAIL_FIXTURE = Path(__file__).parent / "data" / "g007_g046_model_guardrail.json"
PROMPT_CHECKPOINT_FIXTURE = Path(__file__).parent / "data" / "g060_prompt_checkpoints.json"
G007_FIXTURE = Path(__file__).parent / "data" / "g007_effort_capability.json"
G046_FIXTURE = Path(__file__).parent / "data" / "g046_numbered_guardrail.json"


def _model_selection_fixture() -> dict[str, object]:
    fixture_path = Path(__file__).parent / "data" / "model_selection_cases.json"
    assert_fixture_matches_all_variants("B4-G002.model-selection.private", fixture_path)
    parsed: object = json.loads(fixture_path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise AssertionError("model-selection fixture must be a JSON object")
    return cast(dict[str, object], parsed)


def _prompt_transport_fixture() -> dict[str, object]:
    fixture_path = Path(__file__).parent / "data" / "prompt_transport_cases.json"
    assert_fixture_matches_all_variants("B4-G016.prompt-safety", fixture_path)
    parsed: object = json.loads(fixture_path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise AssertionError("prompt-transport fixture must be a JSON object")
    return cast(dict[str, object], parsed)


def _context_budget_case(variant: str) -> dict[str, object]:
    assert_fixture_matches_all_variants("B4-G029.context-budget.private", CONTEXT_BUDGET_FIXTURE)
    parsed: object = json.loads(CONTEXT_BUDGET_FIXTURE.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise AssertionError("context-budget fixture must be a JSON object")
    variants = parsed.get("variants")
    if not isinstance(variants, dict) or not isinstance(variants.get(variant), dict):
        raise AssertionError(f"context-budget fixture has no {variant} variant")
    return cast(dict[str, object], variants[variant])


def _model_guardrail_case(variant: str) -> dict[str, object]:
    parsed: object = json.loads(MODEL_GUARDRAIL_FIXTURE.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise AssertionError("model/guardrail fixture must be a JSON object")
    variants = parsed.get("variants")
    if not isinstance(variants, dict) or not isinstance(variants.get(variant), dict):
        raise AssertionError(f"model/guardrail fixture has no {variant} variant")
    return cast(dict[str, object], variants[variant])


def _g007_effort_case(variant: str) -> dict[str, object]:
    assert_fixture_matches_all_variants("B4-G007.effort-capability.private", G007_FIXTURE)
    parsed: object = json.loads(G007_FIXTURE.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise AssertionError("G007 fixture must be a JSON object")
    variants = parsed.get("variants")
    if not isinstance(variants, dict) or not isinstance(variants.get(variant), dict):
        raise AssertionError(f"G007 fixture has no {variant} variant")
    return cast(dict[str, object], variants[variant])


def _g046_guardrail_case(variant: str) -> dict[str, object]:
    assert_fixture_matches_all_variants("B4-G046.numbered-guardrail.private", G046_FIXTURE)
    parsed: object = json.loads(G046_FIXTURE.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise AssertionError("G046 fixture must be a JSON object")
    variants = parsed.get("variants")
    if not isinstance(variants, dict) or not isinstance(variants.get(variant), dict):
        raise AssertionError(f"G046 fixture has no {variant} variant")
    return cast(dict[str, object], variants[variant])


def _prompt_checkpoint_case(variant: str) -> dict[str, object]:
    assert_fixture_matches_all_variants(
        "B4-G060.prompt-checkpoints.private", PROMPT_CHECKPOINT_FIXTURE
    )
    parsed: object = json.loads(PROMPT_CHECKPOINT_FIXTURE.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise AssertionError("prompt-checkpoint fixture must be a JSON object")
    variants = parsed.get("variants")
    if not isinstance(variants, dict) or not isinstance(variants.get(variant), dict):
        raise AssertionError(f"prompt-checkpoint fixture has no {variant} variant")
    return cast(dict[str, object], variants[variant])


class FakeCancellation:
    def is_cancelled(self) -> bool:
        return False

    def raise_if_cancelled(self) -> None:
        return None

    async def wait(self) -> None:
        await asyncio.Future()


class FakeLedger:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def claim(self, kind: object) -> None:
        self.calls.append(str(kind))


class FakeClient:
    def __init__(self) -> None:
        self.count_inputs: list[dict[str, object]] = []
        self.converse_inputs: list[dict[str, object]] = []

    def count_tokens(self, **kwargs: object) -> dict[str, object]:
        self.count_inputs.append(kwargs)
        return {"inputTokens": 100}

    def converse(self, **kwargs: object) -> dict[str, object]:
        self.converse_inputs.append(kwargs)
        return {
            "output": {"message": {"content": [{"text": '{"schema_version":"1","findings":[]}'}]}},
            "stopReason": "end_turn",
            "usage": {
                "inputTokens": 80,
                "outputTokens": 10,
                "cacheReadInputTokens": 15,
                "cacheWriteInputTokens": 5,
            },
            "ResponseMetadata": {"RequestId": "fake-id"},
        }


def _model(*, efforts: bool = True, context: int = 4096, caching: bool = True) -> ModelCapability:
    supported = (Effort.low, Effort.high) if efforts else ()
    parameters = {Effort.low: {"effort": "low"}, Effort.high: {"effort": "high"}} if efforts else {}
    return ModelCapability(
        id="arn:aws:bedrock:us-east-1:123456789012:inference-profile/test-profile",
        label="Fixture Claude",
        region="us-east-1",
        resource_arns=("arn:aws:bedrock:us-east-1:123456789012:inference-profile/test-profile",),
        context_tokens=context,
        max_output_tokens=512,
        count_tokens_model_id="arn:aws:bedrock:us-east-1:123456789012:inference-profile/test-profile",
        efforts=supported,
        effort_transport="additionalModelRequestFields" if efforts else "none",
        effort_parameters=parameters,
        output_strategy="strict_json_messages",
        count_strategy="count_tokens_converse",
        count_contract_sha256="1" * 64,
        cache_min_tokens=1 if caching else 0,
        cache_max_checkpoints=2 if caching else 0,
        cache_ttl="5m",
        validated_at=NOW,
        primary_doc_url="https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html",
    )


def _ldap_template() -> FindingTemplate:
    return FindingTemplate(
        template_id="ldap_observation",
        topic_id="ldap",
        kind="observation",
        required_bindings={"rule": (FieldId.rule_id,)},
        texts=LocaleText(en="Observed rule: {rule}", es="Regla observada: {rule}"),
        required_check_outcomes=[],
        allowed_evidence_kinds=["row"],
    )


def _request() -> JudgmentRequest:
    model = _model()
    evidence = EvidencePack(
        question_id=uuid4(),
        environment_id="alpha",
        topic_id="ldap",
        policy_hash="2" * 64,
        content_sha="a" * 40,
        fetches=[],
        checks=[],
        items=[],
        sha256="3" * 64,
    )
    return JudgmentRequest(
        question_id=evidence.question_id,
        topic_id="ldap",
        model=model,
        effort=Effort.high,
        language="en",
        standing_rules="RULES-CHECKPOINT",
        topic_pack=TopicPromptPack(
            topic_id="ldap",
            language="en",
            content_sha="a" * 40,
            sha256="4" * 64,
            document_section="DOC-CONTEXT",
            internal_context="PLAYBOOK-CONTEXT",
            missing=[],
        ),
        evidence=evidence,
        question="QUESTION-DATA",
        max_output_tokens=512,
        guardrail=GuardrailPin(identifier="gr-123456", version="7"),
        finding_templates=(_ldap_template(),),
    )


def _execution(ledger: FakeLedger, *, question_id: UUID | None = None) -> ExecutionContext:
    return ExecutionContext(
        question_id=question_id or uuid4(),
        operation="ask",
        owner_key="5" * 64,
        environment_id="alpha",
        deadline_at=NOW,
        cancel=FakeCancellation(),
        calls=ledger,  # type: ignore[arg-type]
        admission=AdmissionGrant(holder_id=uuid4(), slot_ids=("model",), expires_at=NOW, fence=1),
        trace_context=TraceContext(trace_id="1" * 32, span_id="2" * 16, trace_flags=1),
    )


def test_finite_capabilities_reject_duplicate_and_unsupported_selection() -> None:
    model = _model()
    with pytest.raises(CapabilityError, match="unique"):
        finite_models((model, model))
    with pytest.raises(CapabilityError, match="selected effort"):
        validate_selection(model, Effort.xhigh)
    with pytest.raises(CapabilityError, match="numbered guardrail"):
        validate_guardrail(GuardrailPin(identifier="none", version="1"))
    with pytest.raises(CapabilityError, match="transport strategy"):
        validate_selection(
            model.model_copy(update={"output_strategy": "native_schema"}), Effort.high
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["count", "converse"])
@pytest.mark.parametrize(
    "catalog_case",
    [
        "empty",
        "duplicate",
        "corrupt_nested_type",
        "foreign_topic",
        "too_many_templates",
        "oversized_context",
        "missing_placeholder",
        "unclosed_placeholder",
        "indexed_placeholder",
        "formatted_placeholder",
        "converted_placeholder",
        "unknown_same_record_binding",
        "unknown_same_fetch_binding",
        "unknown_aggregate_entity_binding",
        "unbacked_literal",
    ],
)
async def test_provider_rejects_invalid_catalog_before_admission_or_sdk(
    stage: str, catalog_case: str
) -> None:
    request = _request()
    if catalog_case == "empty":
        request = request.model_copy(update={"finding_templates": ()})
    elif catalog_case == "duplicate":
        request = request.model_copy(
            update={"finding_templates": (request.finding_templates[0],) * 2}
        )
    elif catalog_case == "corrupt_nested_type":
        request.finding_templates[0].required_bindings["rule"] = (True,)
    elif catalog_case == "foreign_topic":
        request = request.model_copy(
            update={
                "finding_templates": (
                    request.finding_templates[0].model_copy(update={"topic_id": "vpn"}),
                )
            }
        )
    elif catalog_case == "too_many_templates":
        template = request.finding_templates[0]
        request = request.model_copy(
            update={
                "finding_templates": tuple(
                    template.model_copy(update={"template_id": f"ldap_template_{index:02d}"})
                    for index in range(21)
                )
            }
        )
    elif catalog_case == "oversized_context":
        request.finding_templates[0].texts.__dict__["en"] = "x" * 66_000 + "{rule}"
    elif catalog_case in {
        "missing_placeholder",
        "unclosed_placeholder",
        "indexed_placeholder",
        "formatted_placeholder",
        "converted_placeholder",
    }:
        text = {
            "missing_placeholder": "Observed",
            "unclosed_placeholder": "Observed {rule",
            "indexed_placeholder": "Observed {rule[0]}",
            "formatted_placeholder": "Observed {rule:>8}",
            "converted_placeholder": "Observed {rule!r}",
        }[catalog_case]
        request.finding_templates[0].texts.__dict__["en"] = text
        request.finding_templates[0].texts.__dict__["es"] = text
    elif catalog_case == "unknown_same_record_binding":
        template = request.finding_templates[0].model_copy(
            update={
                "relations": [
                    FindingRelationSameRecord(kind="same_record", bindings=["rule", "unknown"])
                ]
            }
        )
        request = request.model_copy(update={"finding_templates": (template,)})
    elif catalog_case == "unknown_same_fetch_binding":
        template = request.finding_templates[0].model_copy(
            update={
                "relations": [
                    FindingRelationSameFetch(kind="same_fetch", bindings=["rule", "unknown"])
                ]
            }
        )
        request = request.model_copy(update={"finding_templates": (template,)})
    elif catalog_case == "unknown_aggregate_entity_binding":
        template = request.finding_templates[0].model_copy(
            update={
                "required_bindings": {
                    "rule": (FieldId.rule_id,),
                    "count": ("count",),
                },
                "texts": LocaleText(
                    en="Observed {rule} count {count}",
                    es="Observado {rule} cuenta {count}",
                ),
                "relations": [
                    FindingRelationAggregateScope(
                        kind="aggregate_scope",
                        count_binding="count",
                        entity_bindings={"unknown": FieldId.agent_name},
                    )
                ],
            }
        )
        request = request.model_copy(update={"finding_templates": (template,)})
    elif catalog_case == "unbacked_literal":
        request.finding_templates[0].texts.__dict__["en"] = "Rule 42 is visible {rule}"
        request.finding_templates[0].texts.__dict__["es"] = "Regla 42 visible {rule}"

    client = FakeClient()
    store = FakeStageAdmissionStore()
    provider = BedrockJudgmentProvider(client, admission_store=store)
    execution = _execution(FakeLedger(), question_id=request.question_id)

    with pytest.raises(CapabilityError, match="finding template catalog"):
        if stage == "count":
            await provider.count(request, execution=execution)
        else:
            await provider.converse(request, execution=execution)

    assert store.requests == []
    assert client.count_inputs == []
    assert client.converse_inputs == []


@pytest.mark.asyncio
@pytest.mark.case_id("B4-G002.model-selection.private")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G002.model-selection.private"))
@pytest.mark.variant("positive")
@pytest.mark.fixture_sha256(canonical_fixture_sha256("B4-G002.model-selection.private", "positive"))
async def test_b4_model_selection_forwards_selected_model_and_effort_unchanged() -> None:
    fixture = _model_selection_fixture()
    request = _request()
    ledger = FakeLedger()
    client = FakeClient()

    await BedrockJudgmentProvider(client, admission_store=FakeStageAdmissionStore()).converse(
        request, execution=_execution(ledger, question_id=request.question_id)
    )

    invocation = client.converse_inputs[0]
    assert invocation["modelId"] == fixture["model_id"] == request.model.id
    assert invocation["additionalModelRequestFields"] == fixture["expected_effort_fields"]
    assert ledger.calls == [CallKind.converse.value]


@pytest.mark.case_id("B4-G002.model-selection.private")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G002.model-selection.private"))
@pytest.mark.variant("negative")
@pytest.mark.fixture_sha256(canonical_fixture_sha256("B4-G002.model-selection.private", "negative"))
def test_b4_unsupported_selected_effort_is_rejected_before_any_provider_attempt() -> None:
    fixture = _model_selection_fixture()
    request = _request().model_copy(update={"effort": Effort(str(fixture["unsupported_effort"]))})
    client = FakeClient()

    with pytest.raises(CapabilityError, match="selected effort"):
        validate_selection(request.model, request.effort)

    assert client.converse_inputs == []
    assert client.count_inputs == []


@pytest.mark.asyncio
@pytest.mark.case_id("B4-G002.model-selection.private")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G002.model-selection.private"))
@pytest.mark.variant("failure")
@pytest.mark.fixture_sha256(canonical_fixture_sha256("B4-G002.model-selection.private", "failure"))
async def test_b4_provider_timeout_preserves_selected_model_without_downgrade() -> None:
    fixture = _model_selection_fixture()

    class TimeoutClient(FakeClient):
        def converse(self, **kwargs: object) -> dict[str, object]:
            self.converse_inputs.append(kwargs)
            raise TimeoutError(str(fixture["timeout_error"]))

    client = TimeoutClient()
    request = _request()
    ledger = FakeLedger()
    provider = BedrockJudgmentProvider(client, admission_store=FakeStageAdmissionStore())

    with pytest.raises(ProviderFailure, match=str(fixture["timeout_public_state"])):
        await provider.converse(
            request, execution=_execution(ledger, question_id=request.question_id)
        )

    assert len(client.converse_inputs) == fixture["expected_transport_attempts"]
    assert client.converse_inputs[0]["modelId"] == fixture["model_id"]
    assert ledger.calls == [CallKind.converse.value]


@pytest.mark.asyncio
async def test_g007_g046_numbered_guardrail_and_selected_effort_reach_sdk_unchanged() -> None:
    case = _model_guardrail_case("positive")
    request = _request()
    client = FakeClient()
    ledger = FakeLedger()

    await BedrockJudgmentProvider(client, admission_store=FakeStageAdmissionStore()).converse(
        request, execution=_execution(ledger, question_id=request.question_id)
    )

    invocation = client.converse_inputs[0]
    assert invocation["modelId"] == request.model.id
    assert invocation["additionalModelRequestFields"] == case["effort_fields"]
    assert invocation["guardrailConfig"] == case["guardrail_config"]
    assert len(client.converse_inputs) == 1
    assert ledger.calls == [CallKind.converse.value]


@pytest.mark.asyncio
async def test_g046_draft_guardrail_is_rejected_before_any_sdk_attempt() -> None:
    case = _model_guardrail_case("negative")
    request = _request().model_copy(
        update={"guardrail": GuardrailPin(**cast(dict[str, str], case["guardrail"]))}
    )
    client = FakeClient()
    provider = BedrockJudgmentProvider(client, admission_store=FakeStageAdmissionStore())

    with pytest.raises(CapabilityError, match="numbered guardrail"):
        await provider.converse(
            request,
            execution=_execution(FakeLedger(), question_id=request.question_id),
        )

    assert client.converse_inputs == []
    assert client.count_inputs == []


@pytest.mark.asyncio
async def test_g007_effort_is_omitted_when_selected_model_has_no_effort_capability() -> None:
    case = _model_guardrail_case("boundary")
    request = _request().model_copy(update={"model": _model(efforts=False), "effort": None})
    client = FakeClient()

    await BedrockJudgmentProvider(client, admission_store=FakeStageAdmissionStore()).converse(
        request, execution=_execution(FakeLedger(), question_id=request.question_id)
    )

    invocation = client.converse_inputs[0]
    assert invocation["modelId"] == request.model.id
    assert "additionalModelRequestFields" not in invocation
    assert invocation["guardrailConfig"] == case["guardrail_config"]


@pytest.mark.asyncio
async def test_g046_guardrail_intervention_is_preserved_after_one_counted_call() -> None:
    case = _model_guardrail_case("failure")

    class GuardrailClient(FakeClient):
        def converse(self, **kwargs: object) -> dict[str, object]:
            self.converse_inputs.append(kwargs)
            return {
                "output": {"message": {"content": [{"text": str(case["hostile_text"])}]}},
                "stopReason": "guardrail_intervened",
                "ResponseMetadata": {"RequestId": "guardrail-fixture"},
            }

    client = GuardrailClient()
    request = _request()
    ledger = FakeLedger()
    result = await BedrockJudgmentProvider(
        client, admission_store=FakeStageAdmissionStore()
    ).converse(request, execution=_execution(ledger, question_id=request.question_id))

    assert result.guardrail_intervened
    assert result.text == case["hostile_text"]
    assert len(client.converse_inputs) == case["attempts"]
    assert client.converse_inputs[0]["guardrailConfig"] == case["guardrail_config"]
    assert ledger.calls == [CallKind.converse.value]


@pytest.mark.asyncio
@pytest.mark.parametrize("variant", registered_case_variants("B4-G007.effort-capability.private"))
async def test_g007_effort_is_forwarded_only_when_capability_allows_it(variant: str) -> None:
    case = _g007_effort_case(variant)
    request = _request().model_copy(
        update={
            "effort": Effort(str(case["effort"])) if case["effort"] is not None else None,
            "model": _model(efforts=variant != "boundary"),
        }
    )
    ledger = FakeLedger()

    if variant == "negative":
        client = FakeClient()
        with pytest.raises(CapabilityError, match=str(case["error_fragment"])):
            await BedrockJudgmentProvider(
                client, admission_store=FakeStageAdmissionStore()
            ).converse(request, execution=_execution(ledger, question_id=request.question_id))
        assert client.converse_inputs == []
        assert client.count_inputs == []
        assert ledger.calls == []
        assert case["attempts"] == 0
        return

    if variant == "failure":

        class TimeoutClient(FakeClient):
            def converse(self, **kwargs: object) -> dict[str, object]:
                self.converse_inputs.append(kwargs)
                raise TimeoutError(str(case["error"]))

        client = TimeoutClient()
        with pytest.raises(ProviderFailure, match=str(case["public_state"])):
            await BedrockJudgmentProvider(
                client, admission_store=FakeStageAdmissionStore()
            ).converse(request, execution=_execution(ledger, question_id=request.question_id))
    else:
        client = FakeClient()
        await BedrockJudgmentProvider(client, admission_store=FakeStageAdmissionStore()).converse(
            request, execution=_execution(ledger, question_id=request.question_id)
        )

    assert len(client.converse_inputs) == case["attempts"]
    assert client.converse_inputs[0]["modelId"] == request.model.id
    if variant == "boundary":
        assert case["transport_field_absent"] not in client.converse_inputs[0]
    else:
        assert client.converse_inputs[0]["additionalModelRequestFields"] == case["transport_fields"]
    assert ledger.calls == [CallKind.converse.value]


@pytest.mark.asyncio
@pytest.mark.parametrize("variant", registered_case_variants("B4-G046.numbered-guardrail.private"))
async def test_g046_numbered_guardrail_is_enforced_before_candidate_validation(
    variant: str,
) -> None:
    case = _g046_guardrail_case(variant)
    pin = GuardrailPin(**cast(dict[str, str], case["guardrail"]))
    request = _request().model_copy(update={"guardrail": pin})
    ledger = FakeLedger()

    if variant == "negative":
        client = FakeClient()
        with pytest.raises(CapabilityError, match="numbered guardrail"):
            await BedrockJudgmentProvider(
                client, admission_store=FakeStageAdmissionStore()
            ).converse(request, execution=_execution(ledger, question_id=request.question_id))
        assert client.count_inputs == []
        assert client.converse_inputs == []
        assert ledger.calls == []
        return

    candidate = json.dumps(
        {
            "schema_version": "1",
            "findings": [
                {
                    "finding_id": "untrusted-finding",
                    "kind": "observation",
                    "template_id": str(case.get("unsupported_template", "unknown")),
                    "evidence_ids": [],
                    "bindings": {},
                }
            ],
        }
    )

    class GuardrailClient(FakeClient):
        def converse(self, **kwargs: object) -> dict[str, object]:
            self.converse_inputs.append(kwargs)
            if variant == "failure":
                return {
                    "output": {"message": {"content": [{"text": "hostile intervention"}]}},
                    "stopReason": str(case["stop_reason"]),
                    "ResponseMetadata": {"RequestId": "g046-failure"},
                }
            return {
                "output": {"message": {"content": [{"text": candidate}]}},
                "stopReason": "end_turn",
                "ResponseMetadata": {"RequestId": "g046-candidate"},
            }

    client = GuardrailClient()
    raw = await BedrockJudgmentProvider(client, admission_store=FakeStageAdmissionStore()).converse(
        request, execution=_execution(ledger, question_id=request.question_id)
    )

    assert len(client.converse_inputs) == case["attempts"]
    assert client.converse_inputs[0]["guardrailConfig"] == {
        "guardrailIdentifier": pin.identifier,
        "guardrailVersion": pin.version,
    }
    assert ledger.calls == [CallKind.converse.value]
    context = ValidationContext(
        topic_pack=request.topic_pack,
        templates=(),
        policy_hash=request.evidence.policy_hash,
        content_sha=request.evidence.content_sha,
        language=request.language,
        expected_checks=(),
    )
    validated = FindingValidator().validate(raw, request.evidence, context=context)
    assert validated.state == case.get("expected_validation", "all_removed")
    assert validated.sentences == []


@pytest.mark.asyncio
@pytest.mark.case_id("B4-G060.prompt-checkpoints.private")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G060.prompt-checkpoints.private"))
@pytest.mark.variant("positive")
@pytest.mark.fixture_sha256(
    canonical_fixture_sha256("B4-G060.prompt-checkpoints.private", "positive")
)
async def test_g060_checkpoints_surround_only_immutable_rules_and_topic_context() -> None:
    case = _prompt_checkpoint_case("positive")
    request = _request()
    client = FakeClient()
    provider = BedrockJudgmentProvider(client, admission_store=FakeStageAdmissionStore())
    ledger = FakeLedger()

    await provider.count(request, execution=_execution(ledger, question_id=request.question_id))
    await provider.converse(request, execution=_execution(ledger, question_id=request.question_id))

    system = cast(list[dict[str, object]], client.converse_inputs[0]["system"])
    assert ["cachePoint" in item for item in system] == case["cache_point_positions"]
    assert system[0]["text"].startswith(str(case["rules_prefix"]))
    topic_text = str(system[2]["text"])
    assert topic_text.startswith(str(case["topic_block_label"]))
    topic_payload = json.loads(topic_text.removeprefix(str(case["topic_block_label"])))
    assert case["catalog_field"] in topic_payload
    assert topic_payload["finding_templates"] == [
        template.model_dump(mode="json", exclude_none=False)
        for template in request.finding_templates
    ]
    assert client.count_inputs[0]["input"] == {
        "converse": {
            "system": client.converse_inputs[0]["system"],
            "messages": client.converse_inputs[0]["messages"],
        }
    }
    assert ledger.calls == [CallKind.COUNT.value, CallKind.converse.value]


@pytest.mark.asyncio
@pytest.mark.case_id("B4-G060.prompt-checkpoints.private")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G060.prompt-checkpoints.private"))
@pytest.mark.variant("negative")
@pytest.mark.fixture_sha256(
    canonical_fixture_sha256("B4-G060.prompt-checkpoints.private", "negative")
)
async def test_g060_question_and_evidence_are_after_both_checkpoint_positions() -> None:
    case = _prompt_checkpoint_case("negative")
    request = _request()
    client = FakeClient()
    provider = BedrockJudgmentProvider(client, admission_store=FakeStageAdmissionStore())

    await provider.converse(
        request, execution=_execution(FakeLedger(), question_id=request.question_id)
    )

    system = cast(list[dict[str, object]], client.converse_inputs[0]["system"])
    messages = cast(list[dict[str, object]], client.converse_inputs[0]["messages"])
    assert len([item for item in system if "cachePoint" in item]) == case["checkpoint_count"]
    assert all(str(case["untrusted_prefix"]) not in str(item) for item in system)
    assert str(case["evidence_prefix"]) in str(messages)
    assert str(case["question_prefix"]) in str(messages)


@pytest.mark.asyncio
@pytest.mark.case_id("B4-G060.prompt-checkpoints.private")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G060.prompt-checkpoints.private"))
@pytest.mark.variant("boundary")
@pytest.mark.fixture_sha256(
    canonical_fixture_sha256("B4-G060.prompt-checkpoints.private", "boundary")
)
async def test_g060_cache_unsupported_prompt_keeps_topic_and_evidence_without_cachepoints() -> None:
    case = _prompt_checkpoint_case("boundary")
    original = _request()
    evidence_before = original.evidence.model_dump_json()
    request = original.model_copy(update={"model": _model(caching=False)})
    client = FakeClient()

    await BedrockJudgmentProvider(client, admission_store=FakeStageAdmissionStore()).converse(
        request, execution=_execution(FakeLedger(), question_id=request.question_id)
    )

    system = cast(list[dict[str, object]], client.converse_inputs[0]["system"])
    assert all("cachePoint" not in item for item in system)
    assert len(system) == case["system_blocks"]
    assert original.evidence.model_dump_json() == evidence_before
    assert request.evidence.model_dump_json() == evidence_before


@pytest.mark.asyncio
@pytest.mark.case_id("B4-G060.prompt-checkpoints.private")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G060.prompt-checkpoints.private"))
@pytest.mark.variant("failure")
@pytest.mark.fixture_sha256(
    canonical_fixture_sha256("B4-G060.prompt-checkpoints.private", "failure")
)
async def test_g060_count_failure_is_finite_and_does_not_retry_or_mutate_evidence() -> None:
    case = _prompt_checkpoint_case("failure")

    class FailedCountClient(FakeClient):
        def count_tokens(self, **kwargs: object) -> dict[str, object]:
            self.count_inputs.append(kwargs)
            raise TimeoutError(str(case["error"]))

    request = _request()
    before = request.evidence.model_dump_json()
    client = FailedCountClient()
    ledger = FakeLedger()
    provider = BedrockJudgmentProvider(client, admission_store=FakeStageAdmissionStore())

    with pytest.raises(ProviderFailure, match=str(case["expected_state"])):
        await provider.count(request, execution=_execution(ledger, question_id=request.question_id))

    assert len(client.count_inputs) == case["attempts"]
    assert client.count_inputs[0]["modelId"] == request.model.count_tokens_model_id
    assert ledger.calls == [CallKind.COUNT.value]
    assert request.evidence.model_dump_json() == before


@pytest.mark.asyncio
async def test_count_and_converse_use_same_counted_prompt_and_exact_tool_free_parameters() -> None:
    client = FakeClient()
    store = FakeStageAdmissionStore()
    provider = BedrockJudgmentProvider(client, admission_store=store)
    request = _request().model_copy(update={"reservation_id": uuid4(), "reserved_tokens": 900})
    ledger = FakeLedger()

    assert (
        await provider.count(request, execution=_execution(ledger, question_id=request.question_id))
        == 100
    )
    actual = await provider.converse(
        request, execution=_execution(ledger, question_id=request.question_id)
    )

    counted = client.count_inputs[0]
    invoked = client.converse_inputs[0]
    count_prompt = counted["input"]
    assert count_prompt == {
        "converse": {"system": invoked["system"], "messages": invoked["messages"]}
    }
    assert counted["modelId"] == request.model.count_tokens_model_id
    assert invoked["modelId"] == request.model.id
    assert invoked["guardrailConfig"] == {
        "guardrailIdentifier": "gr-123456",
        "guardrailVersion": "7",
    }
    assert invoked["additionalModelRequestFields"] == {"effort": "high"}
    assert invoked["inferenceConfig"] == {"maxTokens": 512, "temperature": 0}
    assert "toolConfig" not in invoked and "outputConfig" not in invoked
    assert not hasattr(provider, "converse_stream")
    system = invoked["system"]
    assert isinstance(system, list)
    assert system[0]["text"].startswith("RULES-CHECKPOINT")
    assert system[1] == {"cachePoint": {"type": "default", "ttl": "5m"}}
    assert "DOC-CONTEXT" in system[2]["text"] and "PLAYBOOK-CONTEXT" in system[2]["text"]
    assert system[3] == {"cachePoint": {"type": "default", "ttl": "5m"}}
    assert actual.text == '{"schema_version":"1","findings":[]}'
    assert actual.usage is not None
    assert actual.usage.input_tokens == 80
    assert actual.usage.cache_read_input_tokens == 15
    assert actual.usage.cache_write_input_tokens == 5
    assert actual.usage.total_input_tokens == 100
    assert actual.usage.topic_id == "ldap"
    assert actual.usage.reserved_tokens == 900
    assert len(client.count_inputs) == len(client.converse_inputs) == 1
    assert ledger.calls == [CallKind.COUNT.value, CallKind.converse.value]
    assert [grant.call for grant in store.grants] == ["count", "converse"]
    assert store.released == store.grants
    assert all(grant.question_id == request.question_id for grant in store.grants)
    assert store.grants[0].operation_id != store.grants[1].operation_id
    assert all(
        released is granted for released, granted in zip(store.released, store.grants, strict=True)
    )


@pytest.mark.asyncio
@pytest.mark.case_id("B4-G016.prompt-safety")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G016.prompt-safety"))
@pytest.mark.variant("positive")
@pytest.mark.fixture_sha256(canonical_fixture_sha256("B4-G016.prompt-safety", "positive"))
async def test_b4_prompt_is_ordered_tool_free_and_uses_only_expected_sdk_methods() -> None:
    fixture = _prompt_transport_fixture()
    request = _request()
    client = FakeClient()
    ledger = FakeLedger()
    provider = BedrockJudgmentProvider(client, admission_store=FakeStageAdmissionStore())

    await provider.count(request, execution=_execution(ledger, question_id=request.question_id))
    await provider.converse(request, execution=_execution(ledger, question_id=request.question_id))

    count_input = client.count_inputs[0]
    invocation = client.converse_inputs[0]
    assert count_input["modelId"] == fixture["model_id"]
    assert invocation["modelId"] == fixture["model_id"]
    assert list(invocation) == [
        "modelId",
        "system",
        "messages",
        "inferenceConfig",
        "guardrailConfig",
        "additionalModelRequestFields",
    ]
    assert all(name not in invocation for name in cast(list[str], fixture["forbidden_arguments"]))
    system = cast(list[dict[str, object]], invocation["system"])
    assert system[0]["text"].startswith("RULES-CHECKPOINT")
    assert system[1] == {"cachePoint": {"type": "default", "ttl": "5m"}}
    assert "DOC-CONTEXT" in str(system[2]["text"])
    assert system[3] == {"cachePoint": {"type": "default", "ttl": "5m"}}
    assert len(client.count_inputs) == len(client.converse_inputs) == 1
    assert ledger.calls == [CallKind.COUNT.value, CallKind.converse.value]


@pytest.mark.asyncio
@pytest.mark.case_id("B4-G016.prompt-safety")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G016.prompt-safety"))
@pytest.mark.variant("negative")
@pytest.mark.fixture_sha256(canonical_fixture_sha256("B4-G016.prompt-safety", "negative"))
async def test_b4_invalid_guardrail_fails_before_converse_and_has_no_streaming_method() -> None:
    fixture = _prompt_transport_fixture()
    request = _request().model_copy(
        update={"guardrail": GuardrailPin(**cast(dict[str, str], fixture["invalid_guardrail"]))}
    )
    client = FakeClient()
    provider = BedrockJudgmentProvider(client, admission_store=FakeStageAdmissionStore())

    assert all(
        not hasattr(provider, method)
        for method in cast(list[str], fixture["forbidden_transport_methods"])
    )
    with pytest.raises(CapabilityError, match="numbered guardrail"):
        await provider.converse(
            request,
            execution=_execution(FakeLedger(), question_id=request.question_id),
        )

    assert client.converse_inputs == []
    assert client.count_inputs == []


@pytest.mark.asyncio
@pytest.mark.case_id("B4-G016.prompt-safety")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G016.prompt-safety"))
@pytest.mark.variant("failure")
@pytest.mark.fixture_sha256(canonical_fixture_sha256("B4-G016.prompt-safety", "failure"))
async def test_b4_converse_timeout_is_one_finite_failure_without_count_or_downgrade() -> None:
    fixture = _prompt_transport_fixture()

    class TimeoutClient(FakeClient):
        def converse(self, **kwargs: object) -> dict[str, object]:
            self.converse_inputs.append(kwargs)
            raise TimeoutError(str(fixture["timeout_error"]))

    request = _request()
    client = TimeoutClient()
    ledger = FakeLedger()
    provider = BedrockJudgmentProvider(client, admission_store=FakeStageAdmissionStore())

    with pytest.raises(ProviderFailure, match=str(fixture["timeout_state"])):
        await provider.converse(
            request, execution=_execution(ledger, question_id=request.question_id)
        )

    assert len(client.converse_inputs) == fixture["timeout_attempts"]
    assert client.count_inputs == []
    assert client.converse_inputs[0]["modelId"] == fixture["model_id"]
    assert ledger.calls == [CallKind.converse.value]


@pytest.mark.asyncio
async def test_count_capacity_rejection_is_unattempted_and_request_context_must_match() -> None:
    client = FakeClient()
    store = FakeStageAdmissionStore()
    store.reject = True
    ledger = FakeLedger()
    request = _request()
    provider = BedrockJudgmentProvider(client, admission_store=store)

    with pytest.raises(ProviderFailure, match="capacity_limited"):
        await provider.count(request, execution=_execution(ledger, question_id=request.question_id))
    assert client.count_inputs == []
    assert ledger.calls == []
    assert store.requests[0][3] == "count"
    assert store.released == []

    with pytest.raises(CapabilityError, match="not bound together"):
        await BedrockJudgmentProvider(client, admission_store=FakeStageAdmissionStore()).converse(
            request, execution=_execution(FakeLedger())
        )
    assert client.converse_inputs == []


@pytest.mark.parametrize("call", ["count", "converse"])
@pytest.mark.asyncio
async def test_model_count_grant_lives_until_sdk_call_finishes_after_cancellation(
    call: str,
) -> None:
    started = threading.Event()
    finish_call = threading.Event()
    physically_finished = threading.Event()
    released = threading.Event()

    class BlockingClient(FakeClient):
        def count_tokens(self, **kwargs: object) -> dict[str, object]:
            self.count_inputs.append(kwargs)
            started.set()
            if not finish_call.wait(timeout=2):
                raise TimeoutError("test physical call barrier timed out")
            physically_finished.set()
            return {"inputTokens": 100}

        def converse(self, **kwargs: object) -> dict[str, object]:
            self.converse_inputs.append(kwargs)
            started.set()
            if not finish_call.wait(timeout=2):
                raise TimeoutError("test physical call barrier timed out")
            physically_finished.set()
            return {
                "output": {
                    "message": {"content": [{"text": '{"schema_version":"1","findings":[]}'}]}
                },
                "stopReason": "end_turn",
            }

    class RecordingAdmissionStore(FakeStageAdmissionStore):
        async def release(self, grant: ModelCountGrant | EmbeddingGrant) -> None:
            await super().release(grant)
            released.set()

    store = RecordingAdmissionStore()
    ledger = FakeLedger()
    client = BlockingClient()
    provider = BedrockJudgmentProvider(client, admission_store=store)
    request = _request()
    execution = _execution(ledger, question_id=request.question_id)
    invoke = (
        provider.count(request, execution=execution)
        if call == "count"
        else provider.converse(request, execution=execution)
    )
    task = asyncio.create_task(invoke)
    assert await asyncio.to_thread(started.wait, 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert store.released == []

    finish_call.set()
    assert await asyncio.to_thread(physically_finished.wait, 1)
    assert await asyncio.to_thread(released.wait, 1)
    assert store.released == store.grants
    assert store.released[0] is store.grants[0]
    assert len(ledger.calls) == 1
    assert store.grants[0].call == call


@pytest.mark.asyncio
async def test_b5_model_count_fixture_store_releases_provider_owned_grants() -> None:
    request = _request()
    store = MemoryModelCountAdmissionStore()
    provider = BedrockJudgmentProvider(FakeClient(), admission_store=store)
    execution = _execution(FakeLedger(), question_id=request.question_id)

    assert await provider.count(request, execution=execution) == 100
    await provider.converse(request, execution=execution)

    now = datetime.now(UTC)
    count_grant = await store.acquire(
        environment_id=execution.environment_id,
        question_id=execution.question_id,
        operation_id=uuid4(),
        call="count",
        now=now,
    )
    converse_grant = await store.acquire(
        environment_id=execution.environment_id,
        question_id=execution.question_id,
        operation_id=uuid4(),
        call="converse",
        now=now,
    )
    assert isinstance(count_grant, ModelCountGrant)
    assert isinstance(converse_grant, ModelCountGrant)
    await store.release(count_grant)
    await store.release(converse_grant)


@pytest.mark.asyncio
async def test_botocore_stubber_validates_count_and_converse_sdk_request_shapes() -> None:
    request = _request()
    request = request.model_copy(update={"reservation_id": uuid4(), "reserved_tokens": 900})
    client = boto3.client(
        "bedrock-runtime",
        region_name="us-east-1",
        aws_access_key_id="offline-test",
        aws_secret_access_key="offline-test-only",
    )
    provider = BedrockJudgmentProvider(client, admission_store=FakeStageAdmissionStore())
    system, messages = BedrockJudgmentProvider._prompt(request)
    expected_count = {
        "modelId": request.model.count_tokens_model_id,
        "input": {"converse": {"system": system, "messages": messages}},
    }
    expected_converse = {
        "modelId": request.model.id,
        "system": system,
        "messages": messages,
        "inferenceConfig": {"maxTokens": 512, "temperature": 0},
        "guardrailConfig": {"guardrailIdentifier": "gr-123456", "guardrailVersion": "7"},
        "additionalModelRequestFields": {"effort": "high"},
    }
    with Stubber(client) as stubber:
        stubber.add_response("count_tokens", {"inputTokens": 100}, expected_count)
        stubber.add_response(
            "converse",
            {
                "output": {
                    "message": {
                        "role": "assistant",
                        "content": [{"text": '{"schema_version":"1","findings":[]}'}],
                    }
                },
                "stopReason": "end_turn",
                "usage": {
                    "inputTokens": 80,
                    "outputTokens": 10,
                    "totalTokens": 110,
                    "cacheReadInputTokens": 15,
                    "cacheWriteInputTokens": 5,
                },
                "metrics": {"latencyMs": 3},
            },
            expected_converse,
        )
        assert (
            await provider.count(
                request, execution=_execution(FakeLedger(), question_id=request.question_id)
            )
            == 100
        )
        raw = await provider.converse(
            request, execution=_execution(FakeLedger(), question_id=request.question_id)
        )
    assert raw.usage is not None and raw.usage.total_input_tokens == 100


def test_boto3_clients_pin_region_timeouts_retries_and_socket_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, object]]] = []
    fake_client = FakeClient()

    def factory(service_name: str, **kwargs: object) -> FakeClient:
        calls.append((service_name, kwargs))
        return fake_client

    monkeypatch.setattr(boto3, "client", factory)
    BedrockJudgmentProvider.from_boto3(_model(), admission_store=FakeStageAdmissionStore())
    assert [name for name, _ in calls] == ["bedrock-runtime", "bedrock-runtime"]
    count_config = calls[1][1]["config"]
    converse_config = calls[0][1]["config"]
    assert calls[0][1]["region_name"] == calls[1][1]["region_name"] == "us-east-1"
    assert count_config.connect_timeout == converse_config.connect_timeout == 3
    assert count_config.read_timeout == 5
    assert converse_config.read_timeout == 27
    assert (
        count_config.retries
        == converse_config.retries
        == {
            "total_max_attempts": 1,
            "mode": "standard",
        }
    )
    assert count_config.max_pool_connections == converse_config.max_pool_connections == 4


@pytest.mark.asyncio
async def test_cache_disabled_preserves_prompt_bytes_and_selected_no_effort_is_unchanged() -> None:
    client = FakeClient()
    provider = BedrockJudgmentProvider(client, admission_store=FakeStageAdmissionStore())
    request = _request().model_copy(
        update={"model": _model(efforts=False, caching=False), "effort": None}
    )
    invoked = await provider.converse(
        request, execution=_execution(FakeLedger(), question_id=request.question_id)
    )
    assert "cachePoint" not in repr(client.converse_inputs[0]["system"])
    assert "additionalModelRequestFields" not in client.converse_inputs[0]
    assert invoked.stop_reason == "end_turn"


def test_context_fit_boundaries_reserve_output_and_margin_without_truncation() -> None:
    request = _request()
    required_input = request.model.context_tokens - request.max_output_tokens - 256
    assert fits_context(required_input, request)
    assert reserved_gross_tokens(required_input, request) == request.model.context_tokens
    assert not fits_context(required_input + 1, request)
    before = request.evidence.model_dump_json()
    assert request.evidence.model_dump_json() == before


@pytest.mark.case_id("B4-G029.context-budget.private")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G029.context-budget.private"))
@pytest.mark.variant("positive")
@pytest.mark.fixture_sha256(canonical_fixture_sha256("B4-G029.context-budget.private", "positive"))
def test_g029_context_budget_allows_bounded_input_without_truncation() -> None:
    fixture = _context_budget_case("positive")
    request = _request()
    input_tokens = int(fixture["input_tokens"])
    before = request.evidence.model_dump_json()

    result = context_outcome(input_tokens, request)

    assert result is None
    assert reserved_gross_tokens(input_tokens, request) == fixture["expected_gross_reserved"]
    assert request.evidence.model_dump_json() == before


@pytest.mark.case_id("B4-G029.context-budget.private")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G029.context-budget.private"))
@pytest.mark.variant("negative")
@pytest.mark.fixture_sha256(canonical_fixture_sha256("B4-G029.context-budget.private", "negative"))
def test_g029_context_overflow_is_left_out_without_evidence_truncation() -> None:
    fixture = _context_budget_case("negative")
    request = _request()
    before = request.evidence.model_dump_json()

    result = context_outcome(int(fixture["input_tokens"]), request)

    assert result is not None
    assert result.result.state == fixture["expected_state"]
    assert result.left_out is not None
    assert result.left_out.reason == fixture["expected_reason"]
    assert request.evidence.model_dump_json() == before


@pytest.mark.case_id("B4-G029.context-budget.private")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G029.context-budget.private"))
@pytest.mark.variant("boundary")
@pytest.mark.fixture_sha256(canonical_fixture_sha256("B4-G029.context-budget.private", "boundary"))
def test_g029_exact_context_boundary_is_accepted() -> None:
    fixture = _context_budget_case("boundary")
    request = _request()
    input_tokens = int(fixture["input_tokens"])

    assert context_outcome(input_tokens, request) is None
    assert reserved_gross_tokens(input_tokens, request) == fixture["expected_gross_reserved"]


@pytest.mark.case_id("B4-G029.context-budget.private")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G029.context-budget.private"))
@pytest.mark.variant("failure")
@pytest.mark.fixture_sha256(canonical_fixture_sha256("B4-G029.context-budget.private", "failure"))
def test_g029_count_failure_has_finite_retryable_topic_outcome() -> None:
    fixture = _context_budget_case("failure")
    result = provider_failure_outcome(str(fixture["provider_state"]), "ldap")

    assert result.result.state == fixture["expected_state"]
    assert result.left_out is not None
    assert result.left_out.reason == fixture["expected_reason"]


def test_context_and_provider_failures_map_to_exact_finite_outcomes() -> None:
    request = _request()
    exact_input = request.model.context_tokens - request.max_output_tokens - 256
    assert context_outcome(exact_input, request) is None
    overflow = context_outcome(exact_input + 1, request)
    assert overflow is not None
    assert overflow.result.state == JudgmentState.context_exceeded
    assert overflow.left_out is not None
    assert overflow.left_out.reason == LeftOutReason.context_exceeded

    expected = {
        "token_count_unavailable": (
            JudgmentState.token_count_unavailable,
            LeftOutReason.token_count_unavailable,
        ),
        "model_unavailable": (JudgmentState.model_unavailable, LeftOutReason.model_unavailable),
        "guardrail_blocked": (JudgmentState.guardrail_blocked, LeftOutReason.guardrail_blocked),
        "capacity_limited": (JudgmentState.capacity_limited, LeftOutReason.capacity_limited),
        "deadline_exceeded": (JudgmentState.deadline_exceeded, LeftOutReason.deadline_exceeded),
    }
    for provider_state, (state, reason) in expected.items():
        skip = provider_failure_outcome(provider_state, "ldap")
        assert skip.result.state == state
        assert skip.left_out is not None and skip.left_out.reason == reason
        assert skip.left_out.retryable is (provider_state != "guardrail_blocked")


@pytest.mark.asyncio
async def test_physical_slot_survives_await_cancellation_until_sdk_call_returns() -> None:
    pool = PhysicalCallPool(1)
    entered = threading.Event()
    release = threading.Event()

    def blocked_call() -> str:
        entered.set()
        release.wait(timeout=2)
        return "complete"

    first = asyncio.create_task(pool.run(blocked_call))
    assert await asyncio.to_thread(entered.wait, 1)
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    with pytest.raises(ProviderFailure, match="capacity_limited"):
        await pool.run(lambda: "must not run")
    release.set()
    await asyncio.sleep(0.02)
    assert await pool.run(lambda: "available") == "available"


@pytest.mark.asyncio
async def test_physical_call_pool_maps_before_call_failure_to_capacity() -> None:
    pool = PhysicalCallPool(1)
    called = False

    def call() -> str:
        nonlocal called
        called = True
        return "called"

    ledger = BoundedCallLedger({CallKind.converse: 0})

    with pytest.raises(ProviderFailure) as failure:
        await pool.run(call, before_call=lambda: ledger.claim(CallKind.converse))

    assert failure.value.state == "capacity_limited"
    assert failure.value.retryable is True
    assert called is False


@pytest.mark.asyncio
async def test_m3_guardrail_with_empty_content_returns_guardrail_not_invalid_output() -> None:
    class EmptyGuardrailClient(FakeClient):
        def converse(self, **kwargs: object) -> dict[str, object]:
            self.converse_inputs.append(kwargs)
            return {
                "output": {"message": {"content": []}},
                "stopReason": "guardrail_intervened",
                "ResponseMetadata": {"RequestId": "empty-guardrail"},
            }

    client = EmptyGuardrailClient()
    request = _request()
    raw = await BedrockJudgmentProvider(client, admission_store=FakeStageAdmissionStore()).converse(
        request, execution=_execution(FakeLedger(), question_id=request.question_id)
    )
    assert raw.guardrail_intervened
    assert raw.text == ""
    validated = FindingValidator().validate(
        raw,
        request.evidence,
        context=ValidationContext(
            topic_pack=request.topic_pack,
            templates=(),
            policy_hash=request.evidence.policy_hash,
            content_sha=request.evidence.content_sha,
            language=request.language,
            expected_checks=(),
        ),
    )
    assert validated.state == JudgmentState.guardrail_blocked


@pytest.mark.asyncio
async def test_m3_guardrail_with_multiple_text_blocks_returns_guardrail_blocked() -> None:
    class MultiBlockClient(FakeClient):
        def converse(self, **kwargs: object) -> dict[str, object]:
            self.converse_inputs.append(kwargs)
            return {
                "output": {
                    "message": {"content": [{"text": "a"}, {"text": "b"}]},
                },
                "stopReason": "guardrail_intervened",
                "ResponseMetadata": {"RequestId": "multi-guardrail"},
            }

    client = MultiBlockClient()
    request = _request()
    raw = await BedrockJudgmentProvider(client, admission_store=FakeStageAdmissionStore()).converse(
        request, execution=_execution(FakeLedger(), question_id=request.question_id)
    )
    assert raw.guardrail_intervened
    assert raw.text == ""


@pytest.mark.asyncio
async def test_end_turn_with_multiple_text_blocks_returns_empty_text_with_usage() -> None:
    class MultiBlockEndTurnClient(FakeClient):
        def converse(self, **kwargs: object) -> dict[str, object]:
            self.converse_inputs.append(kwargs)
            return {
                "output": {"message": {"content": [{"text": "a"}, {"text": "b"}]}},
                "stopReason": "end_turn",
                "usage": {
                    "inputTokens": 80,
                    "outputTokens": 10,
                    "cacheReadInputTokens": 0,
                    "cacheWriteInputTokens": 0,
                },
                "ResponseMetadata": {"RequestId": "multi-end-turn"},
            }

    client = MultiBlockEndTurnClient()
    request = _request().model_copy(update={"reservation_id": uuid4(), "reserved_tokens": 900})
    raw = await BedrockJudgmentProvider(client, admission_store=FakeStageAdmissionStore()).converse(
        request, execution=_execution(FakeLedger(), question_id=request.question_id)
    )
    assert raw.text == ""
    assert raw.guardrail_intervened is False
    assert raw.usage is not None


@pytest.mark.asyncio
async def test_e1_guardrail_scans_only_guard_content_question_not_evidence() -> None:
    request = _request().model_copy(update={"question": "legitimate analyst question"})
    client = FakeClient()
    provider = BedrockJudgmentProvider(client, admission_store=FakeStageAdmissionStore())
    await provider.converse(
        request, execution=_execution(FakeLedger(), question_id=request.question_id)
    )
    messages = cast(list[dict[str, object]], client.converse_inputs[0]["messages"])
    content = cast(list[dict[str, object]], messages[0]["content"])
    evidence_blocks = [
        block for block in content if "text" in block and "guardContent" not in block
    ]
    guarded = [block for block in content if "guardContent" in block]
    assert len(evidence_blocks) == 1
    assert "guardContent" not in evidence_blocks[0]
    assert len(guarded) == 1
    guard = cast(dict[str, object], guarded[0]["guardContent"])
    text_block = cast(dict[str, object], guard["text"])
    assert text_block["qualifiers"] == ["guard_content"]
    assert "UNTRUSTED ORIGINAL QUESTION DATA" in str(text_block["text"])
    assert "UNTRUSTED TOPIC EVIDENCE DATA" in str(evidence_blocks[0]["text"])


@pytest.mark.asyncio
async def test_l8_provider_admission_uses_injected_clock() -> None:
    fixed = datetime(2026, 6, 15, 12, 0, 0, tzinfo=UTC)

    class FixedClock:
        def now(self) -> datetime:
            return fixed

    store = FakeStageAdmissionStore()
    request = _request()
    await BedrockJudgmentProvider(FakeClient(), admission_store=store, clock=FixedClock()).count(
        request, execution=_execution(FakeLedger(), question_id=request.question_id)
    )
    assert store.grants[0].acquired_at == fixed


@pytest.mark.asyncio
async def test_guardrail_output_and_invalid_provider_shapes_fail_without_prose() -> None:
    class GuardrailClient(FakeClient):
        def converse(self, **kwargs: object) -> dict[str, object]:
            self.converse_inputs.append(kwargs)
            return {
                "output": {"message": {"content": [{"text": "HOSTILE-FIRST-TOKEN"}]}},
                "stopReason": "guardrail_intervened",
            }

    client = GuardrailClient()
    request = _request()
    raw = await BedrockJudgmentProvider(client, admission_store=FakeStageAdmissionStore()).converse(
        request, execution=_execution(FakeLedger(), question_id=request.question_id)
    )
    assert raw.guardrail_intervened
    assert raw.text == "HOSTILE-FIRST-TOKEN"  # Raw provider data stays inside this boundary.

    from ai_soc.judgment.capabilities import CapabilityError

    with pytest.raises(CapabilityError):
        bad = _request().model_copy(
            update={"guardrail": GuardrailPin(identifier="DRAFT", version="1")}
        )
        await BedrockJudgmentProvider(
            FakeClient(), admission_store=FakeStageAdmissionStore()
        ).converse(bad, execution=_execution(FakeLedger(), question_id=bad.question_id))
