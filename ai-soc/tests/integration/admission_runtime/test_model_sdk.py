from __future__ import annotations

import asyncio
import json
import threading
from datetime import UTC, datetime
from typing import cast
from uuid import uuid4

import boto3
import pytest
from botocore.client import BaseClient
from botocore.config import Config
from botocore.stub import Stubber
from conftest import DynamoFixture

from ai_soc.contracts.models import (
    AdmissionGrant,
    CallKind,
    Effort,
    EvidencePack,
    ExecutionContext,
    FieldId,
    FindingTemplate,
    GuardrailPin,
    JudgmentRequest,
    LocaleText,
    ModelCapability,
    ModelCountGrant,
    TopicPromptPack,
    TraceContext,
)
from ai_soc.judgment.bedrock import BedrockJudgmentProvider, ProviderFailure
from ai_soc.state.stage_admission import DynamoModelCountAdmissionStore

OUTPUT_RULES = (
    'Return only UTF-8 JSON: {"schema_version":"1","findings":[]}. '
    "Each finding has finding_id, kind, template_id, evidence_ids, and bindings. "
    "Each binding maps a required binding ID to {evidence_id,field}. Never return prose."
)


class NeverCancelled:
    def is_cancelled(self) -> bool:
        return False

    def raise_if_cancelled(self) -> None:
        return None

    async def wait(self) -> None:
        await asyncio.Future()


class CallLedger:
    def __init__(self) -> None:
        self.calls: list[CallKind] = []

    def claim(self, kind: CallKind) -> None:
        self.calls.append(kind)


def _request() -> JudgmentRequest:
    question_id = uuid4()
    model_id = "arn:aws:bedrock:us-east-1:123456789012:inference-profile/offline-fixture"
    model = ModelCapability(
        id=model_id,
        label="Offline fixture model",
        region="us-east-1",
        resource_arns=(model_id,),
        context_tokens=4096,
        max_output_tokens=128,
        count_tokens_model_id=model_id,
        efforts=(Effort.low,),
        effort_transport="additionalModelRequestFields",
        effort_parameters={Effort.low: {"reasoning_effort": "low"}},
        output_strategy="strict_json_messages",
        count_strategy="count_tokens_converse",
        count_contract_sha256="1" * 64,
        cache_min_tokens=0,
        cache_max_checkpoints=0,
        cache_ttl="5m",
        validated_at=datetime.now(UTC),
        primary_doc_url="https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html",
    )
    evidence = EvidencePack(
        question_id=question_id,
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
        question_id=question_id,
        topic_id="ldap",
        model=model,
        effort=Effort.low,
        language="en",
        standing_rules="Fixture rules",
        topic_pack=TopicPromptPack(
            topic_id="ldap",
            language="en",
            content_sha="a" * 40,
            sha256="4" * 64,
            document_section="Fixture documentation",
            internal_context="Fixture playbook",
            missing=[],
        ),
        evidence=evidence,
        question="Why did login fail?",
        max_output_tokens=128,
        guardrail=GuardrailPin(identifier="fixture-guardrail", version="3"),
        finding_templates=(
            FindingTemplate(
                template_id="ldap_observation",
                topic_id="ldap",
                kind="observation",
                required_bindings={"rule": (FieldId.rule_id,)},
                texts=LocaleText(
                    en="Observed rule: {rule}",
                    es="Regla observada: {rule}",
                ),
                required_check_outcomes=[],
                allowed_evidence_kinds=["row"],
            ),
        ),
    )


def _execution(request: JudgmentRequest, ledger: CallLedger) -> ExecutionContext:
    now = datetime.now(UTC)
    return ExecutionContext(
        question_id=request.question_id,
        operation="ask",
        owner_key="5" * 64,
        environment_id="alpha",
        deadline_at=now.replace(microsecond=0),
        cancel=NeverCancelled(),  # type: ignore[arg-type]
        calls=ledger,  # type: ignore[arg-type]
        admission=AdmissionGrant(
            holder_id=uuid4(), slot_ids=("fixture-model",), expires_at=now, fence=1
        ),
        trace_context=TraceContext(trace_id="1" * 32, span_id="2" * 16, trace_flags=1),
    )


def _bedrock_client() -> BaseClient:
    return cast(
        BaseClient,
        boto3.client(
            "bedrock-runtime",
            region_name="us-east-1",
            endpoint_url="https://bedrock.invalid",
            aws_access_key_id="B3FIXTUREKEY",
            aws_secret_access_key="B3-only-stubber-secret-0123456789",
            config=Config(retries={"total_max_attempts": 1}, connect_timeout=1, read_timeout=1),
        ),
    )


def _expected_converse(request: JudgmentRequest) -> dict[str, object]:
    topic_context = {
        "topic_id": "ldap",
        "language": "en",
        "content_sha": "a" * 40,
        "document_section": "Fixture documentation",
        "internal_context": "Fixture playbook",
        "missing": [],
        "finding_templates": [
            template.model_dump(mode="json", exclude_none=False)
            for template in request.finding_templates
        ],
    }
    evidence_json = request.evidence.model_dump_json(exclude_none=False)
    question_json = json.dumps("Why did login fail?", ensure_ascii=False)
    return {
        "modelId": request.model.id,
        "system": [
            {"text": f"Fixture rules\n{OUTPUT_RULES}"},
            {
                "text": "APPROVED TOPIC CONTEXT (data): "
                + json.dumps(
                    topic_context,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            },
        ],
        "messages": [
            {
                "role": "user",
                "content": [
                    {"text": f"UNTRUSTED TOPIC EVIDENCE DATA:\n{evidence_json}"},
                    {
                        "guardContent": {
                            "text": {
                                "text": f"UNTRUSTED ORIGINAL QUESTION DATA:\n{question_json}",
                                "qualifiers": ["guard_content"],
                            }
                        }
                    },
                ],
            }
        ],
        "inferenceConfig": {"maxTokens": 128, "temperature": 0},
        "guardrailConfig": {"guardrailIdentifier": "fixture-guardrail", "guardrailVersion": "3"},
        "additionalModelRequestFields": {"reasoning_effort": "low"},
    }


@pytest.mark.asyncio
async def test_count_and_converse_are_actual_sdk_calls_over_durable_admission(
    dynamo_fixture: DynamoFixture,
) -> None:
    request = _request()
    ledger = CallLedger()
    execution = _execution(request, ledger)
    client = _bedrock_client()
    store = DynamoModelCountAdmissionStore(dynamo_fixture.clients[0], dynamo_fixture.table)
    provider = BedrockJudgmentProvider(
        client=client,
        count_client=client,
        admission_store=store,
    )
    expected_system = _expected_converse(request)["system"]
    expected_messages = _expected_converse(request)["messages"]
    expected_count = {
        "modelId": request.model.count_tokens_model_id,
        "input": {"converse": {"system": expected_system, "messages": expected_messages}},
    }
    expected_output = '{"schema_version":"1","findings":[]}'

    with Stubber(client) as stubber:
        stubber.add_response("count_tokens", {"inputTokens": 63}, expected_count)
        stubber.add_response(
            "converse",
            {
                "output": {
                    "message": {"role": "assistant", "content": [{"text": expected_output}]}
                },
                "stopReason": "end_turn",
                "metrics": {"latencyMs": 2},
                "usage": {"inputTokens": 60, "outputTokens": 8, "totalTokens": 68},
            },
            _expected_converse(request),
        )
        counted = await provider.count(request, execution=execution)
        answer = await provider.converse(request, execution=execution)
        stubber.assert_no_pending_responses()

    assert counted == 63
    assert answer.text == expected_output
    assert ledger.calls == [CallKind.COUNT, CallKind.converse]
    client.close()


@pytest.mark.asyncio
async def test_site_capacity_rejection_precedes_every_bedrock_sdk_attempt(
    dynamo_fixture: DynamoFixture,
) -> None:
    store_a = DynamoModelCountAdmissionStore(dynamo_fixture.clients[0], dynamo_fixture.table)
    store_b = DynamoModelCountAdmissionStore(dynamo_fixture.clients[1], dynamo_fixture.table)
    now = datetime.now(UTC).replace(microsecond=0)
    held: list[ModelCountGrant] = []
    for store in (store_a, store_b):
        grant = await store.acquire(
            environment_id="alpha",
            question_id=uuid4(),
            operation_id=uuid4(),
            call="count",
            now=now,
        )
        assert isinstance(grant, ModelCountGrant)
        held.append(grant)

    client = _bedrock_client()
    attempts: list[str] = []
    client.meta.events.register(
        "before-parameter-build.bedrock-runtime.CountTokens",
        lambda **_: attempts.append("CountTokens"),
    )
    request = _request()
    ledger = CallLedger()
    provider = BedrockJudgmentProvider(
        client=client,
        admission_store=store_a,
    )
    with Stubber(client) as stubber:
        stubber.add_response("count_tokens", {"inputTokens": 1})
        with pytest.raises(ProviderFailure, match="capacity"):
            await provider.count(request, execution=_execution(request, ledger))
        assert attempts == []
        assert ledger.calls == []

    for grant in held:
        await store_b.release(grant)
    client.close()


@pytest.mark.asyncio
async def test_cancelled_caller_keeps_durable_model_slot_until_sdk_thread_finishes(
    dynamo_fixture: DynamoFixture,
) -> None:
    store_a = DynamoModelCountAdmissionStore(dynamo_fixture.clients[0], dynamo_fixture.table)
    request = _request()
    ledger = CallLedger()
    client = _bedrock_client()
    started = threading.Event()
    resume = threading.Event()

    def pause_sdk(*_: object, **__: object) -> None:
        started.set()
        if not resume.wait(timeout=5):
            raise TimeoutError("local test did not resume the stubbed SDK call")

    client.meta.events.register_first("before-parameter-build.bedrock-runtime.Converse", pause_sdk)
    provider = BedrockJudgmentProvider(client=client, admission_store=store_a)
    with Stubber(client) as stubber:
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
                "metrics": {"latencyMs": 1},
                "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
            },
            _expected_converse(request),
        )
        task = asyncio.create_task(
            provider.converse(request, execution=_execution(request, ledger))
        )
        assert await asyncio.to_thread(started.wait, 3), "SDK stub did not enter its blocked call"
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        active_items = (
            dynamo_fixture.clients[1]
            .scan(
                TableName=dynamo_fixture.table,
                ConsistentRead=True,
                FilterExpression="question_id = :question",
                ExpressionAttributeValues={":question": {"S": str(request.question_id)}},
            )
            .get("Items", [])
        )
        assert isinstance(active_items, list) and len(active_items) == 2
        holders = {item.get("holder_id", {}).get("S") for item in active_items}
        assert len(holders) == 1 and None not in holders

        resume.set()
        for _ in range(100):
            slot_items = (
                dynamo_fixture.clients[1]
                .scan(
                    TableName=dynamo_fixture.table,
                    ConsistentRead=True,
                    FilterExpression="question_id = :question",
                    ExpressionAttributeValues={":question": {"S": str(request.question_id)}},
                )
                .get("Items", [])
            )
            if (
                isinstance(slot_items, list)
                and len(slot_items) == 2
                and all("holder_id" not in item for item in slot_items)
            ):
                break
            await asyncio.sleep(0.02)
        else:
            pytest.fail("durable model permit remained held after the SDK call completed")
        stubber.assert_no_pending_responses()

    assert ledger.calls == [CallKind.converse]
    client.close()
