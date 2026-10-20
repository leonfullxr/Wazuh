"""Independent dependency, static-source, and runtime checks for G049."""

from __future__ import annotations

import ast
import asyncio
import json
import re
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import pytest
from case_binding import (
    assert_fixture_matches_all_variants,
    canonical_acceptance_ids,
    canonical_fixture_sha256,
)

ROOT = Path(__file__).resolve().parents[3]
FIXTURE_PATH = Path(__file__).parent / "data" / "g049_tool_free_cases.json"


class NeverCancelled:
    def is_cancelled(self) -> bool:
        return False

    def raise_if_cancelled(self) -> None:
        return None

    async def wait(self) -> None:
        await asyncio.Future()


def _fixture() -> dict[str, object]:
    assert_fixture_matches_all_variants("B4-G049.tool-free-converse.private", FIXTURE_PATH)
    parsed: object = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise AssertionError("G049 fixture must be a JSON object")
    return cast(dict[str, object], parsed)


def _variant(name: str) -> dict[str, object]:
    variants = _fixture().get("variants")
    if not isinstance(variants, dict) or not isinstance(variants.get(name), dict):
        raise AssertionError(f"G049 fixture has no {name} variant")
    return cast(dict[str, object], variants[name])


def _source_violations(source: str) -> list[str]:
    tree = ast.parse(source)
    violations: list[str] = []
    forbidden_streams = {"converse_stream", "invoke_model_with_response_stream"}
    forbidden_tool_keys = {"toolConfig", "tools", "tool_config"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", maxsplit=1)[0]
                if root.casefold().startswith("langchain"):
                    violations.append(f"framework_import:{root}")
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            root = node.module.split(".", maxsplit=1)[0]
            if root.casefold().startswith("langchain"):
                violations.append(f"framework_import:{root}")
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_streams:
                violations.append(f"stream_call:{node.func.attr}")
            for keyword in node.keywords:
                if keyword.arg in forbidden_tool_keys:
                    violations.append(f"tool_configuration:{keyword.arg}")
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            if any(
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and child.func.attr == "converse"
                for child in ast.walk(node)
            ):
                violations.append("tool_loop:converse")
        elif isinstance(node, ast.Dict):
            for key in node.keys:
                if isinstance(key, ast.Constant) and key.value in forbidden_tool_keys:
                    violations.append(f"tool_configuration:{key.value}")
    return sorted(violations)


@pytest.mark.asyncio
@pytest.mark.case_id("B4-G049.tool-free-converse.private")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G049.tool-free-converse.private"))
@pytest.mark.variant("positive")
@pytest.mark.fixture_sha256(
    canonical_fixture_sha256("B4-G049.tool-free-converse.private", "positive")
)
async def test_g049_runtime_provider_exposes_only_count_and_buffered_converse() -> None:
    from admission_fakes import FakeStageAdmissionStore

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
        TopicPromptPack,
        TraceContext,
    )
    from ai_soc.judgment.bedrock import BedrockJudgmentProvider

    fixture = _variant("positive")

    class RecordingClient:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, object]]] = []

        def count_tokens(self, **kwargs: object) -> dict[str, object]:
            self.calls.append(("count_tokens", kwargs))
            return {"inputTokens": 100}

        def converse(self, **kwargs: object) -> dict[str, object]:
            self.calls.append(("converse", kwargs))
            return {
                "output": {
                    "message": {"content": [{"text": '{"schema_version":"1","findings":[]}'}]}
                },
                "stopReason": "end_turn",
            }

    class Ledger:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def claim(self, kind: object) -> None:
            self.calls.append(str(kind))

    client = RecordingClient()
    now = datetime.now(UTC)
    question_id = UUID("a650f780-5e2c-4cf3-a234-1ebd59c22b05")
    content_sha = "a" * 40
    model = ModelCapability(
        id="arn:aws:bedrock:us-east-1:123456789012:inference-profile/g049-fixture",
        label="G049 fixture model",
        region="us-east-1",
        resource_arns=("arn:aws:bedrock:us-east-1:123456789012:inference-profile/g049-fixture",),
        context_tokens=4096,
        max_output_tokens=512,
        count_tokens_model_id="g049-fixture-model",
        efforts=(Effort.low,),
        effort_transport="additionalModelRequestFields",
        effort_parameters={Effort.low: {"effort": "low"}},
        output_strategy="strict_json_messages",
        count_strategy="count_tokens_converse",
        count_contract_sha256="1" * 64,
        cache_min_tokens=0,
        cache_max_checkpoints=0,
        cache_ttl="5m",
        validated_at=now,
        primary_doc_url="https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html",
    )
    evidence = EvidencePack(
        question_id=question_id,
        environment_id="alpha",
        topic_id="ldap",
        policy_hash="2" * 64,
        content_sha=content_sha,
        fetches=[],
        checks=[],
        items=[],
        sha256="3" * 64,
    )
    request = JudgmentRequest(
        question_id=question_id,
        topic_id="ldap",
        model=model,
        effort=Effort.low,
        language="en",
        standing_rules="FIXED-RULES",
        topic_pack=TopicPromptPack(
            topic_id="ldap",
            language="en",
            content_sha=content_sha,
            sha256="4" * 64,
            missing=[],
        ),
        evidence=evidence,
        question="fixture question",
        max_output_tokens=128,
        guardrail=GuardrailPin(identifier="gr-123456", version="7"),
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
    ledger = Ledger()

    def execution() -> ExecutionContext:
        return ExecutionContext(
            question_id=question_id,
            operation="ask",
            owner_key="5" * 64,
            environment_id="alpha",
            deadline_at=now,
            cancel=NeverCancelled(),
            calls=ledger,  # type: ignore[arg-type]
            admission=AdmissionGrant(
                holder_id=uuid4(), slot_ids=("model",), expires_at=now, fence=1
            ),
            trace_context=TraceContext(trace_id="1" * 32, span_id="2" * 16, trace_flags=1),
        )

    provider = BedrockJudgmentProvider(client, admission_store=FakeStageAdmissionStore())
    token_count = await provider.count(request, execution=execution())
    result = await provider.converse(request, execution=execution())

    assert token_count == 100
    assert result.text == '{"schema_version":"1","findings":[]}'
    assert [method for method, _ in client.calls] == fixture["sdk_calls"]
    count_input = client.calls[0][1]
    converse_input = client.calls[1][1]
    assert count_input["modelId"] == model.count_tokens_model_id
    count_payload = cast(dict[str, object], count_input["input"])
    assert set(count_payload) == {"converse"}
    counted_converse = cast(dict[str, object], count_payload["converse"])
    assert set(counted_converse) == {"system", "messages"}
    assert converse_input["modelId"] == model.id
    assert converse_input["guardrailConfig"] == {
        "guardrailIdentifier": "gr-123456",
        "guardrailVersion": "7",
    }
    assert "toolConfig" not in converse_input and "outputConfig" not in converse_input
    assert ledger.calls == [CallKind.COUNT.value, CallKind.converse.value]
    assert len(client.calls) == fixture["attempts"]
    assert not hasattr(provider, "converse_stream")
    assert not hasattr(provider, "invoke_model_with_response_stream")
    _assert_dependencies_and_provider_source(fixture)


def _assert_dependencies_and_provider_source(fixture: dict[str, object]) -> None:
    registry = _fixture()
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    direct = project["project"]["dependencies"]
    dev = project["dependency-groups"]["dev"]
    dependency_names = {
        re.sub(
            r"[-_.]+",
            "-",
            entry.split("[", maxsplit=1)[0].split("=", maxsplit=1)[0],
        ).casefold()
        for entry in [*direct, *dev]
    }
    assert not any(
        name.startswith(tuple(fixture["excluded_dependency_prefixes"])) for name in dependency_names
    )
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    packages = lock["package"]
    resolved_names = {
        re.sub(r"[-_.]+", "-", str(package["name"])).casefold()
        for package in packages
        if isinstance(package, dict) and isinstance(package.get("name"), str)
    }
    forbidden_resolved_names = sorted(
        name
        for name in resolved_names
        if name.startswith(tuple(fixture["excluded_dependency_prefixes"]))
    )
    assert forbidden_resolved_names == fixture["forbidden_locked_dependencies"]

    source_path = ROOT / str(registry["production_source"])
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name.split(".", maxsplit=1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    calls = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert fixture["sdk_import"] in imports
    assert calls & {"count_tokens", "converse"} == set(fixture["sdk_calls"])
    assert _source_violations(source) == []


@pytest.mark.case_id("B4-G049.tool-free-converse.private")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G049.tool-free-converse.private"))
@pytest.mark.variant("negative")
@pytest.mark.fixture_sha256(
    canonical_fixture_sha256("B4-G049.tool-free-converse.private", "negative")
)
def test_g049_forbidden_framework_streaming_and_tool_config_are_detected() -> None:
    fixture = _variant("negative")
    assert set(_source_violations(str(fixture["source"]))) == set(fixture["violations"])


@pytest.mark.case_id("B4-G049.tool-free-converse.private")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G049.tool-free-converse.private"))
@pytest.mark.variant("boundary")
@pytest.mark.fixture_sha256(
    canonical_fixture_sha256("B4-G049.tool-free-converse.private", "boundary")
)
def test_g049_comment_and_string_mentions_are_not_false_positive_calls() -> None:
    fixture = _variant("boundary")
    assert _source_violations(str(fixture["source"])) == fixture["violations"]


@pytest.mark.case_id("B4-G049.tool-free-converse.private")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G049.tool-free-converse.private"))
@pytest.mark.variant("failure")
@pytest.mark.fixture_sha256(
    canonical_fixture_sha256("B4-G049.tool-free-converse.private", "failure")
)
def test_g049_invalid_static_input_fails_closed() -> None:
    fixture = _variant("failure")
    with pytest.raises(SyntaxError):
        _source_violations(str(fixture["source"]))
    assert fixture["error"] == "SyntaxError"
