from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]


def _statements(name: str) -> list[dict[str, Any]]:
    policy = json.loads((ROOT / "config/qualification" / name).read_text(encoding="utf-8"))
    return policy["Statement"]


def test_probe_policy_limits_model_calls_and_never_grants_activation_permissions() -> None:
    statements = _statements("probe-role-policy.json")
    actions = [action for statement in statements for action in _as_list(statement["Action"])]
    assert set(actions) == {
        "bedrock:CountTokens",
        "bedrock:InvokeModel",
        "bedrock:ApplyGuardrail",
    }
    assert all(statement.get("Resource") != "*" for statement in statements)
    assert all(statement.get("NotResource") != "*" for statement in statements)
    count = next(
        statement
        for statement in statements
        if statement["Sid"] == "CountOnlyProfileDestinationFoundationModels"
    )
    count_resources = count["Resource"]
    assert isinstance(count_resources, list) and count_resources
    assert all(
        resource.startswith("arn:aws:bedrock:REPLACE_REGION::foundation-model/")
        for resource in count_resources
    )
    invoke = next(
        statement
        for statement in statements
        if statement["Sid"] == "GuardedInvocationOnlyForSelectedModel"
    )
    invoke_resources = invoke["Resource"]
    assert isinstance(invoke_resources, list)
    assert any(":inference-profile/" in resource for resource in invoke_resources)
    invoke_destinations = [
        resource for resource in invoke_resources if "::foundation-model/" in resource
    ]
    assert invoke_destinations == count_resources
    assert len(invoke_resources) == len(count_resources) + 1
    assert invoke["Condition"]["StringEquals"]["bedrock:GuardrailIdentifier"].endswith(
        ":guardrail/REPLACE_GUARDRAIL_ID:REPLACE_NUMERIC_VERSION"
    )
    apply = next(
        statement for statement in statements if statement["Sid"] == "ApplyOnlyTheSelectedGuardrail"
    )
    assert apply["Resource"].endswith(":guardrail/REPLACE_GUARDRAIL_ID")
    deny_missing = next(
        statement for statement in statements if statement["Sid"] == "DenyMissingGuardrail"
    )
    deny_mismatch = next(
        statement
        for statement in statements
        if statement["Sid"] == "DenyMismatchedGuardrailIdentifier"
    )
    deny_other = next(
        statement
        for statement in statements
        if statement["Sid"] == "DenyNonAllowlistedBedrockResources"
    )
    assert deny_missing["Effect"] == deny_mismatch["Effect"] == deny_other["Effect"] == "Deny"
    assert deny_missing["Resource"] == deny_mismatch["Resource"] == invoke_resources
    assert deny_missing["Condition"]["Null"]["bedrock:GuardrailIdentifier"] == "true"
    assert (
        deny_mismatch["Condition"]["StringNotEquals"]["bedrock:GuardrailIdentifier"]
        == invoke["Condition"]["StringEquals"]["bedrock:GuardrailIdentifier"]
    )
    assert deny_other["NotResource"] == invoke_resources
    assert set(_as_list(deny_other["Action"])) == {"bedrock:InvokeModel", "bedrock:CountTokens"}
    assert not any(
        "aws-marketplace:" in action or action.endswith("PutUseCaseForModelAccess")
        for action in actions
    )


def test_activation_permissions_are_separate_and_subscription_can_be_product_scoped() -> None:
    statements = _statements("activation-principal-policy.json")
    actions = [action for statement in statements for action in _as_list(statement["Action"])]
    assert set(actions) == {
        "aws-marketplace:Subscribe",
        "aws-marketplace:Unsubscribe",
        "aws-marketplace:ViewSubscriptions",
        "bedrock:PutUseCaseForModelAccess",
    }
    subscribe = next(
        statement for statement in statements if statement["Action"] == "aws-marketplace:Subscribe"
    )
    assert subscribe["Condition"]["StringEquals"]["aws-marketplace:ProductId"]
    assert not any(action in {"bedrock:CountTokens", "bedrock:InvokeModel"} for action in actions)


def _as_list(value: str | list[str]) -> list[str]:
    return value if isinstance(value, list) else [value]
