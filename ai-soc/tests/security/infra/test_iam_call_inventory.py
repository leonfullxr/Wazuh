"""Offline boto3 call inventory vs rendered Terraform IAM and VPC endpoint policies."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
MAIN = (ROOT / "infra" / "main.tf").read_text(encoding="utf-8")

BOTO_CLIENT_METHODS = frozenset(
    {
        "get_item",
        "put_item",
        "update_item",
        "query",
        "transact_write_items",
        "converse",
        "count_tokens",
        "invoke_model",
        "send_message",
        "receive_message",
        "delete_message",
        "get_object",
        "put_object",
        "sign",
        "put_metric_data",
    }
)

# IAM action mapping with AWS documentation citations (inventory maintenance contract).
IAM_DOC = {
    "dynamodb:GetItem": "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/iam-policy-example-dynamodb-actions.html",
    "dynamodb:PutItem": "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/iam-policy-example-dynamodb-actions.html",
    "dynamodb:UpdateItem": "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/iam-policy-example-dynamodb-actions.html",
    "dynamodb:Query": "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/iam-policy-example-dynamodb-actions.html",
    "dynamodb:DeleteItem": "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/iam-policy-example-dynamodb-actions.html",
    "dynamodb:TransactWriteItems": "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis-iam.html",
    "dynamodb:ConditionCheckItem": "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis-iam.html",
    "bedrock:InvokeModel": "https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-permissions-id.html",
    "bedrock:CountTokens": "https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonbedrock.html",
    "bedrock:ApplyGuardrail": "https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-permissions-id.html",
    "sqs:SendMessage": "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-api-permissions-reference.html",
    "sqs:ReceiveMessage": "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-api-permissions-reference.html",
    "sqs:DeleteMessage": "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-api-permissions-reference.html",
    "s3:GetObject": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html",
    "s3:PutObject": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html",
    "kms:Sign": "https://docs.aws.amazon.com/kms/latest/developerguide/kms-api-permissions-reference.html",
    "cloudwatch:PutMetricData": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/iam-cw-condition-keys-namespace.html",
}

TRANSACT_ITEM_IAM = {
    "ConditionCheck": "dynamodb:ConditionCheckItem",
    "Put": "dynamodb:PutItem",
    "Update": "dynamodb:UpdateItem",
    "Delete": "dynamodb:DeleteItem",
}

SDK_METHOD_IAM: dict[tuple[str, str], str] = {
    ("dynamodb", "get_item"): "dynamodb:GetItem",
    ("dynamodb", "put_item"): "dynamodb:PutItem",
    ("dynamodb", "update_item"): "dynamodb:UpdateItem",
    ("dynamodb", "query"): "dynamodb:Query",
    ("dynamodb", "transact_write_items"): "dynamodb:TransactWriteItems",
    ("bedrock-runtime", "converse"): "bedrock:InvokeModel",
    ("bedrock-runtime", "count_tokens"): "bedrock:CountTokens",
    ("bedrock-runtime", "invoke_model"): "bedrock:InvokeModel",
    ("sqs", "send_message"): "sqs:SendMessage",
    ("sqs", "receive_message"): "sqs:ReceiveMessage",
    ("sqs", "delete_message"): "sqs:DeleteMessage",
    ("s3", "get_object"): "s3:GetObject",
    ("s3", "put_object"): "s3:PutObject",
    ("kms", "sign"): "kms:Sign",
    ("cloudwatch", "put_metric_data"): "cloudwatch:PutMetricData",
}

ENDPOINT_FOR_SERVICE: dict[str, str] = {
    "dynamodb": "dynamodb",
    "bedrock-runtime": "bedrock-runtime",
    "sqs": "sqs",
    "s3": "s3",
    "kms": "kms",
    "cloudwatch": "monitoring",
}

BOTO3_CLIENT_SERVICES = frozenset({"s3", "dynamodb", "sqs", "kms", "cloudwatch", "bedrock-runtime"})


@dataclass(frozen=True)
class InventoryEntry:
    service: str
    method: str
    iam_action: str
    source: str


def _top_level_block(source: str, declaration: str) -> str:
    start = source.index(declaration)
    candidates = [
        position
        for token in ("\nresource ", "\ndata ", "\noutput ", "\nlocals {")
        if (position := source.find(token, start + len(declaration))) >= 0
    ]
    return source[start : min(candidates)] if candidates else source[start:]


def _policy_actions(policy_text: str) -> set[str]:
    return set(re.findall(r'"([a-z0-9*-]+:[A-Za-z0-9*]+)"', policy_text))


def _is_boto_client_method_attribute(node: ast.Attribute, client_vars: frozenset[str]) -> bool:
    if node.attr not in BOTO_CLIENT_METHODS:
        return False
    if isinstance(node.value, ast.Name) and node.value.id in client_vars:
        return True
    if isinstance(node.value, ast.Attribute) and node.value.attr == "_client":
        return True
    return isinstance(node.value, ast.Name) and node.value.id == "_client"


def _unwrap_cast_call(call: ast.Call) -> ast.Call:
    if (
        isinstance(call.func, ast.Name)
        and call.func.id == "cast"
        and len(call.args) >= 2
        and isinstance(call.args[1], ast.Call)
    ):
        return call.args[1]
    return call


def _boto3_client_service_from_call(call: ast.Call) -> str | None:
    call = _unwrap_cast_call(call)
    if not isinstance(call.func, ast.Attribute) or call.func.attr != "client":
        return None
    if not (isinstance(call.func.value, ast.Name) and call.func.value.id == "boto3"):
        return None
    if not call.args:
        return None
    service = call.args[0]
    if isinstance(service, ast.Constant) and isinstance(service.value, str):
        if service.value in BOTO3_CLIENT_SERVICES:
            return service.value
    return None


def _method_from_client_attribute(node: ast.Attribute, client_vars: frozenset[str]) -> str | None:
    if node.attr not in BOTO_CLIENT_METHODS:
        return None
    if _is_boto_client_method_attribute(node, client_vars):
        return node.attr
    return None


def _infer_boto_service(method: str) -> str | None:
    if method in {"get_object", "put_object"}:
        return "s3"
    if method == "put_metric_data":
        return "cloudwatch"
    if method == "sign":
        return "kms"
    if method in {"converse", "count_tokens", "invoke_model"}:
        return "bedrock-runtime"
    if method in {"send_message", "receive_message", "delete_message"}:
        return "sqs"
    if method in {"get_item", "put_item", "update_item", "query", "transact_write_items"}:
        return "dynamodb"
    return None


def _entry_from_method(method: str, rel: Path, lineno: int) -> InventoryEntry | None:
    service = _infer_boto_service(method)
    if service is None:
        return None
    iam = SDK_METHOD_IAM.get((service, method))
    if iam is None:
        return None
    return InventoryEntry(
        service=service,
        method=method,
        iam_action=iam,
        source=f"{rel}:{lineno}",
    )


def _record_method(
    method: str,
    lineno: int,
    rel: Path,
    found: list[InventoryEntry],
    seen: set[tuple[str, str, int]],
) -> None:
    entry = _entry_from_method(method, rel, lineno)
    if entry is None:
        return
    key = (entry.service, entry.method, lineno)
    if key in seen:
        return
    seen.add(key)
    found.append(entry)


def _calls_from_expr(expr: ast.expr) -> list[ast.Call]:
    if isinstance(expr, ast.Await) and isinstance(expr.value, ast.Call):
        return [expr.value]
    if isinstance(expr, ast.Call):
        return [expr]
    return []


def _register_call(
    call: ast.Call,
    *,
    rel: Path,
    client_vars: frozenset[str],
    bound_aliases: dict[str, str],
    found: list[InventoryEntry],
    seen: set[tuple[str, str, int]],
) -> None:
    if isinstance(call.func, ast.Attribute) and call.func.attr == "to_thread" and call.args:
        target = call.args[0]
        if isinstance(target, ast.Attribute):
            method = _method_from_client_attribute(target, client_vars)
            if method is not None:
                _record_method(method, call.lineno, rel, found, seen)
        elif isinstance(target, ast.Name) and target.id in bound_aliases:
            _record_method(bound_aliases[target.id], call.lineno, rel, found, seen)
    _register_call_target(
        call.func,
        call.lineno,
        rel=rel,
        client_vars=client_vars,
        bound_aliases=bound_aliases,
        found=found,
        seen=seen,
    )
    for arg in call.args:
        for nested in _calls_from_expr(arg):
            _register_call(
                nested,
                rel=rel,
                client_vars=client_vars,
                bound_aliases=bound_aliases,
                found=found,
                seen=seen,
            )
    for keyword in call.keywords:
        for nested in _calls_from_expr(keyword.value):
            _register_call(
                nested,
                rel=rel,
                client_vars=client_vars,
                bound_aliases=bound_aliases,
                found=found,
                seen=seen,
            )


def _register_call_target(
    func: ast.expr,
    lineno: int,
    *,
    rel: Path,
    client_vars: frozenset[str],
    bound_aliases: dict[str, str],
    found: list[InventoryEntry],
    seen: set[tuple[str, str, int]],
) -> None:
    if isinstance(func, ast.Name) and func.id in bound_aliases:
        _record_method(bound_aliases[func.id], lineno, rel, found, seen)
        return
    if isinstance(func, ast.Attribute):
        if func.attr == "to_thread":
            return
        method = _method_from_client_attribute(func, client_vars)
        if method is not None:
            _record_method(method, lineno, rel, found, seen)


def _collect_in_stmts(
    stmts: list[ast.stmt],
    rel: Path,
    found: list[InventoryEntry],
    seen: set[tuple[str, str, int]],
) -> None:
    client_vars: set[str] = set()
    bound_aliases: dict[str, str] = {}

    def client_frozen() -> frozenset[str]:
        return frozenset(client_vars)

    def walk_stmt(stmt: ast.stmt) -> None:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _collect_in_stmts(stmt.body, rel, found, seen)
            return
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if not isinstance(target, ast.Name):
                    continue
                if isinstance(stmt.value, ast.Call):
                    service = _boto3_client_service_from_call(_unwrap_cast_call(stmt.value))
                    if service is not None:
                        client_vars.add(target.id)
                if isinstance(stmt.value, ast.Attribute):
                    method = _method_from_client_attribute(stmt.value, client_frozen())
                    if method is not None:
                        bound_aliases[target.id] = method
                        _record_method(method, stmt.lineno, rel, found, seen)
            for call in _calls_from_expr(stmt.value):
                _register_call(
                    call,
                    rel=rel,
                    client_vars=client_frozen(),
                    bound_aliases=bound_aliases,
                    found=found,
                    seen=seen,
                )
            return
        if isinstance(stmt, ast.Expr):
            for call in _calls_from_expr(stmt.value):
                _register_call(
                    call,
                    rel=rel,
                    client_vars=client_frozen(),
                    bound_aliases=bound_aliases,
                    found=found,
                    seen=seen,
                )
            return
        if isinstance(stmt, ast.Call):
            _register_call(
                stmt,
                rel=rel,
                client_vars=client_frozen(),
                bound_aliases=bound_aliases,
                found=found,
                seen=seen,
            )
            return
        if isinstance(stmt, ast.ClassDef):
            for item in stmt.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    _collect_in_stmts(item.body, rel, found, seen)
            return
        if isinstance(stmt, ast.If):
            for branch in stmt.body:
                walk_stmt(branch)
            for branch in stmt.orelse:
                walk_stmt(branch)
            return
        if isinstance(stmt, (ast.With, ast.AsyncWith, ast.Try)):
            for branch in getattr(stmt, "body", []):
                walk_stmt(branch)
            for handler in getattr(stmt, "handlers", []):
                for branch in handler.body:
                    walk_stmt(branch)
            for branch in getattr(stmt, "orelse", []):
                walk_stmt(branch)
            for branch in getattr(stmt, "finalbody", []):
                walk_stmt(branch)
            return
        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            for branch in stmt.body:
                walk_stmt(branch)
            for branch in stmt.orelse:
                walk_stmt(branch)

    for stmt in stmts:
        walk_stmt(stmt)


def _collect_sdk_calls() -> list[InventoryEntry]:
    found: list[InventoryEntry] = []
    seen: set[tuple[str, str, int]] = set()
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        rel = path.relative_to(ROOT)
        _collect_in_stmts(tree.body, rel, found, seen)
    return found


def _collect_transact_item_types() -> set[str]:
    types: set[str] = set()
    for path in (SRC / "ai_soc/state").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            for key in node.keys:
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    if key.value in TRANSACT_ITEM_IAM:
                        types.add(key.value)
    return types


def _required_iam_actions(sdk_calls: list[InventoryEntry], transact_types: set[str]) -> set[str]:
    actions = {entry.iam_action for entry in sdk_calls}
    for item_type in transact_types:
        actions.add(TRANSACT_ITEM_IAM[item_type])
    return actions


def _role_policy_block(role_policy_name: str) -> str:
    return _top_level_block(MAIN, f'resource "aws_iam_role_policy" "{role_policy_name}" {{')


def _interface_endpoint_policy(service_key: str) -> str:
    start = MAIN.index(f'"{service_key}" = [')
    return MAIN[start : start + 1200]


def _audit_consumer_call(entry: InventoryEntry) -> bool:
    return "telemetry/audit_delivery" in entry.source and entry.method in {
        "receive_message",
        "delete_message",
        "put_object",
    }


def _assert_inventory_against_main(main_text: str) -> None:
    sdk_calls = _collect_sdk_calls()
    transact_types = _collect_transact_item_types()
    application_calls = [entry for entry in sdk_calls if not _audit_consumer_call(entry)]
    audit_calls = [entry for entry in sdk_calls if _audit_consumer_call(entry)]
    required_application = _required_iam_actions(application_calls, transact_types)
    required_audit = _required_iam_actions(audit_calls, set())

    application_actions = _policy_actions(
        _top_level_block(main_text, 'resource "aws_iam_role_policy" "application" {')
    )
    audit_actions = _policy_actions(
        _top_level_block(main_text, 'resource "aws_iam_role_policy" "audit_consumer" {')
    )
    dynamodb_endpoint = _top_level_block(main_text, 'resource "aws_vpc_endpoint" "dynamodb" {')
    s3_endpoint = _top_level_block(main_text, 'resource "aws_vpc_endpoint" "s3" {')
    dynamodb_endpoint_actions = _policy_actions(dynamodb_endpoint)
    s3_endpoint_actions = _policy_actions(s3_endpoint)

    missing_application = sorted(
        action for action in required_application if action not in application_actions
    )
    missing_audit = sorted(action for action in required_audit if action not in audit_actions)
    missing_endpoint = sorted(
        action
        for action in required_application
        if action.startswith("dynamodb:") and action not in dynamodb_endpoint_actions
    )
    missing_s3_endpoint = sorted(
        action
        for action in required_application
        if action.startswith("s3:") and action not in s3_endpoint_actions
    )
    if missing_application:
        raise AssertionError(f"application task role missing IAM: {missing_application}")
    if missing_audit:
        raise AssertionError(f"audit consumer task role missing IAM: {missing_audit}")
    if missing_endpoint:
        raise AssertionError(f"DynamoDB endpoint missing IAM: {missing_endpoint}")
    if missing_s3_endpoint:
        raise AssertionError(f"S3 endpoint missing IAM: {missing_s3_endpoint}")


def test_boto3_inventory_is_allowed_by_task_role_and_endpoints() -> None:
    transact_types = _collect_transact_item_types()
    assert "ConditionCheck" in transact_types, (
        "expected ConditionCheck transact items in state code"
    )

    sdk_calls = _collect_sdk_calls()
    methods = {entry.method for entry in sdk_calls}
    assert "query" in methods
    assert "send_message" in methods
    assert "get_object" in methods
    assert any(entry.source.startswith("src/ai_soc/live/pack.py") for entry in sdk_calls)

    application_calls = [entry for entry in sdk_calls if not _audit_consumer_call(entry)]
    audit_calls = [entry for entry in sdk_calls if _audit_consumer_call(entry)]
    required_application = _required_iam_actions(application_calls, transact_types)
    required_audit = _required_iam_actions(audit_calls, set())
    assert "dynamodb:ConditionCheckItem" in required_application
    assert "dynamodb:Query" in required_application
    assert "sqs:SendMessage" in required_application
    assert "s3:GetObject" in required_application

    application_actions = _policy_actions(_role_policy_block("application"))
    audit_actions = _policy_actions(_role_policy_block("audit_consumer"))
    dynamodb_endpoint = _top_level_block(MAIN, 'resource "aws_vpc_endpoint" "dynamodb" {')
    endpoint_actions = _policy_actions(dynamodb_endpoint)

    missing_application = sorted(
        action for action in required_application if action not in application_actions
    )
    missing_audit = sorted(action for action in required_audit if action not in audit_actions)
    missing_endpoint = sorted(
        action
        for action in required_application
        if action.startswith("dynamodb:") and action not in endpoint_actions
    )
    assert not missing_application, f"application task role missing IAM: {missing_application}"
    assert not missing_audit, f"audit consumer task role missing IAM: {missing_audit}"
    assert not missing_endpoint, f"DynamoDB endpoint missing IAM: {missing_endpoint}"

    all_required = required_application | required_audit
    for action in all_required:
        assert action in IAM_DOC, f"maintain IAM_DOC citation for {action}"

    for entry in application_calls:
        endpoint_key = ENDPOINT_FOR_SERVICE.get(entry.service)
        if endpoint_key is None:
            continue
        if endpoint_key == "dynamodb":
            policy = dynamodb_endpoint
        elif endpoint_key == "bedrock-runtime":
            policy = _interface_endpoint_policy("bedrock-runtime")
        elif endpoint_key == "sqs":
            policy = _interface_endpoint_policy("sqs")
        elif endpoint_key == "s3":
            policy = _top_level_block(MAIN, 'resource "aws_vpc_endpoint" "s3" {')
        elif endpoint_key == "kms":
            policy = _interface_endpoint_policy("kms")
        elif endpoint_key == "monitoring":
            policy = _interface_endpoint_policy("monitoring")
        else:
            continue
        assert entry.iam_action in _policy_actions(policy), (
            f"{entry.source} needs {entry.iam_action} on {endpoint_key} endpoint policy"
        )


def test_inventory_fails_if_dynamodb_query_is_removed_from_policies() -> None:
    broken = MAIN.replace('"dynamodb:Query"', '"dynamodb:QueryRemoved"')
    try:
        _assert_inventory_against_main(broken)
    except AssertionError as error:
        assert "dynamodb:Query" in str(error)
    else:
        raise AssertionError("inventory must fail when dynamodb:Query is stripped from IAM")


def test_inventory_fails_if_s3_get_object_is_removed_from_policies() -> None:
    broken = MAIN.replace('"s3:GetObject"', '"s3:GetObjectRemoved"')
    try:
        _assert_inventory_against_main(broken)
    except AssertionError as error:
        assert "s3:GetObject" in str(error) or "S3 endpoint" in str(error)
    else:
        raise AssertionError("inventory must fail when s3:GetObject is stripped from IAM")


def test_inventory_mapping_table_covers_every_discovered_sdk_call() -> None:
    for entry in _collect_sdk_calls():
        assert (entry.service, entry.method) in SDK_METHOD_IAM
