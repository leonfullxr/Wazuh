from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TypedDict, cast

import pytest

from ai_soc.state.ttl import TTL_ATTRIBUTE

sys.path.insert(0, str(Path(__file__).resolve().parent))
from terraform_iam import (  # noqa: E402
    parse_policy_document_conditions,
    policy_document_to_iam_json,
)
from terraform_root import TERRAFORM, prepare_root_module

INFRA = Path("infra")
MAIN = (INFRA / "main.tf").read_text()
VARS = (INFRA / "variables.tf").read_text()
VERSIONS = (INFRA / "versions.tf").read_text()
G045_FIXTURE = Path(__file__).parent / "data/g045_private_bedrock_cases.json"
G043_FIXTURE = Path(__file__).parent / "data/g043_private_inference_cases.json"


class G045Case(TypedDict):
    variant: str
    expected: list[str]
    forbidden: list[str]


class G045Fixture(TypedDict):
    schema_version: str
    case_id: str
    requirement: str
    task: str
    cases: list[G045Case]


class G043Fixture(TypedDict):
    schema_version: str
    case_id: str
    requirement: str
    task: str
    cases: list[G045Case]


def _g045_cases() -> list[G045Case]:
    fixture: object = json.loads(G045_FIXTURE.read_text(encoding="utf-8"))
    if not isinstance(fixture, dict):
        raise ValueError("G045 fixture must be an object")
    parsed = cast(G045Fixture, fixture)
    if (
        parsed.get("schema_version") != "1"
        or parsed.get("case_id") != "B6-G045.private"
        or parsed.get("requirement") != "G045"
        or parsed.get("task") != "B6-T03"
    ):
        raise ValueError("G045 fixture identity is invalid")
    return parsed["cases"]


def _g043_cases() -> list[G045Case]:
    fixture: object = json.loads(G043_FIXTURE.read_text(encoding="utf-8"))
    if not isinstance(fixture, dict):
        raise ValueError("G043 fixture must be an object")
    parsed = cast(G043Fixture, fixture)
    if (
        parsed.get("schema_version") != "1"
        or parsed.get("case_id") != "B6-G043.private"
        or parsed.get("requirement") != "G043"
        or parsed.get("task") != "B6-T03"
    ):
        raise ValueError("G043 fixture identity is invalid")
    return parsed["cases"]


def top_level_block(source: str, declaration: str) -> str:
    start = source.index(declaration)
    candidates = [
        position
        for token in ("\nresource ", "\ndata ", "\noutput ", "\nlocals {")
        if (position := source.find(token, start + len(declaration))) >= 0
    ]
    return source[start : min(candidates)] if candidates else source[start:]


def test_fargate_and_alb_are_private_with_only_alb_task_ingress() -> None:
    lb = top_level_block(MAIN, 'resource "aws_lb" "service" {')
    task = top_level_block(MAIN, 'resource "aws_ecs_service" "service" {')
    assert re.search(r"^\s*internal\s*=\s*true$", lb, re.M)
    assert "assign_public_ip = false" in task
    assert "desired_count                      = 2" in task
    assert 'description     = "ALB target group only"' in MAIN
    assert "security_groups = [aws_security_group.alb[0].id]" in MAIN
    assert "0.0.0.0/0" not in MAIN
    assert 'name                   = "adot-collector"' in MAIN
    assert '{ name = "OTEL_EXPORTER_OTLP_ENDPOINT", value = "http://127.0.0.1:4317" }' in MAIN
    assert "aws_ecr_repository.adot_collector.repository_url}@${var.adot_collector_digest}" in MAIN


def test_endpoint_inventory_and_private_bedrock_guards_are_complete() -> None:
    for endpoint in (
        "ecr.api",
        "ecr.dkr",
        "logs",
        "kms",
        "secretsmanager",
        "sqs",
        "bedrock-runtime",
        "xray",
        "monitoring",
    ):
        assert f'"{endpoint}"' in MAIN
    interface_endpoint = top_level_block(MAIN, 'resource "aws_vpc_endpoint" "interface" {')
    assert "policy = jsonencode({" in interface_endpoint
    assert "local.interface_policy_statements[each.value]" in interface_endpoint
    assert '"cloudwatch:namespace" = "AISOC/Service"' in MAIN
    assert 'service_name      = "com.amazonaws.${var.aws_region}.s3"' in MAIN
    assert 'service_name      = "com.amazonaws.${var.aws_region}.dynamodb"' in MAIN
    assert '"bedrock:InvokeModel"' in MAIN
    assert '"bedrock:CountTokens"' in MAIN
    assert '"bedrock:Converse"' not in MAIN
    assert '"bedrock:GuardrailIdentifier"' in MAIN
    assert "local.guardrail_qualified_identifier" in MAIN
    assert '"bedrock:GuardrailVersion"' not in MAIN
    assert '"aws:SourceVpce"' in MAIN
    assert '"bedrock:InvokeModelWithResponseStream"' not in MAIN
    assert (
        '"aws:SourceVpce"              = aws_vpc_endpoint.interface["bedrock-runtime"].id' in MAIN
    )


@pytest.mark.parametrize("case", _g045_cases(), ids=lambda case: case["variant"])
def test_g045_private_bedrock_iam_policy_matches_independent_cases(
    case: G045Case, record_property: Callable[[str, str], None]
) -> None:
    record_property("acceptance_ids", "G045")
    record_property("case_id", "B6-G045.private")
    record_property("variant", case["variant"])
    record_property("fixture_sha256", hashlib.sha256(G045_FIXTURE.read_bytes()).hexdigest())

    application = top_level_block(MAIN, 'resource "aws_iam_role_policy" "application" {')
    for expected in case["expected"]:
        assert expected in application, f"missing IAM invariant for {case['variant']}: {expected}"
    for forbidden in case["forbidden"]:
        assert forbidden not in application, (
            f"forbidden IAM capability for {case['variant']}: {forbidden}"
        )


@pytest.mark.parametrize("case", _g043_cases(), ids=lambda case: case["variant"])
def test_g043_inference_requires_private_vpc_endpoint(
    case: G045Case, record_property: Callable[[str, str], None]
) -> None:
    record_property("acceptance_ids", "G043")
    record_property("case_id", "B6-G043.private")
    record_property("variant", case["variant"])
    record_property("fixture_sha256", hashlib.sha256(G043_FIXTURE.read_bytes()).hexdigest())

    for expected in case["expected"]:
        assert "".join(expected.split()) in "".join(MAIN.split()), (
            f"missing private inference invariant for {case['variant']}: {expected}"
        )
    for forbidden in case["forbidden"]:
        assert "".join(forbidden.split()) not in "".join(MAIN.split()), (
            f"public inference route appears in {case['variant']} policy: {forbidden}"
        )


def test_application_role_can_emit_only_the_frozen_cloudwatch_namespace() -> None:
    application = top_level_block(MAIN, 'resource "aws_iam_role_policy" "application" {')
    assert 'Sid      = "BoundedCloudWatchMetrics"' in application
    assert 'Action   = ["cloudwatch:PutMetricData"]' in application
    assert '"cloudwatch:namespace" = "AISOC/Service"' in application
    unscoped_metrics = 'Action   = ["cloudwatch:PutMetricData"]\n        Resource = "*"\n      }'
    assert unscoped_metrics not in application


def test_scheduled_archive_task_uses_consumer_environment_and_one_shot_command() -> None:
    consumer = top_level_block(MAIN, 'resource "aws_ecs_task_definition" "audit_consumer" {')
    assert '"AUDIT_QUEUE_URL"' in consumer
    assert '"AUDIT_ARCHIVE_BUCKET"' in consumer
    assert '"AWS_REGION"' in consumer
    assert '"AWS_EC2_METADATA_DISABLED", value = "true"' in consumer
    assert '"--run-once"' not in consumer


def test_durable_stores_queues_and_archive_have_encryption_retention_and_dlqs() -> None:
    assert "server_side_encryption {" in MAIN
    assert "kms_key_arn = aws_kms_key.storage.arn" in MAIN
    assert "retention_in_days = 90" in MAIN
    assert "message_retention_seconds  = 604800" in MAIN
    assert "deadLetterTargetArn = aws_sqs_queue.audit_dlq.arn" in MAIN
    assert "deadLetterTargetArn = aws_sqs_queue.feedback_dlq.arn" in MAIN
    assert "expiration { days = 90 }" in MAIN
    assert "expiration { days = 30 }" in MAIN
    assert "IfNoneMatch" not in MAIN  # conditional archive writes live in the consumer adapter
    assert '"kms:Decrypt", "kms:GenerateDataKey"' in MAIN


def test_h4_bedrock_iam_actions_match_judgment_sdk_calls() -> None:
    """Judgment uses count_tokens and converse SDK methods; embeddings use invoke_model."""
    application = top_level_block(MAIN, 'resource "aws_iam_role_policy" "application" {')
    assert '"bedrock:Converse"' not in application
    assert '"bedrock:Converse"' not in MAIN
    for action in ("bedrock:InvokeModel", "bedrock:CountTokens"):
        assert action in application
    assert 'Sid      = "GuardrailedBedrockInvokeModel"' in application
    assert 'Sid      = "BedrockCountTokensWithoutGuardrail"' in application
    assert 'Sid         = "DenyNonAllowlistedBedrockResources"' in application
    assert 'bedrock:GuardrailIdentifier" = local.guardrail_qualified_identifier' in application
    allow_invoke = application.split('Sid      = "GuardrailedBedrockInvokeModel"', 1)[1].split(
        'Sid      = "BedrockCountTokensWithoutGuardrail"', 1
    )[0]
    deny_mismatch = application.split('Sid      = "DenyMismatchedGuardrailIdentifier"', 1)[1].split(
        'Sid         = "DenyNonAllowlistedBedrockResources"', 1
    )[0]
    qualified = 'bedrock:GuardrailIdentifier" = local.guardrail_qualified_identifier'
    assert qualified in allow_invoke
    assert qualified in deny_mismatch
    segment = application.split('Sid      = "BedrockCountTokensWithoutGuardrail"', 1)[1]
    count_tokens = segment.split('Sid      = "DenyMissingGuardrail"', 1)[0]
    assert "bedrock:GuardrailIdentifier" not in count_tokens
    assert "local.bedrock_count_token_resources" in count_tokens
    assert "var.bedrock_model_arns" not in count_tokens
    bedrock_endpoint_start = MAIN.index('"bedrock-runtime" = [')
    bedrock_endpoint = MAIN[bedrock_endpoint_start : bedrock_endpoint_start + 900]
    assert '"bedrock:InvokeModel"' in bedrock_endpoint
    assert '"bedrock:Converse"' not in bedrock_endpoint
    assert "local.bedrock_model_resources" in bedrock_endpoint
    assert "local.bedrock_count_token_resources" in bedrock_endpoint
    count_tokens_endpoint = bedrock_endpoint.split('"bedrock:CountTokens"', 1)[1][:400]
    assert "local.bedrock_count_token_resources" in count_tokens_endpoint
    assert "var.bedrock_model_arns" not in count_tokens_endpoint


def test_bedrock_count_tokens_endpoint_policy_evaluates_foundation_model_arns(
    tmp_path: Path,
) -> None:
    module = prepare_root_module(tmp_path / "root")
    fixture = Path(__file__).parent / "data/root_variables_validation/valid.tfvars.json"
    result = subprocess.run(
        [
            str(TERRAFORM),
            "console",
            f"-var-file={fixture}",
        ],
        cwd=module,
        input='jsonencode(local.interface_policy_statements["bedrock-runtime"])\n',
        check=True,
        capture_output=True,
        text=True,
    )
    statements = json.loads(json.loads(result.stdout))
    count_tokens = next(
        statement for statement in statements if statement["Action"] == ["bedrock:CountTokens"]
    )
    assert count_tokens["Resource"] == [
        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-5-sonnet-20241022-v2:0"
    ]


def test_m14_audit_archive_schedule_targets_ecs_cluster() -> None:
    schedule = top_level_block(MAIN, 'resource "aws_scheduler_schedule" "audit_archive" {')
    assert "arn      = aws_ecs_cluster.service.arn" in schedule
    assert "role_arn = aws_iam_role.audit_scheduler[0].arn" in schedule
    assert "arn      = aws_iam_role.audit_scheduler.arn" not in schedule


def test_m15_task_definition_injects_pinned_crypto_secrets() -> None:
    service = top_level_block(MAIN, 'resource "aws_ecs_task_definition" "service" {')
    value_from_lines = [line for line in service.splitlines() if "valueFrom" in line]
    assert len(value_from_lines) >= 6
    for line in value_from_lines:
        assert ":::" in line
        assert "AWSCURRENT" not in line
    assert 'valueFrom = "${site.ca_secret_arn}:::${site.ca_secret_version}"' in service
    assert (
        'valueFrom = "${var.crypto_secrets.cursor_aead_secret_arn}:::'
        '${var.crypto_secrets.cursor_current_version}"' in service
    )
    assert (
        'valueFrom = "${var.crypto_secrets.cursor_aead_secret_arn}:::'
        '${var.crypto_secrets.cursor_previous_version}"' in service
    )
    assert (
        'valueFrom = "${var.crypto_secrets.feedback_receipt_secret_arn}:::'
        '${var.crypto_secrets.receipt_current_version}"' in service
    )
    assert (
        'valueFrom = "${var.crypto_secrets.feedback_receipt_secret_arn}:::'
        '${var.crypto_secrets.receipt_previous_version}"' in service
    )
    assert (
        'valueFrom = "${var.crypto_secrets.csrf_secret_arn}:::'
        '${var.crypto_secrets.csrf_version}"' in service
    )
    assert 'valueFrom = "${site.ca_secret_arn}:${site.ca_secret_version}"' not in service


def test_m16_recovery_alarms_use_the_same_namespace_as_task_metrics() -> None:
    for metric in ("RecoveryLagSeconds", "RecoveryBacklog", "AdmissionRejected"):
        assert f'metric_name         = "{metric}"' in MAIN
        start = MAIN.index(f'metric_name         = "{metric}"')
        window = MAIN[max(0, start - 120) : start + 40]
        assert 'namespace           = "AISOC/Service"' in window
    assert 'namespace           = "AISOC"' not in MAIN


def test_l4_oidc_client_secret_is_loaded_from_secrets_manager() -> None:
    assert "client_secret_arn" in VARS
    assert "data.aws_secretsmanager_secret_version.oidc_client[0].secret_string" in MAIN
    assert "client_secret              =" in MAIN
    assert "client_secret              = var.oidc.client_secret" not in MAIN


def test_bounded_recovery_alarm_and_drain_budget_are_provisioned() -> None:
    for metric in ("RecoveryLagSeconds", "RecoveryBacklog", "AdmissionRejected"):
        assert f'metric_name         = "{metric}"' in MAIN
    assert "idle_timeout               = 150" in MAIN
    assert "deregistration_delay = 160" in MAIN
    assert "stopTimeout            = 120" in MAIN
    assert "min_capacity       = 2" in MAIN
    assert "max_capacity       = var.service_max_capacity" in MAIN


def test_content_pack_is_private_while_task_may_download_packs_prefix() -> None:
    docs_policy = top_level_block(MAIN, 'resource "aws_s3_bucket_policy" "docs_oac" {')
    s3_endpoint = top_level_block(MAIN, 'resource "aws_vpc_endpoint" "s3" {')
    application = top_level_block(MAIN, 'resource "aws_iam_role_policy" "application" {')
    cloudfront = top_level_block(MAIN, 'resource "aws_cloudfront_distribution" "docs" {')
    assert "/public/*" in docs_policy
    assert "/packs/*" not in docs_policy
    assert 'origin_path              = "/public"' in cloudfront
    assert "${aws_s3_bucket.docs.arn}/packs/*" in s3_endpoint
    assert "ContentPackDownload" in application
    assert "${aws_s3_bucket.docs.arn}/packs/*" in application


def test_task_identity_egress_reaches_mcp_jwks_origin() -> None:
    tasks = top_level_block(MAIN, 'resource "aws_security_group" "tasks" {')
    alb = top_level_block(MAIN, 'resource "aws_security_group" "alb" {')
    assert 'description = "Configured identity provider and MCP JWKS endpoints"' in tasks
    assert tasks.count("cidr_blocks = var.identity_egress_cidrs") >= 1
    assert "local.alb_identity_provider_egress_cidrs" in MAIN
    assert "cidr_blocks = local.alb_identity_provider_egress_cidrs" in alb
    assert "cidr_blocks = var.identity_egress_cidrs" not in alb


def test_mcp_jwks_reachability_is_required_at_plan_time() -> None:
    service_task = top_level_block(MAIN, 'resource "aws_ecs_task_definition" "service" {')
    assert "idp_in_vpc" in VARS
    assert "var.idp_in_vpc" in service_task
    assert "identity_egress_cidrs" in service_task
    assert "MCP JWKS reachability" in service_task
    identity_block = VARS.split('variable "identity_egress_cidrs"', 1)[1].split(
        'variable "alb_public_key_egress_mode"', 1
    )[0]
    assert "var.idp_in_vpc" in identity_block


def test_browser_oidc_rule_serves_ui_assets() -> None:
    browser_rule = top_level_block(MAIN, 'resource "aws_lb_listener_rule" "browser_oidc" {')
    assert '"/assets/*"' in browser_rule


def test_egress_cidr_variables_reject_internet_routes() -> None:
    identity = top_level_block(VARS, 'variable "identity_egress_cidrs" {')
    assert '"0.0.0.0/0"' in identity
    assert '"::/0"' in identity
    assert 'strcontains(cidr, ":")' in identity
    assert "== 32" in identity
    assert "== 128" in identity
    key_fetch = top_level_block(VARS, 'variable "alb_public_key_egress_cidrs" {')
    assert '"0.0.0.0/0"' in key_fetch
    assert '"::/0"' in key_fetch
    assert "== 32" in key_fetch
    assert "== 128" in key_fetch


def test_service_hostname_and_mcp_jwks_uri_are_required_inputs() -> None:
    assert 'variable "service_hostname"' in VARS
    assert 'variable "mcp_jwks_uri"' in VARS
    assert "local.service_origin" in MAIN
    assert "var.mcp_jwks_uri" in MAIN
    assert 'variable "browser_origin"' not in VARS


def test_alb_public_key_fetch_egress_is_required_at_plan_time() -> None:
    tasks = top_level_block(MAIN, 'resource "aws_security_group" "tasks" {')
    service_task = top_level_block(MAIN, 'resource "aws_ecs_task_definition" "service" {')
    assert "alb_public_key_egress_mode" in VARS
    assert "alb_public_key_egress_cidrs" in VARS
    assert "alb_public_key_https_proxy" in VARS
    assert 'variable "live_qualification_profile_enabled"' not in VARS
    assert 'description = "Regional ALB OIDC verification public keys"' in tasks
    assert "cidr_blocks = var.alb_public_key_egress_cidrs" in tasks
    assert 'check "alb_public_key_fetch_for_live_qualification"' not in MAIN
    assert "precondition" in service_task
    assert "alb_public_key_egress_cidrs" in service_task
    assert "alb_public_key_https_proxy" in service_task
    assert "alb_public_key_egress_mode" in service_task
    assert "Security groups cannot filter the documented regional key host path" in service_task
    assert "SOC_ALB_PUBLIC_KEY_HTTPS_PROXY" in MAIN


def test_cloudwatch_logs_kms_key_and_execution_role_can_write_service_logs() -> None:
    storage_key = top_level_block(MAIN, 'data "aws_iam_policy_document" "storage_key" {')
    assert "CloudWatchLogsService" in storage_key
    assert "logs.${var.aws_region}.amazonaws.com" in storage_key
    assert "kms:EncryptionContext:aws:logs:arn" in storage_key
    assert "local.service_log_group_arn" in MAIN
    assert "local.service_log_group_name" in MAIN
    assert "aws_cloudwatch_log_group.service.name" not in storage_key
    log_group = top_level_block(MAIN, 'resource "aws_cloudwatch_log_group" "service" {')
    assert "name              = local.service_log_group_name" in log_group
    assert "depends_on = [aws_kms_key_policy.storage]" in log_group
    execution = top_level_block(MAIN, 'resource "aws_iam_role_policy" "execution_pull_logs" {')
    assert "kms:ViaService" in execution
    assert "logs.${var.aws_region}.amazonaws.com" in execution


def test_cloudfront_can_decrypt_docs_bucket_via_storage_key_policy() -> None:
    cloudfront_key = top_level_block(
        MAIN, 'data "aws_iam_policy_document" "storage_key_cloudfront" {'
    )
    assert "CloudFrontDocsDecrypt" in cloudfront_key
    assert "cloudfront.amazonaws.com" in cloudfront_key
    assert "AWS:SourceArn" in cloudfront_key
    assert "aws_cloudfront_distribution.docs.arn" in cloudfront_key


def test_guardrail_arn_validation_and_apply_guardrail_permissions() -> None:
    guardrail_var = VARS.split('variable "guardrail"', 1)[1].split("variable ", 1)[0]
    assert "guardrail/" in guardrail_var
    application = top_level_block(MAIN, 'resource "aws_iam_role_policy" "application" {')
    assert "bedrock:ApplyGuardrail" in application
    bedrock_endpoint = MAIN.split('"bedrock-runtime" = [', 1)[1][:1200]
    assert "bedrock:ApplyGuardrail" in bedrock_endpoint
    assert "var.guardrail.identifier" in bedrock_endpoint


def test_alb_public_key_proxy_allows_http_connect_on_port_443_only() -> None:
    proxy_var = VARS.split('variable "alb_public_key_https_proxy"', 1)[1].split(
        'variable "idp_in_vpc"', 1
    )[0]
    assert "http://[^:/]+:443" in proxy_var
    assert "TCP 443" in proxy_var


def test_sts_interface_endpoint_is_not_provisioned() -> None:
    assert '"sts"' not in MAIN.split("interface_services", 1)[1].split("]", 1)[0]


def test_variables_reject_placeholders_and_require_digest_and_pinned_ca() -> None:
    assert "@sha256:[0-9a-f]{64}" in VARS
    assert "site.ca_secret_version" in VARS
    assert "site.ca_sha256" in VARS
    assert "private_subnet_ids" in VARS and "length(var.private_subnet_ids) >= 2" in VARS
    assert "placeholder" in VARS and "changeme" in VARS
    assert "client_secret_arn" in VARS
    assert "sensitive = true" in VARS
    assert "ca_bundle_pem" in VARS


def test_dynamodb_ttl_attribute_matches_application_constant() -> None:
    table = top_level_block(MAIN, 'resource "aws_dynamodb_table" "state" {')
    assert f'attribute_name = "{TTL_ATTRIBUTE}"' in table


def test_optional_bedrock_spend_budget_backstop_is_variable_gated() -> None:
    assert "enable_bedrock_spend_budget" in VARS
    gross = top_level_block(MAIN, 'resource "aws_budgets_budget" "account_gross_cost" {')
    cash = top_level_block(MAIN, 'resource "aws_budgets_budget" "account_cash_cost" {')
    assert 'resource "aws_budgets_budget_action" "bedrock_spend_deny"' in MAIN
    assert "cost_filter" not in gross
    assert "include_credit = false" in gross
    assert "include_refund = false" in gross
    assert "include_credit = true" in cash
    assert "include_refund = true" in cash
    assert "for_each = var.enable_account_cost_budgets ? [50, 80, 100] : []" in gross
    assert 'resource "aws_budgets_budget_action" "bedrock_spend_deny"' in MAIN
    assert "bedrock:InvokeModel" in MAIN
    assert "bedrock:CountTokens" in MAIN
    backstop_policy = top_level_block(MAIN, 'resource "aws_iam_policy" "bedrock_spend_deny" {')
    assert "count = var.enable_bedrock_spend_budget ? 1 : 0" in backstop_policy
    assert "Verify the actual Claude billing line" in backstop_policy
    assert "aws_iam_role.application.name" in MAIN
    action = top_level_block(MAIN, 'resource "aws_budgets_budget_action" "bedrock_spend_deny" {')
    assert "execution_role_arn" in action
    assert "action_threshold_value" in action
    assert "notification_type" in action
    assert 'resource "aws_iam_role" "bedrock_budget_action"' in MAIN
    assert "iam:AttachRolePolicy" in MAIN


def test_bedrock_budget_action_trust_and_attach_policies_are_scoped() -> None:
    assume_block = top_level_block(
        MAIN, 'data "aws_iam_policy_document" "bedrock_budget_action_assume" {'
    )
    attach_block = top_level_block(
        MAIN, 'data "aws_iam_policy_document" "bedrock_budget_action_attach" {'
    )
    assume_conditions = parse_policy_document_conditions(assume_block)
    attach_conditions = parse_policy_document_conditions(attach_block)
    account = next(
        entry
        for entry in assume_conditions
        if entry["variable"] == "aws:SourceAccount" and entry["test"] == "StringEquals"
    )
    assert account["values"] == ["var.aws_account_id"]
    source_arn = next(
        entry
        for entry in assume_conditions
        if entry["variable"] == "aws:SourceArn" and entry["test"] == "ArnLike"
    )
    arn_value = cast(str, source_arn["values"][0])
    assert arn_value.startswith("arn:aws:budgets::")
    assert ":budget/" in arn_value
    policy_arn = next(
        entry
        for entry in attach_conditions
        if entry["variable"] == "iam:PolicyARN" and entry["test"] == "ArnEquals"
    )
    assert policy_arn["values"] == ["aws_iam_policy.bedrock_spend_deny[0].arn"]
    rendered = json.loads(json.dumps(policy_document_to_iam_json(attach_block)))
    attach_actions = {
        action
        for statement in cast(list[dict[str, object]], rendered["Statement"])
        for action in cast(list[str], statement.get("Action", []))
    }
    assert "iam:AttachRolePolicy" in attach_actions


def test_bedrock_spend_budget_action_validates_with_feature_enabled() -> None:
    terraform = Path("build/tool-cache/terraform/terraform")
    if not terraform.exists():
        pytest.skip("pinned terraform binary is not bootstrapped")
    init = subprocess.run(
        [str(terraform), "-chdir=infra", "init", "-backend=false", "-lockfile=readonly"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert init.returncode == 0, init.stderr
    validate = subprocess.run(
        [str(terraform), "-chdir=infra", "validate"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert validate.returncode == 0, validate.stderr + validate.stdout


def test_provider_and_state_backend_are_pinned_without_live_backend_defaults() -> None:
    assert 'required_version = "= 1.16.5"' in VERSIONS
    assert 'version = "= 6.67.0"' in VERSIONS
    assert 'backend "s3"' in VERSIONS
    assert "encrypt      = true" in VERSIONS
    assert "use_lockfile = true" in VERSIONS
    assert "bucket" not in VERSIONS.split('backend "s3"', 1)[1].split("}", 1)[0]
    assert not any((INFRA / name).exists() for name in ("backend.tf", "terraform.tfstate"))
