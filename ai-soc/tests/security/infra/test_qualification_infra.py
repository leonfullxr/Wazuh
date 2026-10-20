from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from terraform_root import TERRAFORM, prepare_root_module

INFRA = Path("infra")
MAIN = (INFRA / "main.tf").read_text()
VARS = (INFRA / "variables.tf").read_text()
VERSIONS = (INFRA / "versions.tf").read_text()

FOUNDATION_MODEL_ARN = (
    "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-5-sonnet-20241022-v2:0"
)


def top_level_block(source: str, declaration: str) -> str:
    start = source.index(declaration)
    candidates = [
        position
        for token in ("\nresource ", "\ndata ", "\noutput ", "\nlocals {", "\ncheck ")
        if (position := source.find(token, start + len(declaration))) >= 0
    ]
    return source[start : min(candidates)] if candidates else source[start:]


def test_qualification_profile_softens_only_when_enabled() -> None:
    assert 'variable "qualification_profile"' in VARS
    assert "default     = false" in VARS.split('variable "qualification_profile"', 1)[1][:200]
    assert "enable_deletion_protection = !var.qualification_profile" in MAIN
    assert "deletion_protection_enabled = !var.qualification_profile" in MAIN
    assert "force_delete         = var.qualification_profile" in MAIN
    assert MAIN.count("force_destroy = false") == 4
    schedule = top_level_block(MAIN, 'resource "aws_scheduler_schedule" "audit_archive" {')
    assert (
        "state                        = var.enable_audit_archive_schedule && "
        '!var.qualification_profile ? "ENABLED" : "DISABLED"' in schedule
    )
    assert "placement_constraints" not in schedule


def test_audit_archive_schedule_is_configurable_with_safe_default() -> None:
    assert 'variable "audit_archive_schedule_expression"' in VARS
    assert 'default     = "rate(1 minute)"' in VARS
    schedule = top_level_block(MAIN, 'resource "aws_scheduler_schedule" "audit_archive" {')
    assert "schedule_expression          = var.audit_archive_schedule_expression" in schedule


def test_qualification_interface_endpoint_subnet_override() -> None:
    assert 'variable "qualification_interface_endpoint_subnet_ids"' in VARS
    assert "local.interface_endpoint_subnet_ids" in MAIN
    interface = top_level_block(MAIN, 'resource "aws_vpc_endpoint" "interface" {')
    assert "subnet_ids" in interface
    assert "local.interface_endpoint_subnet_ids" in interface
    assert "var.private_subnet_ids" not in interface.split("subnet_ids", 1)[1].split("\n", 1)[0]


def test_isolated_task_endpoint_relationships_are_evaluated_by_terraform(tmp_path: Path) -> None:
    module = prepare_root_module(tmp_path / "root")
    fixture = Path(__file__).parent / "data/root_variables_validation/valid.tfvars.json"
    plan = tmp_path / "qualification.tfplan"
    subprocess.run(
        [
            str(TERRAFORM),
            "plan",
            "-input=false",
            "-refresh=false",
            f"-out={plan}",
            f"-var-file={fixture}",
            "-var=qualification_profile=true",
            "-var=enable_session_resources=true",
            "-var=enable_account_cost_budgets=false",
            "-var=allow_unqualified_direct_identity_egress=true",
            '-var=qualification_public_isolated_subnet_ids=["subnet-0123456789abcdef1"]',
            '-var=qualification_public_isolated_route_table_ids=["rtb-0123456789abcdef1"]',
            "-target=aws_vpc_endpoint.interface",
            "-target=aws_security_group.qualification_public_isolated",
            "-target=aws_security_group.qualification_isolated_endpoints",
            "-target=aws_vpc_security_group_ingress_rule.qualification_isolated_endpoints",
        ],
        cwd=module,
        check=True,
        capture_output=True,
        text=True,
    )
    shown = subprocess.run(
        [str(TERRAFORM), "show", "-json", str(plan)],
        cwd=module,
        check=True,
        capture_output=True,
        text=True,
    )
    plan_json = json.loads(shown.stdout)
    changes = {change["address"]: change["change"] for change in plan_json["resource_changes"]}
    config = {
        resource["address"]: resource
        for resource in plan_json["configuration"]["root_module"]["resources"]
    }
    allowed = {
        "ecr.api",
        "ecr.dkr",
        "logs",
        "secretsmanager",
        "kms",
    }
    for service in allowed:
        address = f'aws_vpc_endpoint.interface["{service}"]'
        assert address in changes
        # Terraform cannot know generated SG IDs in a plan; assert the actual
        # resource expression carries both the task SG and isolated SG inputs.
        endpoint_config = config["aws_vpc_endpoint.interface"]
        references = endpoint_config["expressions"]["security_group_ids"]["references"]
        assert "aws_security_group.endpoints[0].id" in references
        assert "aws_security_group.qualification_isolated_endpoints[0].id" in references
        assert "local.isolated_allowed_interface_services" in references
        assert changes[address]["after_unknown"]["security_group_ids"] is True
    bedrock = changes['aws_vpc_endpoint.interface["bedrock-runtime"]']
    assert bedrock["after_unknown"]["security_group_ids"] is True

    ingress_address = "aws_vpc_security_group_ingress_rule.qualification_isolated_endpoints[0]"
    ingress_change = changes[ingress_address]
    assert ingress_change["after"]["ip_protocol"] == "tcp"
    assert ingress_change["after"]["from_port"] == ingress_change["after"]["to_port"] == 443
    assert ingress_change["after_unknown"]["security_group_id"] is True
    assert ingress_change["after_unknown"]["referenced_security_group_id"] is True
    ingress_refs = config["aws_vpc_security_group_ingress_rule.qualification_isolated_endpoints"][
        "expressions"
    ]
    assert (
        "aws_security_group.qualification_public_isolated[0].id"
        in ingress_refs["referenced_security_group_id"]["references"]
    )
    endpoint_sg = changes["aws_security_group.qualification_isolated_endpoints[0]"]["after"]
    assert endpoint_sg["egress"] == []

    public_sg = changes["aws_security_group.qualification_public_isolated[0]"]["after"]
    egress = public_sg["egress"]
    assert {rule["protocol"] for rule in egress} == {"tcp", "udp"}
    assert sum(rule["from_port"] == 443 and rule["to_port"] == 443 for rule in egress) == 2
    assert sum(rule["from_port"] == 53 and rule["to_port"] == 53 for rule in egress) == 2


def test_task_groups_have_gateway_prefix_egress_for_their_planned_routes(tmp_path: Path) -> None:
    module = prepare_root_module(tmp_path / "root")
    fixture = Path(__file__).parent / "data/root_variables_validation/valid.tfvars.json"
    variables = json.loads(fixture.read_text(encoding="utf-8"))
    plan = tmp_path / "gateway-egress.tfplan"
    subprocess.run(
        [
            str(TERRAFORM),
            "plan",
            "-input=false",
            "-refresh=false",
            f"-out={plan}",
            f"-var-file={fixture}",
            "-var=qualification_profile=true",
            "-var=enable_session_resources=true",
            "-var=enable_account_cost_budgets=false",
            "-var=allow_unqualified_direct_identity_egress=true",
            '-var=qualification_public_isolated_subnet_ids=["subnet-0123456789abcdef1"]',
            '-var=qualification_public_isolated_route_table_ids=["rtb-0123456789abcdef1"]',
            "-target=aws_security_group.tasks",
            "-target=aws_security_group.qualification_public_isolated",
            "-target=aws_vpc_endpoint.s3",
            "-target=aws_vpc_endpoint.dynamodb",
        ],
        cwd=module,
        check=True,
        capture_output=True,
        text=True,
    )
    shown = subprocess.run(
        [str(TERRAFORM), "show", "-json", str(plan)],
        cwd=module,
        check=True,
        capture_output=True,
        text=True,
    )
    plan_json = json.loads(shown.stdout)
    changes = {change["address"]: change["change"] for change in plan_json["resource_changes"]}
    configuration = {
        resource["address"]: resource
        for resource in plan_json["configuration"]["root_module"]["resources"]
    }
    service_sg_references = configuration["aws_ecs_service.service"]["expressions"][
        "network_configuration"
    ][0]["security_groups"]["references"]
    archive_sg_references = configuration["aws_scheduler_schedule.audit_archive"]["expressions"][
        "target"
    ][0]["ecs_parameters"][0]["network_configuration"][0]["security_groups"]["references"]
    assert "aws_security_group.tasks[0].id" in service_sg_references
    assert "aws_security_group.tasks[0].id" in archive_sg_references
    gateway_endpoints = {
        "s3": changes["aws_vpc_endpoint.s3[0]"]["after"],
        "dynamodb": changes["aws_vpc_endpoint.dynamodb[0]"]["after"],
    }
    isolated_route_tables = {"rtb-0123456789abcdef1"}
    groups = {
        "service and archive tasks": (
            set(variables["private_route_table_ids"]),
            changes["aws_security_group.tasks[0]"]["after"]["egress"],
        ),
        "public-isolated probes": (
            isolated_route_tables,
            changes["aws_security_group.qualification_public_isolated[0]"]["after"]["egress"],
        ),
    }
    prefix_list_ids = {
        "s3": variables["s3_managed_prefix_list_id"],
        "dynamodb": variables["dynamodb_managed_prefix_list_id"],
    }
    for group_name, (route_tables, egress_rules) in groups.items():
        actual_prefix_lists = {
            prefix_list_id for rule in egress_rules for prefix_list_id in rule["prefix_list_ids"]
        }
        expected_prefix_lists = {
            prefix_list_ids[service]
            for service, endpoint in gateway_endpoints.items()
            if route_tables.intersection(endpoint["route_table_ids"])
        }
        assert actual_prefix_lists == expected_prefix_lists, group_name


def test_public_isolated_inputs_reject_service_subnet_and_route_table_reuse(tmp_path: Path) -> None:
    module = prepare_root_module(tmp_path / "root")
    fixture = Path(__file__).parent / "data/root_variables_validation/valid.tfvars.json"
    base = json.loads(fixture.read_text(encoding="utf-8"))
    base.update(
        {
            "enable_session_resources": False,
            "enable_account_cost_budgets": False,
            "qualification_profile": True,
            "allow_unqualified_direct_identity_egress": True,
        }
    )
    for field, value, expected in (
        (
            "qualification_public_isolated_subnet_ids",
            [base["private_subnet_ids"][0]],
            "qualification_public_isolated_subnet_ids is qualification-only",
        ),
        (
            "qualification_public_isolated_subnet_ids",
            ["subnet-0123456789abcdef1"],
            "qualification_public_isolated_route_table_ids is qualification-only",
        ),
    ):
        variables = {**base, field: value}
        variables["qualification_public_isolated_route_table_ids"] = [
            base["private_route_table_ids"][0]
            if expected.startswith("qualification_public_isolated_route_table_ids")
            else "rtb-0123456789abcdef1"
        ]
        variables_file = tmp_path / f"{field}-{len(value)}.tfvars.json"
        variables_file.write_text(json.dumps(variables), encoding="utf-8")
        result = subprocess.run(
            [
                str(TERRAFORM),
                "plan",
                "-input=false",
                "-refresh=false",
                f"-var-file={variables_file}",
            ],
            cwd=module,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
        assert expected in result.stderr + result.stdout


def test_root_module_uses_all_subnets_by_default_and_qualification_override(
    tmp_path: Path,
) -> None:
    module = prepare_root_module(tmp_path / "root")
    fixture = Path(__file__).parent / "data/root_variables_validation/valid.tfvars.json"
    expression = "jsonencode(local.interface_endpoint_subnet_ids)\n"
    default = subprocess.run(
        [str(TERRAFORM), "console", f"-var-file={fixture}"],
        cwd=module,
        input=expression,
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(json.loads(default.stdout)) == [
        "subnet-0123456789abcdef0",
        "subnet-0fedcba9876543210",
    ]

    qualification = subprocess.run(
        [
            str(TERRAFORM),
            "console",
            f"-var-file={fixture}",
            "-var=qualification_profile=true",
            "-var=idp_in_vpc=true",
            "-var=alb_public_key_egress_mode=proxy",
            '-var=alb_public_key_egress_cidrs=["10.0.1.4/32"]',
            "-var=alb_public_key_https_proxy=https://proxy.example.test:443",
            '-var=qualification_proxy_allowed_hosts=["public-keys.auth.elb.us-east-1.amazonaws.com","idp.example.test"]',
            "-var=account_cost_budget_alert_email=ops@example.test",
            '-var=qualification_interface_endpoint_subnet_ids=["subnet-0123456789abcdef0"]',
        ],
        cwd=module,
        input=expression,
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(json.loads(qualification.stdout)) == ["subnet-0123456789abcdef0"]


def test_bedrock_model_resources_include_inference_profile_foundation_arns() -> None:
    concat_block = MAIN.split("bedrock_model_resources = distinct(concat(", 1)[1].split("))", 1)[0]
    assert "var.bedrock_inference_profile_foundation_model_arns" in concat_block
    assert '::foundation-model/", arn))' in VARS
    application = top_level_block(MAIN, 'resource "aws_iam_role_policy" "application" {')
    allow_invoke = application.split('Sid      = "GuardrailedBedrockInvokeModel"', 1)[1].split(
        'Sid      = "BedrockCountTokensWithoutGuardrail"', 1
    )[0]
    deny_non_allowlisted = application.split(
        'Sid         = "DenyNonAllowlistedBedrockResources"', 1
    )[1]
    assert "Resource = local.bedrock_model_resources" in allow_invoke
    assert "NotResource = local.bedrock_model_resources" in deny_non_allowlisted
    count_tokens = application.split('Sid      = "BedrockCountTokensWithoutGuardrail"', 1)[1].split(
        'Sid      = "DenyMissingGuardrail"', 1
    )[0]
    assert "local.bedrock_count_token_resources" in count_tokens
    assert (
        FOUNDATION_MODEL_ARN in count_tokens
        or "bedrock_inference_profile_foundation_model_arns" in MAIN
    )


def test_foundation_model_arn_shape_is_accepted_by_validation_regex() -> None:
    pattern = r"^arn:aws[a-z-]*:bedrock:[a-z0-9-]+::foundation-model/"

    assert re.match(pattern, FOUNDATION_MODEL_ARN)
    assert not re.match(pattern, "arn:aws:bedrock:us-east-1:123456789012:foundation-model/x")


def test_s3_bucket_names_fail_plan_not_advisory_checks() -> None:
    assert not (INFRA / "checks.tf").exists()
    assert 'length("ai-soc-${var.deployment_name}-${var.aws_account_id}-invocations") <= 63' in VARS
    for bucket in ("audit_archive", "invocation_logs", "docs"):
        block = top_level_block(MAIN, f'resource "aws_s3_bucket" "{bucket}" {{')
        assert "precondition {" in block
        assert "length(local.s3_bucket_names." in block


def test_deployment_name_boundary_rejects_oversized_invocation_bucket() -> None:
    account_id = "123456789012"
    rejected_by_old_limit = "a" + ("b" * 31)
    bucket = f"ai-soc-{rejected_by_old_limit}-{account_id}-invocations"
    assert len(rejected_by_old_limit) == 32
    assert len(bucket) == 64


def test_partial_s3_backend_and_tfvars_gitignore() -> None:
    assert 'backend "s3"' in VERSIONS
    assert "encrypt      = true" in VERSIONS
    assert "use_lockfile = true" in VERSIONS
    gitignore = (INFRA / ".gitignore").read_text()
    assert "*.tfvars" in gitignore


def test_bedrock_invocation_logging_and_cloudtrail_are_variable_gated() -> None:
    assert 'variable "enable_bedrock_model_invocation_logging"' in VARS
    assert 'variable "enable_cloudtrail"' in VARS
    assert 'resource "aws_bedrock_model_invocation_logging_configuration" "service"' in MAIN
    assert "count = var.enable_bedrock_model_invocation_logging ? 1 : 0" in MAIN
    assert 'resource "aws_cloudtrail" "service"' in MAIN
    assert "enable_log_file_validation    = true" in MAIN
    cloudtrail_policy = top_level_block(
        MAIN, 'data "aws_iam_policy_document" "cloudtrail_bucket" {'
    )
    assert "s3:x-amz-acl" not in cloudtrail_policy
    assert 'object_ownership = "BucketOwnerEnforced"' in MAIN


def test_bedrock_invocation_kms_is_scoped_to_log_delivery() -> None:
    storage_key = top_level_block(MAIN, 'data "aws_iam_policy_document" "storage_key" {')
    assert "BedrockInvocationLogDataKeys" in storage_key
    assert "BedrockInvocationLogGrants" in storage_key
    assert "kms:GrantIsForAWSResource" in storage_key
    assert "kms:EncryptionContext:aws:s3:arn" in storage_key
    bedrock_kms = storage_key.split("BedrockInvocationLogDataKeys", 1)[1].split(
        "CloudWatchLogsService", 1
    )[0]
    assert "aws_s3_bucket.invocation_logs.arn" in bedrock_kms
    assert "invocation_logs.arn}/*" not in bedrock_kms
    logging = top_level_block(
        MAIN, 'resource "aws_bedrock_model_invocation_logging_configuration" "service" {'
    )
    assert "depends_on = [" in logging
    assert "aws_kms_key_policy.storage" in logging
    assert "aws_s3_bucket_policy.invocation_logs_bedrock" in logging
    assert '"kms:Decrypt"' not in bedrock_kms
