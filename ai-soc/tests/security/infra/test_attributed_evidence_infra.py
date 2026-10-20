from __future__ import annotations

import json
import subprocess
from pathlib import Path

from terraform_root import TERRAFORM, prepare_root_module

ROOT = Path(__file__).resolve().parents[3]
MAIN = (ROOT / "infra/main.tf").read_text(encoding="utf-8")
EVIDENCE = (ROOT / "infra/qualification_evidence.tf").read_text(encoding="utf-8")
VARIABLES = (ROOT / "infra/variables.tf").read_text(encoding="utf-8")
OUTPUTS = (ROOT / "infra/outputs.tf").read_text(encoding="utf-8")


def test_resource_map_pin_is_versioned_and_certification_starts_disabled() -> None:
    assert 'resource "aws_s3_object" "qualification_resource_map"' in MAIN
    assert "version_id = aws_s3_object.qualification_resource_map[0].version_id" in MAIN
    assert "sha256     = sha256(local.qualification_resource_map_json)" in MAIN
    assert "certification_enabled = false" in MAIN
    object_resource = MAIN.split('resource "aws_s3_object" "qualification_resource_map"', 1)[
        1
    ].split("\n}", 1)[0]
    assert "source_hash" in object_resource
    assert "etag" not in object_resource
    assert 'output "qualification_resource_map_pin"' in OUTPUTS
    assert "aws_s3_object.qualification_resource_map[0].version_id" in OUTPUTS


def test_qualification_outputs_are_role_separated_conditional_and_undeletable() -> None:
    assert "app_prefix" in EVIDENCE and '"qualification/"' in EVIDENCE
    assert "consumer_prefix" in EVIDENCE and '"events/qualification/"' in EVIDENCE
    assert "WriteApplicationQualificationEvidence" in MAIN
    assert 'Action   = ["s3:PutObject", "s3:PutObjectTagging"]' in MAIN
    assert "QualificationEvidenceNeverDeleted" in MAIN
    assert 'actions = ["s3:DeleteObject", "s3:DeleteObjectVersion"]' in MAIN
    assert "s3:if-none-match" in MAIN
    assert "ApplicationCannotWriteConsumerEvidence" in MAIN
    assert (
        'Resource = "${aws_s3_bucket.audit_archive.arn}/${local.evidence_paths.consumer_prefix}*"'
        in MAIN
    )


def test_bedrock_invocation_prefix_is_service_written_and_source_bound() -> None:
    assert 'key_prefix  = "bedrock-invocations/"' in MAIN
    assert "DenyNonBedrockInvocationLogWritersAndDeletion" in MAIN
    assert "DenyBedrockInvocationWritesOutsideSourceAccount" in MAIN
    assert "DenyBedrockInvocationWritesOutsideSourceArn" in MAIN
    assert 'variable = "aws:SourceAccount"' in MAIN
    assert 'variable = "aws:SourceArn"' in MAIN
    assert 'identifiers = ["bedrock.amazonaws.com"]' in MAIN


def test_isolated_route_tables_are_optional_qualification_inputs() -> None:
    assert 'variable "qualification_public_isolated_subnet_ids"' in VARIABLES
    assert 'variable "qualification_public_isolated_route_table_ids"' in VARIABLES
    assert "qualification_public_isolated_route_table_ids" in MAIN
    assert (
        "distinct(concat(var.private_route_table_ids, "
        "var.qualification_public_isolated_route_table_ids))"
    ) in MAIN


def test_gateway_policy_object_and_list_prefixes_share_evaluated_evidence_paths(
    tmp_path: Path,
) -> None:
    module = prepare_root_module(tmp_path / "root")
    fixture = Path(__file__).parent / "data/root_variables_validation/valid.tfvars.json"
    result = subprocess.run(
        [str(TERRAFORM), "console", f"-var-file={fixture}"],
        cwd=module,
        input=(
            "jsonencode({ paths = local.evidence_paths, "
            "objects = local.audit_archive_object_prefixes, "
            "lists = local.audit_archive_list_prefixes })\n"
        ),
        check=True,
        capture_output=True,
        text=True,
    )
    evaluated = json.loads(json.loads(result.stdout.splitlines()[-1]))
    expected = {
        "events/",
        "feedback/",
        "qualification/",
        "events/qualification/",
        "qualification-maps/resource-map.json",
        "qualification-inputs/",
    }
    assert set(evaluated["objects"]) == expected
    assert set(evaluated["lists"]) == expected
    assert evaluated["paths"]["consumer_prefix"] == "events/qualification/"


def test_application_prefix_bucket_and_isolated_sg_boundaries() -> None:
    assert "QualificationAppPrefixApplicationRoleOnly" in MAIN
    assert 'test     = "ArnNotEquals"' in MAIN
    assert "values   = [aws_iam_role.application.arn]" in MAIN
    network = (ROOT / "infra/qualification_network.tf").read_text(encoding="utf-8")
    assert 'resource "aws_security_group" "qualification_public_isolated"' in network
    isolated_sg = network.split('resource "aws_security_group" "qualification_public_isolated"', 1)[
        1
    ].split('\nresource "', 1)[0]
    assert "prefix_list_ids = [var.s3_managed_prefix_list_id]" in isolated_sg
    assert "qualification_isolated_endpoints[0].id" in isolated_sg
    assert 'resource "aws_security_group" "qualification_isolated_endpoints"' in network
    assert (
        'resource "aws_vpc_security_group_ingress_rule" "qualification_isolated_endpoints"'
        in network
    )
    assert 'resource "aws_vpc_security_group_egress_rule" "qualification_isolated_' not in MAIN
    assert "public_isolated_excluded_interface_services" in MAIN
    assert '"bedrock-runtime"' in MAIN
    service_sg = MAIN.split('resource "aws_security_group" "tasks"', 1)[1].split("\n}", 1)[0]
    assert "var.s3_managed_prefix_list_id" in service_sg
    assert "var.dynamodb_managed_prefix_list_id" in service_sg
    assert (
        "setsubtract(toset(var.qualification_public_isolated_subnet_ids), "
        "toset(var.private_subnet_ids))" in VARIABLES
    )
    assert (
        "setsubtract(toset(var.qualification_public_isolated_route_table_ids), "
        "toset(var.private_route_table_ids))" in VARIABLES
    )
