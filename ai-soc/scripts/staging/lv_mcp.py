from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ai_soc.qualification.mcp_models import LvMcpInputs
from ai_soc.qualification.mcp_oauth import exception_summary, is_scoped_secret_arn
from scripts.staging.attributed_probe import ProbeSpec
from scripts.staging.aws_clients import DeploymentSnapshot
from scripts.staging.clients import AWSServiceClientFactory, GateAdapterReport
from scripts.staging.models import (
    DeploymentBinding,
    GateId,
    ObligationResult,
    ObligationStatus,
    QualificationReceipt,
)
from scripts.staging.qualification_context import (
    QualificationContext,
    require_qualification_context,
)


class LvMcpAdapter:
    gate_id = GateId.LV_MCP

    def evaluate(
        self,
        *,
        inputs: LvMcpInputs,
        clients: AWSServiceClientFactory | QualificationContext,
        binding: DeploymentBinding,
        qualification_context: QualificationContext | None = None,
    ) -> GateAdapterReport:
        try:
            for secret_ref in (
                inputs.access_token_ref,
                inputs.id_token_ref,
                inputs.browser_cookie_ref,
                inputs.csrf_token_ref,
                *inputs.negative_token_refs.model_dump().values(),
            ):
                if not is_scoped_secret_arn(
                    secret_ref, region=binding.region, account_id=binding.account_id
                ):
                    raise ValueError(
                        "secret reference must be a complete ARN scoped to this account and Region"
                    )
            context = require_qualification_context(qualification_context)
            snapshot = context.deployment_snapshot
            if snapshot is None or snapshot.binding != binding:
                raise ValueError("qualification context lacks the bound deployment snapshot")
            targets = _verify_bound_targets(inputs, snapshot)
            receipt = _run_probe_task(
                inputs=inputs,
                targets=targets,
                qualification_context=context,
            )
        except Exception as exc:
            reason = f"MCP probe did not complete: {exception_summary(exc)}"
            return GateAdapterReport(
                binding=binding,
                obligations=tuple(
                    ObligationResult(item, ObligationStatus.NOT_RUN, reason)
                    for item in (
                        "official_client_flows",
                        "mcp_auth_negatives",
                        "frozen_output_parity",
                    )
                ),
                results={"reason": reason},
            )

        reason = "task envelope awaits digest-validated CloudTrail writer proof"
        return GateAdapterReport(
            binding=binding,
            obligations=tuple(
                ObligationResult(item, ObligationStatus.NOT_RUN, reason)
                for item in (
                    "official_client_flows",
                    "mcp_auth_negatives",
                    "frozen_output_parity",
                )
            ),
            results={"reason": reason},
            qualification_receipt=receipt,
        )


def _verify_bound_targets(inputs: LvMcpInputs, snapshot: DeploymentSnapshot) -> dict[str, Any]:
    """Retain MCP-specific target checks over the shared validated snapshot."""
    binding = snapshot.binding
    sealed = snapshot.sealed_document
    environment = snapshot.task_environment
    if environment.get("AUDIT_ARCHIVE_BUCKET") != inputs.evidence_bucket:
        raise ValueError("evidence bucket does not match the bound task definition")
    if (
        environment.get("SOC_SERVICE_SHA") != binding.service_sha
        or environment.get("SOC_CONTENT_SHA") != binding.content_sha
        or environment.get("SOC_CONFIGURATION_SHA256") != binding.configuration_sha256
    ):
        raise ValueError("bound task definition build pins differ from the deployment binding")
    resource = sealed.mcp.resource
    issuer = sealed.mcp.issuer
    origin = sealed.browser_origin
    expected_endpoint = f"{str(origin).rstrip('/')}/mcp" if isinstance(origin, str) else None
    expected_rest_endpoint = (
        f"{str(origin).rstrip('/')}/v1/questions" if isinstance(origin, str) else None
    )
    if (
        str(inputs.endpoint) != expected_endpoint
        or str(inputs.rest_endpoint) != expected_rest_endpoint
        or str(inputs.resource) != resource
        or str(inputs.issuer).rstrip("/") != str(issuer).rstrip("/")
        or str(inputs.origin).rstrip("/") != str(origin).rstrip("/")
    ):
        raise ValueError("configured MCP target does not match the observed task definition")
    network = snapshot.service_networking["awsvpcConfiguration"]
    subnets = network.get("subnets", [])
    security_groups = network.get("securityGroups", [])
    if (
        not subnets
        or not security_groups
        or network.get("assignPublicIp", "DISABLED") != "DISABLED"
    ):
        raise ValueError("bound ECS service has no reusable Fargate network configuration")
    return {
        "service_arn": binding.service_arn,
        "task_definition_arn": binding.task_definition_arn,
        "endpoint_matches": True,
        "rest_endpoint_matches": True,
        "issuer_matches": True,
        "resource_matches": True,
        "origin_matches": True,
        "container_name": "ai-soc",
        "network_configuration": {
            "awsvpcConfiguration": {
                "subnets": subnets,
                "securityGroups": security_groups,
                "assignPublicIp": network.get("assignPublicIp", "DISABLED"),
            }
        },
    }


def _run_probe_task(
    *,
    inputs: LvMcpInputs,
    targets: Mapping[str, Any],
    qualification_context: QualificationContext,
) -> QualificationReceipt:
    probe = qualification_context.bind_probe(GateId.LV_MCP, "mcp")
    spec = ProbeSpec(
        entrypoint="mcp",
        parameters={
            "inputs": inputs.model_dump(mode="json"),
            "container_name": targets["container_name"],
        },
        network="service",
        execution_seconds=min(900, inputs.probe_timeout_seconds),
        collection_seconds=probe.measured_delivery_budget,
    )
    return probe.run(spec).receipt
