"""Single-source construction for qualification launches and reload checks."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any

from ai_soc.qualification.binding import DeploymentBinding as QualificationBinding
from ai_soc.qualification.evidence import EvidencePaths
from ai_soc.qualification.models import (
    CanaryTaskProbeConfig,
    McpTaskProbeConfig,
    ProbeInvocationConfig,
    StateTaskProbeConfig,
    TaskLaunchConfig,
)
from scripts.staging.models import DeploymentBinding, GateId
from scripts.staging.registry import ProbeRegistration


@dataclass(frozen=True, slots=True)
class ProbeLaunchConfig:
    command: tuple[str, ...]
    environment: tuple[dict[str, str], ...]


def resource_arns_for_probe(
    entrypoint: str, scenario: ProbeInvocationConfig, binding: DeploymentBinding
) -> tuple[tuple[str, str], ...]:
    """Return the resource identities a registered probe is allowed to observe."""
    if scenario.entrypoint != entrypoint:
        return ()
    if entrypoint == "state" and isinstance(scenario.parameters, StateTaskProbeConfig):
        table_name = scenario.parameters.inputs.table_name
        return (
            (
                "state_table",
                f"arn:aws:dynamodb:{binding.region}:{binding.account_id}:table/{table_name}",
            ),
        )
    if entrypoint == "mcp" and isinstance(scenario.parameters, McpTaskProbeConfig):
        inputs = scenario.parameters.inputs
        values: list[tuple[str, str]] = []
        for key, value in (
            ("mcp_access_token", inputs.access_token_ref),
            ("mcp_id_token", inputs.id_token_ref),
        ):
            if value:
                values.append((key, value))
        values.append(("mcp_negative_tokens", inputs.negative_token_refs.wrong_resource))
        return tuple(values)
    return ()


def build_probe_config(
    registration: ProbeRegistration,
    *,
    scenario: ProbeInvocationConfig,
    binding: DeploymentBinding,
    run_id: str,
    session_id: str,
    invocation_id: str,
    slot: str,
    deadline_utc: str,
    evidence_bucket: str,
    kms_key_arn: str,
    account_id: str,
) -> ProbeLaunchConfig:
    """Validate scenario input once and derive its task command and environment."""
    if scenario.entrypoint != registration.entrypoint:
        raise ValueError("qualification scenario differs from its registered entrypoint")
    if slot not in registration.slots:
        raise ValueError("qualification slot is not in the registered layout")
    if registration.config_environment is None:
        if not isinstance(scenario.parameters, CanaryTaskProbeConfig):
            raise ValueError("network canary requires registered typed inputs")
        bucket = scenario.parameters.inputs.evidence_bucket
        kms_key = scenario.parameters.inputs.kms_key_arn
        if not bucket or not kms_key:
            raise ValueError("network canary input is incomplete")
        paths: EvidencePaths = scenario.parameters.inputs.evidence_paths
        return ProbeLaunchConfig(
            command=(
                *registration.command,
                "--bucket",
                bucket,
                "--kms-key-arn",
                kms_key,
                "--session-id",
                session_id,
                "--run-id",
                run_id,
                "--placement",
                slot,
                "--account-id",
                account_id,
                "--app-prefix",
                paths.app_prefix,
                "--consumer-prefix",
                paths.consumer_prefix,
                "--map-key",
                paths.map_key,
                "--input-prefix",
                paths.input_prefix,
            ),
            environment=(),
        )

    config = TaskLaunchConfig(
        scenario=scenario,
        binding=QualificationBinding.model_validate(asdict(binding)),
        run_id=run_id,
        session_id=session_id,
        invocation_id=invocation_id,
        slot=slot,
        deadline_utc=deadline_utc,
    )
    environment = [
        {
            "name": registration.config_environment,
            "value": config.model_dump_json(by_alias=True, exclude_none=False),
        },
        {"name": "SOC_QUALIFICATION_PREFIX", "value": f"qualification/{session_id}/{run_id}/"},
        {"name": "SOC_QUALIFICATION_BUCKET", "value": evidence_bucket},
        {"name": "SOC_QUALIFICATION_KMS_KEY_ID", "value": kms_key_arn},
        {"name": "SOC_QUALIFICATION_EXPECTED_OWNER", "value": account_id},
    ]
    if registration.gate_id == GateId.LV_STATE:
        environment.append({"name": "SOC_LV_STATE_EVIDENCE_BUCKET", "value": evidence_bucket})
    command = registration.command
    if registration.entrypoint == "state":
        command = (*command, "--contender", slot)
    return ProbeLaunchConfig(command, tuple(environment))


def build_launch_request(
    registration: ProbeRegistration,
    *,
    config: ProbeLaunchConfig,
    container_name: str,
    cluster_arn: str,
    task_definition_arn: str,
    started_by: str,
    client_token: str,
    network_configuration: dict[str, Any],
    session_id: str,
    invocation_id: str,
    run_id: str,
    slot: str,
    launch_type: str | None,
    capacity_provider_strategy: list[dict[str, Any]],
    platform_version: str | None,
) -> dict[str, Any]:
    command = config.command
    request: dict[str, Any] = {
        "cluster": cluster_arn,
        "taskDefinition": task_definition_arn,
        "count": 1,
        "startedBy": started_by,
        "clientToken": client_token,
        "networkConfiguration": network_configuration,
        "overrides": {
            "containerOverrides": [
                {
                    "name": container_name,
                    "command": list(command),
                    "environment": list(config.environment),
                }
            ]
        },
        "tags": [
            {"key": "qualification", "value": "true"},
            {"key": "qualification-session", "value": session_id},
            {"key": "qualification-invocation", "value": invocation_id},
            {"key": "qualification-run", "value": run_id},
            {"key": "qualification-gate", "value": registration.gate_id.value},
            {"key": "qualification-contributor", "value": registration.contributor_id},
            {"key": "qualification-slot", "value": slot},
        ],
    }
    if capacity_provider_strategy:
        request["capacityProviderStrategy"] = capacity_provider_strategy
    else:
        request["launchType"] = launch_type
        if launch_type == "FARGATE" and platform_version:
            request["platformVersion"] = platform_version
    encoded = json.dumps(request, allow_nan=False, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode()) > 8192:
        raise ValueError("qualification task override exceeds ECS request limit")
    return request
