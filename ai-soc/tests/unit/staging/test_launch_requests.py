from __future__ import annotations

import json

import pytest

from ai_soc.qualification.models import ProbeInvocationConfig
from scripts.staging.launch_requests import build_launch_request, build_probe_config
from scripts.staging.models import DeploymentBinding, GateId
from scripts.staging.registry import PROBE_REGISTRY


def test_registered_state_launch_config_and_request_are_single_source() -> None:
    registration = PROBE_REGISTRY[(GateId.LV_STATE, "state", "state")]
    scenario = ProbeInvocationConfig(
        entrypoint="state",
        parameters={"inputs": {"table_name": "state-table", "evidence_bucket": "evidence"}},
        execution_seconds=90,
        collection_seconds=60,
        network="service",
    )
    binding = DeploymentBinding(
        account_id="123456789012",
        region="eu-central-1",
        cluster_arn="arn:aws:ecs:eu-central-1:123456789012:cluster/service",
        service_arn="arn:aws:ecs:eu-central-1:123456789012:service/service/app",
        task_definition_arn="arn:aws:ecs:eu-central-1:123456789012:task-definition/app:1",
        deployment_name="app",
        deployment_id="ecs-svc/123",
        image_digest="sha256:" + "a" * 64,
        service_sha="b" * 40,
        content_sha="c" * 40,
        configuration_sha256="d" * 64,
    )
    config = build_probe_config(
        registration,
        scenario=scenario,
        binding=binding,
        run_id="00000000-0000-4000-8000-000000000001",
        session_id="00000000-0000-4000-8000-000000000002",
        invocation_id="00000000-0000-4000-8000-000000000003",
        slot="A",
        deadline_utc="2026-10-13T12:00:00Z",
        evidence_bucket="evidence",
        kms_key_arn="arn:aws:kms:eu-central-1:123456789012:key/key",
        account_id="123456789012",
    )

    assert config.command == (*registration.command, "--contender", "A")
    environment = {item["name"]: item["value"] for item in config.environment}
    assert environment["SOC_LV_STATE_EVIDENCE_BUCKET"] == "evidence"
    payload = json.loads(environment["LV_STATE_PROBE_CONFIG"])
    assert payload["scenario"]["parameters"]["inputs"]["replica_kill_replacement"] is False
    assert payload["binding"]["deployment_id"] == "ecs-svc/123"

    request = build_launch_request(
        registration,
        config=config,
        container_name="ai-soc",
        cluster_arn="cluster",
        task_definition_arn="task-definition",
        started_by="qualification-session",
        client_token="token",
        network_configuration={"awsvpcConfiguration": {"subnets": ["subnet-123"]}},
        session_id="00000000-0000-4000-8000-000000000002",
        invocation_id="00000000-0000-4000-8000-000000000003",
        run_id="00000000-0000-4000-8000-000000000001",
        slot="A",
        launch_type="FARGATE",
        capacity_provider_strategy=[],
        platform_version="1.4.0",
    )

    container = request["overrides"]["containerOverrides"][0]
    assert container["command"] == [*registration.command, "--contender", "A"]
    assert request["platformVersion"] == "1.4.0"
    assert request["tags"][-1] == {"key": "qualification-slot", "value": "A"}


def test_registration_rejects_unknown_slots_and_extra_input_fields() -> None:
    registration = PROBE_REGISTRY[(GateId.LV_STATE, "state", "state")]
    scenario = ProbeInvocationConfig(
        entrypoint="state",
        parameters={"inputs": {"table_name": "table", "evidence_bucket": "evidence"}},
        execution_seconds=90,
        collection_seconds=60,
        network="service",
    )
    common = {
        "scenario": scenario,
        "binding": DeploymentBinding(
            account_id="123456789012",
            region="eu-central-1",
            cluster_arn="arn:aws:ecs:eu-central-1:123456789012:cluster/service",
            service_arn="arn:aws:ecs:eu-central-1:123456789012:service/service/app",
            task_definition_arn="arn:aws:ecs:eu-central-1:123456789012:task-definition/app:1",
            deployment_name="app",
            deployment_id="ecs-svc/123",
            image_digest="sha256:" + "a" * 64,
            service_sha="b" * 40,
            content_sha="c" * 40,
            configuration_sha256="d" * 64,
        ),
        "run_id": "00000000-0000-4000-8000-000000000001",
        "session_id": "00000000-0000-4000-8000-000000000002",
        "invocation_id": "00000000-0000-4000-8000-000000000003",
        "deadline_utc": "2026-10-13T12:00:00Z",
        "evidence_bucket": "evidence",
        "kms_key_arn": "key",
        "account_id": "123456789012",
    }
    with pytest.raises(ValueError, match="registered layout"):
        build_probe_config(registration, slot="C", **common)
    with pytest.raises(ValueError):
        ProbeInvocationConfig(
            entrypoint="state",
            parameters={
                "inputs": {
                    "table_name": "table",
                    "evidence_bucket": "evidence",
                    "rogue": True,
                }
            },
            execution_seconds=90,
            collection_seconds=60,
        )
