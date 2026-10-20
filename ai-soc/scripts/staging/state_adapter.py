"""LV-STATE probes executed by bounded copies of the deployed application image."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from ai_soc.qualification.state_models import StateProbeInputs as StateGateInputs
from scripts.staging.attributed_probe import ProbeSpec
from scripts.staging.clients import AWSServiceClientFactory, GateAdapterReport
from scripts.staging.models import (
    DeploymentBinding,
    GateId,
    ObligationResult,
    ObligationStatus,
)
from scripts.staging.qualification_context import (
    ProbeOutcome,
    QualificationContext,
    require_qualification_context,
)

_APP_CONTAINER_NAME = "ai-soc"
_PROBE_TIMEOUT_SECONDS = 360
_RECOVERY_TIMEOUT_SECONDS = 300


@dataclass(frozen=True, slots=True)
class _Observation:
    status: ObligationStatus
    detail: str
    facts: dict[str, Any]


class StateAdapter:
    gate_id = GateId.LV_STATE

    def evaluate(
        self,
        *,
        inputs: StateGateInputs,
        clients: AWSServiceClientFactory | QualificationContext,
        binding: DeploymentBinding,
        qualification_context: QualificationContext | None = None,
    ) -> GateAdapterReport:
        run_id: str | None = None
        facts: dict[str, Any] = {
            "table_name": inputs.table_name,
            "replica_kill_replacement_requested": inputs.replica_kill_replacement,
            "app_probe_tasks": [],
            "replica_replacement": "not_run",
        }
        observations = {
            obligation: _Observation(
                ObligationStatus.NOT_RUN,
                "application-level probe did not produce a complete attributable result",
                {},
            )
            for obligation in (
                "ddb_replica_transactions",
                "stage_admission",
                "cancellation_recovery",
                "exactly_once_settlement",
            )
        }
        qualification_receipt = None

        try:
            context = require_qualification_context(qualification_context)
            snapshot = context.deployment_snapshot
            if snapshot is None or snapshot.binding != binding:
                raise ValueError("qualification context lacks the bound deployment snapshot")
            aws = context.client("dynamodb")
            s3 = context.client("s3")
            if (
                snapshot.task_environment.get("SOC_LV_STATE_EVIDENCE_BUCKET")
                != inputs.evidence_bucket
            ):
                raise ValueError("evidence bucket does not match the bound task definition")
            if snapshot.sealed_document.dynamodb_table != inputs.table_name:
                raise ValueError("state table input does not match the bound task definition")
            if inputs.expected_bucket_owner not in (None, binding.account_id):
                raise ValueError("evidence bucket owner must match observed deployment account")
            table = aws.describe_table(TableName=inputs.table_name)["Table"]
            expected_table_arn = (
                f"arn:aws:dynamodb:{binding.region}:{binding.account_id}:table/{inputs.table_name}"
            )
            if table.get("TableArn") != expected_table_arn:
                raise ValueError("state table ARN does not match the observed deployment")
            if table.get("TableStatus") != "ACTIVE" or _key_schema(table) != {
                "pk": "HASH",
                "sk": "RANGE",
            }:
                raise ValueError("bound state table is not active with pk/sk keys")
            service, service_tasks = snapshot.service, snapshot.task_observations
            if len(service_tasks) < 2 or service.get("runningCount", 0) < 2:
                raise ValueError("two running tasks from the bound deployment are required")
            facts["table_status"] = table.get("TableStatus")
            facts["replica_observation_before"] = {
                "desired_count": service.get("desiredCount"),
                "running_count": service.get("runningCount"),
                "task_arns": [task.get("taskArn") for task in service_tasks],
            }
            s3.head_bucket(
                Bucket=inputs.evidence_bucket,
                ExpectedBucketOwner=inputs.expected_bucket_owner or binding.account_id,
            )
            outcome = _run_pair(
                probe=context.bind_probe(GateId.LV_STATE, "state"),
                service=service,
                inputs=inputs,
            )
            run_id = outcome.receipt.run_id
            probe_tasks = outcome.finished_tasks
            facts["probe_run_id"] = run_id
            qualification_receipt = outcome.receipt
            facts["app_probe_tasks"] = [
                {"task_arn": task.task_arn, "last_status": task.last_status} for task in probe_tasks
            ]
            facts["task_output_provenance"] = "digest_validated_cloudtrail_pending"
            # Measurements are available only inside task-owned strict
            # envelopes. Until CloudTrail authenticates each writer version,
            # every business obligation remains NOT_RUN.

            if inputs.replica_kill_replacement:
                facts["replica_replacement"] = "NOT_RUN: registered recovery scenario unavailable"
        except (BotoCoreError, ClientError, KeyError, TypeError, ValueError, TimeoutError) as exc:
            facts["adapter_error"] = type(exc).__name__

        obligations: list[ObligationResult] = []
        for name, observation in observations.items():
            obligations.append(ObligationResult(name, observation.status, observation.detail))
        return GateAdapterReport(
            binding=binding,
            obligations=tuple(obligations),
            results={"facts": facts, "probe_run_id": run_id},
            qualification_receipt=qualification_receipt,
        )


def _run_pair(
    *,
    probe: Any,
    service: dict[str, Any],
    inputs: StateGateInputs,
) -> ProbeOutcome:
    if not isinstance(service.get("networkConfiguration"), dict):
        raise ValueError("bound ECS service lacks a network configuration")
    spec = ProbeSpec(
        entrypoint="state",
        parameters={
            "inputs": inputs.model_dump(mode="json"),
            "container_name": _APP_CONTAINER_NAME,
        },
        network="service",
        execution_seconds=_PROBE_TIMEOUT_SECONDS,
        collection_seconds=probe.measured_delivery_budget,
    )
    return probe.run(spec)


def _key_schema(table: dict[str, Any]) -> dict[str, str]:
    return {
        str(row.get("AttributeName")): str(row.get("KeyType")) for row in table.get("KeySchema", [])
    }
