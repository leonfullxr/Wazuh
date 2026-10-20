from __future__ import annotations

from scripts.staging.aggregation import aggregate_results
from scripts.staging.models import (
    AcceptanceId,
    DeploymentBinding,
    EvidenceKind,
    EvidenceReference,
    GateId,
    LiveAcceptanceResult,
    ObligationResult,
    ObligationStatus,
)


def _binding() -> DeploymentBinding:
    return DeploymentBinding(
        account_id="123456789012",
        region="eu-central-1",
        cluster_arn="arn:aws:ecs:eu-central-1:123456789012:cluster/q",
        service_arn="arn:aws:ecs:eu-central-1:123456789012:service/q/app",
        task_definition_arn="arn:aws:ecs:eu-central-1:123456789012:task-definition/app:1",
        deployment_name="app",
        deployment_id="ecs-svc/1",
        image_digest="a" * 64,
        service_sha="b" * 40,
        content_sha="c" * 40,
        configuration_sha256="d" * 64,
    )


def test_standalone_acceptance_pass_is_demoted_without_verified_observation() -> None:
    reference = EvidenceReference(EvidenceKind.FILE_SHA256, "evidence/report", "e" * 64)
    acceptance = LiveAcceptanceResult(
        acceptance_id=AcceptanceId.GP3,
        gate_id=GateId.LV_NIGHTLY,
        status="PASS",
        binding=_binding(),
        obligation=ObligationResult("GP3", ObligationStatus.PASS, "claimed", (reference,)),
        evidence_refs=(reference,),
    )

    summary = aggregate_results((), (acceptance,))

    row = summary.acceptances[0]
    assert row is not None
    assert row.status == "NOT_RUN"
    assert row.obligation.status == ObligationStatus.NOT_RUN
    assert not row.evidence_refs
