from __future__ import annotations

from dataclasses import replace

import scripts.staging.adapters as adapters
from scripts.staging.clients import StagingClients
from scripts.staging.manifest import (
    ArtifactPins,
    ExpectedDeploymentBinding,
    GateInputs,
    NightlyBaselineInput,
    NightlyGateInput,
    StagingManifestV3,
)
from scripts.staging.models import (
    AcceptanceId,
    EvidenceKind,
    EvidenceReference,
    GateId,
    LiveAcceptanceResult,
    ObligationResult,
    ObligationStatus,
)
from scripts.staging.registry import GATE_REGISTRY
from tests.unit.staging.session_test_support import _binding, _result


def test_runner_preserves_independent_acceptance_failure_when_final_observation_is_missing(
    monkeypatch,
):
    binding = replace(_binding(), image_digest="f" * 64)

    class Observer:
        observations = 0

        def observe_deployment(self):
            self.observations += 1
            return binding if self.observations == 1 else None

    manifest = StagingManifestV3(
        schema_version="3",
        gate_id=GateId.LV_NIGHTLY,
        acceptance_ids=(AcceptanceId.GP3,),
        owners=("owner",),
        artifacts=ArtifactPins(
            service_sha=binding.service_sha,
            content_sha=binding.content_sha,
            artifact_digest="f" * 64,
        ),
        expected_deployment=ExpectedDeploymentBinding(
            account_id=binding.account_id,
            region=binding.region,
            cluster_arn=binding.cluster_arn,
            service_arn=binding.service_arn,
            task_definition_arn=binding.task_definition_arn,
            deployment_name=binding.deployment_name,
            deployment_id=binding.deployment_id,
            image_digest=f"sha256:{'f' * 64}",
            service_sha=binding.service_sha,
            content_sha=binding.content_sha,
            configuration_sha256=binding.configuration_sha256,
        ),
        inputs=GateInputs(
            nightly=NightlyGateInput(
                required_case_ids=("case-1",),
                baseline=NightlyBaselineInput(
                    sha256="b" * 64,
                    en_cases=1,
                    es_cases=1,
                    drop_rate=0.0,
                    independently_reviewed=True,
                ),
            )
        ),
        commands=("probe",),
    )
    evidence = EvidenceReference(EvidenceKind.FILE_SHA256, "nightly/gp3", "a" * 64)
    failure = LiveAcceptanceResult(
        acceptance_id=AcceptanceId.GP3,
        gate_id=GateId.LV_NIGHTLY,
        status="FAIL",
        binding=binding,
        obligation=ObligationResult(
            "GP3", ObligationStatus.FAIL, "nightly trace failed", (evidence,)
        ),
        evidence_refs=(evidence,),
    )
    result = replace(
        _result(),
        gate_id=GateId.LV_NIGHTLY,
        status="PASS",
        binding=binding,
        expected_binding=binding,
        obligations=tuple(
            ObligationResult(row.obligation_id, ObligationStatus.PASS, "positive")
            for row in GATE_REGISTRY[GateId.LV_NIGHTLY].obligations
        ),
        acceptance_results=(failure,),
        verified_observations=(object(),),
    )
    monkeypatch.setattr(adapters, "run_nightly_gate", lambda *_args, **_kwargs: result)

    actual = adapters.run_live_gate(
        manifest,
        manifest_hash="e" * 64,
        runner_commands=(),
        clients=StagingClients(observer=Observer()),
    )

    assert actual.status == "NOT_RUN"
    assert actual.verified_observations == ()
    assert all(row.status == ObligationStatus.NOT_RUN for row in actual.obligations)
    assert actual.acceptance_results == (failure,)
