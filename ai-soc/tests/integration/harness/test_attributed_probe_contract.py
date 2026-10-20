from __future__ import annotations

import pytest

from scripts.staging.attributed_probe import normalize_live_result
from scripts.staging.models import (
    DeploymentBinding,
    EvidenceKind,
    EvidenceReference,
    GateId,
    KnownResultView,
    LiveAcceptanceResult,
    LiveGateResult,
    ObligationResult,
    ObligationStatus,
)
from scripts.staging.registry import ACCEPTANCE_GATE, GATE_REGISTRY

_CONTRIBUTORS = (
    (GateId.LV_PLATFORM, "platform"),
    (GateId.LV_IDENTITY, "identity"),
    (GateId.LV_UI, "ui"),
    (GateId.LV_SITE, "site"),
    (GateId.LV_MCP, "mcp"),
    (GateId.LV_STATE, "state"),
    (GateId.LV_MODEL, "model"),
    (GateId.LV_CONTENT, "content"),
    (GateId.LV_OBSERVABILITY, "obs_archive"),
    (GateId.LV_OBSERVABILITY, "obs_alarms"),
    (GateId.LV_NIGHTLY, "nightly"),
    (GateId.LV_NETWORK, "network"),
)


def _binding() -> DeploymentBinding:
    return DeploymentBinding(
        account_id="123456789012",
        region="us-east-1",
        cluster_arn="arn:aws:ecs:us-east-1:123456789012:cluster/prod",
        service_arn="arn:aws:ecs:us-east-1:123456789012:service/prod/app",
        task_definition_arn="arn:aws:ecs:us-east-1:123456789012:task-definition/app:1",
        deployment_name="app",
        deployment_id="ecs-svc/123",
        image_digest="sha256:" + "a" * 64,
        service_sha="b" * 40,
        content_sha="c" * 40,
        configuration_sha256="d" * 64,
    )


@pytest.mark.parametrize(("gate_id", "contributor_id"), _CONTRIBUTORS)
def test_shared_normalizer_demotes_every_unverified_contributor_pass(
    gate_id: GateId, contributor_id: str
) -> None:
    binding = _binding()
    reference = EvidenceReference(EvidenceKind.FILE_SHA256, "local-report", "e" * 64)
    obligations = tuple(
        ObligationResult(
            item.obligation_id, ObligationStatus.PASS, "caller says pass", (reference,)
        )
        for item in GATE_REGISTRY[gate_id].obligations
    )
    acceptances = tuple(
        LiveAcceptanceResult(
            acceptance_id=acceptance_id,
            gate_id=gate_id,
            status="PASS",
            binding=binding,
            obligation=ObligationResult(
                acceptance_id.value, ObligationStatus.PASS, "caller says pass", (reference,)
            ),
            evidence_refs=(reference,),
        )
        for acceptance_id, producer in ACCEPTANCE_GATE.items()
        if producer == gate_id
    )
    result = LiveGateResult(
        gate_id=gate_id,
        owners=("owner",),
        inputs_manifest_sha256="f" * 64,
        service_sha=binding.service_sha,
        content_sha=binding.content_sha,
        artifact_digest="a" * 64,
        status="PASS",
        commands=(),
        results={},
        evidence_refs=(reference,),
        checked_at="2026-10-08T00:00:00+00:00",
        binding=binding,
        expected_binding=binding,
        obligations=obligations,
        acceptance_results=acceptances,
        result_views=(
            KnownResultView(
                kind=(
                    "nightly"
                    if gate_id == GateId.LV_NIGHTLY
                    else "network"
                    if gate_id == GateId.LV_NETWORK
                    else "contributor"
                ),
                view_id=contributor_id,
                diagnostics={"status": "PASS", "evidence_refs": ["local-report"]},
                obligation_ids=tuple(row.obligation_id for row in obligations),
            ),
        ),
    )

    normalized = normalize_live_result(result)

    assert normalized.status == "NOT_RUN"
    assert all(row.status == ObligationStatus.NOT_RUN for row in normalized.obligations)
    assert all(row.status == "NOT_RUN" for row in normalized.acceptance_results)
    serialized = normalized.to_dict()["results"]
    if gate_id == GateId.LV_NIGHTLY:
        nested = serialized["nightly"]
        assert nested["status"] == "NOT_RUN"
    elif gate_id == GateId.LV_NETWORK:
        nested = serialized["network"]["obligations"]
        assert all(row["status"] == "NOT_RUN" for row in nested)
    else:
        nested = serialized["contributors"][contributor_id]
        assert nested["status"] == "NOT_RUN"
        assert nested["evidence_refs"] == []


def test_shared_normalizer_keeps_a_fail_when_other_rows_lack_proof() -> None:
    binding = _binding()
    rows = tuple(
        ObligationResult(
            item.obligation_id,
            ObligationStatus.FAIL if index == 0 else ObligationStatus.PASS,
            "observed contradiction" if index == 0 else "untrusted pass",
        )
        for index, item in enumerate(GATE_REGISTRY[GateId.LV_MCP].obligations)
    )
    result = LiveGateResult(
        gate_id=GateId.LV_MCP,
        owners=("owner",),
        inputs_manifest_sha256="f" * 64,
        service_sha=binding.service_sha,
        content_sha=binding.content_sha,
        artifact_digest="a" * 64,
        status="FAIL",
        commands=(),
        results={},
        evidence_refs=(),
        checked_at="2026-10-08T00:00:00+00:00",
        binding=binding,
        expected_binding=binding,
        obligations=rows,
    )

    normalized = normalize_live_result(result)

    assert normalized.status == "FAIL"
    assert normalized.obligations[0].status == ObligationStatus.FAIL
    assert all(row.status == ObligationStatus.NOT_RUN for row in normalized.obligations[1:])
