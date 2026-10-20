from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from uuid import UUID

from scripts.staging.attributed_probe import (
    QualificationSession,
    RunIntent,
)
from scripts.staging.models import (
    EvidenceKind,
    EvidenceReference,
    GateId,
    LiveGateResult,
    ObligationResult,
    ObligationStatus,
)
from scripts.staging.registry import GATE_REGISTRY
from tests.unit.staging.authenticated_evidence_support import binding


def _binding(**overrides):
    return replace(binding(), **overrides)


def _result(gate_id: GateId = GateId.LV_MCP) -> LiveGateResult:
    obligations = tuple(
        ObligationResult(
            item.obligation_id,
            ObligationStatus.PASS,
            "observed",
            (
                EvidenceReference(
                    EvidenceKind.FILE_SHA256, f"evidence/{item.obligation_id}", "e" * 64
                ),
            ),
        )
        for item in GATE_REGISTRY[gate_id].obligations
    )
    return LiveGateResult(
        gate_id=gate_id,
        owners=("owner",),
        inputs_manifest_sha256="e" * 64,
        service_sha="b" * 40,
        content_sha="c" * 40,
        artifact_digest="f" * 64,
        status="PASS",
        commands=(),
        results={},
        evidence_refs=tuple(ref for row in obligations for ref in row.evidence_refs),
        checked_at="2026-10-08T00:00:00+00:00",
        binding=_binding(),
        expected_binding=_binding(),
        obligations=obligations,
    )


def make_run(
    *,
    invocation_id: str,
    run_id: str,
    gate_id: GateId,
    contributor_id: str,
    slots: tuple[str, ...],
    deadline_utc: str,
    task_arns: tuple[str, ...] = (),
    discovered_arns: tuple[str, ...] = (),
    state: str = "stopped",
) -> RunIntent:
    return RunIntent(
        invocation_id=invocation_id,
        run_id=run_id,
        started_by=run_id,
        client_tokens=tuple(str(UUID(int=index + 1)) for index in range(len(slots))),
        gate_id=gate_id.value,
        contributor_id=contributor_id,
        task_slots=slots,
        task_arns=task_arns,
        discovered_arns=discovered_arns,
        probe_spec=None,
        launch_requests=(),
        deadline_utc=deadline_utc,
        state=state,
    )


def make_session(clients, binding_value, journal_root: Path) -> QualificationSession:
    return QualificationSession.open(clients, binding_value, journal_root=journal_root)


def make_task_observation(
    *,
    binding_value,
    arn: str,
    run_id: str,
    session_id: str,
    invocation_id: str,
    gate_id: GateId,
    contributor_id: str,
    slot: str,
    status: str,
) -> dict[str, object]:
    tags = {
        "qualification": "true",
        "qualification-session": session_id,
        "qualification-invocation": invocation_id,
        "qualification-run": run_id,
        "qualification-gate": gate_id.value,
        "qualification-contributor": contributor_id,
        "qualification-slot": slot,
    }
    return {
        "taskArn": arn,
        "clusterArn": binding_value.cluster_arn,
        "taskDefinitionArn": binding_value.task_definition_arn,
        "startedBy": run_id,
        "lastStatus": status,
        "tags": [{"key": key, "value": value} for key, value in tags.items()],
    }
