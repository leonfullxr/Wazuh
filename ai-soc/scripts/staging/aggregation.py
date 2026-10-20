from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scripts.staging.certification import normalize_acceptance, normalize_live_result
from scripts.staging.models import (
    AcceptanceId,
    DeploymentBinding,
    EvidenceReference,
    GateId,
    GateStatus,
    LiveAcceptanceResult,
    LiveGateResult,
    ObligationResult,
    ObligationStatus,
    QualificationReceipt,
    matches_expected_binding,
    redact_secrets,
    utc_now_iso,
)
from scripts.staging.registry import ACCEPTANCE_GATE, GATE_REGISTRY


@dataclass(frozen=True, slots=True)
class LV1Summary:
    status: GateStatus
    binding: DeploymentBinding | None
    gates: tuple[LiveGateResult | None, ...]
    acceptances: tuple[LiveAcceptanceResult | None, ...]
    checked_at: str

    def to_dict(self) -> dict[str, Any]:
        return redact_secrets(
            {
                "schema_version": "1",
                "qualification": "LV-1",
                "status": self.status,
                "binding": (
                    {
                        "account_id": self.binding.account_id,
                        "region": self.binding.region,
                        "cluster_arn": self.binding.cluster_arn,
                        "service_arn": self.binding.service_arn,
                        "task_definition_arn": self.binding.task_definition_arn,
                        "deployment_name": self.binding.deployment_name,
                        "deployment_id": self.binding.deployment_id,
                        "image_digest": self.binding.image_digest,
                        "service_sha": self.binding.service_sha,
                        "content_sha": self.binding.content_sha,
                        "configuration_sha256": self.binding.configuration_sha256,
                    }
                    if self.binding is not None
                    else None
                ),
                "gates": {
                    gate_id.value: result.to_dict() if result is not None else None
                    for gate_id, result in zip(GATE_REGISTRY, self.gates, strict=True)
                },
                "acceptances": {
                    acceptance_id.value: result.to_dict() if result is not None else None
                    for acceptance_id, result in zip(AcceptanceId, self.acceptances, strict=True)
                },
                "checked_at": self.checked_at,
            }
        )


def aggregate_results(
    gate_results: tuple[LiveGateResult, ...],
    acceptance_results: tuple[LiveAcceptanceResult, ...] = (),
) -> LV1Summary:
    # The same guard applies to direct callers and reloaded wire artifacts.
    # Serialized JSON cannot carry the process-local proof capability.
    gate_results = tuple(normalize_live_result(result) for result in gate_results)
    gates: dict[GateId, LiveGateResult] = {}
    acceptances: dict[AcceptanceId, LiveAcceptanceResult] = {}
    observed: set[DeploymentBinding] = set()

    for result in gate_results:
        if result.status not in {"PASS", "FAIL", "NOT_RUN", "NOT_CONFIGURED"}:
            raise ValueError(f"invalid gate status: {result.gate_id.value}")
        if result.gate_id in gates:
            raise ValueError(f"duplicate gate result: {result.gate_id.value}")
        gates[result.gate_id] = result
        if result.binding is None and result.status == "PASS":
            raise ValueError(f"unbound result cannot pass: {result.gate_id.value}")
        if result.status == "PASS" and (
            result.binding is None
            or not matches_expected_binding(result.binding, result.expected_binding)
        ):
            raise ValueError(
                f"passing result differs from its deployment pins: {result.gate_id.value}"
            )
        if result.binding is not None:
            observed.add(result.binding)
        if result.status == "PASS":
            required = {item.obligation_id for item in GATE_REGISTRY[result.gate_id].obligations}
            actual = {item.obligation_id for item in result.obligations}
            if not required.issubset(actual):
                raise ValueError(f"passing result omits obligations: {result.gate_id.value}")
            if any(
                item.status != ObligationStatus.PASS or not item.evidence_refs
                for item in result.obligations
                if item.obligation_id in required
            ):
                raise ValueError(
                    f"passing result has unobserved obligations: {result.gate_id.value}"
                )
        for acceptance in result.acceptance_results:
            if acceptance.gate_id != result.gate_id:
                raise ValueError(
                    f"{acceptance.acceptance_id.value} is embedded in the wrong producer result"
                )
            _add_acceptance(acceptances, acceptance)

    for result in acceptance_results:
        if result.obligation.status.value != result.status:
            raise ValueError(
                f"acceptance status differs from its obligation: {result.acceptance_id.value}"
            )
        if result.obligation.evidence_refs != result.evidence_refs:
            raise ValueError(
                f"acceptance evidence differs from its obligation: {result.acceptance_id.value}"
            )
        # Standalone GP3/GP4 acceptance rows carry no process-local proof
        # capability. A wire row or adapter status cannot cross the shared
        # PASS boundary by itself.
        result = normalize_acceptance((result,))[0]
        _add_acceptance(acceptances, result)
    for result in acceptances.values():
        if result.status not in {"PASS", "FAIL", "NOT_RUN", "NOT_CONFIGURED"}:
            raise ValueError(f"invalid acceptance status: {result.acceptance_id.value}")
        if result.binding is None and result.status == "PASS":
            raise ValueError(f"unbound acceptance cannot pass: {result.acceptance_id.value}")
        if result.binding is not None:
            observed.add(result.binding)
        expected_obligation = result.acceptance_id.value
        if result.obligation.status.value != result.status:
            raise ValueError(
                f"acceptance status differs from its obligation: {result.acceptance_id.value}"
            )
        if result.obligation.evidence_refs != result.evidence_refs:
            raise ValueError(
                f"acceptance evidence differs from its obligation: {result.acceptance_id.value}"
            )
        if result.status == "PASS":
            if (
                result.obligation.obligation_id != expected_obligation
                or result.obligation.status != ObligationStatus.PASS
                or not result.obligation.evidence_refs
                or not result.evidence_refs
            ):
                raise ValueError(
                    "passing acceptance has incomplete obligation evidence: "
                    f"{result.acceptance_id.value}"
                )
        elif result.obligation.obligation_id != expected_obligation:
            raise ValueError(
                f"acceptance obligation identity mismatch: {result.acceptance_id.value}"
            )

    if len(observed) > 1:
        raise ValueError("cannot aggregate results with mismatched deployment bindings")
    binding = next(iter(observed), None)
    all_rows: tuple[LiveGateResult | LiveAcceptanceResult | None, ...] = tuple(
        [gates.get(gate_id) for gate_id in GATE_REGISTRY]
        + [acceptances.get(acceptance_id) for acceptance_id in AcceptanceId]
    )
    statuses = [row.status for row in all_rows if row is not None]
    complete = all(row is not None for row in all_rows)
    if any(status == "FAIL" for status in statuses):
        status: GateStatus = "FAIL"
    elif complete and all(status == "PASS" for status in statuses) and binding is not None:
        status = "PASS"
    else:
        status = "NOT_RUN"
    return LV1Summary(
        status=status,
        binding=binding,
        gates=tuple(gates.get(gate_id) for gate_id in GATE_REGISTRY),
        acceptances=tuple(acceptances.get(acceptance_id) for acceptance_id in AcceptanceId),
        checked_at=utc_now_iso(),
    )


def _add_acceptance(
    acceptances: dict[AcceptanceId, LiveAcceptanceResult], result: LiveAcceptanceResult
) -> None:
    if result.acceptance_id in acceptances:
        raise ValueError(f"duplicate acceptance result: {result.acceptance_id.value}")
    expected_gate = ACCEPTANCE_GATE[result.acceptance_id]
    if result.gate_id != expected_gate:
        raise ValueError(f"{result.acceptance_id.value} must be produced by {expected_gate.value}")
    acceptances[result.acceptance_id] = result


def _binding(raw: object) -> DeploymentBinding | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("evidence binding must be an object")
    return DeploymentBinding(**raw)


def _evidence_refs(raw: object) -> tuple[EvidenceReference, ...]:
    if not isinstance(raw, list):
        raise ValueError("evidence_refs must be a list of typed references")
    if any(not isinstance(item, dict) for item in raw):
        raise ValueError("evidence_refs must be typed references, not manifest strings")
    return tuple(EvidenceReference(**item) for item in raw)


def load_gate_result(path: Path) -> LiveGateResult:
    content = path.read_bytes()
    if len(content) > 2 * 1024 * 1024:
        raise ValueError(f"evidence file exceeds 2 MiB: {path.name}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("evidence file contains duplicate JSON keys")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"evidence file contains non-finite number: {value}")

    document: object = json.loads(
        content.decode("utf-8"),
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )
    if not isinstance(document, dict) or not isinstance(document.get("result"), dict):
        raise ValueError(f"evidence file has no LiveGateResult: {path.name}")
    raw = document["result"]
    expected_binding = _binding(raw.get("expected_binding"))
    if expected_binding is None:
        raise ValueError(f"evidence result is missing its expected deployment binding: {path.name}")
    obligations_raw = raw.get("obligations", [])
    acceptances_raw = raw.get("acceptance_results", [])
    receipts_raw = raw.get("qualification_receipts", [])
    if (
        not isinstance(obligations_raw, list)
        or not isinstance(acceptances_raw, list)
        or not isinstance(receipts_raw, list)
    ):
        raise ValueError(f"evidence result has invalid typed rows: {path.name}")
    obligations = tuple(
        ObligationResult(
            obligation_id=row["obligation_id"],
            status=ObligationStatus(row["status"]),
            detail=row["detail"],
            evidence_refs=_evidence_refs(row.get("evidence_refs", [])),
        )
        for row in obligations_raw
    )
    acceptance_results = tuple(
        LiveAcceptanceResult(
            acceptance_id=AcceptanceId(row["acceptance_id"]),
            gate_id=GateId(row["gate_id"]),
            status=row["status"],
            binding=_binding(row.get("binding")),
            obligation=ObligationResult(
                obligation_id=row["obligation"]["obligation_id"],
                status=ObligationStatus(row["obligation"]["status"]),
                detail=row["obligation"]["detail"],
                evidence_refs=_evidence_refs(row["obligation"].get("evidence_refs", [])),
            ),
            evidence_refs=_evidence_refs(row.get("evidence_refs", [])),
        )
        for row in acceptances_raw
    )
    return LiveGateResult(
        gate_id=GateId(raw["gate_id"]),
        owners=tuple(raw["owners"]),
        inputs_manifest_sha256=raw["inputs_manifest_sha256"],
        service_sha=raw["service_sha"],
        content_sha=raw["content_sha"],
        artifact_digest=raw["artifact_digest"],
        status=raw["status"],
        commands=tuple(raw["commands"]),
        results=raw["results"],
        evidence_refs=_evidence_refs(raw["evidence_refs"]),
        checked_at=raw["checked_at"],
        binding=_binding(raw.get("binding")),
        expected_binding=expected_binding,
        obligations=obligations,
        acceptance_results=acceptance_results,
        qualification_receipts=tuple(
            QualificationReceipt.from_dict(receipt) for receipt in receipts_raw
        ),
        data_source=raw.get("data_source"),
    )
