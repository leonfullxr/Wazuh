"""Typed PASS certification at staging, aggregation and serialization boundaries."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

from scripts.staging.models import (
    DeploymentBinding,
    GateId,
    LiveAcceptanceResult,
    LiveGateResult,
    ObligationResult,
    ObligationStatus,
)
from scripts.staging.registry import GATE_REGISTRY, evaluator_version_for, registered_contributors

_VERIFIER_SEAL = object()


@dataclass(frozen=True, slots=True, init=False)
class VerifiedObservation:
    """In-memory proof capability; deliberately not serializable as a result."""

    gate_id: GateId
    contributor_id: str
    obligation_id: str
    session_id: str
    invocation_id: str
    run_id: str
    binding: DeploymentBinding
    evaluator_version: str
    fact_digest: str
    _seal: object

    def __init__(
        self,
        *,
        _seal: object,
        gate_id: GateId,
        contributor_id: str,
        obligation_id: str,
        session_id: str,
        invocation_id: str,
        run_id: str,
        binding: DeploymentBinding,
        evaluator_version: str,
        fact_digest: str,
    ) -> None:
        if _seal is not _VERIFIER_SEAL:
            raise TypeError("VerifiedObservation can only be minted by the evidence verifier")
        object.__setattr__(self, "gate_id", gate_id)
        object.__setattr__(self, "contributor_id", contributor_id)
        object.__setattr__(self, "obligation_id", obligation_id)
        object.__setattr__(self, "session_id", session_id)
        object.__setattr__(self, "invocation_id", invocation_id)
        object.__setattr__(self, "run_id", run_id)
        object.__setattr__(self, "binding", binding)
        object.__setattr__(self, "evaluator_version", evaluator_version)
        object.__setattr__(self, "fact_digest", fact_digest)
        object.__setattr__(self, "_seal", _seal)

    def __reduce__(self):
        raise TypeError("VerifiedObservation is process-local and cannot be serialized")


def is_verified_observation(
    value: object,
    *,
    gate_id: GateId,
    contributor_id: str,
    obligation_id: str,
    binding: DeploymentBinding,
) -> bool:
    if not isinstance(value, VerifiedObservation) or value._seal is not _VERIFIER_SEAL:
        return False
    expected_evaluator = evaluator_version_for(gate_id, contributor_id, obligation_id)
    return bool(
        expected_evaluator
        and value.gate_id == gate_id
        and value.contributor_id == contributor_id
        and value.obligation_id == obligation_id
        and value.binding == binding
        and value.evaluator_version == expected_evaluator
        and re.fullmatch(r"[0-9a-f]{64}", value.fact_digest) is not None
    )


def _mint_verified_observation(
    *,
    gate_id: GateId,
    contributor_id: str,
    obligation_id: str,
    session_id: str,
    invocation_id: str,
    run_id: str,
    binding: DeploymentBinding,
    fact_digest: str,
) -> VerifiedObservation:
    evaluator_version = evaluator_version_for(gate_id, contributor_id, obligation_id)
    if evaluator_version is None or not re.fullmatch(r"[0-9a-f]{64}", fact_digest):
        raise ValueError("verified observation is not supported by the fixed evaluator registry")
    return VerifiedObservation(
        _seal=_VERIFIER_SEAL,
        gate_id=gate_id,
        contributor_id=contributor_id,
        obligation_id=obligation_id,
        session_id=session_id,
        invocation_id=invocation_id,
        run_id=run_id,
        binding=binding,
        evaluator_version=evaluator_version,
        fact_digest=fact_digest,
    )


def certify_obligations(
    rows: tuple[ObligationResult, ...],
    capabilities: tuple[VerifiedObservation, ...],
    *,
    gate_id: GateId,
    contributors: frozenset[str],
    binding: DeploymentBinding,
) -> tuple[ObligationResult, ...]:
    """Retain PASS rows only when their exact typed capability is present."""
    authorized: set[str] = set()
    for row in rows:
        if row.status != ObligationStatus.PASS:
            continue
        verified = any(
            capability.contributor_id in contributors
            and is_verified_observation(
                capability,
                gate_id=gate_id,
                contributor_id=capability.contributor_id,
                obligation_id=row.obligation_id,
                binding=binding,
            )
            for capability in capabilities
        )
        if verified:
            authorized.add(row.obligation_id)
    return demote_positive_rows(
        rows,
        authorized_obligations=frozenset(authorized),
        detail="no matching authenticated VerifiedObservation was produced",
    )


def demote_positive_rows(
    rows: tuple[ObligationResult, ...],
    *,
    authorized_obligations: frozenset[str] = frozenset(),
    detail: str = "positive row lacks an authenticated VerifiedObservation",
) -> tuple[ObligationResult, ...]:
    return tuple(
        row
        if row.status != ObligationStatus.PASS or row.obligation_id in authorized_obligations
        else ObligationResult(row.obligation_id, ObligationStatus.NOT_RUN, detail)
        for row in rows
    )


def summarize_obligations(
    gate_id: GateId,
    rows: tuple[ObligationResult, ...],
    *,
    source_status: str,
    contributor_registered: bool,
) -> str:
    """Apply the shared integrity and completeness precedence to typed rows."""
    if source_status == "FAIL" or any(row.status == ObligationStatus.FAIL for row in rows):
        return "FAIL"
    row_by_id = {row.obligation_id: row for row in rows}
    if contributor_registered and all(
        row_by_id.get(definition.obligation_id) is not None
        and row_by_id[definition.obligation_id].status == ObligationStatus.PASS
        for definition in GATE_REGISTRY[gate_id].obligations
    ):
        return "PASS"
    return "NOT_RUN"


def normalize_acceptance(
    rows: tuple[LiveAcceptanceResult, ...],
) -> tuple[LiveAcceptanceResult, ...]:
    return tuple(
        replace(
            row,
            status=("NOT_RUN" if row.status == "PASS" else row.status),
            obligation=replace(
                row.obligation,
                status=ObligationStatus.NOT_RUN
                if row.obligation.status == ObligationStatus.PASS
                else row.obligation.status,
                detail=(
                    "acceptance lacks an authenticated VerifiedObservation"
                    if row.obligation.status == ObligationStatus.PASS
                    else row.obligation.detail
                ),
                evidence_refs=()
                if row.obligation.status == ObligationStatus.PASS
                else row.obligation.evidence_refs,
            ),
            evidence_refs=() if row.status == "PASS" else row.evidence_refs,
        )
        for row in rows
    )


def normalize_live_result(result: LiveGateResult) -> LiveGateResult:
    """Apply the shared typed PASS boundary without inspecting arbitrary payloads."""
    contributors = registered_contributors(result.gate_id)
    capabilities = tuple(
        capability
        for capability in result.verified_observations
        if isinstance(capability, VerifiedObservation)
    )
    rows = (
        certify_obligations(
            result.obligations,
            capabilities,
            gate_id=result.gate_id,
            contributors=contributors,
            binding=result.binding,
        )
        if result.binding is not None
        else tuple(
            row
            if row.status != ObligationStatus.PASS
            else ObligationResult(
                row.obligation_id,
                ObligationStatus.NOT_RUN,
                "no matching authenticated VerifiedObservation was produced",
            )
            for row in result.obligations
        )
    )
    status = summarize_obligations(
        result.gate_id,
        rows,
        source_status=result.status,
        contributor_registered=bool(contributors),
    )
    acceptances = normalize_acceptance(result.acceptance_results)
    if result.status == "PASS" and status != "PASS":
        # The error is a diagnostic; it carries no authority to certify rows.
        results = {
            **result.results,
            "certification_error": "PASS lacks an authenticated VerifiedObservation",
        }
    else:
        results = result.results
    if (
        status == result.status
        and rows == result.obligations
        and acceptances == result.acceptance_results
        and results == result.results
    ):
        return result
    return replace(
        result,
        status=status,
        results=results,
        obligations=rows,
        acceptance_results=acceptances,
        evidence_refs=tuple(dict.fromkeys(ref for row in rows for ref in row.evidence_refs)),
    )
