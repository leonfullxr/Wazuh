"""Fixed MCP and state evaluators for authenticated reload certification."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from scripts.staging.certification import VerifiedObservation, _mint_verified_observation
from scripts.staging.models import (
    DeploymentBinding,
    EvidenceKind,
    EvidenceReference,
    GateId,
    ObligationResult,
    ObligationStatus,
)
from scripts.staging.registry import (
    GATE_REGISTRY,
    evaluator_version_for,
    required_facts_for,
)
from scripts.staging.verifier import (
    VerifiedArtifact,
    VerifiedFactChain,
    is_verified_artifact,
    is_verified_fact_chain,
)

_MCP_CASES = frozenset(
    {
        "wrong_resource",
        "wrong_issuer",
        "wrong_scope",
        "wrong_type",
        "browser_cookie",
        "origin",
        "protocol_version",
    }
)


@dataclass(frozen=True, slots=True)
class RegisteredEvaluation:
    obligations: tuple[ObligationResult, ...]
    verified_observations: tuple[VerifiedObservation, ...]
    evidence_refs: tuple[EvidenceReference, ...]
    evaluator_version: str


def _mcp_candidates(artifacts: tuple[VerifiedArtifact, ...]) -> dict[str, tuple[bool | None, str]]:
    if len(artifacts) != 1:
        return {
            item: (None, "one authenticated MCP task envelope is required")
            for item in ("official_client_flows", "mcp_auth_negatives", "frozen_output_parity")
        }
    measurements = artifacts[0].envelope.measurements
    flows = measurements.get("official_client_flows")
    negatives = measurements.get("mcp_auth_negatives")
    parity = measurements.get("frozen_output_parity")
    flow_pass = flows.get("passed") if isinstance(flows, dict) else None
    cases = negatives.get("cases") if isinstance(negatives, dict) else None
    negative_pass = (
        all(value.get("passed") is True for value in cases.values())
        if isinstance(cases, dict)
        and set(cases) == _MCP_CASES
        and all(isinstance(value, dict) for value in cases.values())
        else None
    )
    parity_pass = parity.get("passed") if isinstance(parity, dict) else None
    return {
        "official_client_flows": (
            flow_pass if type(flow_pass) is bool else None,
            "MCP initialize/list/ask/page/feedback",
        ),
        "mcp_auth_negatives": (negative_pass, "all registered MCP authentication negatives"),
        "frozen_output_parity": (
            parity_pass if type(parity_pass) is bool else None,
            "frozen output contracts and parity",
        ),
    }


def _state_candidates(
    artifacts: tuple[VerifiedArtifact, ...],
) -> dict[str, tuple[bool | None, str]]:
    by_slot: dict[str, dict[str, Any]] = {}
    for artifact in artifacts:
        slot = artifact.envelope.measurements.get("contender")
        facts = artifact.envelope.measurements.get("facts")
        if slot in {"A", "B"} and isinstance(facts, dict) and slot not in by_slot:
            by_slot[slot] = facts
    return _state_candidate_rows(by_slot)


def _state_candidate_rows(
    by_slot: dict[str, dict[str, Any]],
) -> dict[str, tuple[bool | None, str]]:
    """Evaluate only facts from authenticated contender envelopes."""
    required = {"A", "B"}
    if set(by_slot) != required:
        # Incompleteness cannot erase a failure already measured in an
        # authenticated contender envelope. Preserve explicit negative facts;
        # pair-dependent success remains unavailable until both slots exist.
        available = tuple(by_slot.values())

        def observed_false(name: str) -> bool:
            return any(facts.get(name) is False for facts in available)

        cancellation_failed = observed_false("stale_fence_rejected") or observed_false(
            "recovery_terminalized"
        )

        return {
            "ddb_replica_transactions": (
                None,
                "authenticated A and B task envelopes are required",
            ),
            "stage_admission": (
                False if observed_false("stage_admission") else None,
                "authenticated admission failure"
                if observed_false("stage_admission")
                else "authenticated A and B task envelopes are required",
            ),
            "cancellation_recovery": (
                False if cancellation_failed else None,
                "authenticated cancellation or recovery invariant failed"
                if cancellation_failed
                else (
                    "blocked cancellation and crashed started-liability recovery "
                    "experiments are not implemented"
                ),
            ),
            "exactly_once_settlement": (
                False if observed_false("ambiguous_settlement_exactly_once") else None,
                "authenticated settlement observation was not exactly once"
                if observed_false("ambiguous_settlement_exactly_once")
                else "completion experiment is not implemented",
            ),
        }
    a, b = by_slot["A"], by_slot["B"]
    cancellation_failed = any(
        slot.get(name) is False
        for slot in (a, b)
        for name in ("stale_fence_rejected", "recovery_terminalized")
    )
    lease_a, lease_b = a.get("lease_acquired"), b.get("lease_acquired")
    contended_a, contended_b = a.get("lease_contended"), b.get("lease_contended")
    contention = (
        lease_a is True and contended_b is True or lease_b is True and contended_a is True
        if all(type(value) is bool for value in (lease_a, lease_b, contended_a, contended_b))
        else None
    )
    winner = a if lease_a is True else b if lease_b is True else {}
    return {
        "ddb_replica_transactions": (
            False if contention is False else None,
            "two contender reports did not produce one lease and one BUSY result"
            if contention is False
            else "positive certification requires item keys, conditional-error matching, "
            "linked retained reads, and authenticated rendezvous versions",
        ),
        "stage_admission": (
            False if winner.get("stage_admission") is False else None,
            "a single admission grant cannot establish configured maxima",
        ),
        "cancellation_recovery": (
            False if cancellation_failed else None,
            "authenticated cancellation or recovery invariant failed"
            if cancellation_failed
            else (
                "blocked cancellation and crashed started-liability recovery "
                "experiments are not implemented"
            ),
        ),
        "exactly_once_settlement": (
            False
            if a.get("ambiguous_settlement_exactly_once") is False
            or b.get("ambiguous_settlement_exactly_once") is False
            else None,
            "authenticated settlement observation was not exactly once"
            if a.get("ambiguous_settlement_exactly_once") is False
            or b.get("ambiguous_settlement_exactly_once") is False
            else "completion experiment is not implemented",
        ),
    }


_HANDLERS: MappingProxyType[
    tuple[GateId, str], Callable[..., dict[str, tuple[bool | None, str]]]
] = MappingProxyType(
    {
        (GateId.LV_MCP, "mcp"): _mcp_candidates,
        (GateId.LV_STATE, "state"): _state_candidates,
    }
)


def evaluate_registered_artifacts(
    *,
    gate_id: GateId,
    contributor_id: str,
    artifacts: tuple[VerifiedArtifact, ...],
    fact_chains: tuple[VerifiedFactChain, ...] = (),
    binding: DeploymentBinding,
    deadline_guard: Callable[[], None] | None = None,
) -> RegisteredEvaluation:
    """Recompute candidate rows with the installed evaluator and require facts for PASS."""
    handler = _HANDLERS.get((gate_id, contributor_id))
    if handler is None:
        raise ValueError("no evaluator is registered for this gate contributor")
    obligation_versions = tuple(
        evaluator_version_for(gate_id, contributor_id, row.obligation_id)
        for row in GATE_REGISTRY[gate_id].obligations
    )
    if not obligation_versions or any(version is None for version in obligation_versions):
        raise ValueError("registered evaluator version is missing")
    if len(set(obligation_versions)) != 1:
        raise ValueError("registered evaluator versions are inconsistent")
    evaluator_version = obligation_versions[0]
    assert evaluator_version is not None
    if any(not is_verified_artifact(item) for item in artifacts):
        artifacts = ()
    elif any(
        item.launch.expectation.binding != binding
        or item.launch.expectation.gate_id != gate_id
        or item.launch.expectation.contributor_id != contributor_id
        for item in artifacts
    ):
        artifacts = ()
    candidates = handler(artifacts)
    required_obligations = {row.obligation_id for row in GATE_REGISTRY[gate_id].obligations}
    if set(candidates) != required_obligations:
        raise ValueError("registered evaluator did not produce the complete obligation set")
    refs = tuple(
        EvidenceReference(
            EvidenceKind.S3_VERSION,
            f"s3://{item.bucket}/{item.key}?versionId={item.version_id}",
            item.sha256,
        )
        for item in artifacts
    )
    rows: list[ObligationResult] = []
    observations: list[VerifiedObservation] = []
    for obligation_id, (passed, detail) in candidates.items():
        required_facts = required_facts_for(gate_id, contributor_id, obligation_id)
        if required_facts is None:
            raise ValueError("no fact contract is registered for the obligation")
        available_chains = tuple(fact_chains) + tuple(
            artifact.fact_chain for artifact in artifacts if artifact.fact_chain is not None
        )
        matching = tuple(
            chain
            for chain in available_chains
            if any(is_verified_fact_chain(chain, artifact.launch) for artifact in artifacts)
        )
        matched_fact_ids = {fact.fact_id for chain in matching for fact in chain.facts}
        if passed is False:
            status = ObligationStatus.FAIL
            evidence = refs
        elif passed is True and matching and required_facts.issubset(matched_fact_ids):
            if deadline_guard is not None:
                deadline_guard()
            status = ObligationStatus.PASS
            evidence = refs
            digest = hashlib.sha256(
                json.dumps(
                    sorted(chain.chain_digest for chain in matching),
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            launch = matching[0].launch
            observations.append(
                _mint_verified_observation(
                    gate_id=gate_id,
                    contributor_id=contributor_id,
                    obligation_id=obligation_id,
                    session_id=launch.expectation.session_id,
                    invocation_id=launch.expectation.invocation_id,
                    run_id=launch.expectation.run_id,
                    binding=binding,
                    fact_digest=digest,
                )
            )
        else:
            status = ObligationStatus.NOT_RUN
            evidence = ()
        rows.append(ObligationResult(obligation_id, status, detail, evidence))
    return RegisteredEvaluation(tuple(rows), tuple(observations), refs, evaluator_version)
