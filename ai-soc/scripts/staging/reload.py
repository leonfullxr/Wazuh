"""Authenticate and recompute qualification evidence during a live reload."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from scripts.staging.aws_clients import (
    build_explicit_staging_aws,
    load_aws_client_config,
    observe_deployment_snapshot,
)
from scripts.staging.certification import demote_positive_rows, summarize_obligations
from scripts.staging.evaluators import evaluate_registered_artifacts
from scripts.staging.models import (
    DeploymentBinding,
    GateId,
    LiveGateResult,
    ObligationResult,
    ObligationStatus,
    QualificationReceipt,
)
from scripts.staging.qualification_context import open_qualification_context
from scripts.staging.resource_map import load_pinned_resource_map
from scripts.staging.verifier import EvidenceContradiction, EvidenceIncomplete


@dataclass(frozen=True, slots=True)
class ReceiptSource:
    result_index: int
    contributor_id: str
    receipt: QualificationReceipt


@dataclass(frozen=True, slots=True)
class ContributorReloadEvidence:
    """Authenticated evidence and diagnostics for one gate contributor."""

    gate_id: GateId
    contributor_id: str
    result_index: int
    run_ids: tuple[str, ...]
    artifacts: tuple[Any, ...]
    diagnostics: tuple[str, ...] = ()
    contradiction: str | None = None


def collect_receipts(
    results: Sequence[LiveGateResult],
    *,
    session_id: str,
    invocation_id: str,
    run_ids: tuple[str, ...],
) -> dict[str, ReceiptSource]:
    """Require an exact, unique receipt set matching the caller allowlist."""
    if not run_ids or len(set(run_ids)) != len(run_ids):
        raise ValueError("caller run allowlist must be unique and nonempty")
    receipts: dict[str, ReceiptSource] = {}
    for result_index, result in enumerate(results):
        for receipt in result.qualification_receipts:
            if receipt.run_id in receipts:
                raise ValueError("serialized receipts contain a duplicate run")
            if (
                receipt.session_id != session_id
                or receipt.invocation_id != invocation_id
                or receipt.gate_id != result.gate_id
            ):
                raise ValueError("serialized receipt identity differs from its source result")
            receipts[receipt.run_id] = ReceiptSource(
                result_index,
                receipt.contributor_id,
                receipt,
            )
    if set(receipts) != set(run_ids):
        raise ValueError("caller run allowlist does not exactly match serialized receipts")
    return receipts


def authenticate_reload_groups(
    session: Any,
    results: Sequence[LiveGateResult],
    receipts: dict[str, ReceiptSource],
    run_ids: tuple[str, ...],
) -> tuple[ContributorReloadEvidence, ...]:
    """Authenticate caller-selected runs, retaining valid siblings and negatives."""
    grouped: dict[tuple[GateId, str], dict[str, Any]] = {}
    for run_id in run_ids:
        source = receipts[run_id]
        result = results[source.result_index]
        key = (result.gate_id, source.contributor_id)
        entry = grouped.setdefault(
            key,
            {
                "result_index": source.result_index,
                "run_ids": [],
                "artifacts": [],
                "diagnostics": [],
                "contradiction": None,
            },
        )
        if entry["result_index"] != source.result_index:
            raise ValueError("one contributor reload group spans multiple source results")
        entry["run_ids"].append(run_id)
        try:
            entry["artifacts"].extend(session.authenticate_run(run_id))
        except EvidenceIncomplete:
            entry["diagnostics"].append("authenticated evidence is incomplete")
        except EvidenceContradiction as exc:
            entry["contradiction"] = str(exc)
        except Exception:
            entry["diagnostics"].append("authenticated evidence could not be completely reloaded")
        diagnostics = session.run_diagnostics(run_id)
        entry["diagnostics"].extend(diagnostics)
    return tuple(
        ContributorReloadEvidence(
            gate_id=gate_id,
            contributor_id=contributor_id,
            result_index=entry["result_index"],
            run_ids=tuple(entry["run_ids"]),
            artifacts=tuple(entry["artifacts"]),
            diagnostics=tuple(entry["diagnostics"]),
            contradiction=entry["contradiction"],
        )
        for (gate_id, contributor_id), entry in grouped.items()
    )


def recompute_reload_group(
    group: ContributorReloadEvidence,
    *,
    original: LiveGateResult,
    binding: DeploymentBinding,
    session: Any,
    binding_changed: bool,
    observation_unavailable: bool = False,
    deadline_expired: bool,
) -> LiveGateResult:
    """Run one registered evaluation and apply shared positive-demotion rules."""

    def deadline_guard() -> None:
        session.require_run_deadlines(group.run_ids)

    evaluated = evaluate_registered_artifacts(
        gate_id=group.gate_id,
        contributor_id=group.contributor_id,
        artifacts=group.artifacts,
        binding=binding,
    )
    if not binding_changed and not deadline_expired:
        try:
            deadline_guard()
        except EvidenceIncomplete:
            deadline_expired = True
    if deadline_expired:
        rows = demote_positive_rows(
            evaluated.obligations,
            detail="positive certification unavailable after qualification deadline",
        )
        evaluated = replace(evaluated, obligations=rows, verified_observations=())
    if observation_unavailable and not binding_changed:
        rows = demote_positive_rows(
            evaluated.obligations,
            detail="final live deployment observation is unavailable",
        )
        evaluated = replace(evaluated, obligations=rows, verified_observations=())
    contradiction = group.contradiction
    if binding_changed or contradiction:
        reason = (
            "live deployment binding changed during reload"
            if binding_changed
            else "authenticated evidence contradicted the registered launch"
        )
        rows = tuple(
            ObligationResult(row.obligation_id, ObligationStatus.FAIL, reason, row.evidence_refs)
            for row in evaluated.obligations
        )
        evaluated = replace(evaluated, obligations=rows, verified_observations=())
    elif original.status == "FAIL" and not any(
        row.status == ObligationStatus.FAIL for row in evaluated.obligations
    ):
        rows = tuple(
            ObligationResult(
                row.obligation_id,
                ObligationStatus.FAIL,
                "historical FAIL preserved; fresh evidence is unavailable",
                row.evidence_refs,
            )
            for row in evaluated.obligations
        )
        evaluated = replace(evaluated, obligations=rows, verified_observations=())
    status = summarize_obligations(
        group.gate_id,
        evaluated.obligations,
        source_status="NOT_RUN",
        contributor_registered=bool(evaluated.verified_observations),
    )
    return replace(
        original,
        status=status,
        obligations=evaluated.obligations,
        evidence_refs=tuple(
            dict.fromkeys(ref for row in evaluated.obligations for ref in row.evidence_refs)
        ),
        results={
            **original.results,
            "reload": (
                "authenticated and recomputed"
                if not contradiction and not binding_changed and not observation_unavailable
                else "reload evidence rejected"
            ),
            "authenticated_run_ids": list(group.run_ids),
            "reload_diagnostics": list(group.diagnostics),
        },
        verified_observations=evaluated.verified_observations,
    )


def reload_qualification(
    results: Sequence[LiveGateResult],
    *,
    clients_config: Path,
    session_id: str,
    invocation_id: str,
    run_ids: tuple[str, ...],
) -> tuple[LiveGateResult, ...]:
    """Reauthenticate a sealed qualification session and refresh gate results."""
    config = load_aws_client_config(clients_config)
    configured = build_explicit_staging_aws(config)
    bindings = {result.binding for result in results if result.binding is not None}
    if len(bindings) != 1:
        raise ValueError("reload requires one complete, nonempty deployment binding")
    binding = next(iter(bindings))
    if not binding.deployment_id:
        raise ValueError("reload requires a nonempty deployment ID")
    snapshot = observe_deployment_snapshot(configured.observer, binding)
    if snapshot.binding != binding or not binding.deployment_id:
        raise ValueError("reload live deployment observation differs from saved evidence")
    pin = snapshot.sealed_document.qualification
    if pin is None:
        raise ValueError("reload live sealed configuration has no qualification map pin")
    resource_map = load_pinned_resource_map(
        pin, binding=binding, s3_client=configured.clients.client("s3")
    )
    context = open_qualification_context(
        aws=configured.clients,
        binding=binding,
        observer=configured.observer,
        resource_map=resource_map,
        deployment_snapshot=snapshot,
    )
    session = context.coordinator
    try:
        try:
            runs = session.resume_invocation(
                session_id=session_id, invocation_id=invocation_id, run_ids=run_ids
            )
        except EvidenceIncomplete:
            return tuple(_abstain_result(result) for result in results)
        receipts = collect_receipts(
            results,
            session_id=session_id,
            invocation_id=invocation_id,
            run_ids=run_ids,
        )
        if {run.run_id for run in runs} != set(run_ids):
            raise ValueError("caller run allowlist does not exactly match serialized receipts")
        groups = authenticate_reload_groups(session, results, receipts, run_ids)
        try:
            after = configured.observer.observe_deployment()
        except Exception:
            after = None
        observation_unavailable = after is None or not after.deployment_id
        binding_changed = not observation_unavailable and after != binding
        deadline_expired = False
        if not binding_changed:
            try:
                session.require_run_deadlines(run_ids)
            except EvidenceIncomplete:
                deadline_expired = True
        refreshed = list(results)
        for group in groups:
            index = group.result_index
            refreshed[index] = recompute_reload_group(
                group,
                original=refreshed[index],
                binding=binding,
                session=session,
                binding_changed=binding_changed,
                observation_unavailable=observation_unavailable,
                deadline_expired=deadline_expired,
            )
        return tuple(refreshed)
    finally:
        context.close()


def _abstain_result(result: LiveGateResult) -> LiveGateResult:
    rows = demote_positive_rows(
        result.obligations,
        detail="resume delivery calibration is unavailable",
    )
    status = summarize_obligations(
        result.gate_id,
        rows,
        source_status=result.status,
        contributor_registered=False,
    )
    return replace(
        result,
        status=status,
        obligations=rows,
        evidence_refs=tuple(dict.fromkeys(ref for row in rows for ref in row.evidence_refs)),
        verified_observations=(),
        results={**result.results, "reload": "delivery calibration unavailable"},
    )
