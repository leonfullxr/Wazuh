from __future__ import annotations

from dataclasses import replace
from importlib import import_module

from scripts.staging.certification import (
    demote_positive_rows,
    is_verified_observation,
    normalize_acceptance,
    normalize_live_result,
    summarize_obligations,
)
from scripts.staging.clients import (
    AdapterConfig,
    GateAdapterRegistration,
    GateAdapterReport,
    StagingClients,
)
from scripts.staging.manifest import NightlyCaseInput, StagingManifestV3
from scripts.staging.models import (
    AcceptanceId,
    GateDataSource,
    GateId,
    GateStatus,
    KnownResultView,
    LiveAcceptanceResult,
    LiveGateResult,
    ObligationResult,
    ObligationStatus,
    utc_now_iso,
)
from scripts.staging.network_adapter import run_network_gate
from scripts.staging.nightly_eval import (
    CaseOutcome,
    CaseResult,
    ReviewedBaseline,
    evaluate_nightly,
)
from scripts.staging.qualification_context import open_qualification_context
from scripts.staging.registry import ACCEPTANCE_GATE, GATE_REGISTRY


def build_gate_adapters(
    configs: tuple[AdapterConfig, ...],
) -> dict[GateId, tuple[GateAdapterRegistration, ...]]:
    """Load explicitly configured adapter factories and their typed input models."""
    registrations: dict[GateId, list[GateAdapterRegistration]] = {}

    def resolve(reference: str):
        module_name, separator, symbol_name = reference.partition(":")
        if not separator or not module_name or not symbol_name:
            raise ValueError("adapter factory and input_model must use module:Symbol syntax")
        return getattr(import_module(module_name), symbol_name)

    for config in configs:
        if any(
            item.contributor_id == config.contributor_id
            for item in registrations.get(config.gate_id, ())
        ):
            raise ValueError(f"duplicate adapter contributor ID for {config.gate_id.value}")
        adapter_type = resolve(config.factory)
        input_model = resolve(config.input_model)
        adapter = adapter_type(**config.options)
        registrations.setdefault(config.gate_id, []).append(
            GateAdapterRegistration(
                contributor_id=config.contributor_id,
                gate_id=config.gate_id,
                adapter=adapter,
                input_model=input_model,
            )
        )
    return {gate_id: tuple(rows) for gate_id, rows in registrations.items()}


def _not_run_result(
    manifest: StagingManifestV3,
    *,
    manifest_hash: str,
    reason: str,
    commands: tuple[str, ...],
    binding=None,
    obligations: tuple[ObligationResult, ...] = (),
    data_source: GateDataSource | None = None,
) -> LiveGateResult:
    definition = GATE_REGISTRY[manifest.gate_id]
    if not obligations:
        obligations = tuple(
            ObligationResult(item.obligation_id, ObligationStatus.NOT_RUN, reason)
            for item in definition.obligations
        )
    acceptance_results = tuple(
        LiveAcceptanceResult(
            acceptance_id=acceptance_id,
            gate_id=manifest.gate_id,
            status="NOT_RUN",
            binding=binding,
            obligation=ObligationResult(
                acceptance_id.value,
                ObligationStatus.NOT_RUN,
                reason,
            ),
        )
        for acceptance_id in manifest.acceptance_ids
        if ACCEPTANCE_GATE.get(acceptance_id) == manifest.gate_id
    )
    return LiveGateResult(
        gate_id=manifest.gate_id,
        owners=manifest.owners,
        inputs_manifest_sha256=manifest_hash,
        service_sha=manifest.artifacts.service_sha,
        content_sha=manifest.artifacts.content_sha,
        artifact_digest=manifest.artifacts.artifact_digest,
        status="NOT_RUN",
        commands=commands,
        results={"reason": reason},
        evidence_refs=(),
        checked_at=utc_now_iso(),
        binding=binding,
        expected_binding=manifest.expected_deployment.to_observed_binding(),
        obligations=obligations,
        acceptance_results=acceptance_results,
        data_source=data_source,
    )


def _acceptances(
    manifest: StagingManifestV3,
    *,
    status: GateStatus,
    binding,
    obligations: tuple[ObligationResult, ...],
) -> tuple[LiveAcceptanceResult, ...]:
    obligation_by_id = {item.obligation_id: item for item in obligations}
    rows: list[LiveAcceptanceResult] = []
    for acceptance_id in manifest.acceptance_ids:
        if ACCEPTANCE_GATE.get(acceptance_id) != manifest.gate_id:
            continue
        obligation = ObligationResult(
            obligation_id=acceptance_id.value,
            status=ObligationStatus(status),
            detail=f"{acceptance_id.value} is derived from {manifest.gate_id.value}",
            evidence_refs=tuple(
                ref for item in obligation_by_id.values() for ref in item.evidence_refs
            ),
        )
        rows.append(
            LiveAcceptanceResult(
                acceptance_id=acceptance_id,
                gate_id=manifest.gate_id,
                status=status,
                binding=binding,
                obligation=obligation,
                evidence_refs=obligation.evidence_refs,
            )
        )
    return tuple(rows)


def _nightly_cases(inputs: tuple[NightlyCaseInput, ...]) -> tuple[CaseResult, ...]:
    return tuple(
        CaseResult(
            case_id=row.case_id,
            language=row.language,
            outcome=CaseOutcome(row.outcome),
            route_matches=row.route_matches,
            valid_candidates=row.valid_candidates,
            dropped_candidates=row.dropped_candidates,
        )
        for row in inputs
    )


def run_nightly_gate(
    manifest: StagingManifestV3,
    *,
    manifest_hash: str,
    commands: tuple[str, ...],
    clients: StagingClients,
    binding,
) -> LiveGateResult:
    nightly = manifest.inputs.nightly
    if nightly is None:
        return _not_run_result(
            manifest,
            manifest_hash=manifest_hash,
            reason="LV-NIGHTLY missing inputs.nightly",
            commands=commands,
            binding=binding,
        )
    if clients.nightly is None:
        reason = (
            "no configured nightly results client; inline manifest rows are not live observations"
        )
        obligations = tuple(
            ObligationResult(item.obligation_id, ObligationStatus.NOT_RUN, reason)
            for item in GATE_REGISTRY[GateId.LV_NIGHTLY].obligations
        )
        return _not_run_result(
            manifest,
            manifest_hash=manifest_hash,
            reason=reason,
            commands=commands,
            binding=binding,
            obligations=obligations,
            data_source="unconfigured" if nightly.results is None else None,
        )
    try:
        report = clients.nightly.collect_case_results()
    except Exception as exc:
        reason = f"nightly collector failed before producing a report: {type(exc).__name__}"
        return _not_run_result(
            manifest,
            manifest_hash=manifest_hash,
            reason=reason,
            commands=commands,
            binding=binding,
            data_source="nightly_client",
        )
    case_inputs = report.cases
    if report.binding != binding:
        reason = "nightly report deployment binding differs from the runner observation"
        obligations = tuple(
            ObligationResult(item.obligation_id, ObligationStatus.FAIL, reason)
            for item in GATE_REGISTRY[GateId.LV_NIGHTLY].obligations
        )
        return LiveGateResult(
            gate_id=manifest.gate_id,
            owners=manifest.owners,
            inputs_manifest_sha256=manifest_hash,
            service_sha=manifest.artifacts.service_sha,
            content_sha=manifest.artifacts.content_sha,
            artifact_digest=manifest.artifacts.artifact_digest,
            status="FAIL",
            commands=commands,
            results={"reason": reason},
            evidence_refs=tuple(ref for row in case_inputs for ref in row.evidence_refs),
            checked_at=utc_now_iso(),
            binding=binding,
            expected_binding=manifest.expected_deployment.to_observed_binding(),
            obligations=obligations,
            acceptance_results=_acceptances(
                manifest, status="FAIL", binding=binding, obligations=obligations
            ),
            data_source="nightly_client",
        )
    required = set(nightly.required_case_ids)
    observed_ids = {row.case_id for row in case_inputs}
    evidence_missing = [
        row.case_id for row in case_inputs if not row.evidence_refs or not all(row.evidence_refs)
    ]
    if evidence_missing or not required.issubset(observed_ids):
        reason = "nightly observations lack required cases or their evidence references"
        obligations = tuple(
            ObligationResult(item.obligation_id, ObligationStatus.NOT_RUN, reason)
            for item in GATE_REGISTRY[GateId.LV_NIGHTLY].obligations
        )
        return _not_run_result(
            manifest,
            manifest_hash=manifest_hash,
            reason=reason,
            commands=commands,
            binding=binding,
            obligations=obligations,
            data_source="nightly_client",
        )
    baseline = ReviewedBaseline(
        sha256=nightly.baseline.sha256,
        en_cases=nightly.baseline.en_cases,
        es_cases=nightly.baseline.es_cases,
        drop_rate=nightly.baseline.drop_rate,
        independently_reviewed=nightly.baseline.independently_reviewed,
    )
    try:
        scored = evaluate_nightly(
            required_case_ids=nightly.required_case_ids,
            results=_nightly_cases(case_inputs),
            baseline=baseline,
        )
    except ValueError as exc:
        obligations = tuple(
            ObligationResult(item.obligation_id, ObligationStatus.FAIL, str(exc))
            for item in GATE_REGISTRY[GateId.LV_NIGHTLY].obligations
        )
        return LiveGateResult(
            gate_id=manifest.gate_id,
            owners=manifest.owners,
            inputs_manifest_sha256=manifest_hash,
            service_sha=manifest.artifacts.service_sha,
            content_sha=manifest.artifacts.content_sha,
            artifact_digest=manifest.artifacts.artifact_digest,
            status="FAIL",
            commands=commands,
            results={"error": str(exc)},
            evidence_refs=tuple(ref for row in case_inputs for ref in row.evidence_refs),
            checked_at=utc_now_iso(),
            binding=binding,
            expected_binding=manifest.expected_deployment.to_observed_binding(),
            obligations=obligations,
            acceptance_results=_acceptances(
                manifest, status="FAIL", binding=binding, obligations=obligations
            ),
            data_source="nightly_client",
        )
    status: GateStatus = "PASS" if scored.status == "PASS" else "FAIL"
    case_refs = tuple(dict.fromkeys(ref for row in case_inputs for ref in row.evidence_refs))
    observed_obligations = {}
    for row in report.obligations:
        previous = observed_obligations.get(row.obligation_id)
        if previous is None or row.status == ObligationStatus.FAIL:
            observed_obligations[row.obligation_id] = row
    allowed_observation_ids = {
        item.obligation_id for item in GATE_REGISTRY[GateId.LV_NIGHTLY].obligations
    } | {"gp3_stage_evidence", "gp3_trace_evidence"}
    observed_ids = [row.obligation_id for row in report.obligations]
    unknown_obligations = set(observed_ids) - allowed_observation_ids
    duplicate_obligations = {
        obligation_id
        for obligation_id in set(observed_ids)
        if observed_ids.count(obligation_id) > 1
    }
    derived = {
        "nightly_required_cases": ObligationResult(
            "nightly_required_cases",
            ObligationStatus(status),
            "required case denominator observed",
            case_refs,
        ),
        "nightly_router_accuracy": ObligationResult(
            "nightly_router_accuracy", ObligationStatus(status), "route outcomes scored", case_refs
        ),
        "nightly_drop_alarm": ObligationResult(
            "nightly_drop_alarm",
            ObligationStatus(status),
            "candidate drop rate compared to reviewed baseline",
            case_refs,
        ),
    }
    obligations_list = []
    for item in GATE_REGISTRY[GateId.LV_NIGHTLY].obligations:
        reported = observed_obligations.get(item.obligation_id)
        computed = derived.get(item.obligation_id)
        if reported is not None and reported.status == ObligationStatus.FAIL:
            obligations_list.append(reported)
        elif computed is not None:
            if (
                computed.status == ObligationStatus.PASS
                and reported is not None
                and reported.status == ObligationStatus.PASS
            ):
                if not reported.evidence_refs:
                    computed = ObligationResult(
                        computed.obligation_id,
                        ObligationStatus.NOT_RUN,
                        "passing nightly observation requires evidence references",
                    )
                else:
                    computed = reported
            obligations_list.append(computed)
        else:
            obligations_list.append(
                ObligationResult(
                    reported.obligation_id,
                    ObligationStatus.NOT_RUN,
                    "passing nightly observation requires evidence references",
                    reported.evidence_refs,
                )
                if reported is not None
                and reported.status == ObligationStatus.PASS
                and not reported.evidence_refs
                else reported
                or ObligationResult(
                    item.obligation_id,
                    ObligationStatus.NOT_RUN,
                    "no independent observation returned",
                )
            )
    obligations = tuple(obligations_list)
    if any(item.status == ObligationStatus.FAIL for item in obligations):
        status = "FAIL"
    elif any(item.status != ObligationStatus.PASS for item in obligations):
        status = "NOT_RUN"
    if unknown_obligations or duplicate_obligations:
        status = "FAIL"
        reason = "nightly report has duplicate or unknown obligation IDs"
        obligations = (
            obligations
            + (ObligationResult("nightly_obligation_integrity", ObligationStatus.FAIL, reason),)
            + tuple(
                ObligationResult(obligation_id, ObligationStatus.FAIL, reason, row.evidence_refs)
                for obligation_id in sorted(unknown_obligations)
                for row in report.obligations
                if row.obligation_id == obligation_id
            )
        )
    stage = observed_obligations.get("gp3_stage_evidence")
    trace = observed_obligations.get("gp3_trace_evidence")
    stage_pass = (
        stage is not None and stage.status == ObligationStatus.PASS and bool(stage.evidence_refs)
    )
    trace_pass = (
        trace is not None and trace.status == ObligationStatus.PASS and bool(trace.evidence_refs)
    )
    gp3_status: GateStatus = (
        "FAIL"
        if (stage is not None and stage.status == ObligationStatus.FAIL)
        or (trace is not None and trace.status == ObligationStatus.FAIL)
        else "PASS"
        if stage_pass and trace_pass
        else "NOT_RUN"
    )
    if unknown_obligations or duplicate_obligations:
        gp3_status = "FAIL"
    gp3_refs = tuple(
        dict.fromkeys(ref for row in (stage, trace) if row is not None for ref in row.evidence_refs)
    )
    acceptance_results = tuple(
        LiveAcceptanceResult(
            acceptance_id=acceptance_id,
            gate_id=manifest.gate_id,
            status=gp3_status,
            binding=binding,
            obligation=ObligationResult(
                "GP3",
                ObligationStatus(gp3_status),
                "nightly stage and trace evidence",
                gp3_refs,
            ),
            evidence_refs=gp3_refs,
        )
        for acceptance_id in manifest.acceptance_ids
        if acceptance_id == AcceptanceId.GP3
    )
    refs = tuple(dict.fromkeys(ref for row in case_inputs for ref in row.evidence_refs))
    return LiveGateResult(
        gate_id=manifest.gate_id,
        owners=manifest.owners,
        inputs_manifest_sha256=manifest_hash,
        service_sha=manifest.artifacts.service_sha,
        content_sha=manifest.artifacts.content_sha,
        artifact_digest=manifest.artifacts.artifact_digest,
        status=status,
        commands=commands,
        results={},
        result_views=(
            KnownResultView(
                kind="nightly",
                view_id="nightly",
                diagnostics={
                    "status": scored.status,
                    "required_cases": scored.required_cases,
                    "routed_correctly": scored.routed_correctly,
                    "router_accuracy": scored.router_accuracy,
                    "missing_cases": list(scored.missing_cases),
                    "outcome_counts": scored.outcome_counts,
                    "candidate_count": scored.candidate_count,
                    "dropped_count": scored.dropped_count,
                    "empty_cohort": scored.empty_cohort,
                    "drop_rate": scored.drop_rate,
                    "drop_alarm": scored.drop_alarm,
                    "unknown_obligations": sorted(unknown_obligations),
                    "duplicate_obligations": sorted(duplicate_obligations),
                },
                obligation_ids=tuple(row.obligation_id for row in obligations),
            ),
        ),
        evidence_refs=refs,
        checked_at=utc_now_iso(),
        binding=binding,
        expected_binding=manifest.expected_deployment.to_observed_binding(),
        obligations=obligations,
        acceptance_results=acceptance_results,
        data_source="nightly_client",
    )


def run_registered_adapter(
    manifest: StagingManifestV3,
    *,
    manifest_hash: str,
    commands: tuple[str, ...],
    clients: StagingClients,
    binding,
) -> LiveGateResult:
    registrations = (clients.adapters or {}).get(manifest.gate_id, ())
    definition = GATE_REGISTRY[manifest.gate_id]
    if not registrations or clients.aws is None:
        reason = "no registered gate adapter or AWS service-client factory is configured"
        obligations = tuple(
            ObligationResult(item.obligation_id, ObligationStatus.NOT_RUN, reason)
            for item in definition.obligations
        )
        return _not_run_result(
            manifest,
            manifest_hash=manifest_hash,
            reason=reason,
            commands=commands,
            binding=binding,
            obligations=obligations,
            data_source="unconfigured",
        )
    required = {item.obligation_id for item in definition.obligations}
    raw_inputs = manifest.inputs.adapter or {}
    contributor_inputs = raw_inputs
    if not isinstance(contributor_inputs, dict):
        contributor_inputs = {}
    contributor_ids = {item.contributor_id for item in registrations}
    unknown_input_keys = set(contributor_inputs) - contributor_ids
    if unknown_input_keys:
        reason = "adapter inputs name unregistered contributors"
        obligations = tuple(
            ObligationResult(item.obligation_id, ObligationStatus.NOT_RUN, reason)
            for item in definition.obligations
        )
        return _not_run_result(
            manifest,
            manifest_hash=manifest_hash,
            reason=reason,
            commands=commands,
            binding=binding,
            obligations=obligations,
            data_source="aws_client",
        )
    reports: list[tuple[str, GateAdapterReport]] = []
    try:
        for registration in registrations:
            if (
                registration.gate_id != manifest.gate_id
                or registration.adapter.gate_id != manifest.gate_id
            ):
                raise ValueError("registered adapter gate ID does not match manifest gate ID")
            if registration.input_model.model_config.get("extra") != "forbid":
                raise ValueError("registered adapter input model must reject unknown fields")
            inputs = registration.input_model.model_validate(
                contributor_inputs.get(registration.contributor_id, {})
            )
            report = registration.adapter.evaluate(
                inputs=inputs,
                clients=(
                    clients.qualification_context
                    if manifest.gate_id in {GateId.LV_MCP, GateId.LV_STATE}
                    and clients.qualification_context is not None
                    else clients.aws
                ),
                binding=binding,
                qualification_context=clients.qualification_context,
            )
            reports.append((registration.contributor_id, report))
    except Exception as exc:  # adapter/config errors are never evidence
        reason = f"adapter failed before producing an observation: {type(exc).__name__}"
        obligations = tuple(
            ObligationResult(item.obligation_id, ObligationStatus.NOT_RUN, reason)
            for item in definition.obligations
        )
        return _not_run_result(
            manifest,
            manifest_hash=manifest_hash,
            reason=reason,
            commands=commands,
            binding=binding,
            obligations=obligations,
            data_source="aws_client",
        )
    contributor_ids = [name for name, _ in reports]
    all_rows = [row for _, report in reports for row in report.obligations]
    actual_ids = [row.obligation_id for row in all_rows]
    duplicates = {item for item in set(actual_ids) if actual_ids.count(item) > 1}
    unknown = set(actual_ids) - required
    missing = required - set(actual_ids)
    rows_by_id = {row.obligation_id: row for row in all_rows}
    rows = tuple(
        rows_by_id.get(
            item.obligation_id,
            ObligationResult(
                item.obligation_id,
                ObligationStatus.NOT_RUN,
                "no contributor observed this obligation",
            ),
        )
        for item in definition.obligations
    )
    binding_mismatch = any(report.binding != binding for _, report in reports)
    if binding_mismatch or len(set(contributor_ids)) != len(contributor_ids):
        reason = (
            "adapter report deployment binding differs from the runner observation"
            if binding_mismatch
            else "adapter contributor IDs must be unique per gate"
        )
        rows = tuple(
            ObligationResult(row.obligation_id, ObligationStatus.FAIL, reason, row.evidence_refs)
            for row in rows
        )
    if (
        len(set(contributor_ids)) != len(contributor_ids)
        or unknown
        or duplicates
        or binding_mismatch
    ):
        status: GateStatus = "FAIL"
    elif any(row.status == ObligationStatus.FAIL for row in rows):
        status = "FAIL"
    elif missing or any(
        row.status != ObligationStatus.PASS or not row.evidence_refs for row in rows
    ):
        status = "NOT_RUN"
    else:
        status = "PASS"
    verified_observations = tuple(
        capability
        for contributor_id, report in reports
        for capability in report.verified_observations
        if any(
            is_verified_observation(
                capability,
                gate_id=manifest.gate_id,
                contributor_id=contributor_id,
                obligation_id=row.obligation_id,
                binding=binding,
            )
            for row in report.obligations
        )
    )
    qualification_receipts = tuple(
        report.qualification_receipt
        for _contributor_id, report in reports
        if report.qualification_receipt is not None
    )
    results = {
        "binding_error": binding_mismatch,
        "unknown_obligations": sorted(unknown),
        "duplicate_obligations": sorted(duplicates),
    }
    refs = tuple(dict.fromkeys(ref for item in rows for ref in item.evidence_refs))
    return LiveGateResult(
        gate_id=manifest.gate_id,
        owners=manifest.owners,
        inputs_manifest_sha256=manifest_hash,
        service_sha=manifest.artifacts.service_sha,
        content_sha=manifest.artifacts.content_sha,
        artifact_digest=manifest.artifacts.artifact_digest,
        status=status,
        commands=commands,
        results=results,
        result_views=tuple(
            KnownResultView(
                kind="contributor",
                view_id=contributor_id,
                diagnostics=report.results,
                obligation_ids=tuple(row.obligation_id for row in report.obligations),
            )
            for contributor_id, report in reports
        ),
        evidence_refs=refs,
        checked_at=utc_now_iso(),
        binding=binding,
        expected_binding=manifest.expected_deployment.to_observed_binding(),
        obligations=rows,
        acceptance_results=_acceptances(manifest, status=status, binding=binding, obligations=rows),
        qualification_receipts=qualification_receipts,
        data_source="aws_client",
        verified_observations=verified_observations,
    )


def run_live_gate(
    manifest: StagingManifestV3,
    *,
    manifest_hash: str,
    runner_commands: tuple[str, ...],
    clients: StagingClients | None = None,
) -> LiveGateResult:
    commands = runner_commands + manifest.commands
    active = clients or StagingClients()
    if active.observer is None:
        has_inline_results = (
            manifest.gate_id == GateId.LV_NIGHTLY
            and manifest.inputs.nightly is not None
            and manifest.inputs.nightly.results is not None
        )
        data_source = "inline_manifest" if has_inline_results else "unconfigured"
        reason = (
            "inline manifest data cannot certify a live gate; no configured deployment observer"
            if has_inline_results
            else "no configured deployment observer; gate evidence is unbound"
        )
        return _not_run_result(
            manifest,
            manifest_hash=manifest_hash,
            reason=reason,
            commands=commands,
            data_source=data_source,
        )
    try:
        binding = active.observer.observe_deployment()
    except Exception:
        binding = None
    if binding is None:
        return _not_run_result(
            manifest,
            manifest_hash=manifest_hash,
            reason="deployment observer returned no complete AWS observation",
            commands=commands,
            data_source="aws_client",
        )
    if not binding.deployment_id:
        return _not_run_result(
            manifest,
            manifest_hash=manifest_hash,
            reason="deployment observer returned no ECS deployment ID",
            commands=commands,
            binding=None,
            data_source="aws_client",
        )
    expected = manifest.expected_deployment.to_observed_binding()
    differences = [
        name
        for name in (
            "account_id",
            "region",
            "cluster_arn",
            "service_arn",
            "task_definition_arn",
            "deployment_name",
            "image_digest",
            "service_sha",
            "content_sha",
            "configuration_sha256",
        )
        if getattr(binding, name) != getattr(expected, name)
    ]
    if not expected.deployment_id or not binding.deployment_id:
        differences.append("deployment_id")
    elif binding.deployment_id != expected.deployment_id:
        differences.append("deployment_id")
    if differences:
        reason = "observed deployment does not match pins: " + ", ".join(differences)
        obligations = tuple(
            ObligationResult(item.obligation_id, ObligationStatus.FAIL, reason)
            for item in GATE_REGISTRY[manifest.gate_id].obligations
        )
        return LiveGateResult(
            gate_id=manifest.gate_id,
            owners=manifest.owners,
            inputs_manifest_sha256=manifest_hash,
            service_sha=manifest.artifacts.service_sha,
            content_sha=manifest.artifacts.content_sha,
            artifact_digest=manifest.artifacts.artifact_digest,
            status="FAIL",
            commands=commands,
            results={"reason": reason},
            evidence_refs=(),
            checked_at=utc_now_iso(),
            binding=binding,
            expected_binding=expected,
            obligations=obligations,
            acceptance_results=_acceptances(
                manifest, status="FAIL", binding=binding, obligations=obligations
            ),
            data_source="aws_client",
        )
    qualification_context = active.qualification_context
    if (
        active.aws is not None
        and qualification_context is None
        and manifest.gate_id in {GateId.LV_MCP, GateId.LV_STATE}
    ):
        try:
            qualification_context = open_qualification_context(
                aws=active.aws,
                binding=binding,
                observer=active.observer,
            )
        except Exception as exc:
            return _not_run_result(
                manifest,
                manifest_hash=manifest_hash,
                reason=(
                    f"qualification launch barrier could not be established: {type(exc).__name__}"
                ),
                commands=commands,
                binding=binding,
                data_source="aws_client",
            )
    if qualification_context is not None and active.aws is not None:
        active = replace(
            active,
            qualification_context=qualification_context,
        )
    try:
        if manifest.gate_id == GateId.LV_NIGHTLY:
            result = run_nightly_gate(
                manifest,
                manifest_hash=manifest_hash,
                commands=commands,
                clients=active,
                binding=binding,
            )
        elif manifest.gate_id == GateId.LV_NETWORK:
            result = run_network_gate(
                manifest,
                manifest_hash=manifest_hash,
                commands=commands,
                clients=active,
                binding=binding,
            )
        else:
            result = run_registered_adapter(
                manifest,
                manifest_hash=manifest_hash,
                commands=commands,
                clients=active,
                binding=binding,
            )
        try:
            after = active.observer.observe_deployment()
        except Exception:
            after = None
        if after is None or not after.deployment_id:
            reason = "final live deployment observation is unavailable"
            obligations = demote_positive_rows(result.obligations, detail=reason)
            status = summarize_obligations(
                result.gate_id,
                obligations,
                source_status=result.status,
                contributor_registered=False,
            )
            return replace(
                result,
                status=status,
                results={**result.results, "reason": reason},
                obligations=obligations,
                verified_observations=(),
                acceptance_results=normalize_acceptance(result.acceptance_results),
            )
        if after != binding:
            reason = "deployment binding changed during gate evaluation"
            failed = tuple(
                ObligationResult(
                    item.obligation_id, ObligationStatus.FAIL, reason, item.evidence_refs
                )
                for item in result.obligations
            )
            return replace(
                result,
                status="FAIL",
                results={**result.results, "reason": reason},
                obligations=failed,
                acceptance_results=_acceptances(
                    manifest, status="FAIL", binding=binding, obligations=failed
                ),
            )
        return normalize_live_result(result)
    finally:
        if qualification_context is not None:
            qualification_context.close()
