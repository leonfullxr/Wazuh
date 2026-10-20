from __future__ import annotations

from scripts.staging.clients import StagingClients
from scripts.staging.manifest import NetworkGateInput, StagingManifestV3
from scripts.staging.models import (
    AcceptanceId,
    GateId,
    GateStatus,
    KnownResultView,
    LiveAcceptanceResult,
    LiveGateResult,
    ObligationResult,
    ObligationStatus,
    utc_now_iso,
)
from scripts.staging.registry import GATE_REGISTRY


def run_network_gate(
    manifest: StagingManifestV3,
    *,
    manifest_hash: str,
    commands: tuple[str, ...],
    clients: StagingClients,
    binding,
) -> LiveGateResult:
    from scripts.staging.adapters import _not_run_result

    configured = manifest.inputs.network
    sites = (configured,) if isinstance(configured, NetworkGateInput) else configured
    if not sites or clients.network is None:
        reason = "network inputs or configured network probe client are missing"
        obligations = tuple(
            ObligationResult(item.obligation_id, ObligationStatus.NOT_RUN, reason)
            for item in GATE_REGISTRY[GateId.LV_NETWORK].obligations
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
    try:
        reports = tuple(clients.network.probe_network(site) for site in sites)
    except Exception as exc:
        reason = f"network probe failed before producing a report: {type(exc).__name__}"
        return _not_run_result(
            manifest,
            manifest_hash=manifest_hash,
            reason=reason,
            commands=commands,
            binding=binding,
            data_source="aws_client",
        )
    expected_site_ids = tuple(site.environment_id for site in sites)
    actual_site_ids = tuple(report.site_id for report in reports)
    binding_mismatch = any(report.binding != binding for report in reports)
    site_coverage_mismatch = (
        len(set(expected_site_ids)) != len(expected_site_ids)
        or len(set(actual_site_ids)) != len(actual_site_ids)
        or set(actual_site_ids) != set(expected_site_ids)
    )
    required = tuple(item.obligation_id for item in GATE_REGISTRY[GateId.LV_NETWORK].obligations)
    per_site_rows: dict[str, tuple[ObligationResult, ...]] = {}
    unknown_ids: set[str] = set()
    duplicate_ids: set[str] = set()
    for report in reports:
        ids = [row.obligation_id for row in report.obligations]
        unknown_ids.update(set(ids) - set(required))
        duplicate_ids.update(item for item in set(ids) if ids.count(item) > 1)
        by_id: dict[str, list[ObligationResult]] = {}
        for row in report.obligations:
            by_id.setdefault(row.obligation_id, []).append(row)
        per_site_rows[report.site_id] = tuple(
            (
                ObligationResult(
                    obligation_id,
                    ObligationStatus.FAIL,
                    "multiple observations conflict or duplicate the obligation",
                    tuple(
                        dict.fromkeys(
                            ref for row in by_id[obligation_id] for ref in row.evidence_refs
                        )
                    ),
                )
                if len(by_id.get(obligation_id, ())) > 1
                else by_id[obligation_id][0]
                if by_id.get(obligation_id)
                else ObligationResult(
                    obligation_id,
                    ObligationStatus.NOT_RUN,
                    f"site {report.site_id} returned no observation",
                )
            )
            for obligation_id in required
        )
    rows = tuple(
        ObligationResult(
            obligation_id,
            (
                ObligationStatus.FAIL
                if any(
                    row.status == ObligationStatus.FAIL
                    for values in per_site_rows.values()
                    for row in values
                    if row.obligation_id == obligation_id
                )
                else ObligationStatus.PASS
                if len(per_site_rows) == len(sites)
                and all(
                    next(
                        row for row in per_site_rows[site_id] if row.obligation_id == obligation_id
                    ).status
                    == ObligationStatus.PASS
                    and bool(
                        next(
                            row
                            for row in per_site_rows[site_id]
                            if row.obligation_id == obligation_id
                        ).evidence_refs
                    )
                    for site_id in expected_site_ids
                    if site_id in per_site_rows
                )
                else ObligationStatus.NOT_RUN
            ),
            "observed for every configured site"
            if len(per_site_rows) == len(sites)
            else "site coverage incomplete",
            tuple(
                dict.fromkeys(
                    ref
                    for values in per_site_rows.values()
                    for row in values
                    if row.obligation_id == obligation_id
                    for ref in row.evidence_refs
                )
            ),
        )
        for obligation_id in required
    )
    missing = [row.obligation_id for row in rows if row.status == ObligationStatus.NOT_RUN]
    if binding_mismatch or site_coverage_mismatch:
        status: GateStatus = "FAIL"
    elif any(row.status == ObligationStatus.FAIL for row in rows):
        status = "FAIL"
    elif missing or unknown_ids or any(not row.evidence_refs for row in rows):
        status: GateStatus = (
            "NOT_RUN" if missing or any(not row.evidence_refs for row in rows) else "FAIL"
        )
    elif duplicate_ids:
        status = "FAIL"
    elif any(row.status == ObligationStatus.FAIL for row in rows):
        status = "FAIL"
    elif all(row.status == ObligationStatus.PASS for row in rows):
        status = "PASS"
    else:
        status = "NOT_RUN"
    if binding_mismatch:
        reason = "network report deployment binding differs from the runner observation"
        rows = tuple(
            ObligationResult(row.obligation_id, ObligationStatus.FAIL, reason, row.evidence_refs)
            for row in rows
        )
    elif site_coverage_mismatch:
        reason = "network reports do not cover every configured site exactly once"
        rows = tuple(
            ObligationResult(row.obligation_id, ObligationStatus.FAIL, reason, row.evidence_refs)
            for row in rows
        )
    elif unknown_ids:
        reason = "unexpected obligation IDs: " + ", ".join(sorted(unknown_ids))
    elif duplicate_ids:
        reason = "duplicate obligation observations: " + ", ".join(sorted(duplicate_ids))
    elif missing:
        reason = "missing observed obligations: " + ", ".join(missing)
    elif status == "NOT_RUN":
        reason = "network observations are incomplete or lack evidence references"
    else:
        reason = status
    refs = tuple(dict.fromkeys(ref for row in rows for ref in row.evidence_refs))
    gp4_ids = {"gp4_missing_pin_denied", "gp4_wrong_pin_denied", "gp4_rotation_invalidates_hash"}
    gp4_rows = tuple(row for row in rows if row.obligation_id in gp4_ids)
    gp4_status: GateStatus = (
        "FAIL"
        if any(row.status == ObligationStatus.FAIL for row in gp4_rows)
        else "PASS"
        if len(gp4_rows) == len(gp4_ids)
        and all(row.status == ObligationStatus.PASS for row in gp4_rows)
        else "NOT_RUN"
    )
    gp4_refs = tuple(dict.fromkeys(ref for row in gp4_rows for ref in row.evidence_refs))
    acceptance_results = (
        LiveAcceptanceResult(
            acceptance_id=AcceptanceId.GP4,
            gate_id=GateId.LV_NETWORK,
            status=gp4_status,
            binding=binding,
            obligation=ObligationResult(
                "GP4",
                ObligationStatus(gp4_status),
                "GP4 pin, rejection and rotation observations",
                gp4_refs,
            ),
            evidence_refs=gp4_refs,
        ),
    )
    return LiveGateResult(
        gate_id=manifest.gate_id,
        owners=manifest.owners,
        inputs_manifest_sha256=manifest_hash,
        service_sha=manifest.artifacts.service_sha,
        content_sha=manifest.artifacts.content_sha,
        artifact_digest=manifest.artifacts.artifact_digest,
        status=status,
        commands=commands,
        results={
            "reason": reason,
        },
        result_views=(
            KnownResultView(
                kind="network",
                view_id="network",
                diagnostics={
                    "sites": [
                        {"environment_id": site.environment_id, "hostname": site.hostname}
                        for site in sites
                    ],
                    "observed_site_ids": list(actual_site_ids),
                    "required_site_ids": list(expected_site_ids),
                },
                obligation_ids=tuple(row.obligation_id for row in rows),
            ),
        ),
        evidence_refs=refs,
        checked_at=utc_now_iso(),
        binding=binding,
        expected_binding=manifest.expected_deployment.to_observed_binding(),
        obligations=rows,
        acceptance_results=acceptance_results,
        data_source="aws_client",
    )
