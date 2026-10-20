"""Reauthentication of journaled qualification launches and output artifacts."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from botocore.exceptions import BotoCoreError, ClientError

from ai_soc.qualification.models import ProbeInvocationConfig
from scripts.staging.launch_requests import build_probe_config
from scripts.staging.models import GateId
from scripts.staging.registry import PROBE_REGISTRY

if TYPE_CHECKING:
    from scripts.staging.verifier import VerifiedArtifact


def authenticate_run(session: Any, run_id: str) -> tuple[VerifiedArtifact, ...]:
    """Reauthenticate every task launch and exact output version from trail logs."""
    from scripts.staging.artifact_verification import AuthenticatedEvidenceVerifier
    from scripts.staging.attributed_probe import _parse_time
    from scripts.staging.cloudtrail import validate_session_logs
    from scripts.staging.launch_requests import resource_arns_for_probe
    from scripts.staging.verifier import (
        EvidenceContradiction,
        EvidenceIncomplete,
        LaunchExpectation,
        canonical_request_digest,
    )

    if (
        session.resource_map is None
        or not session.launcher_role_arn
        or not session.resource_map.certification_enabled
    ):
        raise EvidenceIncomplete("reload lacks the sealed map or approved launcher role")
    run = next((item for item in session._journal.runs if item.run_id == run_id), None)
    if run is None or run.state != "stopped" or len(run.launch_requests) != len(run.task_slots):
        raise EvidenceIncomplete("reload run is absent, incomplete or not cleanly stopped")
    if not run.task_arns or len(run.task_arns) != len(run.task_slots):
        raise EvidenceIncomplete("reload task set is incomplete")
    deadline = datetime.fromisoformat(run.deadline_utc.replace("Z", "+00:00"))
    session_expiry = _parse_time(session._journal.session_expires_at or "")
    if datetime.now(UTC) >= session_expiry or deadline > session_expiry:
        raise EvidenceIncomplete("absolute qualification session deadline expired")
    if datetime.now(UTC) >= deadline:
        raise EvidenceIncomplete("original qualification delivery deadline expired")
    if run.probe_spec is None:
        raise EvidenceContradiction("journaled ProbeSpec is missing")
    execution = run.probe_spec.execution_seconds
    collection = run.probe_spec.collection_seconds
    if (
        type(execution) is not int
        or not 1 <= execution <= 900
        or type(collection) is not int
        or not 1 <= collection <= 86_400
    ):
        raise EvidenceContradiction("journaled probe budgets are malformed")
    start_time = deadline - timedelta(seconds=execution + collection)
    delivery_remaining = (deadline - datetime.now(UTC)).total_seconds()
    if delivery_remaining < 1:
        raise EvidenceIncomplete("original qualification delivery deadline expired")
    reload_deadline = time.monotonic() + delivery_remaining
    credentials = getattr(
        getattr(session.clients, "session", None), "get_credentials", lambda: None
    )()
    logs = validate_session_logs(
        resource_map=session.resource_map,
        binding=session.binding,
        s3_client=session.clients.client("s3"),
        cloudtrail_client=session.clients.client("cloudtrail"),
        credentials=credentials,
        start_time=start_time,
        end_time=datetime.now(UTC),
        timeout_seconds=max(1, min(120, int(delivery_remaining))),
        deadline_monotonic=reload_deadline,
    )
    if time.monotonic() >= reload_deadline:
        raise EvidenceIncomplete("original qualification delivery deadline expired")
    verifier = AuthenticatedEvidenceVerifier(logs)
    ecs = session.clients.client("ecs")
    listed: set[str] = set()
    for page in ecs.get_paginator("list_tasks").paginate(
        cluster=session.binding.cluster_arn,
        startedBy=run.started_by,
    ):
        listed.update(page.get("taskArns", []))
        if time.monotonic() >= reload_deadline:
            raise EvidenceIncomplete("original qualification delivery deadline expired")
    if listed - set(run.task_arns):
        raise EvidenceIncomplete("reload discovered an unjournaled task for the run")
    described_response = ecs.describe_tasks(
        cluster=session.binding.cluster_arn,
        tasks=list(run.task_arns),
        include=["TAGS"],
    )
    if time.monotonic() >= reload_deadline:
        raise EvidenceIncomplete("original qualification delivery deadline expired")
    described = described_response.get("tasks", [])
    if (
        described_response.get("failures")
        or len(described) != len(run.task_slots)
        or {row.get("taskArn") for row in described} != set(run.task_arns)
    ):
        raise EvidenceIncomplete("reload task set could not be reconciled")
    tasks_by_slot: dict[str, str] = {}
    for task in described:
        valid, slot = session._task_identity(task, run)
        if (
            not valid
            or not session._task_runtime_binding(task, run)
            or slot in tasks_by_slot
            or not isinstance(slot, str)
        ):
            raise EvidenceIncomplete("reload task slot identity is ambiguous")
        if task.get("lastStatus") != "STOPPED":
            raise EvidenceIncomplete("reload task cleanup is not confirmed")
        app = next(
            (
                container
                for container in task.get("containers", [])
                if container.get("name") == "ai-soc"
            ),
            None,
        )
        if app is None or app.get("exitCode") != 0:
            raise EvidenceIncomplete("reload application task did not complete successfully")
        tasks_by_slot[slot] = task["taskArn"]
    artifacts: list[VerifiedArtifact] = []
    diagnostics: list[str] = []
    try:
        for index, slot in enumerate(run.task_slots):
            request = run.launch_requests[index]
            spec = run.probe_spec
            if not isinstance(spec, ProbeInvocationConfig):
                raise EvidenceContradiction("journaled ProbeSpec is missing or malformed")
            registration = PROBE_REGISTRY.get(
                (GateId(run.gate_id), run.contributor_id, spec.entrypoint)
            )
            if registration is None or registration.config_environment is None:
                raise EvidenceContradiction("journaled ProbeSpec has an unknown entrypoint")
            network = spec.network
            if network not in {"service", "public_isolated"}:
                raise EvidenceContradiction("journaled ProbeSpec is incomplete or malformed")
            expected_config = build_probe_config(
                registration,
                scenario=spec,
                binding=session.binding,
                run_id=run.run_id,
                session_id=session.session_id,
                invocation_id=run.invocation_id,
                slot=slot,
                deadline_utc=run.deadline_utc,
                evidence_bucket=session.resource_map.evidence.bucket,
                kms_key_arn=session.resource_map.evidence.kms_key_arn,
                account_id=session.binding.account_id,
            )
            overrides = request.get("overrides")
            containers = (
                overrides.get("containerOverrides") if isinstance(overrides, dict) else None
            )
            if not isinstance(containers, list) or len(containers) != 1:
                raise EvidenceContradiction("launch intent omits its exact probe configuration")
            container = containers[0]
            environment = container.get("environment") if isinstance(container, dict) else None
            if not isinstance(environment, list):
                raise EvidenceContradiction("launch intent omits its exact probe environment")
            environment_values: dict[str, str] = {}
            for item in environment:
                if (
                    not isinstance(item, dict)
                    or not isinstance(item.get("name"), str)
                    or not isinstance(item.get("value"), str)
                    or item["name"] in environment_values
                ):
                    raise EvidenceContradiction("launch probe environment is ambiguous")
                environment_values[item["name"]] = item["value"]
            expected_environment = {
                item["name"]: item["value"] for item in expected_config.environment
            }
            expected_command = list(expected_config.command)
            if (
                container.get("name") != "ai-soc"
                or environment_values != expected_environment
                or container.get("command") != expected_command
            ):
                raise EvidenceContradiction(
                    "launch request differs from the journaled ProbeSpec, binding or deadline"
                )
            expectation = LaunchExpectation(
                account_id=session.binding.account_id,
                region=session.binding.region,
                launcher_role_arn=session.launcher_role_arn,
                cluster_arn=session.binding.cluster_arn,
                task_definition_arn=session.binding.task_definition_arn,
                started_by=run.started_by,
                client_token=run.client_tokens[index],
                session_id=session.session_id,
                invocation_id=run.invocation_id,
                run_id=run.run_id,
                gate_id=GateId(run.gate_id),
                contributor_id=run.contributor_id,
                slot=slot,
                task_role_arn=session.resource_map.service.application_role_arn,
                binding=session.binding,
                deadline_utc=run.deadline_utc,
                launch_request_digest=canonical_request_digest(request),
                required_request_fields=tuple(request),
                execution_seconds=execution,
                collection_seconds=collection,
                resource_arns=resource_arns_for_probe(spec.entrypoint, spec, session.binding),
            )
            try:
                launch = verifier.authenticate_launch(expectation)
            except EvidenceIncomplete as exc:
                # Keep other independently authenticated slots. The
                # registered state evaluator can preserve a measured failure
                # from one contender while the pair remains incomplete.
                diagnostics.append(f"launch unavailable: {type(exc).__name__}")
                continue
            except Exception as exc:
                diagnostics.append(f"launch authentication failed: {type(exc).__name__}")
                continue
            if datetime.now(UTC) >= deadline:
                diagnostics.append("original qualification delivery deadline expired")
                break
            if launch.task_arn != tasks_by_slot[slot]:
                diagnostics.append("authenticated launch response differs from reconciled task")
                continue
            task_id = launch.task_arn.rsplit("/", 1)[-1]
            key = (
                f"{session.resource_map.evidence.app_prefix}{session.session_id}/{run.run_id}/"
                f"{run.gate_id}/{run.contributor_id}/{task_id}.json"
            )
            try:
                artifact = verifier.authenticate_output(
                    launch,
                    bucket=session.resource_map.evidence.bucket,
                    key=key,
                    role_arn=session.resource_map.service.application_role_arn,
                    expected_kms_key_arn=session.resource_map.evidence.kms_key_arn,
                    expected_bucket_owner=session.binding.account_id,
                    s3_client=session.clients.client("s3"),
                )
                # Envelope and writer authentication are sufficient to preserve
                # an independently measured negative if fact verification or
                # later deadline checks become incomplete.
                artifacts.append(artifact)
                try:
                    artifact_with_facts = verifier.attach_registered_facts(artifact)
                    artifacts[-1] = artifact_with_facts
                except EvidenceIncomplete as exc:
                    diagnostics.append(f"fact chain unavailable: {type(exc).__name__}")
            except EvidenceIncomplete as exc:
                diagnostics.append(f"output unavailable: {type(exc).__name__}")
                continue
            except (BotoCoreError, ClientError) as exc:
                diagnostics.append(f"output fetch failed: {type(exc).__name__}")
                continue
            except Exception as exc:
                diagnostics.append(f"output authentication failed: {type(exc).__name__}")
                continue
            if datetime.now(UTC) >= deadline:
                diagnostics.append("original qualification delivery deadline expired")
                break
    except Exception as exc:
        # A malformed later contender cannot erase artifacts authenticated earlier.
        diagnostics.append(f"contender authentication failed: {type(exc).__name__}")
    session._authentication_diagnostics[run_id] = tuple(diagnostics)
    return tuple(artifacts)
