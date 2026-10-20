from __future__ import annotations

from types import SimpleNamespace

import pytest

from scripts.staging import verifier as evidence_verifier
from scripts.staging.evaluators import evaluate_registered_artifacts
from scripts.staging.models import DeploymentBinding, GateId, ObligationStatus
from scripts.staging.verifier import (
    EvidenceIncomplete,
    LaunchExpectation,
    VerifiedArtifact,
    VerifiedFact,
    VerifiedFactChain,
    VerifiedLaunch,
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
        service_sha="a" * 40,
        content_sha="b" * 40,
        configuration_sha256="c" * 64,
    )


def _artifact(
    measurements: dict[str, object],
    *,
    gate_id: GateId = GateId.LV_STATE,
    binding: DeploymentBinding | None = None,
    fact_chain: VerifiedFactChain | None = None,
) -> VerifiedArtifact:
    binding = binding or _binding()
    expectation = LaunchExpectation(
        account_id=binding.account_id,
        region=binding.region,
        launcher_role_arn="arn:aws:iam::123456789012:role/qualification-launcher",
        cluster_arn=binding.cluster_arn,
        task_definition_arn=binding.task_definition_arn,
        started_by="00000000-0000-4000-8000-000000000003",
        client_token="token-a",
        session_id="00000000-0000-4000-8000-000000000001",
        invocation_id="00000000-0000-4000-8000-000000000002",
        run_id="00000000-0000-4000-8000-000000000003",
        gate_id=gate_id,
        contributor_id="state" if gate_id == GateId.LV_STATE else "mcp",
        slot=str(measurements.get("contender", "probe")),
        task_role_arn="arn:aws:iam::123456789012:role/application",
        binding=binding,
        deadline_utc="2026-10-08T12:10:00Z",
        launch_request_digest="f" * 64,
        required_request_fields=("cluster",),
    )
    task_arn = f"arn:aws:ecs:us-east-1:123456789012:task/prod/{'a' * 32}"
    launch = VerifiedLaunch(
        _seal=evidence_verifier._SEAL,
        expectation=expectation,
        task_arn=task_arn,
        request_id="request-1",
        event_id="event-1",
        event_digest="e" * 64,
        started_at="2026-10-08T12:00:00Z",
    )
    return VerifiedArtifact(
        _seal=evidence_verifier._SEAL,
        launch=launch,
        bucket="evidence",
        key="app/session/run/envelope.json",
        version_id="version-1",
        sha256="d" * 64,
        envelope=SimpleNamespace(measurements=measurements),
        event_id="output-event-1",
        event_digest="e" * 64,
        fact_chain=fact_chain,
    )


def test_mcp_pass_candidates_stay_not_run_without_authenticated_fact_chain() -> None:
    artifact = _artifact(
        {
            "official_client_flows": {"passed": True},
            "mcp_auth_negatives": {
                "cases": {
                    name: {"passed": True}
                    for name in (
                        "wrong_resource",
                        "wrong_issuer",
                        "wrong_scope",
                        "wrong_type",
                        "browser_cookie",
                        "origin",
                        "protocol_version",
                    )
                }
            },
            "frozen_output_parity": {"passed": True},
        },
        gate_id=GateId.LV_MCP,
    )
    evaluated = evaluate_registered_artifacts(
        gate_id=GateId.LV_MCP,
        contributor_id="mcp",
        artifacts=(artifact,),
        binding=_binding(),
    )

    assert all(row.status == ObligationStatus.NOT_RUN for row in evaluated.obligations)
    assert evaluated.verified_observations == ()


def test_state_requires_both_authenticated_contender_envelopes_and_fact_chains() -> None:
    artifacts = tuple(
        _artifact(
            {
                "contender": slot,
                "facts": {
                    "lease_acquired": slot == "A",
                    "lease_contended": slot == "B",
                    "stage_admission": True,
                    "stale_fence_rejected": True,
                    "recovery_terminalized": True,
                    "ambiguous_settlement_exactly_once": True,
                },
            }
        )
        for slot in ("A", "B")
    )
    chains = tuple(
        VerifiedFactChain(
            _seal=evidence_verifier._SEAL,
            launch=artifact.launch,
            facts=tuple(
                VerifiedFact(
                    fact_id=fact_id,
                    request_id=f"request-{fact_id}",
                    event_id=f"event-{fact_id}",
                    event_digest="a" * 64,
                    resource_arn="arn:aws:dynamodb:us-east-1:123456789012:table/state",
                    outcome="success",
                )
                for fact_id in (
                    "state_contender_a",
                    "state_contender_b",
                    "state_stage_admission",
                    "state_stale_fence",
                    "state_terminal_recovery",
                    "state_exactly_once_settlement",
                )
            ),
            chain_digest="b" * 64,
        )
        for artifact in artifacts
    )
    evaluated = evaluate_registered_artifacts(
        gate_id=GateId.LV_STATE,
        contributor_id="state",
        artifacts=artifacts,
        fact_chains=chains,
        binding=_binding(),
    )

    rows = {row.obligation_id: row for row in evaluated.obligations}
    assert rows["ddb_replica_transactions"].status == ObligationStatus.NOT_RUN
    assert rows["cancellation_recovery"].status == ObligationStatus.NOT_RUN
    assert rows["exactly_once_settlement"].status == ObligationStatus.NOT_RUN
    assert {item.obligation_id for item in evaluated.verified_observations}.isdisjoint(
        {"ddb_replica_transactions", "cancellation_recovery", "exactly_once_settlement"}
    )


def test_authenticated_state_negative_fails_while_unimplemented_positive_abstains() -> None:
    artifact = _artifact(
        {
            "contender": "A",
            "facts": {
                "lease_acquired": True,
                "stale_fence_rejected": False,
                "recovery_terminalized": True,
                "ambiguous_settlement_exactly_once": True,
            },
        }
    )

    evaluated = evaluate_registered_artifacts(
        gate_id=GateId.LV_STATE,
        contributor_id="state",
        artifacts=(artifact,),
        binding=_binding(),
    )

    rows = {row.obligation_id: row for row in evaluated.obligations}
    assert rows["cancellation_recovery"].status == ObligationStatus.FAIL
    assert rows["exactly_once_settlement"].status == ObligationStatus.NOT_RUN
    assert rows["ddb_replica_transactions"].status == ObligationStatus.NOT_RUN
    assert evaluated.verified_observations == ()


def test_evaluator_rejects_incomplete_artifact_set_without_certifying() -> None:
    evaluated = evaluate_registered_artifacts(
        gate_id=GateId.LV_STATE,
        contributor_id="state",
        artifacts=(),
        binding=_binding(),
    )

    assert len(evaluated.obligations) == 4
    assert all(row.status == ObligationStatus.NOT_RUN for row in evaluated.obligations)


def test_real_evaluator_rechecks_deadline_at_observation_mint() -> None:
    artifact = _artifact(
        {
            "official_client_flows": {"passed": True},
            "mcp_auth_negatives": {
                "cases": {
                    name: {"passed": True}
                    for name in (
                        "wrong_resource",
                        "wrong_issuer",
                        "wrong_scope",
                        "wrong_type",
                        "browser_cookie",
                        "origin",
                        "protocol_version",
                    )
                }
            },
            "frozen_output_parity": {"passed": True},
        },
        gate_id=GateId.LV_MCP,
    )
    chain = VerifiedFactChain(
        _seal=evidence_verifier._SEAL,
        launch=artifact.launch,
        facts=tuple(
            VerifiedFact(
                fact_id=fact_id,
                request_id=f"request-{fact_id}",
                event_id=f"event-{fact_id}",
                event_digest="a" * 64,
                resource_arn="arn:aws:execute-api:us-east-1:123456789012:api",
                outcome="success",
            )
            for fact_id in (
                "mcp_official_client_flows",
                "mcp_auth_negatives",
                "mcp_output_parity",
            )
        ),
        chain_digest="b" * 64,
    )
    deadline = 100.0
    clock = [99.0]

    def advance_across_deadline() -> None:
        clock[0] = 101.0
        if clock[0] >= deadline:
            raise EvidenceIncomplete("original qualification delivery deadline expired")

    with pytest.raises(EvidenceIncomplete, match="deadline expired"):
        evaluate_registered_artifacts(
            gate_id=GateId.LV_MCP,
            contributor_id="mcp",
            artifacts=(artifact,),
            fact_chains=(chain,),
            binding=_binding(),
            deadline_guard=advance_across_deadline,
        )
    assert clock[0] > deadline


def test_incomplete_state_reload_preserves_authenticated_failure() -> None:
    artifact = _artifact(
        {
            "contender": "A",
            "facts": {
                "lease_acquired": True,
                "stage_admission": False,
                "stale_fence_rejected": None,
                "recovery_terminalized": None,
                "ambiguous_settlement_exactly_once": None,
            },
        }
    )
    evaluated = evaluate_registered_artifacts(
        gate_id=GateId.LV_STATE,
        contributor_id="state",
        artifacts=(artifact,),
        binding=_binding(),
    )

    by_id = {row.obligation_id: row for row in evaluated.obligations}
    assert by_id["stage_admission"].status == ObligationStatus.FAIL
    assert by_id["ddb_replica_transactions"].status == ObligationStatus.NOT_RUN
