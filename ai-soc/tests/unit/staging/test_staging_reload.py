from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import scripts.staging.reload as reload_core
from ai_soc.qualification.models import ProbeInvocationConfig
from scripts.staging.attributed_probe import QualificationSession
from scripts.staging.models import (
    DeploymentBinding,
    EvidenceKind,
    EvidenceReference,
    GateId,
    LiveGateResult,
    ObligationResult,
    ObligationStatus,
    QualificationReceipt,
)
from scripts.staging.registry import GATE_REGISTRY
from scripts.staging.verifier import (
    _SEAL,
    EvidenceIncomplete,
    VerifiedFact,
    VerifiedFactChain,
)
from tests.unit.staging.authenticated_evidence_support import mcp_probe_inputs
from tests.unit.staging.test_registered_evaluators import _artifact


def _binding(**overrides: str | None) -> DeploymentBinding:
    values: dict[str, str | None] = {
        "account_id": "123456789012",
        "region": "eu-central-1",
        "cluster_arn": "arn:aws:ecs:eu-central-1:123456789012:cluster/qualification",
        "service_arn": "arn:aws:ecs:eu-central-1:123456789012:service/qualification/app",
        "task_definition_arn": "arn:aws:ecs:eu-central-1:123456789012:task-definition/app:7",
        "deployment_name": "app",
        "deployment_id": "ecs-svc/1234567890123456789",
        "image_digest": "a" * 64,
        "service_sha": "b" * 40,
        "content_sha": "c" * 40,
        "configuration_sha256": "d" * 64,
    }
    values.update(overrides)
    return DeploymentBinding(**values)  # type: ignore[arg-type]


def _result(binding: DeploymentBinding) -> LiveGateResult:
    obligations = tuple(
        ObligationResult(
            item.obligation_id,
            ObligationStatus.PASS,
            "saved result",
            (EvidenceReference(EvidenceKind.S3_VERSION, "s3://bucket/key?versionId=v1"),),
        )
        for item in GATE_REGISTRY[GateId.LV_MCP].obligations
    )
    return LiveGateResult(
        gate_id=GateId.LV_MCP,
        owners=("owner",),
        inputs_manifest_sha256="e" * 64,
        service_sha="b" * 40,
        content_sha="c" * 40,
        artifact_digest="f" * 64,
        status="PASS",
        commands=(),
        results={"contributors": {"mcp": {"reason": "probe pending"}}},
        evidence_refs=tuple(ref for row in obligations for ref in row.evidence_refs),
        checked_at="2026-10-08T00:00:00+00:00",
        binding=binding,
        expected_binding=binding,
        obligations=obligations,
        qualification_receipts=(
            QualificationReceipt(
                session_id="00000000-0000-4000-8000-000000000001",
                invocation_id="00000000-0000-4000-8000-000000000002",
                run_id="00000000-0000-4000-8000-000000000003",
                started_by="qualification-session",
                gate_id=GateId.LV_MCP,
                contributor_id="mcp",
                task_slots=("probe",),
                task_arns=("arn:aws:ecs:eu-central-1:123456789012:task/q/task",),
                deadline_utc="2026-10-13T12:00:00Z",
                probe_spec=ProbeInvocationConfig(
                    entrypoint="mcp",
                    parameters={"inputs": mcp_probe_inputs().model_dump(mode="json")},
                    execution_seconds=60,
                    collection_seconds=90,
                ),
                launch_requests=(),
                state="stopped",
            ),
        ),
    )


def test_reload_reauthenticates_caller_run_and_recomputes_saved_pass(
    monkeypatch, tmp_path: Path
) -> None:
    binding = _binding()
    observed = iter((None,))

    class Observer:
        qualification_launcher_role_arn = "role"

        def observe_deployment(self):
            return next(observed)

        def qualification_map_pin(self, actual):
            assert actual == binding
            return "sealed-pin"

    class Session:
        closed = False
        resumed = None
        authenticated = []
        artifact = object()

        def resume_invocation(self, **kwargs):
            self.resumed = kwargs
            return (SimpleNamespace(run_id="00000000-0000-4000-8000-000000000003"),)

        def authenticate_run(self, run_id):
            self.authenticated.append(run_id)
            return (self.artifact,)

        def require_run_deadlines(self, run_ids):
            assert run_ids == ("00000000-0000-4000-8000-000000000003",)

        def run_diagnostics(self, run_id):
            assert run_id == "00000000-0000-4000-8000-000000000003"
            return ("output fetch failed: ClientError",)

        def close(self):
            self.closed = True

    session = Session()
    evaluated_artifacts = []
    configured = SimpleNamespace(
        observer=Observer(),
        clients=SimpleNamespace(client=lambda name: object()),
    )
    monkeypatch.setattr(
        reload_core, "load_aws_client_config", lambda _: SimpleNamespace(role_arn="role")
    )
    monkeypatch.setattr(reload_core, "build_explicit_staging_aws", lambda _: configured)
    monkeypatch.setattr(
        reload_core,
        "observe_deployment_snapshot",
        lambda _observer, actual: SimpleNamespace(
            binding=actual,
            sealed_document=SimpleNamespace(qualification="sealed-pin"),
        ),
    )
    monkeypatch.setattr(reload_core, "load_pinned_resource_map", lambda *_args, **_kwargs: "map")
    monkeypatch.setattr(
        QualificationSession,
        "open",
        lambda *args, **kwargs: session,
    )

    @dataclass
    class Evaluation:
        obligations: tuple[ObligationResult, ...]
        verified_observations: tuple[object, ...]

    def evaluate(**kwargs):
        evaluated_artifacts.extend(kwargs["artifacts"])
        return Evaluation(
            obligations=tuple(
                ObligationResult(
                    item.obligation_id,
                    ObligationStatus.PASS,
                    "fresh evidence",
                )
                for item in GATE_REGISTRY[GateId.LV_MCP].obligations
            ),
            verified_observations=(),
        )

    monkeypatch.setattr(reload_core, "evaluate_registered_artifacts", evaluate)

    refreshed = reload_core.reload_qualification(
        (_result(binding),),
        clients_config=tmp_path / "clients.json",
        session_id="00000000-0000-4000-8000-000000000001",
        invocation_id="00000000-0000-4000-8000-000000000002",
        run_ids=("00000000-0000-4000-8000-000000000003",),
    )

    assert session.resumed == {
        "session_id": "00000000-0000-4000-8000-000000000001",
        "invocation_id": "00000000-0000-4000-8000-000000000002",
        "run_ids": ("00000000-0000-4000-8000-000000000003",),
    }
    assert session.authenticated == ["00000000-0000-4000-8000-000000000003"]
    assert session.closed
    assert evaluated_artifacts == [session.artifact]
    assert refreshed[0].status == "NOT_RUN"
    assert refreshed[0].results["reload"] == "reload evidence rejected"
    assert all(row.status == ObligationStatus.NOT_RUN for row in refreshed[0].obligations)
    assert refreshed[0].results["reload_diagnostics"] == ["output fetch failed: ClientError"]
    assert all(row.status == ObligationStatus.NOT_RUN for row in refreshed[0].obligations)


def test_reload_abstains_when_final_observation_crosses_original_deadline(
    monkeypatch, tmp_path: Path
) -> None:
    binding = _binding()
    run_id = "00000000-0000-4000-8000-000000000003"
    now = [0.0]
    deadline = 1.0
    artifact = _artifact(
        {
            "official_client_flows": {"passed": True},
            "mcp_auth_negatives": {
                "cases": {
                    name: {"passed": name != "wrong_resource"}
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
        binding=binding,
    )
    chain = VerifiedFactChain(
        _seal=_SEAL,
        launch=artifact.launch,
        facts=tuple(
            VerifiedFact(
                fact_id=fact_id,
                request_id=f"request-{fact_id}",
                event_id=f"event-{fact_id}",
                event_digest="a" * 64,
                resource_arn="arn:aws:execute-api:eu-central-1:123456789012:api",
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
    artifact = artifact.__class__(
        _seal=_SEAL,
        launch=artifact.launch,
        bucket=artifact.bucket,
        key=artifact.key,
        version_id=artifact.version_id,
        sha256=artifact.sha256,
        envelope=artifact.envelope,
        event_id=artifact.event_id,
        event_digest=artifact.event_digest,
        fact_chain=chain,
    )

    class Observer:
        observations = 0
        qualification_launcher_role_arn = "role"

        def observe_deployment(self):
            self.observations += 1
            if self.observations == 2:
                now[0] = deadline + 1
            return binding

        def qualification_map_pin(self, actual):
            assert actual == binding
            return "sealed-pin"

    class Session:
        closed = False

        def resume_invocation(self, **kwargs):
            return (SimpleNamespace(run_id=run_id),)

        def authenticate_run(self, actual_run_id):
            assert actual_run_id == run_id
            return (artifact,)

        def require_run_deadlines(self, run_ids):
            assert run_ids == (run_id,)
            if now[0] >= deadline:
                raise EvidenceIncomplete("original qualification delivery deadline expired")

        def run_diagnostics(self, _run_id):
            return ()

        def close(self):
            self.closed = True

    session = Session()
    configured = SimpleNamespace(
        observer=Observer(),
        clients=SimpleNamespace(client=lambda name: object()),
    )
    monkeypatch.setattr(
        reload_core, "load_aws_client_config", lambda _: SimpleNamespace(role_arn="role")
    )
    monkeypatch.setattr(reload_core, "build_explicit_staging_aws", lambda _: configured)
    monkeypatch.setattr(
        reload_core,
        "observe_deployment_snapshot",
        lambda _observer, actual: (
            now.__setitem__(0, deadline + 1)
            or SimpleNamespace(
                binding=actual,
                sealed_document=SimpleNamespace(qualification="sealed-pin"),
            )
        ),
    )
    monkeypatch.setattr(reload_core, "load_pinned_resource_map", lambda *_args, **_kwargs: "map")
    monkeypatch.setattr(
        QualificationSession,
        "open",
        lambda *args, **kwargs: session,
    )

    refreshed = reload_core.reload_qualification(
        (_result(binding),),
        clients_config=tmp_path / "clients.json",
        session_id="00000000-0000-4000-8000-000000000001",
        invocation_id="00000000-0000-4000-8000-000000000002",
        run_ids=(run_id,),
    )

    assert now[0] > deadline
    assert session.closed
    assert refreshed[0].status == "FAIL"
    rows = {row.obligation_id: row for row in refreshed[0].obligations}
    assert rows["mcp_auth_negatives"].status == ObligationStatus.FAIL
    assert rows["mcp_auth_negatives"].evidence_refs
    assert rows["official_client_flows"].status == ObligationStatus.NOT_RUN
    assert rows["frozen_output_parity"].status == ObligationStatus.NOT_RUN
    assert refreshed[0].verified_observations == ()
