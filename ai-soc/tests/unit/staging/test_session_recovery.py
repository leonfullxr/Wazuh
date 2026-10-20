from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import boto3
import pytest
from botocore.config import Config
from botocore.stub import Stubber

from ai_soc.qualification.models import ProbeInvocationConfig
from scripts.staging.attributed_probe import (
    QualificationJournal,
    QualificationSession,
    RunIntent,
)
from scripts.staging.journal import _journal_dict
from scripts.staging.models import (
    GateId,
)
from scripts.staging.verifier import EvidenceIncomplete
from tests.unit.staging.authenticated_evidence_support import mcp_probe_inputs
from tests.unit.staging.session_test_support import (
    _binding,
    make_run,
    make_session,
    make_task_observation,
)


def test_restart_reconciles_intent_and_keeps_launch_barrier_closed(tmp_path: Path) -> None:
    binding = _binding()
    ecs = boto3.client(
        "ecs",
        region_name=binding.region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )

    class Clients:
        def client(self, service_name: str):
            assert service_name == "ecs"
            return ecs

    with Stubber(ecs) as stubber:
        stubber.add_response(
            "list_tasks",
            {"taskArns": []},
            {"cluster": binding.cluster_arn},
        )
        first = QualificationSession.open(Clients(), binding, journal_root=tmp_path)
        intent = first.record_intent(
            gate_id=GateId.LV_STATE,
            contributor_id="state",
            slots=("A", "B"),
            deadline_utc=(datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        )
        first.close()
        stubber.add_response(
            "list_tasks",
            {"taskArns": []},
            {"cluster": binding.cluster_arn, "startedBy": intent.started_by},
        )

        resumed = QualificationSession.open(Clients(), binding, journal_root=tmp_path)
        try:
            assert not resumed.launch_allowed
            with pytest.raises(RuntimeError, match="qualification run identity"):
                resumed.require_launch_allowed()
        finally:
            resumed.close()


@pytest.mark.parametrize(
    "describe_response",
    [
        {
            "tasks": [],
            "failures": [
                {
                    "arn": "arn:aws:ecs:eu-central-1:123456789012:task/q/x",
                    "reason": "MISSING",
                }
            ],
        },
        {"tasks": [], "failures": []},
    ],
    ids=("describe-failure", "omitted-task"),
)
def test_initial_recovery_closes_barrier_when_task_discovery_is_incomplete(
    tmp_path: Path, describe_response: dict[str, object]
) -> None:
    binding = _binding()
    ecs = boto3.client(
        "ecs",
        region_name=binding.region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )

    class Clients:
        def client(self, service_name: str):
            assert service_name == "ecs"
            return ecs

    task_arn = "arn:aws:ecs:eu-central-1:123456789012:task/q/x"
    with Stubber(ecs) as stubber:
        stubber.add_response(
            "list_tasks", {"taskArns": [task_arn]}, {"cluster": binding.cluster_arn}
        )
        stubber.add_response(
            "describe_tasks",
            describe_response,
            {"cluster": binding.cluster_arn, "tasks": [task_arn], "include": ["TAGS"]},
        )
        session = make_session(Clients(), binding, tmp_path)
        try:
            assert not session.launch_allowed
            assert session._journal.session_fault == (
                "active qualification task discovery is incomplete or ambiguous"
            )
            assert session._journal.barrier_reason == session._journal.session_fault
        finally:
            session.close()


def test_reconcile_cleanup_reopen_keeps_discovered_unowned_identity_barrier(
    tmp_path: Path, monkeypatch
) -> None:
    binding = _binding()
    session_id = str(UUID(int=70))
    invocation_id = str(UUID(int=71))
    run_id = str(UUID(int=72))
    known_arn = f"arn:aws:ecs:{binding.region}:{binding.account_id}:task/q/known"
    stray_arn = f"arn:aws:ecs:{binding.region}:{binding.account_id}:task/q/stray"
    run = make_run(
        invocation_id=invocation_id,
        run_id=run_id,
        gate_id=GateId.LV_MCP,
        contributor_id="mcp",
        slots=("probe",),
        task_arns=(known_arn,),
        discovered_arns=(stray_arn,),
        deadline_utc=(datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        state="stopped",
    )
    journal = QualificationJournal(
        schema_version=7,
        account_id=binding.account_id,
        region=binding.region,
        cluster_arn=binding.cluster_arn,
        session_id=session_id,
        binding=binding,
        runs=(run,),
        session_expires_at=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    )
    cluster_hash = hashlib.sha256(binding.cluster_arn.encode()).hexdigest()[:24]
    path = tmp_path / binding.account_id / binding.region / f"{cluster_hash}.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(_journal_dict(journal)))
    path.with_suffix(".known").write_text("qualification journal initialized\n")

    ecs = boto3.client(
        "ecs",
        region_name=binding.region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    clients = type("Clients", (), {"client": lambda self, name: ecs})()
    monkeypatch.setattr(QualificationSession, "_stop_owned_tasks", lambda *_args, **_kwargs: True)

    def task(arn: str, slot: str, status: str) -> dict[str, object]:
        return make_task_observation(
            binding_value=binding,
            arn=arn,
            run_id=run_id,
            session_id=session_id,
            invocation_id=invocation_id,
            gate_id=GateId.LV_MCP,
            contributor_id="mcp",
            slot=slot,
            status=status,
        )

    with Stubber(ecs) as stubber:
        for _ in range(2):
            stubber.add_response(
                "list_tasks",
                {"taskArns": [stray_arn]},
                {"cluster": binding.cluster_arn, "startedBy": run_id},
            )
            stubber.add_response(
                "describe_tasks",
                {
                    "tasks": [
                        task(known_arn, "probe", "STOPPED"),
                        task(stray_arn, "unexpected", "STOPPED"),
                    ],
                    "failures": [],
                },
                {
                    "cluster": binding.cluster_arn,
                    "tasks": [known_arn, stray_arn],
                    "include": ["TAGS"],
                },
            )
        first = QualificationSession.open(clients, binding, journal_root=tmp_path)
        assert not first.launch_allowed
        assert first._journal.runs[0].state == "ambiguous"
        first.close()

        reopened = QualificationSession.open(clients, binding, journal_root=tmp_path)
        try:
            assert not reopened.launch_allowed
            assert reopened._journal.runs[0].state == "ambiguous"
            assert stray_arn in reopened._journal.runs[0].discovered_arns
        finally:
            reopened.close()


@pytest.mark.parametrize("already_stopped", (False, True), ids=("live", "stopped"))
def test_restart_reconciles_live_and_terminal_tasks_with_authenticated_ownership(
    tmp_path: Path, already_stopped: bool
) -> None:
    binding = _binding()
    session_id = str(UUID(int=40))
    invocation_id = str(UUID(int=41))
    run_id = str(UUID(int=42))
    task_arn = f"arn:aws:ecs:{binding.region}:{binding.account_id}:task/q/live"
    token = str(UUID(int=43))
    run = RunIntent(
        invocation_id=invocation_id,
        run_id=run_id,
        started_by=run_id,
        client_tokens=(token,),
        gate_id=GateId.LV_MCP.value,
        contributor_id="mcp",
        task_slots=("probe",),
        task_arns=(task_arn,),
        probe_spec=ProbeInvocationConfig(
            entrypoint="mcp",
            parameters={"inputs": mcp_probe_inputs().model_dump(mode="json")},
            execution_seconds=30,
            collection_seconds=60,
        ),
        launch_requests=({"overrides": {"containerOverrides": [{"name": "ai-soc"}]}},),
        deadline_utc=(datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        state="launched",
    )
    journal = QualificationJournal(
        schema_version=7,
        account_id=binding.account_id,
        region=binding.region,
        cluster_arn=binding.cluster_arn,
        session_id=session_id,
        binding=binding,
        runs=(run,),
        session_expires_at=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    )
    cluster_hash = hashlib.sha256(binding.cluster_arn.encode()).hexdigest()[:24]
    path = tmp_path / binding.account_id / binding.region / f"{cluster_hash}.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(_journal_dict(journal)))
    path.with_suffix(".known").write_text("qualification journal initialized\n")

    class ECS:
        def __init__(self) -> None:
            self.stopped = [task_arn] if already_stopped else []
            self.stop_calls = 0

        def get_paginator(self, operation: str):
            assert operation == "list_tasks"

            class Paginator:
                def paginate(self, **kwargs):
                    assert kwargs == {"cluster": binding.cluster_arn, "startedBy": run_id}
                    return [{"taskArns": [task_arn]}]

            return Paginator()

        def describe_tasks(self, *, tasks: list[str], **_kwargs):
            assert tasks == [task_arn]
            owned = {
                "taskArn": task_arn,
                "clusterArn": binding.cluster_arn,
                "taskDefinitionArn": binding.task_definition_arn,
                "startedBy": run_id,
                "lastStatus": "STOPPED" if task_arn in self.stopped else "RUNNING",
                "tags": [
                    {"key": key, "value": value}
                    for key, value in {
                        "qualification": "true",
                        "qualification-session": session_id,
                        "qualification-invocation": invocation_id,
                        "qualification-run": run_id,
                        "qualification-gate": GateId.LV_MCP.value,
                        "qualification-contributor": "mcp",
                        "qualification-slot": "probe",
                    }.items()
                ],
            }
            return {"tasks": [owned], "failures": []}

        def stop_task(self, *, task: str, **_kwargs):
            self.stop_calls += 1
            self.stopped.append(task)
            return {}

    ecs = ECS()
    clients = type("Clients", (), {"client": lambda self, _name: ecs})()
    changed_binding = replace(binding, deployment_id="ecs-svc/9876543210987654321")
    with QualificationSession.open(clients, changed_binding, journal_root=tmp_path) as resumed:
        assert resumed._journal.runs == ()
        assert resumed._journal.binding == changed_binding
        assert resumed.launch_allowed
    assert ecs.stopped == [task_arn]
    assert ecs.stop_calls == (0 if already_stopped else 1)


def test_resume_invocation_requires_exact_journaled_stopped_run(tmp_path: Path) -> None:
    binding = _binding()
    ecs = boto3.client(
        "ecs",
        region_name=binding.region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )

    class Clients:
        def client(self, service_name: str):
            assert service_name == "ecs"
            return ecs

    with Stubber(ecs) as stubber:
        stubber.add_response("list_tasks", {"taskArns": []}, {"cluster": binding.cluster_arn})
        session = QualificationSession.open(Clients(), binding, journal_root=tmp_path)
        try:
            intent = session.record_intent(
                gate_id=GateId.LV_STATE,
                contributor_id="state",
                slots=("A", "B"),
                deadline_utc=(datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
            )
            stopped = replace(
                intent,
                state="stopped",
                task_arns=(
                    f"arn:aws:ecs:{binding.region}:{binding.account_id}:task/q/a",
                    f"arn:aws:ecs:{binding.region}:{binding.account_id}:task/q/b",
                ),
            )
            session._replace_run(stopped)
            with pytest.raises(EvidenceIncomplete, match="delivery measurement"):
                session.resume_invocation(
                    session_id=session.session_id,
                    invocation_id=intent.invocation_id,
                    run_ids=(intent.run_id,),
                )
            with pytest.raises(ValueError, match="foreign run"):
                session.resume_invocation(
                    session_id=session.session_id,
                    invocation_id=intent.invocation_id,
                    run_ids=(str(UUID(int=100)),),
                )
            with pytest.raises(ValueError, match="unique nonempty"):
                session.resume_invocation(
                    session_id=session.session_id,
                    invocation_id=intent.invocation_id,
                    run_ids=(),
                )
        finally:
            session.close()
