from __future__ import annotations

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
from scripts.staging.models import (
    GateId,
)
from scripts.staging.qualification_context import QualificationContext
from tests.unit.staging.authenticated_evidence_support import mcp_probe_inputs
from tests.unit.staging.session_test_support import _binding


def test_coordinator_root_is_absolute_and_shared_across_checkouts(
    tmp_path: Path, monkeypatch
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

    coordinator = tmp_path / "shared-coordinator"
    checkout_a = tmp_path / "checkout-a"
    checkout_b = tmp_path / "checkout-b"
    checkout_a.mkdir()
    checkout_b.mkdir()
    monkeypatch.delenv("AI_SOC_QUALIFICATION_JOURNAL_ROOT", raising=False)
    with pytest.raises(RuntimeError, match="must name the shared absolute coordinator root"):
        QualificationSession.open(Clients(), binding)
    monkeypatch.setenv("AI_SOC_QUALIFICATION_JOURNAL_ROOT", str(coordinator))
    with Stubber(ecs) as stubber:
        stubber.add_response("list_tasks", {"taskArns": []}, {"cluster": binding.cluster_arn})
        monkeypatch.chdir(checkout_a)
        first = QualificationSession.open(Clients(), binding)
        first_id, first_path = first.session_id, first.path
        first.close()
        monkeypatch.chdir(checkout_b)
        second = QualificationSession.open(Clients(), binding)
        try:
            assert second.session_id == first_id
            assert second.path == first_path
            assert second.path.is_relative_to(coordinator)
        finally:
            second.close()


def test_cleanup_stops_only_tasks_with_positive_run_ownership(tmp_path: Path) -> None:
    binding = _binding()
    session_id = str(UUID(int=20))
    invocation_id = str(UUID(int=21))
    run_id = str(UUID(int=22))
    owned_arn = f"arn:aws:ecs:{binding.region}:{binding.account_id}:task/q/owned"
    foreign_arn = f"arn:aws:ecs:{binding.region}:{binding.account_id}:task/q/foreign"

    def task(arn: str, *, owned: bool, stopped: bool = False) -> dict[str, object]:
        return {
            "taskArn": arn,
            "clusterArn": binding.cluster_arn,
            "taskDefinitionArn": (
                binding.task_definition_arn
                if owned
                else binding.task_definition_arn.replace(":7", ":8")
            ),
            "startedBy": run_id,
            "tags": [
                {"key": "qualification", "value": "true"},
                {"key": "qualification-session", "value": session_id},
                {"key": "qualification-invocation", "value": invocation_id},
                {"key": "qualification-run", "value": run_id},
                {"key": "qualification-gate", "value": GateId.LV_MCP.value},
                {"key": "qualification-contributor", "value": "mcp"},
                {"key": "qualification-slot", "value": "probe"},
            ],
            "lastStatus": "STOPPED" if stopped else "RUNNING",
        }

    class ECS:
        stopped: list[str] = []

        def describe_tasks(self, *, tasks: list[str], **_kwargs):
            if set(tasks) == {owned_arn, foreign_arn}:
                return {"tasks": [task(owned_arn, owned=True), task(foreign_arn, owned=False)]}
            return {"tasks": [task(owned_arn, owned=True, stopped=owned_arn in self.stopped)]}

        def stop_task(self, *, task: str, **_kwargs):
            self.stopped.append(task)
            return {}

    ecs = ECS()
    session = object.__new__(QualificationSession)
    session.clients = type("Clients", (), {"client": lambda self, _name: ecs})()
    session.binding = binding
    session.session_id = session_id
    session.path = tmp_path / "journal.json"
    run = RunIntent(
        invocation_id=invocation_id,
        run_id=run_id,
        started_by=run_id,
        client_tokens=(str(UUID(int=23)),),
        gate_id=GateId.LV_MCP.value,
        contributor_id="mcp",
        task_slots=("probe",),
        task_arns=(foreign_arn, owned_arn),
        probe_spec=None,
        launch_requests=(),
        deadline_utc=(datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        state="ambiguous",
    )
    session._journal = QualificationJournal(
        schema_version=7,
        account_id=binding.account_id,
        region=binding.region,
        cluster_arn=binding.cluster_arn,
        session_id=session_id,
        binding=binding,
        runs=(run,),
        session_expires_at=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    )
    session._persist = lambda **_kwargs: (_ for _ in ()).throw(ValueError("journal full"))

    assert not session.stop_and_wait(run_id, timeout_seconds=1)
    assert ecs.stopped == [owned_arn]


def test_partial_launch_cleanup_keeps_barrier_closed_after_known_task_stops(
    tmp_path: Path,
) -> None:
    binding = _binding()
    session_id = str(UUID(int=24))
    invocation_id = str(UUID(int=25))
    run_id = str(UUID(int=26))
    task_arn = f"arn:aws:ecs:{binding.region}:{binding.account_id}:task/q/partial"
    run = RunIntent(
        invocation_id=invocation_id,
        run_id=run_id,
        started_by=run_id,
        client_tokens=(str(UUID(int=27)), str(UUID(int=28))),
        gate_id=GateId.LV_STATE.value,
        contributor_id="state",
        task_slots=("A", "B"),
        task_arns=(task_arn,),
        probe_spec=None,
        launch_requests=(),
        deadline_utc=(datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        state="ambiguous",
    )

    class ECS:
        stopped = False

        def describe_tasks(self, *, tasks: list[str], **_kwargs):
            assert tasks == [task_arn]
            return {
                "tasks": [
                    {
                        "taskArn": task_arn,
                        "clusterArn": binding.cluster_arn,
                        "taskDefinitionArn": binding.task_definition_arn,
                        "startedBy": run_id,
                        "lastStatus": "STOPPED" if self.stopped else "RUNNING",
                        "tags": [
                            {"key": key, "value": value}
                            for key, value in {
                                "qualification": "true",
                                "qualification-session": session_id,
                                "qualification-invocation": invocation_id,
                                "qualification-run": run_id,
                                "qualification-gate": GateId.LV_STATE.value,
                                "qualification-contributor": "state",
                                "qualification-slot": "A",
                            }.items()
                        ],
                    }
                ],
                "failures": [],
            }

        def stop_task(self, *, task: str, **_kwargs):
            assert task == task_arn
            self.stopped = True
            return {}

    ecs = ECS()
    session = object.__new__(QualificationSession)
    session.clients = type("Clients", (), {"client": lambda self, _name: ecs})()
    session.binding = binding
    session.session_id = session_id
    session.path = tmp_path / "journal.json"
    session._journal = QualificationJournal(
        schema_version=7,
        account_id=binding.account_id,
        region=binding.region,
        cluster_arn=binding.cluster_arn,
        session_id=session_id,
        binding=binding,
        runs=(run,),
        session_expires_at=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    )
    session._persist = lambda **_kwargs: None

    assert not session.stop_and_wait(run_id, timeout_seconds=1)
    assert ecs.stopped
    assert session._journal.runs[0].state == "ambiguous"
    assert session._journal.barrier_reason
    assert not session.launch_allowed


@pytest.mark.parametrize(
    ("exit_code", "timeout"),
    ((0, False), (1, False), (0, True)),
    ids=("success", "failed-container", "deadline"),
)
def test_completion_and_failure_cleanup_record_terminal_run(
    tmp_path: Path, exit_code: int, timeout: bool
) -> None:
    binding = _binding()
    session_id = str(UUID(int=34))
    invocation_id = str(UUID(int=35))
    run_id = str(UUID(int=36))
    task_arn = f"arn:aws:ecs:{binding.region}:{binding.account_id}:task/q/completed"
    request = {
        "overrides": {"containerOverrides": [{"name": "ai-soc", "command": [], "environment": []}]}
    }
    run = RunIntent(
        invocation_id=invocation_id,
        run_id=run_id,
        started_by=run_id,
        client_tokens=(str(UUID(int=37)),),
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
        launch_requests=(request,),
        deadline_utc=(
            datetime.now(UTC) - timedelta(seconds=1)
            if timeout
            else datetime.now(UTC) + timedelta(minutes=5)
        ).isoformat(),
        state="launched",
    )

    class ECS:
        stopped = False

        def describe_tasks(self, *, tasks: list[str], **_kwargs):
            assert tasks == [task_arn]
            return {
                "tasks": [
                    {
                        "taskArn": task_arn,
                        "clusterArn": binding.cluster_arn,
                        "taskDefinitionArn": binding.task_definition_arn,
                        "startedBy": run_id,
                        "lastStatus": "STOPPED" if self.stopped or not timeout else "RUNNING",
                        "overrides": request["overrides"],
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
                        "containers": [
                            {
                                "name": "ai-soc",
                                "imageDigest": binding.image_digest,
                                "exitCode": exit_code,
                            }
                        ],
                    }
                ],
                "failures": [],
            }

        def stop_task(self, **_kwargs):
            if not timeout:
                raise AssertionError("already completed task must not be stopped")
            self.stopped = True
            return {}

    ecs = ECS()
    session = object.__new__(QualificationSession)
    session.clients = type("Clients", (), {"client": lambda self, _name: ecs})()
    session.binding = binding
    session.session_id = session_id
    session.path = tmp_path / "journal.json"
    session._journal = QualificationJournal(
        schema_version=7,
        account_id=binding.account_id,
        region=binding.region,
        cluster_arn=binding.cluster_arn,
        session_id=session_id,
        binding=binding,
        runs=(run,),
        session_expires_at=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    )
    session._persist = lambda **_kwargs: None

    if timeout:
        with pytest.raises(TimeoutError, match="execution deadline expired"):
            session.wait_for_completion(run_id)
    elif exit_code == 0:
        completed = session.wait_for_completion(run_id)
        assert completed[0].task_arn == task_arn
        assert completed[0].exit_code == 0
    else:
        with pytest.raises(RuntimeError, match="container did not exit 0"):
            session.wait_for_completion(run_id)
    assert session._journal.runs[0].state == "stopped"
    assert session._journal.barrier_reason is None


def test_runtime_binding_allows_only_name_only_sidecar_overrides() -> None:
    binding = _binding()
    session_id = str(UUID(int=30))
    invocation_id = str(UUID(int=31))
    run_id = str(UUID(int=32))
    session = object.__new__(QualificationSession)
    session.binding = binding
    session.session_id = session_id
    app_override = {
        "name": "ai-soc",
        "command": ["python", "-m", "ai_soc.qualification.mcp_probe"],
        "environment": [{"name": "LV_MCP_PROBE_CONFIG", "value": "{}"}],
    }
    run = RunIntent(
        invocation_id=invocation_id,
        run_id=run_id,
        started_by=run_id,
        client_tokens=(str(UUID(int=33)),),
        gate_id=GateId.LV_MCP.value,
        contributor_id="mcp",
        task_slots=("probe",),
        task_arns=(),
        probe_spec=None,
        launch_requests=({"overrides": {"containerOverrides": [app_override]}},),
        deadline_utc=(datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        state="launched",
    )
    tags = [
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
    ]
    observed = {
        "taskArn": "arn:aws:ecs:eu-central-1:123456789012:task/q/probe",
        "clusterArn": binding.cluster_arn,
        "taskDefinitionArn": binding.task_definition_arn,
        "startedBy": run_id,
        "tags": tags,
        "containers": [{"name": "ai-soc", "imageDigest": binding.image_digest}],
        "overrides": {"containerOverrides": [app_override, {"name": "adot-collector"}]},
    }

    assert session._task_runtime_binding(observed, run)
    observed["overrides"]["containerOverrides"][1]["command"] = ["unexpected"]
    assert not session._task_runtime_binding(observed, run)


def test_qualification_client_blocks_legacy_ecs_launch_and_cleanup() -> None:
    class ECS:
        def describe_tasks(self, **kwargs):
            return kwargs

        def run_task(self, **kwargs):
            raise AssertionError("legacy launch must not reach AWS")

    class Delegate:
        def client(self, service_name: str):
            assert service_name == "ecs"
            return ECS()

    guarded = QualificationContext(Delegate(), object(), None, False).client("ecs")
    assert guarded.describe_tasks(cluster="cluster") == {"cluster": "cluster"}
    with pytest.raises(RuntimeError, match="qualification coordinator"):
        guarded.run_task(cluster="cluster")
    with pytest.raises(RuntimeError, match="qualification coordinator"):
        guarded.stop_task(cluster="cluster", task="task")
