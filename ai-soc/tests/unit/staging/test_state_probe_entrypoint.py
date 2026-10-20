from __future__ import annotations

import asyncio
import json
from argparse import Namespace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import boto3
import pytest
from botocore.config import Config
from botocore.stub import Stubber

import ai_soc.qualification.state_probe as state_probe
from ai_soc.qualification.models import ProbeInvocationConfig, TaskLaunchConfig
from ai_soc.qualification.state_probe import ProbeInvocation
from scripts.staging.evaluators import _state_candidate_rows


def test_task_entrypoint_accepts_coordinator_uuid_config(monkeypatch) -> None:
    run_id = "a7cd5c57-2a2b-4c90-9d11-7689901b7777"
    binding = {
        "account_id": "123456789012",
        "region": "eu-central-1",
        "cluster_arn": "arn:aws:ecs:eu-central-1:123456789012:cluster/q",
        "service_arn": "arn:aws:ecs:eu-central-1:123456789012:service/q/app",
        "task_definition_arn": "arn:aws:ecs:eu-central-1:123456789012:task-definition/app:1",
        "deployment_name": "app",
        "deployment_id": "ecs-svc/1234567890123456789",
        "image_digest": "sha256:" + "a" * 64,
        "service_sha": "b" * 40,
        "content_sha": "c" * 40,
        "configuration_sha256": "d" * 64,
    }
    deadline = datetime.now(UTC) + timedelta(hours=2)
    config = TaskLaunchConfig(
        scenario=ProbeInvocationConfig(
            entrypoint="state",
            parameters={
                "inputs": {
                    "table_name": "qualification-state",
                    "evidence_bucket": "qualification-evidence",
                    "replica_kill_replacement": False,
                }
            },
            execution_seconds=120,
            collection_seconds=3600,
        ),
        binding=binding,
        run_id=run_id,
        session_id="0ceaa332-b703-4806-a9b9-abc6884561c1",
        invocation_id="c0029fc7-0f7e-47c5-89fe-01e271f65ed3",
        slot="A",
        deadline_utc=deadline,
    )
    monkeypatch.setenv("LV_STATE_PROBE_CONFIG", config.model_dump_json())
    monkeypatch.setenv("SOC_LV_STATE_EVIDENCE_BUCKET", "qualification-evidence")
    monkeypatch.setattr(
        state_probe,
        "load_sealed_document",
        lambda: SimpleNamespace(
            dynamodb_table="qualification-state",
            provenance=SimpleNamespace(service_sha="b" * 40),
        ),
    )
    monkeypatch.setattr(state_probe, "require_region", lambda: "eu-central-1")
    monkeypatch.setattr(state_probe, "_parse_args", lambda: Namespace(contender="A"))
    monkeypatch.setattr(
        state_probe,
        "task_arn_from_metadata",
        lambda: "arn:aws:ecs:eu-central-1:123456789012:task/q/abc",
    )
    monkeypatch.setattr(state_probe, "_TaskRoleClients", lambda *_args: object())
    captured = {}

    async def fake_run_state_probe(*, clients, invocation):
        captured["probe_id"] = invocation.probe_id
        captured["contender"] = invocation.contender
        return {"facts": {"stage_admission": False}}

    monkeypatch.setattr(state_probe, "run_state_probe", fake_run_state_probe)
    monkeypatch.setattr(
        state_probe,
        "emit_probe_envelope",
        lambda envelope, **_kwargs: captured.update(envelope=envelope),
    )

    assert state_probe.main() == 0
    assert captured["probe_id"] == run_id
    assert captured["contender"] == "A"
    assert captured["envelope"].run_id == run_id


def test_real_state_probe_rejects_invalid_coordinator_uuid_before_clients() -> None:
    class Clients:
        def client(self, _service: str):
            raise AssertionError("invalid coordinator UUID must fail before AWS clients")

    invocation = ProbeInvocation(
        probe_id="not-a-uuid",
        contender="A",
        task_arn="arn:aws:ecs:eu-central-1:123456789012:task/q/task",
        table_name="qualification-state",
        evidence_bucket="qualification-evidence",
        account_id="123456789012",
        service_sha="b" * 40,
    )
    with pytest.raises(ValueError, match="coordinator UUID"):
        asyncio.run(state_probe.run_state_probe(clients=Clients(), invocation=invocation))


def test_real_probe_report_keeps_negative_fact_when_partner_report_is_missing(monkeypatch) -> None:
    class Clients:
        def client(self, service: str):
            assert service in {"s3", "dynamodb"}
            return object()

    lease = SimpleNamespace(owner_key="owner", environment_id="env", question_id="question")

    class State:
        def __init__(self, *_args, **_kwargs):
            pass

        async def acquire_lease(self, **_kwargs):
            return lease

    async def fake_winner(**_kwargs):
        return {
            "stale_fence_rejected": False,
            "stage_admission": None,
            "ambiguous_settlement_exactly_once": None,
            "recovery_terminalized": None,
        }

    monkeypatch.setenv("SOC_LV_STATE_EVIDENCE_BUCKET", "qualification-evidence")
    monkeypatch.setattr(state_probe, "DynamoState", State)
    monkeypatch.setattr(state_probe, "_rendezvous", lambda *_args: None)
    monkeypatch.setattr(state_probe, "_publish_acquisition_and_wait", lambda *_args: None)
    monkeypatch.setattr(state_probe, "_run_winner", fake_winner)
    invocation = ProbeInvocation(
        probe_id="0ceaa332-b703-4806-a9b9-abc6884561c1",
        contender="A",
        task_arn="arn:aws:ecs:eu-central-1:123456789012:task/q/task",
        table_name="qualification-state",
        evidence_bucket="qualification-evidence",
        account_id="123456789012",
        service_sha="b" * 40,
    )

    report = asyncio.run(state_probe.run_state_probe(clients=Clients(), invocation=invocation))

    assert report["facts"]["stale_fence_rejected"] is False
    evaluated = _state_candidate_rows({"A": report["facts"]})
    assert evaluated["cancellation_recovery"][0] is False


def test_skipped_recovery_observation_remains_unobserved(monkeypatch) -> None:
    class State:
        def __init__(self):
            self.db = SimpleNamespace(transaction_calls=0, fail_next_transaction=False)
            self.leases = iter(
                (
                    SimpleNamespace(
                        owner_key="owner", environment_id="env", question_id="q", fence=2
                    ),
                    SimpleNamespace(
                        owner_key="recovery", environment_id="env", question_id="r", fence=1
                    ),
                )
            )
            self.reservations = iter(
                (
                    SimpleNamespace(reservation_id="settlement", recover_after=datetime.now(UTC)),
                    SimpleNamespace(reservation_id="recovery", recover_after=datetime.now(UTC)),
                )
            )

        async def release_lease(self, _lease):
            return None

        async def acquire_lease(self, **_kwargs):
            return next(self.leases)

        async def renew_lease(self, lease, **_kwargs):
            return lease

        async def open_budget(self, **_kwargs):
            return None

        async def reserve(self, **_kwargs):
            return next(self.reservations)

        async def mark_started(self, reservation, **_kwargs):
            return reservation

        async def settle(self, *_args, **_kwargs):
            self.db.transaction_calls += 1
            if self.db.fail_next_transaction:
                self.db.fail_next_transaction = False
                raise state_probe.ReadTimeoutError(endpoint_url="http://qualification.test")

        async def reconcile(self, **_kwargs):
            raise AssertionError("await_service_recovery skips the recovery observation")

    class Admission:
        async def acquire(self, **_kwargs):
            return SimpleNamespace(fence=1)

        async def release(self, _grant):
            return None

    class Clients:
        def client(self, _service):
            return object()

    state = State()
    monkeypatch.setattr(state_probe, "DynamoReadAdmissionStore", lambda *_args: Admission())
    monkeypatch.setattr(state_probe, "state_client_for_ambiguity", lambda _state: state.db)
    monkeypatch.setattr(
        state_probe,
        "_raw_item",
        lambda *_args: {
            "payload": json.dumps({"charged_tokens": 3, "reserved_tokens": 0, "state": "settled"})
        },
    )
    invocation = ProbeInvocation(
        probe_id="0ceaa332-b703-4806-a9b9-abc6884561c1",
        contender="A",
        task_arn="arn:aws:ecs:eu-central-1:123456789012:task/q/task",
        table_name="qualification-state",
        evidence_bucket="qualification-evidence",
        account_id="123456789012",
        service_sha="b" * 40,
        await_service_recovery=True,
    )
    lease = SimpleNamespace(owner_key="owner", environment_id="env", question_id="q", fence=1)

    report = asyncio.run(
        state_probe._run_winner(
            clients=Clients(),
            invocation=invocation,
            state=state,
            lease=lease,
            now=datetime.now(UTC),
        )
    )

    assert report["recovery_terminalized"] is None
    assert _state_candidate_rows({"A": report})["cancellation_recovery"][0] is None


def test_deadline_client_records_request_ids_from_botocore_response_shape() -> None:
    client = boto3.client(
        "dynamodb",
        region_name="eu-central-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    wrapped = state_probe._DeadlineClient(client, state_probe.time.monotonic() + 30, [])
    facts = wrapped._fact_requests
    token = state_probe._ACTIVE_FACT.set(("state_contender_a", facts))
    try:
        with Stubber(client) as stubber:
            stubber.add_response(
                "update_item",
                {"ResponseMetadata": {"RequestId": "request-from-botocore"}},
                {
                    "TableName": "qualification-state",
                    "Key": {"pk": {"S": "LEASE#owner#env"}, "sk": {"S": "ACTIVE"}},
                    "UpdateExpression": "SET #value = :value",
                    "ExpressionAttributeNames": {"#value": "value"},
                    "ExpressionAttributeValues": {":value": {"S": "x"}},
                },
            )
            wrapped.update_item(
                TableName="qualification-state",
                Key={"pk": {"S": "LEASE#owner#env"}, "sk": {"S": "ACTIVE"}},
                UpdateExpression="SET #value = :value",
                ExpressionAttributeNames={"#value": "value"},
                ExpressionAttributeValues={":value": {"S": "x"}},
            )
    finally:
        state_probe._ACTIVE_FACT.reset(token)
    assert facts == [
        {
            "fact_id": "state_contender_a",
            "operation": "UpdateItem",
            "request_id": "request-from-botocore",
        }
    ]
