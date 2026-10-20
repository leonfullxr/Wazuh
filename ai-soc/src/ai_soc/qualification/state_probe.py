"""Bounded LV-STATE probe command for explicit one-off ECS task overrides."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import time
from collections.abc import Callable
from contextlib import AbstractContextManager, contextmanager, nullcontext
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any, Protocol, cast
from urllib.request import urlopen
from uuid import UUID, uuid4

import boto3
from boto3.dynamodb.types import TypeDeserializer
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, ReadTimeoutError

from ai_soc.contracts.models import ErrorCode
from ai_soc.live.env import load_sealed_document, require_region
from ai_soc.qualification.binding import DeploymentBinding
from ai_soc.qualification.evidence import ProbeEnvelope, emit_probe_envelope
from ai_soc.qualification.models import StateTaskProbeConfig
from ai_soc.qualification.task_runtime import execution_deadline, load_task_config
from ai_soc.state.dynamodb import DynamoClient, DynamoState
from ai_soc.state.errors import StateFailure
from ai_soc.state.stage_admission import DynamoReadAdmissionStore

PROBE_EVIDENCE_ROOT = "qualification/lv-state"
_RENDEZVOUS_SECONDS = 180
_MAX_WAIT_SECONDS = 5
_ACTIVE_FACT: ContextVar[tuple[str, list[dict[str, str]]] | None] = ContextVar(
    "lv_state_active_fact", default=None
)


class ProbeClientFactory(Protocol):
    def client(self, service_name: str) -> Any: ...


class _Credentials(Protocol):
    @property
    def method(self) -> str: ...


class _BotoSession(Protocol):
    def get_credentials(self) -> _Credentials | None: ...
    def client(self, service_name: str, *, region_name: str, config: Config) -> object: ...


class _Deserializer(Protocol):
    def deserialize(self, value: object) -> object: ...


@dataclass(frozen=True, slots=True)
class ProbeInvocation:
    probe_id: str
    contender: str
    task_arn: str
    table_name: str
    evidence_bucket: str
    account_id: str
    service_sha: str
    await_service_recovery: bool = False


class _Clock:
    def now(self) -> datetime:
        return datetime.now(UTC).replace(microsecond=0)

    def monotonic(self) -> float:
        return time.monotonic()


class _TaskRoleClients:
    """Build clients with the ECS task role resolved by the SDK provider chain."""

    def __init__(self, region: str, deadline: float) -> None:
        self._region = region
        self._deadline = deadline
        self._session = cast(_BotoSession, boto3.Session(region_name=region))
        self.fact_requests: list[dict[str, str]] = []
        credentials = self._session.get_credentials()
        if credentials is None or credentials.method != "container-role":
            raise RuntimeError("LV-STATE probe requires ECS task-role credentials")

    def client(self, service_name: str) -> Any:
        client = self._session.client(
            service_name,
            region_name=self._region,
            config=Config(
                connect_timeout=5,
                read_timeout=5,
                retries={"total_max_attempts": 1, "mode": "standard"},
            ),
        )
        return _DeadlineClient(client, self._deadline, self.fact_requests)

    @contextmanager
    def fact_scope(self, fact_id: str):
        token = _ACTIVE_FACT.set((fact_id, self.fact_requests))
        try:
            yield
        finally:
            _ACTIVE_FACT.reset(token)


def _response_field(value: object, key: str) -> object:
    return cast(dict[str, object], value).get(key) if isinstance(value, dict) else None


class _DeadlineClient:
    def __init__(self, client: Any, deadline: float, fact_requests: list[dict[str, str]]) -> None:
        self._client = client
        self._deadline = deadline
        self._fact_requests = fact_requests

    def __getattr__(self, name: str) -> Any:
        value = getattr(self._client, name)
        if not callable(value):
            return value

        def bounded(*args: Any, **kwargs: Any) -> Any:
            if time.monotonic() >= self._deadline:
                raise TimeoutError("state qualification execution deadline expired")
            active = _ACTIVE_FACT.get()
            try:
                response = value(*args, **kwargs)
            except Exception as exc:
                self._record_fact(name, active, getattr(exc, "response", None))
                raise
            self._record_fact(name, active, response)
            if time.monotonic() >= self._deadline:
                raise TimeoutError("state qualification execution deadline expired")
            return response

        return bounded

    def _record_fact(
        self, operation: str, active: tuple[str, list[dict[str, str]]] | None, response: object
    ) -> None:
        if active is None or operation not in {"update_item", "transact_write_items"}:
            return
        fact_id, collector = active
        if collector is not self._fact_requests:
            return
        metadata = _response_field(response, "ResponseMetadata")
        request_id = _response_field(metadata, "RequestId")
        if isinstance(request_id, str) and request_id:
            self._fact_requests.append(
                {
                    "fact_id": fact_id,
                    "operation": "UpdateItem"
                    if operation == "update_item"
                    else "TransactWriteItems",
                    "request_id": request_id,
                }
            )


class _AmbiguousOnce:
    def __init__(self, client: DynamoClient) -> None:
        self._client = client
        self.fail_next_transaction = False
        self.transaction_calls = 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)

    def get_item(self, **kwargs: object) -> dict[str, object]:
        return self._client.get_item(**kwargs)

    def put_item(self, **kwargs: object) -> dict[str, object]:
        return self._client.put_item(**kwargs)

    def update_item(self, **kwargs: object) -> dict[str, object]:
        return self._client.update_item(**kwargs)

    def transact_write_items(self, **kwargs: object) -> dict[str, object]:
        self.transaction_calls += 1
        response = self._client.transact_write_items(**kwargs)
        if self.fail_next_transaction:
            self.fail_next_transaction = False
            raise ReadTimeoutError(endpoint_url="http://ambiguous-state-probe.local")
        return response

    def query(self, **kwargs: object) -> dict[str, object]:
        return self._client.query(**kwargs)


def _fact_scope(clients: ProbeClientFactory, fact_id: str) -> AbstractContextManager[None]:
    scope = getattr(clients, "fact_scope", None)
    if callable(scope):
        typed_scope = cast(Callable[[str], AbstractContextManager[None]], scope)
        return typed_scope(fact_id)
    return nullcontext()


def task_arn_from_metadata() -> str:
    endpoint = os.environ.get("ECS_CONTAINER_METADATA_URI_V4")
    if not endpoint:
        raise ValueError("ECS task metadata endpoint is required")
    with urlopen(f"{endpoint.rstrip('/')}/task", timeout=2) as response:
        payload: object = json.loads(response.read())
    task_arn = _response_field(payload, "TaskARN")
    if not isinstance(task_arn, str) or not task_arn.startswith("arn:"):
        raise ValueError("ECS task metadata did not return a task ARN")
    return task_arn


def _probe_prefix(invocation: ProbeInvocation) -> str:
    return f"{PROBE_EVIDENCE_ROOT}/{invocation.service_sha}/{invocation.probe_id}"


def _barrier_key(invocation: ProbeInvocation, contender: str) -> str:
    return f"{_probe_prefix(invocation)}/barrier/{contender}"


def _acquisition_key(invocation: ProbeInvocation, contender: str) -> str:
    return f"{_probe_prefix(invocation)}/acquisition/{contender}.json"


def result_key(invocation: ProbeInvocation) -> str:
    task_segment = quote_task_arn(invocation.task_arn)
    return f"{_probe_prefix(invocation)}/results/{task_segment}.json"


def quote_task_arn(value: str) -> str:
    return value.replace("%", "%25").replace(":", "%3A").replace("/", "%2F")


def _rendezvous(s3: Any, invocation: ProbeInvocation) -> None:
    other = "B" if invocation.contender == "A" else "A"
    body = json.dumps(
        {"probe_id": invocation.probe_id, "contender": invocation.contender},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    s3.put_object(
        Bucket=invocation.evidence_bucket,
        Key=_barrier_key(invocation, invocation.contender),
        Body=body,
        ContentType="application/json",
        IfNoneMatch="*",
        ExpectedBucketOwner=invocation.account_id,
    )
    deadline = time.monotonic() + _RENDEZVOUS_SECONDS
    while time.monotonic() < deadline:
        try:
            s3.head_object(
                Bucket=invocation.evidence_bucket,
                Key=_barrier_key(invocation, other),
                ExpectedBucketOwner=invocation.account_id,
            )
            return
        except ClientError as exc:
            response = cast(dict[str, object], exc.response)
            error = cast(dict[str, object], response.get("Error", {}))
            if str(error.get("Code", "")) not in {"404", "NoSuchKey", "NotFound"}:
                raise
        time.sleep(0.25)
    raise TimeoutError("paired qualification task did not reach the rendezvous")


def _publish_acquisition_and_wait(s3: Any, invocation: ProbeInvocation, acquired: bool) -> None:
    other = "B" if invocation.contender == "A" else "A"
    s3.put_object(
        Bucket=invocation.evidence_bucket,
        Key=_acquisition_key(invocation, invocation.contender),
        Body=json.dumps(
            {"probe_id": invocation.probe_id, "acquired": acquired},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8"),
        ContentType="application/json",
        IfNoneMatch="*",
        ExpectedBucketOwner=invocation.account_id,
    )
    deadline = time.monotonic() + _RENDEZVOUS_SECONDS
    while time.monotonic() < deadline:
        try:
            s3.head_object(
                Bucket=invocation.evidence_bucket,
                Key=_acquisition_key(invocation, other),
                ExpectedBucketOwner=invocation.account_id,
            )
            return
        except ClientError as exc:
            response = cast(dict[str, object], exc.response)
            error = cast(dict[str, object], response.get("Error", {}))
            if str(error.get("Code", "")) not in {"404", "NoSuchKey", "NotFound"}:
                raise
        time.sleep(0.25)
    raise TimeoutError("paired qualification task did not publish its lease outcome")


def _raw_item(client: Any, table_name: str, pk: str, sk: str) -> dict[str, object] | None:
    response = client.get_item(
        TableName=table_name,
        Key={"pk": {"S": pk}, "sk": {"S": sk}},
        ConsistentRead=True,
    )
    raw = response.get("Item")
    if not isinstance(raw, dict):
        return None
    deserializer = cast(_Deserializer, TypeDeserializer())
    return {
        key: deserializer.deserialize(value) for key, value in cast(dict[str, object], raw).items()
    }


async def _run_winner(
    *,
    clients: ProbeClientFactory,
    invocation: ProbeInvocation,
    state: DynamoState,
    lease: Any,
    now: datetime,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "stale_fence_rejected": False,
        "stage_admission": False,
        "ambiguous_settlement_exactly_once": False,
        "recovery_terminalized": None,
        "pending_recovery": None,
    }
    owner = lease.owner_key
    environment = lease.environment_id
    question_id = lease.question_id

    with _fact_scope(clients, "state_stale_fence"):
        await state.release_lease(lease)
        replacement_lease = await state.acquire_lease(
            owner_key=owner,
            environment_id=environment,
            question_id=question_id,
            holder_id=uuid4(),
            now=now + timedelta(seconds=1),
        )
        await state.release_lease(lease)
        replacement_lease = await state.renew_lease(
            replacement_lease, now=now + timedelta(seconds=2)
        )
    result["stale_fence_rejected"] = replacement_lease.fence > lease.fence

    admission = DynamoReadAdmissionStore(
        cast(DynamoClient, clients.client("dynamodb")), invocation.table_name
    )
    with _fact_scope(clients, "state_stage_admission"):
        admission_grant = await admission.acquire(
            environment_id=environment,
            question_id=question_id,
            operation_id=uuid4(),
            call="probe",
            now=now + timedelta(seconds=2),
        )
    admission_granted = hasattr(admission_grant, "fence")
    # One grant only proves that one request can acquire a slot; it does not
    # establish service or site maxima. Keep a denial as a concrete failure,
    # and abstain after a successful single grant until a saturation drill is
    # registered.
    result["stage_admission"] = False if not admission_granted else None
    if admission_granted:
        with _fact_scope(clients, "state_stage_admission"):
            await admission.release(cast(Any, admission_grant))

    working_now = now + timedelta(seconds=3)
    budget_operation_id = uuid4()
    await state.open_budget(
        question_id=question_id,
        owner_key=owner,
        environment_id=environment,
        token_limit=9,
        expires_at=working_now + timedelta(hours=1),
        lease=replacement_lease,
        operation_id=budget_operation_id,
    )
    reservation = await state.reserve(
        question_id=question_id,
        topic_id="lv-state-probe",
        tokens=7,
        lease=replacement_lease,
        operation_id=uuid4(),
        now=working_now,
        owner_daily_limit=1_000_000,
        service_daily_limit=1_000_000,
    )
    started = await state.mark_started(
        reservation,
        lease=replacement_lease,
        operation_id=uuid4(),
        now=working_now,
    )

    settlement_id = uuid4()
    dynamodb = state_client_for_ambiguity(state)
    before_calls = dynamodb.transaction_calls
    dynamodb.fail_next_transaction = True
    ambiguous_response_observed = False
    with _fact_scope(clients, "state_exactly_once_settlement"):
        try:
            await state.settle(
                started,
                charged_tokens=3,
                lease=replacement_lease,
                operation_id=settlement_id,
                now=working_now,
            )
        except BotoCoreError:
            ambiguous_response_observed = True
        await state.settle(
            started,
            charged_tokens=3,
            lease=replacement_lease,
            operation_id=settlement_id,
            now=working_now,
        )
    settlement_request_count = dynamodb.transaction_calls - before_calls
    budget_row = _raw_item(
        clients.client("dynamodb"),
        invocation.table_name,
        f"QUESTION#{question_id}",
        "BUDGET",
    )
    budget_payload: dict[str, object] = json.loads(str(budget_row["payload"])) if budget_row else {}
    reservation_row = _raw_item(
        clients.client("dynamodb"),
        invocation.table_name,
        f"QUESTION#{question_id}",
        f"RESERVATION#{reservation.reservation_id}",
    )
    reservation_payload: dict[str, object] = (
        json.loads(str(reservation_row["payload"])) if reservation_row else {}
    )
    result["ambiguous_settlement_exactly_once"] = bool(
        ambiguous_response_observed
        and settlement_request_count == 1
        and budget_payload.get("charged_tokens") == 3
        and budget_payload.get("reserved_tokens") == 0
        and reservation_payload.get("state") == "settled"
        and reservation_payload.get("charged_tokens") == 3
    )
    result["settlement_transaction_calls"] = settlement_request_count
    result["settled_charged_tokens"] = budget_payload.get("charged_tokens")
    result["settled_reservation_state"] = reservation_payload.get("state")

    recovery_owner = sha256(f"{invocation.probe_id}:recovery".encode()).hexdigest()
    recovery_question = uuid4()
    recovery_lease = await state.acquire_lease(
        owner_key=recovery_owner,
        environment_id=environment,
        question_id=recovery_question,
        holder_id=uuid4(),
        now=working_now,
    )
    await state.open_budget(
        question_id=recovery_question,
        owner_key=recovery_owner,
        environment_id=environment,
        token_limit=11,
        expires_at=working_now + timedelta(hours=1),
        lease=recovery_lease,
        operation_id=uuid4(),
    )
    pending = await state.reserve(
        question_id=recovery_question,
        topic_id="lv-state-recovery-probe",
        tokens=5,
        lease=recovery_lease,
        operation_id=uuid4(),
        now=working_now,
        owner_daily_limit=1_000_000,
        service_daily_limit=1_000_000,
    )
    await state.release_lease(recovery_lease)
    result["pending_recovery"] = {
        "question_id": str(recovery_question),
        "reservation_id": str(pending.reservation_id),
        "owner_key": recovery_owner,
        "environment_id": environment,
        "due_at": pending.recover_after.isoformat(),
        "due_bucket": (int(pending.recover_after.timestamp()) // 30) % 128,
    }
    if not invocation.await_service_recovery:
        with _fact_scope(clients, "state_terminal_recovery"):
            page = await state.reconcile(
                now=pending.recover_after + timedelta(seconds=1),
                bucket=(int(pending.recover_after.timestamp()) // 30) % 128,
                question_id=recovery_question,
                reservation_id=pending.reservation_id,
            )
        if page.examined == 1 and page.after is None and not page.errors:
            recovered_row = _raw_item(
                clients.client("dynamodb"),
                invocation.table_name,
                f"QUESTION#{recovery_question}",
                f"RESERVATION#{pending.reservation_id}",
            )
            recovered: dict[str, object] = (
                json.loads(str(recovered_row["payload"])) if recovered_row else {}
            )
            result["recovery_terminalized"] = bool(
                page.terminalized == 1 and recovered.get("state") == "released"
            )
            result["recovery_terminal_state"] = recovered.get("state")
    return result


def state_client_for_ambiguity(state: DynamoState) -> _AmbiguousOnce:
    """Return the explicitly supplied DynamoDB client used by this probe state."""
    return cast(_AmbiguousOnce, cast(Any, state)._client)


async def run_state_probe(
    *, clients: ProbeClientFactory, invocation: ProbeInvocation
) -> dict[str, Any]:
    if invocation.contender not in {"A", "B"}:
        raise ValueError("contender must be A or B")
    try:
        UUID(invocation.probe_id)
    except (ValueError, AttributeError) as exc:
        raise ValueError("probe_id must be a coordinator UUID") from exc
    if not invocation.task_arn.startswith("arn:"):
        raise ValueError("task_arn must be an ARN")
    if invocation.evidence_bucket != os.environ.get("SOC_LV_STATE_EVIDENCE_BUCKET"):
        raise ValueError("evidence bucket does not match the deployed task configuration")

    s3 = clients.client("s3")
    _rendezvous(s3, invocation)
    now = _Clock().now()
    owner_key = sha256(f"qualification:{invocation.probe_id}".encode()).hexdigest()
    environment_id = "lv-state-qualification"
    question_id = UUID(invocation.probe_id)
    state_client = _AmbiguousOnce(cast(DynamoClient, clients.client("dynamodb")))
    state = DynamoState(state_client, invocation.table_name, clock=_Clock())
    facts: dict[str, Any] = {
        "lease_acquired": False,
        "lease_contended": False,
        "stale_fence_rejected": None,
        "stage_admission": None,
        "ambiguous_settlement_exactly_once": None,
        "recovery_terminalized": None,
        "pending_recovery": None,
    }
    lease = None
    try:
        with _fact_scope(clients, f"state_contender_{invocation.contender.lower()}"):
            lease = await state.acquire_lease(
                owner_key=owner_key,
                environment_id=environment_id,
                question_id=question_id,
                holder_id=uuid4(),
                now=now,
            )
        facts["lease_acquired"] = True
    except StateFailure as exc:
        if exc.code != ErrorCode.BUSY:
            raise
        facts["lease_contended"] = True

    _publish_acquisition_and_wait(s3, invocation, lease is not None)

    if lease is not None:
        winner_facts = await _run_winner(
            clients=clients,
            invocation=invocation,
            state=state,
            lease=lease,
            now=now,
        )
        facts.update(winner_facts)

    report = {
        "schema_version": 1,
        "probe_id": invocation.probe_id,
        "task_arn": invocation.task_arn,
        "table_name": invocation.table_name,
        "contender": invocation.contender,
        "checked_at": datetime.now(UTC).isoformat(),
        "facts": facts,
    }
    return report


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe-id")
    parser.add_argument("--contender", choices=("A", "B"), required=True)
    parser.add_argument("--evidence-bucket")
    parser.add_argument("--account-id")
    parser.add_argument("--service-sha")
    parser.add_argument("--await-service-recovery", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    raw_config = os.environ.get("LV_STATE_PROBE_CONFIG")
    if not raw_config:
        raise RuntimeError("qualification task configuration is unavailable")
    config = load_task_config(raw_config, entrypoint="state")
    if not isinstance(config.scenario.parameters, StateTaskProbeConfig):
        raise ValueError("state qualification scenario is invalid")
    sealed = load_sealed_document()
    bucket = os.environ.get("SOC_LV_STATE_EVIDENCE_BUCKET")
    input_data = config.scenario.parameters.inputs
    if input_data.table_name != sealed.dynamodb_table:
        raise ValueError("state table input differs from the deployed sealed table")
    evidence_bucket = input_data.evidence_bucket
    if bucket != evidence_bucket:
        raise ValueError("probe evidence bucket differs from deployed task configuration")
    if config.binding.service_sha != sealed.provenance.service_sha:
        raise ValueError("probe service SHA differs from sealed provenance")
    binding: DeploymentBinding = config.binding
    run_id = str(config.run_id)
    session_id = str(config.session_id)
    invocation_id = str(config.invocation_id)
    recovery = input_data.replica_kill_replacement
    if args.contender != config.slot:
        raise ValueError("qualification contender differs from its launch slot")
    task_arn = task_arn_from_metadata()
    invocation = ProbeInvocation(
        probe_id=run_id,
        contender=args.contender,
        task_arn=task_arn,
        table_name=input_data.table_name,
        evidence_bucket=evidence_bucket,
        account_id=binding.account_id,
        service_sha=binding.service_sha,
        await_service_recovery=recovery,
    )
    execution_budget, deadline = execution_deadline(config)
    clients = _TaskRoleClients(require_region(), deadline)
    started = datetime.now(UTC)
    report = asyncio.run(
        asyncio.wait_for(
            run_state_probe(clients=clients, invocation=invocation), timeout=execution_budget
        )
    )
    if time.monotonic() >= deadline:
        raise TimeoutError("state qualification execution deadline expired")
    completed = datetime.now(UTC)
    scenario = json.dumps(
        input_data.model_dump(mode="json"), allow_nan=False, sort_keys=True, separators=(",", ":")
    )
    envelope = ProbeEnvelope(
        schema_version=1,
        session_id=session_id,
        invocation_id=invocation_id,
        run_id=run_id,
        gate_id="LV-STATE",
        contributor_id="state",
        binding=binding,
        scenario_sha256=hashlib.sha256(scenario.encode()).hexdigest(),
        started_at=started,
        completed_at=completed,
        measurements={
            "contender": args.contender,
            "facts": report.get("facts", {}),
            "fact_requests": list(getattr(clients, "fact_requests", ())),
        },
    )
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("state qualification execution deadline expired")
    emit_probe_envelope(envelope, timeout_seconds=min(10.0, remaining))
    if time.monotonic() >= deadline:
        raise TimeoutError("state qualification execution deadline expired")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
