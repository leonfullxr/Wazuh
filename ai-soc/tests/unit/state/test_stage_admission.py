from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import re
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, Protocol, cast
from uuid import uuid4

import pytest
from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
from botocore.exceptions import ClientError

from ai_soc.contracts.models import (
    EmbeddingGrant,
    ModelCountGrant,
    ReadOperationGrant,
    StageCapacityRejection,
)
from ai_soc.state.errors import StateFailure
from ai_soc.state.stage_admission import (
    DynamoEmbeddingAdmissionStore,
    DynamoModelCountAdmissionStore,
    DynamoReadAdmissionStore,
    MemoryEmbeddingAdmissionStore,
    MemoryModelCountAdmissionStore,
    MemoryReadAdmissionStore,
)

NOW = datetime(2026, 10, 3, 12, tzinfo=UTC)
ReadCall = Literal["mapping", "validate", "pit", "search", "probe"]
_CASE_FIXTURE = Path(__file__).parent / "data" / "stage_admission_cases.json"
_CASE_FIXTURE_SHA256 = hashlib.sha256(_CASE_FIXTURE.read_bytes()).hexdigest()
_CASE_REGISTRY = cast(dict[str, object], json.loads(_CASE_FIXTURE.read_text(encoding="utf-8")))


def _case_variant(name: str) -> dict[str, object]:
    variants = cast(dict[str, object], _CASE_REGISTRY["variants"])
    return cast(dict[str, object], variants[name])


def _assert_expression_values_are_used(action: dict[str, object]) -> None:
    operation = cast(dict[str, object], action.get("Update", action.get("Put", {})))
    expression = " ".join(
        str(operation.get(name, "")) for name in ("UpdateExpression", "ConditionExpression")
    )
    referenced = set(re.findall(r"(?<![A-Za-z0-9_]):[A-Za-z_][A-Za-z0-9_]*", expression))
    values = cast(dict[str, object], operation.get("ExpressionAttributeValues", {}))
    assert set(values) == referenced


class _Codec(Protocol):
    def serialize(self, value: object) -> object: ...
    def deserialize(self, value: object) -> object: ...


@pytest.mark.asyncio
async def test_memory_read_pool_is_site_isolated_bounded_and_fenced() -> None:
    store = MemoryReadAdmissionStore()
    question = uuid4()
    first_batch = await asyncio.gather(
        *(
            store.acquire(
                environment_id="alpha",
                question_id=question,
                operation_id=uuid4(),
                call="search",
                now=NOW,
            )
            for _ in range(9)
        )
    )
    grants = [item for item in first_batch if isinstance(item, ReadOperationGrant)]
    assert len(grants) == 8
    assert sum(isinstance(item, StageCapacityRejection) for item in first_batch) == 1

    beta = await store.acquire(
        environment_id="beta",
        question_id=uuid4(),
        operation_id=uuid4(),
        call="mapping",
        now=NOW,
    )
    assert isinstance(beta, ReadOperationGrant)

    first = grants[0]
    too_early = await store.acquire(
        environment_id="alpha",
        question_id=uuid4(),
        operation_id=uuid4(),
        call="pit",
        now=NOW + timedelta(seconds=44),
    )
    assert isinstance(too_early, StageCapacityRejection)
    recovered = await store.acquire(
        environment_id="alpha",
        question_id=uuid4(),
        operation_id=uuid4(),
        call="pit",
        now=NOW + timedelta(seconds=45),
    )
    assert isinstance(recovered, ReadOperationGrant)
    assert recovered.service_slot_id == first.service_slot_id
    assert recovered.fence > first.fence
    await store.release(first)
    current_holder = await store.acquire(
        environment_id="alpha",
        question_id=recovered.question_id,
        operation_id=recovered.operation_id,
        call="pit",
        now=NOW + timedelta(seconds=45),
    )
    assert current_holder == recovered
    await store.release(recovered)


@pytest.mark.asyncio
async def test_memory_shared_count_converse_pool_caps_site_and_service_independently() -> None:
    store = MemoryModelCountAdmissionStore()
    same_site = await asyncio.gather(
        *(
            store.acquire(
                environment_id="alpha",
                question_id=uuid4(),
                operation_id=uuid4(),
                call="count" if index % 2 == 0 else "converse",
                now=NOW,
            )
            for index in range(3)
        )
    )
    assert sum(isinstance(item, ModelCountGrant) for item in same_site) == 2
    assert sum(isinstance(item, StageCapacityRejection) for item in same_site) == 1

    grants = [item for item in same_site if isinstance(item, ModelCountGrant)]
    another_site = await asyncio.gather(
        *(
            store.acquire(
                environment_id=site,
                question_id=uuid4(),
                operation_id=uuid4(),
                call="converse",
                now=NOW,
            )
            for site in ("beta", "gamma", "delta")
            for _ in range(2)
        )
    )
    grants.extend(item for item in another_site if isinstance(item, ModelCountGrant))
    assert len(grants) == 8
    full = await store.acquire(
        environment_id="epsilon",
        question_id=uuid4(),
        operation_id=uuid4(),
        call="count",
        now=NOW,
    )
    assert isinstance(full, StageCapacityRejection)
    assert grants[0].hard_deadline_at - NOW == timedelta(seconds=5)
    assert next(
        grant for grant in grants if grant.call == "converse"
    ).hard_deadline_at - NOW == timedelta(seconds=30)


@pytest.mark.asyncio
async def test_memory_embedding_is_one_inflight_per_question_and_operation_is_idempotent() -> None:
    store = MemoryEmbeddingAdmissionStore()
    question = uuid4()
    operation = uuid4()
    first = await store.acquire(
        environment_id="alpha", question_id=question, operation_id=operation, now=NOW
    )
    assert isinstance(first, EmbeddingGrant)
    repeated = await store.acquire(
        environment_id="alpha", question_id=question, operation_id=operation, now=NOW
    )
    assert repeated == first
    blocked = await store.acquire(
        environment_id="alpha", question_id=question, operation_id=uuid4(), now=NOW
    )
    assert isinstance(blocked, StageCapacityRejection)

    independent = await store.acquire(
        environment_id="alpha", question_id=uuid4(), operation_id=uuid4(), now=NOW
    )
    assert isinstance(independent, EmbeddingGrant)
    await store.release(first)
    available = await store.acquire(
        environment_id="alpha", question_id=question, operation_id=uuid4(), now=NOW
    )
    assert isinstance(available, EmbeddingGrant)
    assert available.fence > first.fence
    with pytest.raises(StateFailure) as reused:
        await store.acquire(
            environment_id="alpha", question_id=question, operation_id=operation, now=NOW
        )
    assert reused.value.code == "IDEMPOTENCY_CONFLICT"


class AtomicDynamo:
    """Small transaction-aware fake that evaluates the emitted conditional request shape."""

    def __init__(self) -> None:
        self.serializer = cast(_Codec, TypeSerializer())
        self.deserializer = cast(_Codec, TypeDeserializer())
        self.items: dict[tuple[str, str], dict[str, object]] = {}
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.lock = threading.Lock()
        self.fail_after_commit = False

    def get_item(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("get_item", kwargs))
        assert kwargs.get("ConsistentRead") is True
        key = self._decode(cast(dict[str, object], kwargs["Key"]))
        primary = str(key["pk"])
        sort = str(key["sk"])
        with self.lock:
            item = self.items.get((primary, sort))
            return {"Item": self._encode(item)} if item is not None else {}

    def transact_write_items(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("transact_write_items", kwargs))
        actions = cast(list[dict[str, object]], kwargs["TransactItems"])
        with self.lock:
            updated = copy.deepcopy(self.items)
            for action in actions:
                if not self._apply_action(updated, action):
                    response = {
                        "Error": {
                            "Code": "TransactionCanceledException",
                            "Message": "conditional stage slot changed",
                        },
                        "CancellationReasons": [{"Code": "ConditionalCheckFailed"}],
                    }
                    raise ClientError(response, "TransactWriteItems")
            self.items = updated
        if self.fail_after_commit:
            self.fail_after_commit = False
            raise OSError("simulated lost transaction response")
        return {}

    def _apply_action(
        self, items: dict[tuple[str, str], dict[str, object]], action: dict[str, object]
    ) -> bool:
        if "Put" in action:
            put = cast(dict[str, object], action["Put"])
            item = self._decode(cast(dict[str, object], put["Item"]))
            key = (str(item["pk"]), str(item["sk"]))
            prior = items.get(key)
            values = self._decode(cast(dict[str, object], put.get("ExpressionAttributeValues", {})))
            condition = str(put.get("ConditionExpression", ""))
            if prior is not None and not (
                "expires_epoch <= :now" in condition
                and int(cast(int, prior.get("expires_epoch", 0))) <= int(cast(int, values[":now"]))
            ):
                return False
            items[key] = item
            return True

        update = cast(dict[str, object], action["Update"])
        key_value = self._decode(cast(dict[str, object], update["Key"]))
        key = (str(key_value["pk"]), str(key_value["sk"]))
        prior = items.get(key)
        values = self._decode(cast(dict[str, object], update.get("ExpressionAttributeValues", {})))
        condition = str(update.get("ConditionExpression", ""))
        names = cast(dict[str, str], update.get("ExpressionAttributeNames", {}))
        if condition == "attribute_not_exists(pk)":
            if prior is not None:
                return False
        elif "recover_after_epoch <= :now" in condition:
            if prior is None or int(cast(int, prior.get("fence", 0))) != int(
                cast(int, values[":previous"])
            ):
                return False
            if prior.get("holder_id") is not None and int(
                cast(int, prior.get("recover_after_epoch", 0))
            ) > int(cast(int, values[":now"])):
                return False
        elif "operation_id = :operation" in condition:
            if (
                prior is None
                or prior.get("holder_id") != values[":holder"]
                or prior.get("fence") != values[":fence"]
                or prior.get("operation_id") != values[":operation"]
            ):
                return False
        elif "#state = :active" in condition:
            state_key = names["#state"]
            if (
                prior is None
                or prior.get("holder_id") != values[":holder"]
                or prior.get("fence") != values[":fence"]
                or prior.get(state_key) != values[":active"]
            ):
                return False

        result = {} if prior is None else dict(prior)
        expression = str(update["UpdateExpression"])
        set_expression = (
            expression.split(" SET ", 1)[-1].removeprefix("SET ").split(" REMOVE ", 1)[0]
        )
        for assignment in set_expression.split(","):
            if "=" not in assignment:
                continue
            name, token = (part.strip() for part in assignment.split("=", 1))
            result[names.get(name, name)] = values[token]
        if " REMOVE " in expression:
            for name in expression.split(" REMOVE ", 1)[1].split(","):
                result.pop(names.get(name.strip(), name.strip()), None)
        items[key] = result
        return True

    def _encode(self, item: dict[str, object]) -> dict[str, object]:
        return {key: self.serializer.serialize(value) for key, value in item.items()}

    def _decode(self, item: dict[str, object]) -> dict[str, object]:
        return {key: self.deserializer.deserialize(value) for key, value in item.items()}


@pytest.mark.asyncio
@pytest.mark.acceptance("G044", "GN02")
@pytest.mark.case_id("QA-011.resolution")
@pytest.mark.variant("positive")
@pytest.mark.fixture_sha256(_CASE_FIXTURE_SHA256)
async def test_dynamo_read_pool_admits_exact_typed_physical_grant() -> None:
    fixture = _case_variant("positive")
    client = AtomicDynamo()
    store = DynamoReadAdmissionStore(client, "soc-state")
    grant = await store.acquire(
        environment_id=str(fixture["environment_id"]),
        question_id=uuid4(),
        operation_id=uuid4(),
        call=cast(ReadCall, fixture["call"]),
        now=NOW,
    )

    assert isinstance(grant, ReadOperationGrant)
    assert grant.call == fixture["call"]
    assert len([name for name, _ in client.calls if name == "transact_write_items"]) == 1


@pytest.mark.asyncio
async def test_first_stage_admission_transaction_has_no_unused_expression_values() -> None:
    client = AtomicDynamo()
    store = DynamoReadAdmissionStore(client, "soc-state")
    grant = await store.acquire(
        environment_id="alpha",
        question_id=uuid4(),
        operation_id=uuid4(),
        call="search",
        now=NOW,
    )
    assert isinstance(grant, ReadOperationGrant)
    transaction = next(params for name, params in client.calls if name == "transact_write_items")
    actions = cast(list[dict[str, object]], transaction["TransactItems"])
    for action in actions:
        _assert_expression_values_are_used(action)


@pytest.mark.asyncio
@pytest.mark.acceptance("G044", "GN02")
@pytest.mark.case_id("QA-011.resolution")
@pytest.mark.variant("negative")
@pytest.mark.fixture_sha256(_CASE_FIXTURE_SHA256)
async def test_dynamo_read_pool_rejects_the_ninth_request_for_one_site() -> None:
    fixture = _case_variant("negative")
    client = AtomicDynamo()
    store = DynamoReadAdmissionStore(client, "soc-state")
    results = [
        await store.acquire(
            environment_id=str(fixture["environment_id"]),
            question_id=uuid4(),
            operation_id=uuid4(),
            call=cast(ReadCall, fixture["call"]),
            now=NOW,
        )
        for _ in range(int(fixture["attempts"]))
    ]

    assert (
        sum(isinstance(item, ReadOperationGrant) for item in results) == fixture["expected_grants"]
    )
    rejected = [item for item in results if isinstance(item, StageCapacityRejection)]
    assert len(rejected) == fixture["expected_rejections"]
    assert all(item.call == "search" and item.code == "CAPACITY_LIMIT" for item in rejected)


@pytest.mark.asyncio
@pytest.mark.acceptance("G044", "GN02")
@pytest.mark.case_id("QA-011.resolution")
@pytest.mark.variant("failure")
@pytest.mark.fixture_sha256(_CASE_FIXTURE_SHA256)
async def test_dynamo_transaction_shape_release_and_ambiguous_commit() -> None:
    fixture = _case_variant("failure")
    client = AtomicDynamo()
    store = DynamoReadAdmissionStore(client, "soc-state")
    client.fail_after_commit = fixture["failure_mode"] == "transaction_committed_response_lost"
    question_id = uuid4()
    operation_id = uuid4()
    grant = await store.acquire(
        environment_id="alpha",
        question_id=question_id,
        operation_id=operation_id,
        call="search",
        now=NOW,
    )
    assert isinstance(grant, ReadOperationGrant)
    assert (
        await store.acquire(
            environment_id="alpha",
            question_id=question_id,
            operation_id=operation_id,
            call="search",
            now=NOW,
        )
        == grant
    )
    assert len([name for name, _ in client.calls if name == "transact_write_items"]) == int(
        fixture["expected_attempts"]
    )
    with pytest.raises(StateFailure) as reused:
        await store.acquire(
            environment_id="alpha",
            question_id=question_id,
            operation_id=operation_id,
            call="probe",
            now=NOW,
        )
    assert reused.value.code == "IDEMPOTENCY_CONFLICT"
    reads = [params for name, params in client.calls if name == "get_item"]
    assert reads and all(params["ConsistentRead"] is True for params in reads)
    transaction = next(params for name, params in client.calls if name == "transact_write_items")
    actions = cast(list[dict[str, object]], transaction["TransactItems"])
    assert len(actions) == 3
    updates = [cast(dict[str, object], action["Update"]) for action in actions[:2]]
    assert all(
        "recover_after_epoch <= :now" in str(item["ConditionExpression"])
        or "attribute_not_exists(pk)" == item["ConditionExpression"]
        for item in updates
    )
    operation_put = cast(dict[str, object], actions[2]["Put"])
    assert (
        operation_put["ConditionExpression"] == "attribute_not_exists(pk) OR expires_epoch <= :now"
    )

    await store.release(grant)
    release = [params for name, params in client.calls if name == "transact_write_items"][-1]
    release_updates = cast(list[dict[str, object]], release["TransactItems"])
    assert len(release_updates) == 3
    assert all(
        "holder_id = :holder AND fence = :fence"
        in str(cast(dict[str, object], item["Update"])["ConditionExpression"])
        for item in release_updates
    )


@pytest.mark.asyncio
async def test_dynamo_racing_model_count_calls_share_service_and_site_capacity() -> None:
    client = AtomicDynamo()
    store = DynamoModelCountAdmissionStore(client, "soc-state")
    results = await asyncio.gather(
        *(
            store.acquire(
                environment_id="alpha",
                question_id=uuid4(),
                operation_id=uuid4(),
                call="count" if index % 2 == 0 else "converse",
                now=NOW,
            )
            for index in range(3)
        )
    )
    grants = [item for item in results if isinstance(item, ModelCountGrant)]
    assert len(grants) == 2
    assert sum(isinstance(item, StageCapacityRejection) for item in results) == 1

    other_sites = await asyncio.gather(
        *(
            store.acquire(
                environment_id=site,
                question_id=uuid4(),
                operation_id=uuid4(),
                call="count",
                now=NOW,
            )
            for site in ("beta", "gamma", "delta")
            for _ in range(2)
        )
    )
    grants.extend(item for item in other_sites if isinstance(item, ModelCountGrant))
    assert len(grants) == 8
    service_slots = [key for key in client.items if key[0] == "STAGE#model-count#SERVICE"]
    assert len(service_slots) == 8
    full = await store.acquire(
        environment_id="epsilon",
        question_id=uuid4(),
        operation_id=uuid4(),
        call="converse",
        now=NOW,
    )
    assert isinstance(full, StageCapacityRejection)


@pytest.mark.asyncio
@pytest.mark.acceptance("G044", "GN02")
@pytest.mark.case_id("QA-011.resolution")
@pytest.mark.variant("boundary")
@pytest.mark.fixture_sha256(_CASE_FIXTURE_SHA256)
async def test_dynamo_read_pool_enforces_site_and_service_boundaries() -> None:
    fixture = _case_variant("boundary")
    client = AtomicDynamo()
    store = DynamoReadAdmissionStore(client, "soc-state")
    requests = [
        (environment, uuid4(), call)
        for environment, count in cast(dict[str, int], fixture["site_attempts"]).items()
        for index in range(count)
        for call in (("mapping", "validate", "pit", "search", "probe")[index % 5],)
    ]
    environment_by_operation = {
        operation_id: environment for environment, operation_id, _ in requests
    }

    results = [
        await store.acquire(
            environment_id=environment,
            question_id=uuid4(),
            operation_id=operation_id,
            call=call,
            now=NOW,
        )
        for environment, operation_id, call in requests
    ]

    grants = [item for item in results if isinstance(item, ReadOperationGrant)]
    rejections = [item for item in results if isinstance(item, StageCapacityRejection)]
    assert len(grants) == fixture["expected_grants"]
    assert len(rejections) == fixture["expected_rejections"]
    assert {environment_by_operation[item.operation_id] for item in rejections} == {
        "alpha",
        "delta",
    }
    assert all(item.code == "CAPACITY_LIMIT" and item.outcome == "capacity" for item in rejections)
    expected_site_grants = cast(dict[str, int], fixture["expected_site_grants"])
    assert len([key for key in client.items if key[0] == "STAGE#read#SERVICE"]) == int(
        fixture["expected_grants"]
    )
    for site, expected in expected_site_grants.items():
        actual = len([key for key in client.items if key[0] == f"STAGE#read#SITE#{site}"])
        assert actual == expected
    assert all(
        params["ConsistentRead"] is True for name, params in client.calls if name == "get_item"
    )


@pytest.mark.asyncio
async def test_dynamo_embedding_question_slot_only_recovers_after_hard_deadline_plus_grace() -> (
    None
):
    client = AtomicDynamo()
    store = DynamoEmbeddingAdmissionStore(client, "soc-state")
    question = uuid4()
    first = await store.acquire(
        environment_id="alpha", question_id=question, operation_id=uuid4(), now=NOW
    )
    assert isinstance(first, EmbeddingGrant)
    blocked = await store.acquire(
        environment_id="alpha", question_id=question, operation_id=uuid4(), now=NOW
    )
    assert isinstance(blocked, StageCapacityRejection)
    before_recovery = await store.acquire(
        environment_id="alpha",
        question_id=question,
        operation_id=uuid4(),
        now=NOW + timedelta(seconds=44),
    )
    assert isinstance(before_recovery, StageCapacityRejection)
    recovered = await store.acquire(
        environment_id="alpha",
        question_id=question,
        operation_id=uuid4(),
        now=NOW + timedelta(seconds=45),
    )
    assert isinstance(recovered, EmbeddingGrant)
    assert recovered.fence > first.fence
    await store.release(first)
    still_full = await store.acquire(
        environment_id="alpha",
        question_id=question,
        operation_id=uuid4(),
        now=NOW + timedelta(seconds=45),
    )
    assert isinstance(still_full, StageCapacityRejection)
    await store.release(recovered)


@pytest.mark.asyncio
async def test_dynamo_embedding_release_clears_the_allocated_question_slot() -> None:
    client = AtomicDynamo()
    store = DynamoEmbeddingAdmissionStore(client, "soc-state")
    question = uuid4()
    first = await store.acquire(
        environment_id="alpha", question_id=question, operation_id=uuid4(), now=NOW
    )
    assert isinstance(first, EmbeddingGrant)
    await store.release(first)

    retry = await store.acquire(
        environment_id="alpha",
        question_id=question,
        operation_id=uuid4(),
        now=NOW + timedelta(seconds=1),
    )

    assert isinstance(retry, EmbeddingGrant)
    slot_key = (f"STAGE#embedding#QUESTION#{question}", "SLOT#0")
    assert client.items[slot_key]["holder_id"] == str(retry.holder_id)
