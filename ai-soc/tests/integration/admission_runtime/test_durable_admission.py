from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from conftest import DynamoFixture

from ai_soc.contracts.models import (
    EmbeddingGrant,
    ModelCountGrant,
    StageCapacityRejection,
)
from ai_soc.state.errors import StateFailure
from ai_soc.state.stage_admission import (
    DynamoEmbeddingAdmissionStore,
    DynamoModelCountAdmissionStore,
)


@pytest.mark.asyncio
async def test_two_durable_replicas_enforce_site_limit_and_observe_release(
    dynamo_fixture: DynamoFixture,
) -> None:
    first, second = dynamo_fixture.clients
    replica_a = DynamoModelCountAdmissionStore(first, dynamo_fixture.table)
    replica_b = DynamoModelCountAdmissionStore(second, dynamo_fixture.table)
    now = datetime.now(UTC).replace(microsecond=0)
    question = uuid4()
    try:
        first_grant = await replica_a.acquire(
            environment_id="alpha",
            question_id=question,
            operation_id=uuid4(),
            call="count",
            now=now,
        )
    except StateFailure as error:
        request = next(
            params
            for operation, params in reversed(dynamo_fixture.calls)
            if operation == "TransactWriteItems"
        )
        pytest.fail(
            f"actual TransactWriteItems failed: {error}; "
            f"request={json.dumps(request, sort_keys=True)}; "
            f"response={json.dumps(dynamo_fixture.responses[-1][1], sort_keys=True)}"
        )
    second_grant = await replica_b.acquire(
        environment_id="alpha",
        question_id=question,
        operation_id=uuid4(),
        call="converse",
        now=now,
    )
    blocked = await replica_a.acquire(
        environment_id="alpha",
        question_id=question,
        operation_id=uuid4(),
        call="count",
        now=now,
    )
    other_site = await replica_b.acquire(
        environment_id="bravo",
        question_id=uuid4(),
        operation_id=uuid4(),
        call="count",
        now=now,
    )

    assert isinstance(first_grant, ModelCountGrant)
    assert isinstance(second_grant, ModelCountGrant)
    assert isinstance(blocked, StageCapacityRejection)
    assert blocked.call == "count" and blocked.question_id == question
    assert isinstance(other_site, ModelCountGrant)
    assert other_site.environment_id == "bravo"

    await replica_b.release(first_grant)
    after_release = await replica_b.acquire(
        environment_id="alpha",
        question_id=question,
        operation_id=uuid4(),
        call="count",
        now=now,
    )
    assert isinstance(after_release, ModelCountGrant)
    assert after_release.site_slot_id == first_grant.site_slot_id
    assert after_release.fence > first_grant.fence

    get_calls = [params for name, params in dynamo_fixture.calls if name == "GetItem"]
    assert get_calls
    assert all(call["TableName"] == dynamo_fixture.table for call in get_calls)
    assert all(call.get("ConsistentRead") is True for call in get_calls)
    assert any("STAGEOP#" in str(call.get("Key")) for call in get_calls)

    await replica_a.release(second_grant)
    await replica_a.release(other_site)
    await replica_a.release(after_release)


@pytest.mark.asyncio
async def test_stale_replica_release_cannot_clear_a_reclaimed_fence(
    dynamo_fixture: DynamoFixture,
) -> None:
    replica_a = DynamoModelCountAdmissionStore(dynamo_fixture.clients[0], dynamo_fixture.table)
    replica_b = DynamoModelCountAdmissionStore(dynamo_fixture.clients[1], dynamo_fixture.table)
    now = datetime.now(UTC).replace(microsecond=0)
    question = uuid4()
    old = await replica_a.acquire(
        environment_id="alpha",
        question_id=question,
        operation_id=uuid4(),
        call="converse",
        now=now - timedelta(seconds=60),
    )
    peer = await replica_a.acquire(
        environment_id="alpha",
        question_id=uuid4(),
        operation_id=uuid4(),
        call="converse",
        now=now,
    )
    assert isinstance(old, ModelCountGrant) and isinstance(peer, ModelCountGrant)

    recovered_at = old.recover_after + timedelta(seconds=1)
    replacement = await replica_b.acquire(
        environment_id="alpha",
        question_id=question,
        operation_id=uuid4(),
        call="count",
        now=recovered_at,
    )
    assert isinstance(replacement, ModelCountGrant)
    assert replacement.service_slot_id == old.service_slot_id
    assert replacement.fence > old.fence

    await replica_b.release(old)
    still_full = await replica_a.acquire(
        environment_id="alpha",
        question_id=uuid4(),
        operation_id=uuid4(),
        call="count",
        now=recovered_at,
    )
    assert isinstance(still_full, StageCapacityRejection)
    assert still_full.outcome == "capacity"
    await replica_a.release(peer)
    await replica_a.release(replacement)


@pytest.mark.asyncio
async def test_embedding_slot_is_durable_per_question_across_replicas(
    dynamo_fixture: DynamoFixture,
) -> None:
    replica_a = DynamoEmbeddingAdmissionStore(dynamo_fixture.clients[0], dynamo_fixture.table)
    replica_b = DynamoEmbeddingAdmissionStore(dynamo_fixture.clients[1], dynamo_fixture.table)
    now = datetime.now(UTC).replace(microsecond=0)
    question = uuid4()
    grant = await replica_a.acquire(
        environment_id="alpha", question_id=question, operation_id=uuid4(), now=now
    )
    rejected = await replica_b.acquire(
        environment_id="alpha", question_id=question, operation_id=uuid4(), now=now
    )
    separate_question = await replica_b.acquire(
        environment_id="alpha", question_id=uuid4(), operation_id=uuid4(), now=now
    )

    assert isinstance(grant, EmbeddingGrant)
    assert isinstance(rejected, StageCapacityRejection)
    assert rejected.call == "embedding" and rejected.question_id == question
    assert isinstance(separate_question, EmbeddingGrant)
    await replica_b.release(grant)
    question_pk = f"STAGE#embedding#QUESTION#{question}"
    persisted_slots = {
        number: dynamo_fixture.clients[1]
        .get_item(
            TableName=dynamo_fixture.table,
            Key={"pk": {"S": question_pk}, "sk": {"S": f"SLOT#{number}"}},
            ConsistentRead=True,
        )
        .get("Item")
        for number in (0, 1)
    }
    assert isinstance(persisted_slots[0], dict)
    assert "holder_id" not in persisted_slots[0]
    assert persisted_slots[0]["fence"] == {"N": str(grant.fence)}
    assert persisted_slots[1] is None
    release_request = next(
        params
        for operation, params in reversed(dynamo_fixture.calls)
        if operation == "TransactWriteItems"
    )
    available_again = await replica_a.acquire(
        environment_id="alpha", question_id=question, operation_id=uuid4(), now=now
    )
    assert isinstance(available_again, EmbeddingGrant), json.dumps(
        {
            "release_request": release_request,
            "release_response": dynamo_fixture.responses[-1][1],
            "persisted_slots_after_release": persisted_slots,
            "reacquisition": available_again.model_dump(mode="json"),
        },
        sort_keys=True,
    )
    assert available_again.fence > grant.fence
    await replica_a.release(separate_question)
    await replica_b.release(available_again)
