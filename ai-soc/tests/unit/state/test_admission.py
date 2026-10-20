from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import uuid4

import pytest
from botocore.exceptions import ClientError

from ai_soc.state.admission import (
    DynamoAdmissionStore,
    MemoryAdmissionStore,
    _rate_failure,
)
from ai_soc.state.errors import StateFailure

NOW = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)


@pytest.mark.asyncio
async def test_memory_admission_fences_owner_site_and_conservatively_keeps_rate_count() -> None:
    store = MemoryAdmissionStore(lease_seconds=10)
    first = await store.acquire("owner", "alpha", "ask", uuid4(), NOW)

    with pytest.raises(StateFailure) as busy:
        await store.acquire("owner", "alpha", "ask", uuid4(), NOW)
    assert busy.value.code == "BUSY"

    await store.release(first)
    second = await store.acquire("owner", "beta", "ask", uuid4(), NOW)
    assert second.holder_id != first.holder_id
    await store.release(second)

    # Rate counters are intentionally not refunded when a slot is released.
    for _ in range(10):
        grant = await store.acquire("owner", "alpha", "ask", uuid4(), NOW)
        await store.release(grant)
    with pytest.raises(StateFailure) as limited:
        await store.acquire("owner", "alpha", "ask", uuid4(), NOW)
    assert limited.value.code == "RATE_LIMITED"


def test_g6_rate_failure_classifies_owner_counter_failures_after_slots() -> None:
    """Ask acquire uses three slots then owner, site, and ingress minute counters."""
    reasons = [
        {"Code": "None"},
        {"Code": "None"},
        {"Code": "None"},
        {"Code": "ConditionalCheckFailed"},
        {"Code": "None"},
        {"Code": "None"},
    ]
    error = ClientError(
        {
            "Error": {"Code": "TransactionCanceledException"},
            "CancellationReasons": reasons,
        },
        "TransactWriteItems",
    )
    assert _rate_failure(error, slot_count=3) is True
    last_two_only = any(
        isinstance(item, dict) and item.get("Code") == "ConditionalCheckFailed"
        for item in reasons[-2:]
    )
    assert last_two_only is False


@pytest.mark.asyncio
async def test_g6_dynamo_admission_increments_owner_ingress_and_service_semantic_rates() -> None:
    client = _DynamoRecorder()
    store = DynamoAdmissionStore(client, "soc-state", lease_seconds=30)
    await store.acquire("a" * 64, "alpha", "semantic", uuid4(), NOW)
    transact = next(kwargs for method, kwargs in client.calls if method == "transact_write_items")
    actions = cast(list[dict[str, object]], transact["TransactItems"])
    rate_updates = [action for action in actions if "Update" in action][2:]
    assert len(rate_updates) == 3


@pytest.mark.asyncio
async def test_g6_service_semantic_rate_is_distinct_from_site_bulkheads() -> None:
    store = MemoryAdmissionStore(lease_seconds=10)
    for index in range(60):
        owner = f"{index:064x}"
        grant = await store.acquire(owner, f"site-{index:03d}", "semantic", uuid4(), NOW)
        await store.release(grant)
    with pytest.raises(StateFailure) as limited:
        await store.acquire("f" * 64, "site-extra", "semantic", uuid4(), NOW)
    assert limited.value.code == "RATE_LIMITED"


@pytest.mark.asyncio
async def test_memory_admission_renewal_requires_current_holder_and_expiry() -> None:
    store = MemoryAdmissionStore(lease_seconds=5)
    grant = await store.acquire("owner", "alpha", "ask", uuid4(), NOW)
    renewed = await store.renew(grant, NOW + timedelta(seconds=2))
    assert renewed.expires_at == NOW + timedelta(seconds=7)

    with pytest.raises(StateFailure):
        await store.renew(grant, NOW + timedelta(seconds=8))


class _DynamoRecorder:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def get_item(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("get_item", kwargs))
        return {}

    def transact_write_items(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("transact_write_items", kwargs))
        return {}

    def update_item(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("update_item", kwargs))
        return {}


@pytest.mark.asyncio
async def test_dynamo_admission_uses_strong_reads_atomic_slots_and_owner_site_rates() -> None:
    client = _DynamoRecorder()
    store = DynamoAdmissionStore(client, "soc-state", lease_seconds=30)
    grant = await store.acquire("owner", "alpha", "ask", uuid4(), NOW)

    reads = [kwargs for method, kwargs in client.calls if method == "get_item"]
    assert len(reads) == 3
    assert all(read["ConsistentRead"] is True for read in reads)
    transact = next(kwargs for method, kwargs in client.calls if method == "transact_write_items")
    actions = cast(list[dict[str, object]], transact["TransactItems"])
    assert len(actions) == 5  # three fixed slots plus owner and site minute counters
    assert all("Update" in item for item in actions)
    slots = [item["Update"] for item in actions[:3]]
    assert all("ConditionExpression" in cast(dict[str, object], slot) for slot in slots)

    await store.renew(grant, NOW + timedelta(seconds=1))
    await store.release(grant)
    assert sum(method == "transact_write_items" for method, _ in client.calls) == 3


@pytest.mark.asyncio
async def test_dynamo_owner_ingress_admission_uses_only_its_rate_counter() -> None:
    client = _DynamoRecorder()
    store = DynamoAdmissionStore(client, "soc-state", lease_seconds=30)

    grant = await store.acquire("owner", "alpha", "ingress", uuid4(), NOW)

    assert grant.slot_ids == ()
    assert not [kwargs for method, kwargs in client.calls if method == "get_item"]
    transact = next(kwargs for method, kwargs in client.calls if method == "transact_write_items")
    actions = cast(list[dict[str, object]], transact["TransactItems"])
    assert len(actions) == 1
    update = cast(dict[str, object], actions[0]["Update"])
    key = cast(dict[str, dict[str, str]], update["Key"])
    assert key["pk"]["S"].startswith("RATE#ingress#")
    assert key["sk"]["S"].endswith("#all")
