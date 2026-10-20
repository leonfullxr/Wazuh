from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import uuid4

import pytest
from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
from botocore.exceptions import ClientError

from ai_soc.contracts.models import ErrorCode
from ai_soc.state.daily_tokens import utc_day_start_epoch
from ai_soc.state.dynamo_conditions import evaluate_condition
from ai_soc.state.dynamodb import DynamoClient, DynamoState
from ai_soc.state.errors import StateFailure
from ai_soc.state.memory import MemoryState
from ai_soc.state.ttl import TTL_ATTRIBUTE


class LedgerDynamo:
    def __init__(self) -> None:
        self.serializer = TypeSerializer()
        self.deserializer = TypeDeserializer()
        self.items: dict[tuple[str, str], dict[str, object]] = {}
        self.budget_remaining = 100_000
        self.fail_daily = False

    def get_item(self, **kwargs: object) -> dict[str, object]:
        key = cast(dict[str, dict[str, str]], kwargs["Key"])
        pk = key["pk"]["S"]
        sk = key["sk"]["S"]
        item = self.items.get((pk, sk))
        if item is None:
            return {}
        return {"Item": {k: self.serializer.serialize(v) for k, v in item.items()}}

    def transact_write_items(self, **kwargs: object) -> dict[str, object]:
        if self.fail_daily:
            raise ClientError(
                {"Error": {"Code": "TransactionCanceledException", "Message": "fail"}},
                "TransactWriteItems",
            )
        items = cast(list[dict[str, object]], kwargs["TransactItems"])
        for entry in items:
            if "Update" not in entry:
                continue
            update = cast(dict[str, object], entry["Update"])
            key = cast(dict[str, dict[str, str]], update["Key"])
            pk = key["pk"]["S"]
            sk = key["sk"]["S"]
            values = cast(dict[str, dict[str, object]], update["ExpressionAttributeValues"])
            decoded = {k: self.deserializer.deserialize(v) for k, v in values.items()}
            if pk.startswith("TOKENDAY#"):
                row = self.items.get((pk, sk), {})
                condition = str(update.get("ConditionExpression", ""))
                if not evaluate_condition(row, condition, decoded):
                    raise ClientError(
                        {"Error": {"Code": "ConditionalCheckFailedException"}},
                        "TransactWriteItems",
                    )
                delta = int(cast(int, decoded[":tokens"]))
                row = self.items.setdefault((pk, sk), {})
                row["tokens_used"] = int(cast(int, row.get("tokens_used", 0))) + delta
        return {}

    def update_item(self, **kwargs: object) -> dict[str, object]:
        return {"Attributes": self.serializer.serialize({"fence": 1})}


NOW = datetime(2026, 9, 30, 12, tzinfo=UTC)
OWNER = "a" * 64


@pytest.mark.asyncio
async def test_owner_daily_cap_blocks_reserve_without_question_budget_change() -> None:
    state = MemoryState()
    lease = await state.acquire(
        owner_key=OWNER,
        environment_id="alpha",
        question_id=uuid4(),
        holder_id=uuid4(),
        now=NOW,
    )
    await state.open_budget(
        question_id=lease.question_id,
        owner_key=OWNER,
        environment_id="alpha",
        token_limit=100_000,
        expires_at=NOW + timedelta(hours=1),
        lease=lease,
        operation_id=uuid4(),
    )
    state._daily_tokens[(f"owner:{OWNER}", utc_day_start_epoch(NOW))] = 200_000
    with pytest.raises(StateFailure) as error:
        await state.reserve(
            question_id=lease.question_id,
            topic_id="ldap",
            tokens=100,
            lease=lease,
            operation_id=uuid4(),
            now=NOW,
            owner_daily_limit=200_000,
            service_daily_limit=1_000_000,
        )
    assert error.value.code == ErrorCode.BUDGET_EXCEEDED
    assert state.budgets[lease.question_id].budget.remaining_tokens == 100_000


@pytest.mark.asyncio
async def test_new_question_does_not_reset_owner_daily_ledger() -> None:
    state = MemoryState()
    day = utc_day_start_epoch(NOW)
    state._daily_tokens[(f"owner:{OWNER}", day)] = 150_000
    lease = await state.acquire(
        owner_key=OWNER,
        environment_id="alpha",
        question_id=uuid4(),
        holder_id=uuid4(),
        now=NOW,
    )
    await state.open_budget(
        question_id=lease.question_id,
        owner_key=OWNER,
        environment_id="alpha",
        token_limit=100_000,
        expires_at=NOW + timedelta(hours=1),
        lease=lease,
        operation_id=uuid4(),
    )
    with pytest.raises(StateFailure):
        await state.reserve(
            question_id=lease.question_id,
            topic_id="ldap",
            tokens=60_000,
            lease=lease,
            operation_id=uuid4(),
            now=NOW,
            owner_daily_limit=200_000,
            service_daily_limit=1_000_000,
        )
    assert state._daily_tokens[(f"owner:{OWNER}", day)] == 150_000


@pytest.mark.asyncio
async def test_service_daily_cap_holds_across_owners() -> None:
    state = MemoryState()
    day = utc_day_start_epoch(NOW)
    state._daily_tokens[("service", day)] = 1_000_000
    owner_b = "b" * 64
    lease = await state.acquire(
        owner_key=owner_b,
        environment_id="alpha",
        question_id=uuid4(),
        holder_id=uuid4(),
        now=NOW,
    )
    await state.open_budget(
        question_id=lease.question_id,
        owner_key=owner_b,
        environment_id="alpha",
        token_limit=100_000,
        expires_at=NOW + timedelta(hours=1),
        lease=lease,
        operation_id=uuid4(),
    )
    with pytest.raises(StateFailure) as error:
        await state.reserve(
            question_id=lease.question_id,
            topic_id="ldap",
            tokens=100,
            lease=lease,
            operation_id=uuid4(),
            now=NOW,
            owner_daily_limit=200_000,
            service_daily_limit=1_000_000,
        )
    assert error.value.code == ErrorCode.BUDGET_EXCEEDED


@pytest.mark.asyncio
async def test_dynamo_daily_claim_uses_conditional_transaction_items() -> None:
    client = LedgerDynamo()
    state = DynamoState(cast(DynamoClient, client), "soc-state")
    assert (
        await state.daily_judgment_blocked(
            owner_key=OWNER,
            now=NOW,
            owner_daily_limit=200_000,
            service_daily_limit=1_000_000,
        )
        is False
    )
    owner_pk, owner_sk = (
        f"TOKENDAY#owner#{OWNER}",
        str(utc_day_start_epoch(NOW)),
    )
    client.items[(owner_pk, owner_sk)] = {"tokens_used": 200_000}
    assert (
        await state.daily_judgment_blocked(
            owner_key=OWNER,
            now=NOW,
            owner_daily_limit=200_000,
            service_daily_limit=1_000_000,
        )
        is True
    )


def test_terraform_ttl_attribute_matches_code_constant() -> None:
    from pathlib import Path

    main_tf = (Path("infra") / "main.tf").read_text(encoding="utf-8")
    assert f'attribute_name = "{TTL_ATTRIBUTE}"' in main_tf


@pytest.mark.asyncio
async def test_dynamo_first_daily_claim_rejects_tokens_above_limit() -> None:
    client = LedgerDynamo()
    state = DynamoState(cast(DynamoClient, client), "soc-state")
    owner_pk, owner_sk = (
        f"TOKENDAY#owner#{OWNER}",
        str(utc_day_start_epoch(NOW)),
    )
    items = state._daily_token_claim_items(
        owner_key=OWNER,
        tokens=250_000,
        now=NOW,
        owner_daily_limit=200_000,
        service_daily_limit=1_000_000,
    )
    owner_update = cast(dict[str, object], items[0]["Update"])
    key = cast(dict[str, dict[str, str]], owner_update["Key"])
    assert key["pk"]["S"] == owner_pk
    assert key["sk"]["S"] == owner_sk
    with pytest.raises(ClientError):
        client.transact_write_items(TransactItems=items[:1])


@pytest.mark.asyncio
async def test_terminalize_refunds_reservation_charge_day_not_settle_day() -> None:
    from ai_soc.contracts.models import Reservation

    state = MemoryState()
    reserve_at = datetime(2026, 9, 30, 23, 59, tzinfo=UTC)
    settle_at = datetime(2026, 10, 1, 0, 1, tzinfo=UTC)
    reserve_day = utc_day_start_epoch(reserve_at)
    settle_day = utc_day_start_epoch(settle_at)
    lease = await state.acquire(
        owner_key=OWNER,
        environment_id="alpha",
        question_id=uuid4(),
        holder_id=uuid4(),
        now=reserve_at,
    )
    await state.open_budget(
        question_id=lease.question_id,
        owner_key=OWNER,
        environment_id="alpha",
        token_limit=10_000,
        expires_at=settle_at + timedelta(hours=1),
        lease=lease,
        operation_id=uuid4(),
    )
    reservation = Reservation(
        reservation_id=uuid4(),
        operation_id=uuid4(),
        question_id=lease.question_id,
        topic_id="ldap",
        owner_key=OWNER,
        environment_id="alpha",
        lease_id=lease.lease_id,
        holder_id=lease.holder_id,
        fence=lease.fence,
        reserved_tokens=1_000,
        state="started",
        created_at=reserve_at,
        started_at=reserve_at,
        hard_deadline_at=reserve_at + timedelta(minutes=2),
        recover_after=reserve_at + timedelta(minutes=2),
        daily_token_day_epoch=reserve_day,
        version=1,
    )
    state.reservations[reservation.reservation_id] = reservation
    state._daily_tokens[(f"owner:{OWNER}", reserve_day)] = 1_000
    state._daily_tokens[("service", reserve_day)] = 1_000
    state._terminalize(reservation, 100, settle_at, uuid4())
    assert state._daily_tokens[(f"owner:{OWNER}", reserve_day)] == 100
    assert state._daily_tokens.get((f"owner:{OWNER}", settle_day), 0) == 0


@pytest.mark.asyncio
async def test_dynamo_reserve_put_omits_ttl_on_non_terminal_reservation() -> None:
    from test_dynamodb import RecordingDynamo

    now = NOW
    client = RecordingDynamo()
    state = DynamoState(cast(DynamoClient, client), "soc-state")
    lease = await state.acquire(
        owner_key=OWNER,
        environment_id="alpha",
        question_id=uuid4(),
        holder_id=uuid4(),
        now=now,
    )
    from ai_soc.contracts.models import QuestionBudget

    budget = QuestionBudget(
        question_id=lease.question_id,
        token_limit=100_000,
        reserved_tokens=0,
        charged_tokens=0,
        remaining_tokens=100_000,
        version=1,
        overflow_tokens=0,
        state="open",
        owner_key=lease.owner_key,
        environment_id=lease.environment_id,
        created_at=now,
        expires_at=now + timedelta(hours=1),
    )
    client.reply = {
        "Item": {"payload": client.serializer.serialize(budget.model_dump_json())},
    }
    await state.reserve(
        question_id=lease.question_id,
        topic_id="ldap",
        tokens=500,
        lease=lease,
        operation_id=uuid4(),
        now=now,
        owner_daily_limit=200_000,
        service_daily_limit=1_000_000,
    )
    _, params = next(
        (name, params) for name, params in client.calls if name == "transact_write_items"
    )
    deserializer = TypeDeserializer()
    reservation_items: list[dict[str, object]] = []
    for entry in cast(list[dict[str, object]], params["TransactItems"]):
        if "Put" not in entry:
            continue
        put = cast(dict[str, object], entry["Put"])
        item = {
            key: deserializer.deserialize(value)
            for key, value in cast(dict[str, object], put["Item"]).items()
        }
        if str(item.get("sk", "")).startswith("RESERVATION#"):
            reservation_items.append(item)
    assert reservation_items
    assert TTL_ATTRIBUTE not in reservation_items[0]


@pytest.mark.asyncio
async def test_lease_acquire_writes_no_ttl_attribute() -> None:
    from test_dynamodb import RecordingDynamo

    client = RecordingDynamo()
    state = DynamoState(cast(DynamoClient, client), "soc-state")
    await state.acquire(
        owner_key=OWNER,
        environment_id="alpha",
        question_id=uuid4(),
        holder_id=uuid4(),
        now=NOW,
    )
    update_calls = [params for name, params in client.calls if name == "update_item"]
    assert update_calls
    assert TTL_ATTRIBUTE not in str(update_calls[0])
