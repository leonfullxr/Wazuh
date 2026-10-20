from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

import pytest
from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
from botocore.exceptions import ClientError

from ai_soc.contracts.models import (
    AnswerStatus,
    AuditAck,
    CompletionCommand,
    FollowupRecord,
    PlanProvenance,
    QuestionBudget,
    QuestionPlan,
    RecoveryTicket,
)
from ai_soc.state.dynamo_conditions import evaluate_condition
from ai_soc.state.dynamodb import DynamoClient, DynamoState
from ai_soc.state.errors import StateFailure
from ai_soc.telemetry.metrics import FixtureMetricExporter, MetricName


class RecordingDynamo:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.serializer = TypeSerializer()
        self.reply: dict[str, object] = {}

    def get_item(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("get_item", kwargs))
        key = cast(dict[str, dict[str, str]], kwargs.get("Key", {}))
        primary = key.get("pk", {}).get("S", "")
        sort = key.get("sk", {}).get("S", "")
        return self.reply if sort == "BUDGET" or primary.startswith("PLAN#") else {}

    def put_item(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("put_item", kwargs))
        return {}

    def update_item(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("update_item", kwargs))
        response = {"Attributes": {"fence": self.serializer.serialize(1)}}
        return cast(dict[str, object], response)

    def transact_write_items(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("transact_write_items", kwargs))
        return {}

    def query(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("query", kwargs))
        return {}


class RecoveryGaugeDynamo(RecordingDynamo):
    def query(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("query", kwargs))
        values = cast(dict[str, dict[str, str]], kwargs.get("ExpressionAttributeValues", {}))
        pk = values.get(":pk", {}).get("S", "")
        if pk != "RECOVERY#0":
            return {"Items": []}
        return {
            "Items": [
                "corrupt-row",
                {
                    "due_epoch": self.serializer.serialize(1),
                    "sk": self.serializer.serialize("due-ticket"),
                },
            ],
        }


class UnrelatedRecoveryDynamo(RecordingDynamo):
    def __init__(self, ticket: RecoveryTicket, due_epoch: int) -> None:
        super().__init__()
        self.ticket = ticket
        self.due_epoch = due_epoch

    def query(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("query", kwargs))
        return {
            "Items": [
                {
                    "pk": self.serializer.serialize(f"RECOVERY#{self.ticket.bucket}"),
                    "sk": self.serializer.serialize(
                        f"{self.ticket.question_id}#{self.ticket.reservation_id}"
                    ),
                    "due_epoch": self.serializer.serialize(self.due_epoch),
                    "payload": self.serializer.serialize(self.ticket.model_dump_json()),
                }
            ]
        }

    def get_item(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("get_item", kwargs))
        raise AssertionError("reservation-scoped recovery must skip unrelated tickets")


class DelayedTargetRecoveryDynamo(RecordingDynamo):
    def __init__(self, tickets: list[RecoveryTicket]) -> None:
        super().__init__()
        self.tickets = tickets
        self.target = tickets[-1]

    def query(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("query", kwargs))
        values = cast(dict[str, dict[str, str]], kwargs["ExpressionAttributeValues"])
        target_key = values.get(":sk", {}).get("S")
        if target_key is None:
            selected = self.tickets[:100]
            return {
                "Items": [self._row(ticket) for ticket in selected],
                "LastEvaluatedKey": {
                    "pk": self.serializer.serialize(f"RECOVERY#{self.target.bucket}"),
                    "sk": self.serializer.serialize(
                        f"{selected[-1].question_id}#{selected[-1].reservation_id}"
                    ),
                },
            }
        selected = [
            ticket
            for ticket in self.tickets
            if f"{ticket.question_id}#{ticket.reservation_id}" == target_key
        ]
        return {"Items": [self._row(ticket) for ticket in selected]}

    def _row(self, ticket: RecoveryTicket) -> dict[str, object]:
        return {
            "pk": self.serializer.serialize(f"RECOVERY#{ticket.bucket}"),
            "sk": self.serializer.serialize(f"{ticket.question_id}#{ticket.reservation_id}"),
            "due_epoch": self.serializer.serialize(int(ticket.due_at.timestamp())),
            "payload": self.serializer.serialize(ticket.model_dump_json()),
        }

    def get_item(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("get_item", kwargs))
        return {}


@pytest.mark.asyncio
async def test_scoped_recovery_does_not_terminalize_an_unrelated_due_reservation() -> None:
    now = datetime(2026, 10, 13, 12, tzinfo=UTC)
    ticket = RecoveryTicket(
        bucket=17,
        due_at=now - timedelta(minutes=5),
        question_id=uuid4(),
        reservation_id=uuid4(),
        version=1,
    )
    client = UnrelatedRecoveryDynamo(ticket, int((now - timedelta(minutes=5)).timestamp()))
    state = DynamoState(cast(DynamoClient, client), "soc-state")

    page = await state.reconcile(
        now=now + timedelta(days=1),
        bucket=ticket.bucket,
        question_id=uuid4(),
        reservation_id=uuid4(),
    )

    assert page.examined == 1
    assert page.terminalized == 0
    assert [name for name, _ in client.calls] == ["query"]


@pytest.mark.asyncio
async def test_scoped_recovery_targets_its_ticket_after_more_than_one_page() -> None:
    now = datetime(2026, 10, 13, 12, tzinfo=UTC)
    tickets = [
        RecoveryTicket(
            bucket=18,
            due_at=now - timedelta(minutes=5),
            question_id=uuid4(),
            reservation_id=UUID(int=index),
            version=1,
        )
        for index in range(1, 106)
    ]
    target = RecoveryTicket(
        bucket=18,
        due_at=now - timedelta(minutes=5),
        question_id=uuid4(),
        reservation_id=UUID(int=999),
        version=1,
    )
    tickets.append(target)
    client = DelayedTargetRecoveryDynamo(tickets)
    state = DynamoState(cast(DynamoClient, client), "soc-state")

    page = await state.reconcile(
        now=now + timedelta(days=1),
        bucket=target.bucket,
        question_id=target.question_id,
        reservation_id=target.reservation_id,
    )

    query = client.calls[0][1]
    assert query["KeyConditionExpression"] == "pk = :pk AND sk = :sk"
    assert query["ExpressionAttributeValues"][":sk"]["S"] == (
        f"{target.question_id}#{target.reservation_id}"
    )
    assert page.examined == 1
    assert page.after is None
    assert client.calls[1][0] == "get_item"
    assert client.calls[1][1]["Key"] == {
        "pk": {"S": f"QUESTION#{target.question_id}"},
        "sk": {"S": f"RESERVATION#{target.reservation_id}"},
    }


@pytest.mark.asyncio
async def test_publish_recovery_gauges_skips_undecodable_items() -> None:
    client = RecoveryGaugeDynamo()
    metrics = FixtureMetricExporter()
    state = DynamoState(cast(DynamoClient, client), "soc-state", metrics=metrics)
    now = datetime(2026, 9, 30, 12, tzinfo=UTC)

    await state.publish_recovery_gauges(now)

    backlog = next(s for s in metrics.samples if s.name is MetricName.recovery_backlog)
    assert backlog.value == 1.0


@pytest.mark.asyncio
async def test_ddb_lease_claim_uses_atomic_fence_increment_and_expiry_condition() -> None:
    client = RecordingDynamo()
    state = DynamoState(cast(DynamoClient, client), "soc-state")
    lease = await state.acquire(
        owner_key="d" * 64,
        environment_id="alpha",
        question_id=uuid4(),
        holder_id=uuid4(),
        now=datetime(2026, 9, 30, tzinfo=UTC),
    )
    assert lease.fence == 1
    operation, params = client.calls[0]
    assert operation == "update_item"
    assert params["ConditionExpression"] == "attribute_not_exists(pk) OR expires_epoch <= :now"
    assert "ADD fence :one" in cast(str, params["UpdateExpression"])
    assert params["ReturnValues"] == "ALL_NEW"


@pytest.mark.asyncio
async def test_plan_load_is_a_strong_read_and_missing_is_uniform_expiry() -> None:
    client = RecordingDynamo()
    state = DynamoState(cast(DynamoClient, client), "soc-state")
    with pytest.raises(StateFailure) as error:
        await state.load_plan(
            uuid4(),
            owner_key="e" * 64,
            environment_id="alpha",
            revision=1,
            policy_hash="f" * 64,
            content_sha="a" * 40,
            now=datetime(2026, 9, 30, tzinfo=UTC),
        )
    assert error.value.code == "FOLLOWUP_EXPIRED"
    assert client.calls[0][1]["ConsistentRead"] is True


def ddb_followup_record(now: datetime) -> FollowupRecord:
    plan = QuestionPlan(
        question_id=uuid4(),
        environment_id="alpha",
        owner_key="a" * 64,
        content_sha="b" * 40,
        policy_hash="c" * 63 + "1",
        language="en",
        timezone="UTC",
        anchor_at=now,
        topics=[],
        provenance=PlanProvenance(
            cue_pack_sha="d" * 64,
            normalized_question_hash="e" * 64,
            origin="new",
            matched_spans=[],
        ),
    )
    return FollowupRecord(
        followup_id=uuid4(),
        owner_key=plan.owner_key,
        environment_id=plan.environment_id,
        plan=plan,
        answered_topic_ids=[],
        leftout_topic_ids=[],
        leftout_stages=[],
        created_at=now,
        expires_at=now + timedelta(minutes=30),
    )


@pytest.mark.asyncio
async def test_plan_load_accepts_only_the_current_policy_and_content_binding() -> None:
    now = datetime(2026, 9, 30, tzinfo=UTC)
    record = ddb_followup_record(now)
    client = RecordingDynamo()
    client.reply = {
        "Item": {
            "owner_key": client.serializer.serialize(record.owner_key),
            "environment_id": client.serializer.serialize(record.environment_id),
            "expires_epoch": client.serializer.serialize(int(record.expires_at.timestamp())),
            "payload": client.serializer.serialize(record.model_dump_json()),
        }
    }
    state = DynamoState(cast(DynamoClient, client), "soc-state")

    loaded = await state.load_plan(
        record.followup_id,
        owner_key=record.owner_key,
        environment_id=record.environment_id,
        revision=record.revision,
        policy_hash=record.plan.policy_hash,
        content_sha=record.plan.content_sha,
        now=now,
    )
    assert loaded == record
    assert client.calls[0][1]["ConsistentRead"] is True

    with pytest.raises(StateFailure) as stale_policy:
        await state.load_plan(
            record.followup_id,
            owner_key=record.owner_key,
            environment_id=record.environment_id,
            revision=record.revision,
            policy_hash="f" * 64,
            content_sha=record.plan.content_sha,
            now=now,
        )
    assert stale_policy.value.code == "POLICY_CHANGED"

    with pytest.raises(StateFailure) as stale_content:
        await state.load_plan(
            record.followup_id,
            owner_key=record.owner_key,
            environment_id=record.environment_id,
            revision=record.revision,
            policy_hash=record.plan.policy_hash,
            content_sha="1" * 40,
            now=now,
        )
    assert stale_content.value.code == "CONTENT_CHANGED"


@pytest.mark.asyncio
async def test_completion_transaction_fences_question_and_records_audit_ack_operation() -> None:
    now = datetime(2026, 9, 30, tzinfo=UTC)
    client = RecordingDynamo()
    state = DynamoState(cast(DynamoClient, client), "soc-state")
    question_id = uuid4()
    owner = "a" * 64
    lease = await state.acquire(
        owner_key=owner,
        environment_id="alpha",
        question_id=question_id,
        holder_id=uuid4(),
        now=now,
    )
    command = CompletionCommand(
        question_id=question_id,
        owner_key=owner,
        environment_id="alpha",
        answer_status=AnswerStatus.answered,
        followup=None,
        idempotency=None,
        audit_ack=AuditAck(event_id=uuid4(), delivery_id="durable-queue-ack", accepted_at=now),
        metadata_sha256="b" * 64,
    )
    operation_id = uuid4()

    receipt = await state.commit_completion(
        command, lease=lease, now=now, operation_id=operation_id
    )

    assert receipt.question_id == question_id
    assert any(
        name == "get_item" and params.get("ConsistentRead") is True for name, params in client.calls
    )
    transaction = next(params for name, params in client.calls if name == "transact_write_items")
    operations = cast(list[dict[str, object]], transaction["TransactItems"])
    question_update = cast(dict[str, object], operations[0]["Update"])
    question_condition = cast(str, question_update["ConditionExpression"])
    assert "fence = :fence" in question_condition
    assert "owner_key = :owner" in question_condition
    assert "environment_id = :site" in question_condition
    assert "expires_epoch > :now" in question_condition
    operation_put = cast(dict[str, object], operations[2]["Put"])
    assert operation_put["ConditionExpression"] == "attribute_not_exists(pk)"


@pytest.mark.asyncio
async def test_reserve_uses_strong_budget_read_and_fenced_transaction() -> None:
    now = datetime(2026, 9, 30, tzinfo=UTC)
    client = RecordingDynamo()
    state = DynamoState(cast(DynamoClient, client), "soc-state")
    lease = await state.acquire(
        owner_key="a" * 64, environment_id="alpha", question_id=uuid4(), holder_id=uuid4(), now=now
    )
    budget = QuestionBudget(
        question_id=lease.question_id,
        token_limit=1000,
        reserved_tokens=0,
        charged_tokens=0,
        remaining_tokens=1000,
        version=1,
        overflow_tokens=0,
        state="open",
        owner_key=lease.owner_key,
        environment_id=lease.environment_id,
        created_at=now,
        expires_at=now.replace(hour=13),
    )
    client.reply = {
        "Item": {
            "payload": client.serializer.serialize(budget.model_dump_json()),
        }
    }
    await state.reserve(
        question_id=lease.question_id,
        topic_id="ldap",
        tokens=400,
        lease=lease,
        operation_id=uuid4(),
        now=now,
        owner_daily_limit=1_000_000,
        service_daily_limit=1_000_000,
    )
    read = next(params for name, params in client.calls if name == "get_item")
    assert read["ConsistentRead"] is True
    name, params = next(
        (name, params) for name, params in client.calls if name == "transact_write_items"
    )
    assert name == "transact_write_items"
    operations = cast(list[dict[str, object]], params["TransactItems"])
    budget_update = next(
        cast(dict[str, object], item["Update"])
        for item in operations
        if "Update" in item
        and "remaining_tokens >= :tokens" in cast(str, item["Update"]["ConditionExpression"])
    )
    assert "version = :old" in cast(str, budget_update["ConditionExpression"])
    assert len(operations) == 7


@pytest.mark.asyncio
async def test_g2_mark_started_escapes_dynamodb_state_reserved_word() -> None:
    now = datetime(2026, 9, 30, tzinfo=UTC)
    client = BudgetTransactDynamo()
    state = DynamoState(cast(DynamoClient, client), "soc-state")
    question_id = uuid4()
    lease = await state.acquire(
        owner_key="a" * 64,
        environment_id="alpha",
        question_id=question_id,
        holder_id=uuid4(),
        now=now,
    )
    await state.open_budget(
        question_id=question_id,
        owner_key=lease.owner_key,
        environment_id=lease.environment_id,
        token_limit=1000,
        expires_at=now + timedelta(hours=1),
        lease=lease,
        operation_id=uuid4(),
    )
    reservation = await state.reserve(
        question_id=question_id,
        topic_id="ldap",
        tokens=400,
        lease=lease,
        operation_id=uuid4(),
        now=now,
        owner_daily_limit=1_000_000,
        service_daily_limit=1_000_000,
    )
    client.calls.clear()
    await state.mark_started(reservation, lease=lease, operation_id=uuid4(), now=now)
    transaction = next(params for name, params in client.calls if name == "transact_write_items")
    reservation_update = next(
        cast(dict[str, object], item["Update"])
        for item in cast(list[dict[str, object]], transaction["TransactItems"])
        if "Update" in item
        and "#state = :reserved" in cast(str, item["Update"]["ConditionExpression"])
    )
    assert reservation_update.get("ExpressionAttributeNames") == {"#state": "state"}
    assert "#state = :reserved" in cast(str, reservation_update["ConditionExpression"])


class BudgetTransactDynamo:
    """Evaluates reservation fence attributes and mark_started conditions."""

    def __init__(self) -> None:
        self.serializer = TypeSerializer()
        self.deserializer = TypeDeserializer()
        self.items: dict[tuple[str, str], dict[str, object]] = {}
        self.calls: list[tuple[str, dict[str, object]]] = []

    def get_item(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("get_item", kwargs))
        key = self._decode(cast(dict[str, object], kwargs["Key"]))
        item = self.items.get((str(key["pk"]), str(key["sk"])))
        return {"Item": self._encode(item)} if item is not None else {}

    def update_item(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("update_item", kwargs))
        key = self._decode(cast(dict[str, object], kwargs["Key"]))
        pk, sk = str(key["pk"]), str(key["sk"])
        values = self._decode(cast(dict[str, object], kwargs.get("ExpressionAttributeValues", {})))
        prior = self.items.get((pk, sk), {})
        fence = int(cast(int, prior.get("fence", 0))) + 1
        lease_id = str(values.get(":lease", uuid4()))
        self.items[(pk, sk)] = {
            "pk": pk,
            "sk": sk,
            "lease_id": lease_id,
            "holder_id": str(values.get(":holder", uuid4())),
            "fence": fence,
            "question_id": str(values.get(":question", uuid4())),
            "owner_key": str(values.get(":owner", "a" * 64)),
            "environment_id": str(values.get(":site", "alpha")),
            "expires_epoch": int(cast(int, values.get(":expires", 0))),
            "last_renewed_epoch": int(cast(int, values.get(":now", 0))),
        }
        return {"Attributes": self._encode(self.items[(pk, sk)])}

    def transact_write_items(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("transact_write_items", kwargs))
        actions = cast(list[dict[str, object]], kwargs["TransactItems"])
        updated = {key: dict(value) for key, value in self.items.items()}
        for action in actions:
            if "ConditionCheck" in action:
                check = cast(dict[str, object], action["ConditionCheck"])
                key = self._decode(cast(dict[str, object], check["Key"]))
                item = updated.get((str(key["pk"]), str(key["sk"])))
                values = self._decode(
                    cast(dict[str, object], check.get("ExpressionAttributeValues", {}))
                )
                if item is None or not self._matches(
                    item, str(check["ConditionExpression"]), values
                ):
                    raise ClientError(
                        {
                            "Error": {"Code": "TransactionCanceledException"},
                            "CancellationReasons": [{"Code": "ConditionalCheckFailed"}],
                        },
                        "TransactWriteItems",
                    )
                continue
            if "Put" in action:
                put = cast(dict[str, object], action["Put"])
                item = self._decode(cast(dict[str, object], put["Item"]))
                key = (str(item["pk"]), str(item["sk"]))
                values = self._decode(
                    cast(dict[str, object], put.get("ExpressionAttributeValues", {}))
                )
                condition = str(put.get("ConditionExpression", ""))
                prior = updated.get(key)
                if condition == "attribute_not_exists(pk)":
                    if prior is not None:
                        raise ClientError(
                            {
                                "Error": {"Code": "TransactionCanceledException"},
                                "CancellationReasons": [{"Code": "ConditionalCheckFailed"}],
                            },
                            "TransactWriteItems",
                        )
                elif "version = :old" in condition:
                    if prior is None or prior.get("version") != values.get(":old"):
                        raise ClientError(
                            {
                                "Error": {"Code": "TransactionCanceledException"},
                                "CancellationReasons": [{"Code": "ConditionalCheckFailed"}],
                            },
                            "TransactWriteItems",
                        )
                updated[key] = item
                continue
            if "Update" in action:
                update = cast(dict[str, object], action["Update"])
                key = self._decode(cast(dict[str, object], update["Key"]))
                pk, sk = str(key["pk"]), str(key["sk"])
                prior = updated.get((pk, sk))
                values = self._decode(
                    cast(dict[str, object], update.get("ExpressionAttributeValues", {}))
                )
                names = cast(dict[str, str], update.get("ExpressionAttributeNames", {}))
                condition = str(update.get("ConditionExpression", ""))
                if prior is None:
                    prior = {}
                if not self._matches(prior, condition, values, names):
                    raise ClientError(
                        {
                            "Error": {"Code": "TransactionCanceledException"},
                            "CancellationReasons": [{"Code": "ConditionalCheckFailed"}],
                        },
                        "TransactWriteItems",
                    )
                result = dict(prior)
                expression = str(update["UpdateExpression"])
                if "ADD tokens_used" in expression:
                    delta_key = ":tokens" if ":tokens" in values else ":refund"
                    result["tokens_used"] = int(result.get("tokens_used", 0)) + int(
                        cast(int, values[delta_key])
                    )
                if "SET " in expression:
                    set_expression, _, remove_expression = expression.partition(" REMOVE ")
                    for assignment in set_expression.split("SET ", 1)[-1].split(","):
                        name, token = (part.strip() for part in assignment.split("=", 1))
                        result[names.get(name, name)] = values[token]
                    if remove_expression:
                        for attribute in remove_expression.split(","):
                            result.pop(attribute.strip(), None)
                elif expression.startswith("REMOVE "):
                    for attribute in expression.removeprefix("REMOVE ").split(","):
                        result.pop(attribute.strip(), None)
                updated[(pk, sk)] = result
        self.items = updated
        return {}

    def _matches(
        self,
        item: dict[str, object],
        condition: str,
        values: dict[str, object],
        names: dict[str, str] | None = None,
    ) -> bool:
        return evaluate_condition(item, condition, values, names)

    def _encode(self, item: dict[str, object]) -> dict[str, object]:
        return {key: self.serializer.serialize(value) for key, value in item.items()}

    def _decode(self, item: dict[str, object]) -> dict[str, object]:
        return {key: self.deserializer.deserialize(value) for key, value in item.items()}


@pytest.mark.asyncio
async def test_g2_reservation_mark_started_and_settle_succeed_on_fenced_attributes() -> None:
    now = datetime(2026, 9, 30, tzinfo=UTC)
    client = BudgetTransactDynamo()
    state = DynamoState(cast(DynamoClient, client), "soc-state")
    question_id = uuid4()
    holder = uuid4()
    lease = await state.acquire(
        owner_key="a" * 64,
        environment_id="alpha",
        question_id=question_id,
        holder_id=holder,
        now=now,
    )
    budget_open_operation_id = uuid4()
    await state.open_budget(
        question_id=question_id,
        owner_key=lease.owner_key,
        environment_id=lease.environment_id,
        token_limit=1000,
        expires_at=now + timedelta(hours=1),
        lease=lease,
        operation_id=budget_open_operation_id,
    )
    reserve_operation_id = uuid4()
    reservation = await state.reserve(
        question_id=question_id,
        topic_id="ldap",
        tokens=400,
        lease=lease,
        operation_id=reserve_operation_id,
        now=now,
        owner_daily_limit=1_000_000,
        service_daily_limit=1_000_000,
    )
    stored = client.items[(f"QUESTION#{question_id}", f"RESERVATION#{reservation.reservation_id}")]
    assert stored["lease_id"] == str(lease.lease_id)
    assert stored["holder_id"] == str(lease.holder_id)
    assert stored["fence"] == lease.fence
    mark_started_operation_id = uuid4()
    started = await state.mark_started(
        reservation, lease=lease, operation_id=mark_started_operation_id, now=now
    )
    assert started.state == "started"
    ticket = state._ticket(started)
    ticket_item = client.items[
        (f"RECOVERY#{ticket.bucket}", f"{ticket.question_id}#{ticket.reservation_id}")
    ]
    assert "ttl_epoch" not in ticket_item
    await state.settle(started, charged_tokens=120, lease=lease, operation_id=uuid4(), now=now)
    reservation_key = (f"QUESTION#{question_id}", f"RESERVATION#{reservation.reservation_id}")
    terminal = client.items[reservation_key]
    assert terminal["state"] == "settled"
    assert terminal["ttl_epoch"] == int(now.timestamp()) + 86400
    for operation_id in (reserve_operation_id, mark_started_operation_id):
        operation = client.items[(f"OP#{operation_id}", "V1")]
        assert operation["ttl_epoch"] == int(now.timestamp()) + 86400
    budget_open_operation = client.items[(f"OP#{budget_open_operation_id}", "V1")]
    assert budget_open_operation["ttl_epoch"] == int(now.timestamp()) + 86400
    budget = client.items[(f"QUESTION#{question_id}", "BUDGET")]
    assert budget["ttl_epoch"] == int(now.timestamp()) + 86400
    assert (
        "ttl_epoch"
        not in client.items[(f"LEASE#{lease.owner_key}#{lease.environment_id}", "ACTIVE")]
    )


@pytest.mark.asyncio
async def test_dynamo_reserve_rejects_first_daily_claim_above_limit() -> None:
    now = datetime(2026, 9, 30, tzinfo=UTC)
    client = BudgetTransactDynamo()
    state = DynamoState(cast(DynamoClient, client), "soc-state")
    question_id = uuid4()
    lease = await state.acquire(
        owner_key="a" * 64,
        environment_id="alpha",
        question_id=question_id,
        holder_id=uuid4(),
        now=now,
    )
    await state.open_budget(
        question_id=question_id,
        owner_key=lease.owner_key,
        environment_id=lease.environment_id,
        token_limit=100_000,
        expires_at=now + timedelta(hours=1),
        lease=lease,
        operation_id=uuid4(),
    )
    with pytest.raises(StateFailure):
        await state.reserve(
            question_id=question_id,
            topic_id="ldap",
            tokens=250_000,
            lease=lease,
            operation_id=uuid4(),
            now=now,
            owner_daily_limit=200_000,
            service_daily_limit=1_000_000,
        )


@pytest.mark.asyncio
async def test_m4_dynamo_settle_release_replay_is_idempotent_for_same_operation() -> None:
    now = datetime(2026, 9, 30, tzinfo=UTC)
    client = BudgetTransactDynamo()
    state = DynamoState(cast(DynamoClient, client), "soc-state")
    question_id = uuid4()
    lease = await state.acquire(
        owner_key="a" * 64,
        environment_id="alpha",
        question_id=question_id,
        holder_id=uuid4(),
        now=now,
    )
    await state.open_budget(
        question_id=question_id,
        owner_key=lease.owner_key,
        environment_id=lease.environment_id,
        token_limit=1000,
        expires_at=now + timedelta(hours=1),
        lease=lease,
        operation_id=uuid4(),
    )
    reservation = await state.reserve(
        question_id=question_id,
        topic_id="ldap",
        tokens=400,
        lease=lease,
        operation_id=uuid4(),
        now=now,
        owner_daily_limit=1_000_000,
        service_daily_limit=1_000_000,
    )
    started = await state.mark_started(reservation, lease=lease, operation_id=uuid4(), now=now)
    operation_id = uuid4()
    await state.settle(
        started,
        charged_tokens=None,
        lease=lease,
        operation_id=operation_id,
        now=now,
        release=True,
    )
    await state.settle(
        started,
        charged_tokens=None,
        lease=lease,
        operation_id=operation_id,
        now=now,
        release=True,
    )
