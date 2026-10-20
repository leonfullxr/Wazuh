from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import uuid4

import pytest
from boto3.dynamodb.types import TypeDeserializer

from ai_soc.contracts.models import (
    AnswerStatus,
    AuditAck,
    CompletionCommand,
    FollowupRecord,
    Lease,
    PlanProvenance,
    QuestionBudget,
    QuestionPlan,
)
from ai_soc.state.dynamodb import DynamoClient, DynamoState
from ai_soc.state.ttl import TTL_ATTRIBUTE
from tests.unit.state.test_dynamodb import RecordingDynamo


@pytest.mark.asyncio
async def test_completion_rows_include_ttl_epoch_after_budget_has_no_liability() -> None:
    client = RecordingDynamo()
    state = DynamoState(cast(DynamoClient, client), "soc-state")
    now = datetime(2026, 9, 30, 12, tzinfo=UTC)
    lease = Lease(
        lease_id=uuid4(),
        question_id=uuid4(),
        holder_id=uuid4(),
        fence=1,
        owner_key="a" * 64,
        environment_id="alpha",
        expires_at=now + timedelta(minutes=1),
        last_renewed_at=now,
    )
    followup_plan = QuestionPlan(
        question_id=lease.question_id,
        environment_id=lease.environment_id,
        owner_key=lease.owner_key,
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
    followup = FollowupRecord(
        followup_id=uuid4(),
        owner_key=lease.owner_key,
        environment_id=lease.environment_id,
        plan=followup_plan,
        answered_topic_ids=[],
        leftout_topic_ids=[],
        leftout_stages=[],
        created_at=now,
        expires_at=now + timedelta(minutes=30),
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
        expires_at=now + timedelta(hours=1),
    )
    budget_open_operation_id = uuid4()
    client.reply = {
        "Item": {
            "payload": client.serializer.serialize(budget.model_dump_json()),
            "budget_open_operation_id": client.serializer.serialize(str(budget_open_operation_id)),
        }
    }
    command = CompletionCommand(
        question_id=lease.question_id,
        owner_key=lease.owner_key,
        environment_id=lease.environment_id,
        answer_status=AnswerStatus.answered,
        metadata_sha256="a" * 64,
        followup=followup,
        idempotency=None,
        audit_ack=AuditAck(event_id=uuid4(), delivery_id="ack", accepted_at=now),
    )
    await state.commit_completion(command, lease=lease, operation_id=uuid4(), now=now)
    transact_calls = [call for call in client.calls if call[0] == "transact_write_items"]
    assert transact_calls
    items = cast(list[dict[str, object]], transact_calls[-1][1]["TransactItems"])
    deserializer = TypeDeserializer()
    ttl_rows: set[tuple[object, object]] = set()
    budget_open_operation_ttl = None
    closed_budget = None
    for action in items:
        put = action.get("Put")
        if isinstance(put, dict):
            item = cast(dict[str, object], put.get("Item", {}))
            decoded = {key: deserializer.deserialize(value) for key, value in item.items()}
            if decoded.get("sk") in {"COMPLETION", "V1"} and decoded.get("record_type") in {
                "completion",
                "operation",
            }:
                assert decoded.get(TTL_ATTRIBUTE) == int(now.timestamp()) + 86400
                ttl_rows.add((decoded.get("record_type"), decoded.get("sk")))
            if decoded.get("record_type") == "plan":
                assert decoded.get(TTL_ATTRIBUTE) == int(followup.expires_at.timestamp())
                ttl_rows.add(("plan", "V1"))
        update = action.get("Update")
        if not isinstance(update, dict):
            continue
        key = cast(dict[str, dict[str, str]], update["Key"])
        pk = key["pk"]["S"]
        values = cast(dict[str, dict[str, str]], update["ExpressionAttributeValues"])
        if pk == f"OP#{budget_open_operation_id}":
            budget_open_operation_ttl = deserializer.deserialize(values[":ttl"])
        if pk == f"QUESTION#{lease.question_id}" and key["sk"]["S"] == "BUDGET":
            closed_budget = QuestionBudget.model_validate_json(
                deserializer.deserialize(values[":payload"])
            )
            assert deserializer.deserialize(values[":ttl"]) == int(now.timestamp()) + 86400
            assert deserializer.deserialize(values[":next"]) == budget.version + 1
    assert ttl_rows == {
        ("completion", "COMPLETION"),
        ("operation", "V1"),
        ("plan", "V1"),
    }
    assert budget_open_operation_ttl == int(now.timestamp()) + 86400
    assert closed_budget is not None
    assert closed_budget.state == "closed"
    assert closed_budget.version == budget.version + 1
