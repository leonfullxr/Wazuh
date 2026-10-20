"""DynamoDB state adapter using explicit conditional transactions and strong reads."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Protocol, cast
from uuid import UUID, uuid4

from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
from botocore.exceptions import ClientError

from ai_soc.contracts.canonical import sha256_hex
from ai_soc.contracts.errors import public_error
from ai_soc.contracts.models import (
    SHA256,
    CompletionCommand,
    CompletionReceipt,
    ContentId,
    ErrorCode,
    FeedbackControlContext,
    FeedbackMetadata,
    FollowupRecord,
    GitSHA40,
    IdempotencyRecord,
    Lease,
    PolicyHash,
    QuestionBudget,
    QuestionRecord,
    RecoveryPage,
    RecoveryTicket,
    Reservation,
)
from ai_soc.contracts.ports import Clock
from ai_soc.state.daily_tokens import (
    daily_ledger_ttl_epoch,
    owner_daily_key,
    service_daily_key,
    utc_day_start_epoch,
)
from ai_soc.state.errors import StateFailure
from ai_soc.state.feedback_control import FeedbackControlPool
from ai_soc.state.ttl import TTL_ATTRIBUTE
from ai_soc.telemetry.metrics import MetricExporter
from ai_soc.telemetry.operational import (
    emit_content_provenance_failure,
    emit_recovery_backlog,
    emit_recovery_lag_seconds,
)


def _as_int(value: object) -> int:
    if isinstance(value, (int, float, str, Decimal)) and not isinstance(value, bool):
        return int(value)
    return 0


class DynamoClient(Protocol):
    def get_item(self, **kwargs: object) -> dict[str, object]: ...
    def put_item(self, **kwargs: object) -> dict[str, object]: ...
    def update_item(self, **kwargs: object) -> dict[str, object]: ...
    def transact_write_items(self, **kwargs: object) -> dict[str, object]: ...
    def query(self, **kwargs: object) -> dict[str, object]: ...


class AttributeCodec(Protocol):
    def serialize(self, value: object) -> object: ...
    def deserialize(self, value: object) -> object: ...


class DynamoState:
    """Stores metadata only; callers provide a region-local, least-privilege client."""

    def __init__(
        self,
        client: DynamoClient,
        table_name: str,
        *,
        lease_seconds: int = 60,
        metrics: MetricExporter | None = None,
        clock: Clock | None = None,
        feedback_control_pool: FeedbackControlPool | None = None,
    ) -> None:
        if not table_name:
            raise ValueError("table_name is required")
        self._client = client
        self._table = table_name
        self._lease_seconds = lease_seconds
        self._metrics = metrics
        self._clock = clock
        self._feedback_control_pool = feedback_control_pool
        self._serializer = cast(AttributeCodec, TypeSerializer())
        self._deserializer = cast(AttributeCodec, TypeDeserializer())
        self._io = asyncio.Semaphore(8)

    async def read_feedback(
        self,
        *,
        receipt_id: UUID,
        note_hash: SHA256,
        now: datetime,
        control: FeedbackControlContext,
    ) -> FeedbackMetadata | None:
        key = self._feedback_key(receipt_id, note_hash)
        response = await self._feedback_call(
            "get_item",
            control=control,
            TableName=self._table,
            Key=self._key(*key),
            ConsistentRead=True,
        )
        raw = response.get("Item")
        if raw is None:
            return None
        item = self._decode(raw)
        if item is None or item.get("record_type") != "feedback":
            raise self._feedback_error()
        try:
            allowed = {
                "pk",
                "sk",
                "record_type",
                "schema_version",
                "feedback_id",
                "status",
                "created_at",
                "ttl_epoch",
            }
            if set(item) != allowed:
                raise ValueError("feedback record shape is invalid")
            ttl = item["ttl_epoch"]
            if isinstance(ttl, Decimal):
                if ttl != ttl.to_integral_value():
                    raise ValueError("feedback ttl is invalid")
                ttl = int(ttl)
            values = {
                name: item[name]
                for name in ("schema_version", "feedback_id", "status", "created_at", "ttl_epoch")
            }
            values["ttl_epoch"] = ttl
            record = FeedbackMetadata.model_validate_json(json.dumps(values))
        except (KeyError, ValueError, TypeError):
            raise self._feedback_error() from None
        return None if record.ttl_epoch <= self._epoch(now) else record

    async def try_create_feedback(
        self,
        *,
        receipt_id: UUID,
        note_hash: SHA256,
        now: datetime,
        control: FeedbackControlContext,
    ) -> FeedbackMetadata | None:
        now_epoch = self._epoch(now)
        candidate = FeedbackMetadata(
            feedback_id=uuid4(),
            status="pending",
            created_at=now,
            ttl_epoch=now_epoch + 604800,
        )
        record: dict[str, object] = {
            "pk": self._feedback_key(receipt_id, note_hash)[0],
            "sk": self._feedback_key(receipt_id, note_hash)[1],
            "record_type": "feedback",
        }
        record.update(cast(dict[str, object], candidate.model_dump(mode="json")))
        try:
            await self._feedback_call(
                "put_item",
                control=control,
                TableName=self._table,
                Item=self._encode(record),
                ConditionExpression="attribute_not_exists(pk) OR ttl_epoch <= :now",
                ExpressionAttributeValues=self._values({":now": now_epoch}),
            )
            return candidate
        except ClientError as error:
            if self._conditional(error):
                return None
            raise self._feedback_error() from None

    async def mark_feedback_queued(
        self,
        *,
        receipt_id: UUID,
        note_hash: SHA256,
        feedback_id: UUID,
        now: datetime,
        control: FeedbackControlContext,
    ) -> bool:
        try:
            await self._feedback_call(
                "update_item",
                control=control,
                TableName=self._table,
                Key=self._key(*self._feedback_key(receipt_id, note_hash)),
                UpdateExpression="SET #status = :queued",
                ConditionExpression=(
                    "feedback_id = :expected_id AND #status = :pending AND ttl_epoch > :now"
                ),
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues=self._values(
                    {
                        ":queued": "queued",
                        ":pending": "pending",
                        ":expected_id": str(feedback_id),
                        ":now": self._epoch(now),
                    }
                ),
            )
            return True
        except ClientError as error:
            if self._conditional(error):
                return False
            raise self._feedback_error() from None

    async def _feedback_call(
        self, method: str, *, control: FeedbackControlContext, **kwargs: object
    ) -> dict[str, object]:
        if method not in {"get_item", "put_item", "update_item"}:
            raise self._feedback_error()
        if self._feedback_control_pool is None:
            raise self._feedback_error()
        try:
            sdk_method = getattr(self._client, method)
            return await self._feedback_control_pool.run(
                lambda: cast(dict[str, object], sdk_method(**kwargs)), control=control
            )
        except StateFailure:
            raise
        except ClientError as error:
            if method in {"put_item", "update_item"} and self._conditional(error):
                raise
            raise self._feedback_error() from None
        except Exception:
            if control.cancel.is_cancelled():
                control.cancel.raise_if_cancelled()
            raise self._feedback_error() from None

    @staticmethod
    def _feedback_key(receipt_id: UUID, note_hash: SHA256) -> tuple[str, str]:
        return f"FEEDBACK#{receipt_id}", note_hash

    @staticmethod
    def _feedback_error() -> StateFailure:
        return StateFailure(
            public_error(
                ErrorCode.FEEDBACK_UNAVAILABLE,
                "Feedback is temporarily unavailable.",
                trace_id=uuid4().hex,
                retryable=True,
            )
        )

    async def load(
        self,
        followup_id: UUID,
        *,
        owner_key: SHA256,
        environment_id: ContentId,
        revision: int,
        policy_hash: PolicyHash,
        content_sha: GitSHA40,
        now: datetime,
    ) -> FollowupRecord:
        return await self.load_plan(
            followup_id,
            owner_key=owner_key,
            environment_id=environment_id,
            revision=revision,
            policy_hash=policy_hash,
            content_sha=content_sha,
            now=now,
        )

    async def acquire(
        self,
        *,
        owner_key: str,
        environment_id: str,
        question_id: UUID,
        holder_id: UUID,
        now: datetime,
    ) -> Lease:
        return await self.acquire_lease(
            owner_key=owner_key,
            environment_id=environment_id,
            question_id=question_id,
            holder_id=holder_id,
            now=now,
        )

    async def renew(self, lease: Lease, *, now: datetime) -> Lease:
        return await self.renew_lease(lease, now=now)

    async def release(self, lease: Lease) -> None:
        await self.release_lease(lease)

    async def load_plan(
        self,
        followup_id: UUID,
        *,
        owner_key: SHA256,
        environment_id: ContentId,
        revision: int,
        policy_hash: PolicyHash,
        content_sha: GitSHA40,
        now: datetime,
    ) -> FollowupRecord:
        response = await self._call(
            "get_item",
            TableName=self._table,
            Key=self._key(f"PLAN#{followup_id}", "V1"),
            ConsistentRead=True,
        )
        raw = response.get("Item")
        item = self._decode(raw)
        if (
            item is None
            or item.get("owner_key") != owner_key
            or item.get("environment_id") != environment_id
            or _as_int(item.get("expires_epoch", 0)) <= self._epoch(now)
        ):
            raise self._error(ErrorCode.FOLLOWUP_EXPIRED, "Follow-up is unavailable.")
        record = FollowupRecord.model_validate_json(str(item["payload"]))
        if record.revision != revision:
            raise self._error(ErrorCode.FOLLOWUP_CONFLICT, "Follow-up changed; ask a new question.")
        if record.plan.policy_hash != policy_hash:
            raise self._error(
                ErrorCode.POLICY_CHANGED, "Authorization changed; ask a new question."
            )
        if record.plan.content_sha != content_sha:
            if self._metrics is not None:
                emit_content_provenance_failure(self._metrics)
            raise self._error(ErrorCode.CONTENT_CHANGED, "Content changed; ask a new question.")
        return record

    async def acquire_lease(
        self,
        *,
        owner_key: str,
        environment_id: str,
        question_id: UUID,
        holder_id: UUID,
        now: datetime,
    ) -> Lease:
        pk = f"LEASE#{owner_key}#{environment_id}"
        sk = "ACTIVE"
        lease_id = uuid4()
        expires = now + timedelta(seconds=self._lease_seconds)
        try:
            response = await self._call(
                "update_item",
                TableName=self._table,
                Key=self._key(pk, sk),
                UpdateExpression=(
                    "SET record_type = :kind, lease_id = :lease, question_id = :question, "
                    "owner_key = :owner, environment_id = :site, holder_id = :holder, "
                    "expires_epoch = :expires, last_renewed_epoch = :now ADD fence :one"
                ),
                ConditionExpression="attribute_not_exists(pk) OR expires_epoch <= :now",
                ExpressionAttributeValues=self._values(
                    {
                        ":kind": "lease",
                        ":lease": str(lease_id),
                        ":question": str(question_id),
                        ":owner": owner_key,
                        ":site": environment_id,
                        ":holder": str(holder_id),
                        ":expires": self._epoch(expires),
                        ":now": self._epoch(now),
                        ":one": 1,
                    }
                ),
                ReturnValues="ALL_NEW",
            )
            attrs = self._decode(response.get("Attributes"))
            fence = _as_int(attrs.get("fence", 0)) if attrs else 0
            if fence < 1:
                raise self._error(
                    ErrorCode.DEPENDENCY_UNAVAILABLE, "State lease response is invalid."
                )
            return Lease(
                lease_id=lease_id,
                question_id=question_id,
                owner_key=owner_key,
                environment_id=environment_id,
                holder_id=holder_id,
                fence=fence,
                expires_at=expires,
                last_renewed_at=now,
            )
        except ClientError as exc:
            if self._conditional(exc):
                raise self._error(ErrorCode.BUSY, "Another request is active.") from None
            raise self._error(
                ErrorCode.DEPENDENCY_UNAVAILABLE, "State storage is unavailable."
            ) from None

    async def renew_lease(self, lease: Lease, *, now: datetime) -> Lease:
        expires = now + timedelta(seconds=self._lease_seconds)
        try:
            await self._call(
                "update_item",
                TableName=self._table,
                Key=self._key(f"LEASE#{lease.owner_key}#{lease.environment_id}", "ACTIVE"),
                UpdateExpression="SET expires_epoch = :expires, last_renewed_epoch = :now",
                ConditionExpression=(
                    "lease_id = :lease AND holder_id = :holder AND fence = :fence "
                    "AND question_id = :question AND expires_epoch > :now"
                ),
                ExpressionAttributeValues=self._values(
                    {
                        ":expires": self._epoch(expires),
                        ":now": self._epoch(now),
                        ":lease": str(lease.lease_id),
                        ":holder": str(lease.holder_id),
                        ":fence": lease.fence,
                        ":question": str(lease.question_id),
                    }
                ),
            )
        except ClientError as exc:
            if self._conditional(exc):
                raise self._error(ErrorCode.LEASE_LOST, "Request lease was lost.") from None
            raise self._error(
                ErrorCode.DEPENDENCY_UNAVAILABLE, "State storage is unavailable."
            ) from None
        return lease.model_copy(update={"expires_at": expires, "last_renewed_at": now})

    async def release_lease(self, lease: Lease) -> None:
        try:
            await self._call(
                "update_item",
                TableName=self._table,
                Key=self._key(f"LEASE#{lease.owner_key}#{lease.environment_id}", "ACTIVE"),
                UpdateExpression="SET expires_epoch = :zero",
                ConditionExpression="lease_id = :lease AND holder_id = :holder AND fence = :fence",
                ExpressionAttributeValues=self._values(
                    {
                        ":zero": 0,
                        ":lease": str(lease.lease_id),
                        ":holder": str(lease.holder_id),
                        ":fence": lease.fence,
                    }
                ),
            )
        except ClientError as exc:
            if not self._conditional(exc):
                raise self._error(
                    ErrorCode.DEPENDENCY_UNAVAILABLE, "State storage is unavailable."
                ) from None

    async def admit_question(
        self, question: QuestionRecord, idem: IdempotencyRecord | None, *, now: datetime
    ) -> Lease:
        """Atomically fence and admit a question with its optional idempotency key."""
        lease_pk = f"LEASE#{question.owner_key}#{question.environment_id}"
        existing_response = await self._call(
            "get_item",
            TableName=self._table,
            Key=self._key(lease_pk, "ACTIVE"),
            ConsistentRead=True,
        )
        prior = self._decode(existing_response.get("Item"))
        prior_fence = _as_int(prior.get("fence", 0)) if prior else 0
        if question.fence != prior_fence + 1:
            raise self._error(ErrorCode.LEASE_LOST, "Question lease fence is stale.")
        lease = Lease(
            lease_id=question.lease_id,
            question_id=question.question_id,
            owner_key=question.owner_key,
            environment_id=question.environment_id,
            holder_id=question.holder_id,
            fence=question.fence,
            expires_at=now + timedelta(seconds=self._lease_seconds),
            last_renewed_at=now,
        )
        lease_values: dict[str, object] = {
            ":kind": "lease",
            ":lease": str(lease.lease_id),
            ":question": str(lease.question_id),
            ":owner": lease.owner_key,
            ":site": lease.environment_id,
            ":holder": str(lease.holder_id),
            ":expires": self._epoch(lease.expires_at),
            ":now": self._epoch(now),
            ":one": 1,
        }
        lease_condition = (
            "attribute_not_exists(pk)"
            if prior is None
            else "fence = :prior AND expires_epoch <= :now"
        )
        if prior is not None:
            lease_values[":prior"] = prior_fence
        operations: list[object] = cast(
            list[object],
            [
                {
                    "Update": {
                        "TableName": self._table,
                        "Key": self._key(lease_pk, "ACTIVE"),
                        "UpdateExpression": (
                            "SET record_type = :kind, lease_id = :lease, question_id = :question, "
                            "owner_key = :owner, environment_id = :site, holder_id = :holder, "
                            "expires_epoch = :expires, last_renewed_epoch = :now ADD fence :one"
                        ),
                        "ConditionExpression": lease_condition,
                        "ExpressionAttributeValues": self._values(lease_values),
                    }
                },
                self._put_absent(
                    f"QUESTION#{question.question_id}",
                    "STATUS",
                    {
                        "record_type": "question",
                        "payload": question.model_dump_json(),
                        "state": "active",
                        "owner_key": question.owner_key,
                        "environment_id": question.environment_id,
                        "lease_id": str(lease.lease_id),
                        "holder_id": str(lease.holder_id),
                        "fence": lease.fence,
                        "expires_epoch": self._epoch(question.expires_at),
                    },
                ),
            ],
        )
        if idem is not None:
            operations.append(
                {
                    "Put": {
                        "TableName": self._table,
                        "Item": self._encode(
                            {
                                "pk": f"IDEMPOTENCY#{idem.owner_key}#{idem.environment_id}",
                                "sk": str(idem.key),
                                "record_type": "idempotency",
                                "payload": idem.model_dump_json(),
                                "request_hash": idem.request_hash,
                                "question_id": str(idem.question_id),
                                "status": idem.status,
                                "expires_epoch": self._epoch(idem.expires_at),
                                TTL_ATTRIBUTE: self._epoch(idem.expires_at),
                            }
                        ),
                        "ConditionExpression": "attribute_not_exists(pk) OR expires_epoch <= :now",
                        "ExpressionAttributeValues": self._values({":now": self._epoch(now)}),
                    }
                }
            )
        await self._transact(
            lambda attempt_now: self._transaction_items_at(operations, attempt_now),
            ErrorCode.BUSY,
            now=now,
        )
        return lease

    async def begin_request(
        self,
        *,
        owner_key: str,
        environment_id: str,
        question_id: UUID,
        request_hash: str,
        idempotency_key: UUID | None,
        now: datetime,
    ) -> Lease:
        if idempotency_key is not None:
            idem_pk = f"IDEMPOTENCY#{owner_key}#{environment_id}"
            existing_response = await self._call(
                "get_item",
                TableName=self._table,
                Key=self._key(idem_pk, str(idempotency_key)),
                ConsistentRead=True,
            )
            existing = self._decode(existing_response.get("Item"))
            if existing and _as_int(existing.get("expires_epoch", 0)) > self._epoch(now):
                payload = existing.get("payload")
                if isinstance(payload, str):
                    prior = IdempotencyRecord.model_validate_json(payload)
                    if prior.request_hash != request_hash:
                        raise self._error(ErrorCode.IDEMPOTENCY_CONFLICT, "Request key was reused.")
                    code = {
                        "active": ErrorCode.QUESTION_ACTIVE,
                        "completed": ErrorCode.REQUEST_COMPLETED,
                        "abandoned": ErrorCode.REQUEST_ABANDONED,
                    }[prior.status]
                    raise self._error(code, "This request key was already used.")
                raise self._error(ErrorCode.DEPENDENCY_UNAVAILABLE, "Request key is malformed.")
        lease_pk = f"LEASE#{owner_key}#{environment_id}"
        response = await self._call(
            "get_item",
            TableName=self._table,
            Key=self._key(lease_pk, "ACTIVE"),
            ConsistentRead=True,
        )
        prior = self._decode(response.get("Item"))
        prior_fence = _as_int(prior.get("fence", 0)) if prior else 0
        lease = Lease(
            lease_id=uuid4(),
            question_id=question_id,
            owner_key=owner_key,
            environment_id=environment_id,
            holder_id=uuid4(),
            fence=prior_fence + 1,
            expires_at=now + timedelta(seconds=self._lease_seconds),
            last_renewed_at=now,
        )
        question = QuestionRecord(
            question_id=question_id,
            owner_key=owner_key,
            environment_id=environment_id,
            lease_id=lease.lease_id,
            holder_id=lease.holder_id,
            fence=lease.fence,
            request_hash=request_hash,
            state="active",
            created_at=now,
            expires_at=now + timedelta(hours=24),
        )
        lease_values: dict[str, object] = {
            ":kind": "lease",
            ":lease": str(lease.lease_id),
            ":question": str(lease.question_id),
            ":owner": owner_key,
            ":site": environment_id,
            ":holder": str(lease.holder_id),
            ":expires": self._epoch(lease.expires_at),
            ":now": self._epoch(now),
            ":one": 1,
        }
        lease_condition = (
            "attribute_not_exists(pk)"
            if prior is None
            else ("fence = :prior AND expires_epoch <= :now")
        )
        if prior is not None:
            lease_values[":prior"] = prior_fence
        operations: list[object] = cast(
            list[object],
            [
                {
                    "Update": {
                        "TableName": self._table,
                        "Key": self._key(lease_pk, "ACTIVE"),
                        "UpdateExpression": (
                            "SET record_type = :kind, lease_id = :lease, question_id = :question, "
                            "owner_key = :owner, environment_id = :site, holder_id = :holder, "
                            "expires_epoch = :expires, last_renewed_epoch = :now ADD fence :one"
                        ),
                        "ConditionExpression": lease_condition,
                        "ExpressionAttributeValues": self._values(lease_values),
                    }
                },
                self._put_absent(
                    f"QUESTION#{question_id}",
                    "STATUS",
                    {
                        "record_type": "question",
                        "payload": question.model_dump_json(),
                        "state": "active",
                        "owner_key": owner_key,
                        "environment_id": environment_id,
                        "lease_id": str(lease.lease_id),
                        "holder_id": str(lease.holder_id),
                        "fence": lease.fence,
                        "expires_epoch": self._epoch(question.expires_at),
                    },
                ),
            ],
        )
        if idempotency_key is not None:
            idem = IdempotencyRecord(
                owner_key=owner_key,
                environment_id=environment_id,
                key=idempotency_key,
                request_hash=request_hash,
                question_id=question_id,
                status="active",
                expires_at=now + timedelta(minutes=10),
            )
            operations.append(
                {
                    "Put": {
                        "TableName": self._table,
                        "Item": self._encode(
                            {
                                "pk": f"IDEMPOTENCY#{owner_key}#{environment_id}",
                                "sk": str(idempotency_key),
                                "record_type": "idempotency",
                                "payload": idem.model_dump_json(),
                                "request_hash": request_hash,
                                "question_id": str(question_id),
                                "status": "active",
                                "expires_epoch": self._epoch(idem.expires_at),
                                TTL_ATTRIBUTE: self._epoch(idem.expires_at),
                            }
                        ),
                        "ConditionExpression": "attribute_not_exists(pk) OR expires_epoch <= :now",
                        "ExpressionAttributeValues": self._values({":now": self._epoch(now)}),
                    }
                }
            )
        await self._transact(
            lambda attempt_now: self._transaction_items_at(operations, attempt_now),
            ErrorCode.BUSY,
            now=now,
        )
        return lease

    async def open_budget(
        self,
        *,
        question_id: UUID,
        owner_key: str,
        environment_id: str,
        token_limit: int,
        expires_at: datetime,
        lease: Lease,
        operation_id: UUID,
        lease_supplier: Callable[[], Lease] | None = None,
    ) -> None:
        now = lease.last_renewed_at
        budget = QuestionBudget(
            question_id=question_id,
            token_limit=token_limit,
            reserved_tokens=0,
            charged_tokens=0,
            remaining_tokens=token_limit,
            version=1,
            overflow_tokens=0,
            state="open",
            owner_key=owner_key,
            environment_id=environment_id,
            created_at=now,
            expires_at=expires_at,
        )
        digest = sha256_hex({"question_id": str(question_id), "token_limit": token_limit})
        empty_budget_ttl = self._epoch(expires_at) + 86400
        prior_operation = await self._get_operation(operation_id)
        if prior_operation is not None:
            if prior_operation.get("input_hash") == digest:
                return
            raise self._error(ErrorCode.IDEMPOTENCY_CONFLICT, "Operation identity was reused.")
        ops = [
            self._put_absent(
                f"QUESTION#{question_id}",
                "BUDGET",
                {
                    "record_type": "budget",
                    "payload": budget.model_dump_json(),
                    "owner_key": owner_key,
                    "environment_id": environment_id,
                    "version": 1,
                    "remaining_tokens": token_limit,
                    "reserved_tokens": 0,
                    "charged_tokens": 0,
                    "lease_id": str(lease.lease_id),
                    "holder_id": str(lease.holder_id),
                    "fence": lease.fence,
                    "expires_epoch": self._epoch(expires_at),
                    TTL_ATTRIBUTE: empty_budget_ttl,
                    "budget_open_operation_id": str(operation_id),
                },
            ),
            self._put_absent(
                f"OP#{operation_id}",
                "V1",
                {
                    "record_type": "operation",
                    "kind": "budget_open",
                    "input_hash": digest,
                    "state": "completed",
                    "expires_epoch": self._epoch(expires_at),
                    TTL_ATTRIBUTE: empty_budget_ttl,
                },
            ),
            self._lease_condition(lease, now),
        ]
        await self._transact(
            lambda attempt_now: self._transaction_items_at(ops, attempt_now),
            ErrorCode.IDEMPOTENCY_CONFLICT,
            now=now,
            lease=lease,
            lease_supplier=lease_supplier,
        )

    async def open(
        self,
        *,
        question_id: UUID,
        owner_key: str,
        environment_id: str,
        token_limit: int,
        expires_at: datetime,
        lease: Lease,
        operation_id: UUID,
        lease_supplier: Callable[[], Lease] | None = None,
    ) -> None:
        await self.open_budget(
            question_id=question_id,
            owner_key=owner_key,
            environment_id=environment_id,
            token_limit=token_limit,
            expires_at=expires_at,
            lease=lease,
            operation_id=operation_id,
            lease_supplier=lease_supplier,
        )

    async def question_budget_remaining(self, question_id: UUID) -> int | None:
        response = await self._call(
            "get_item",
            TableName=self._table,
            Key=self._key(f"QUESTION#{question_id}", "BUDGET"),
            ConsistentRead=True,
        )
        item = self._decode(response.get("Item"))
        if item is None:
            return None
        return _as_int(item.get("remaining_tokens", 0))

    async def daily_judgment_blocked(
        self,
        *,
        owner_key: str,
        now: datetime,
        owner_daily_limit: int,
        service_daily_limit: int,
    ) -> bool:
        day = utc_day_start_epoch(now)
        owner_pk, owner_sk = owner_daily_key(owner_key, day)
        service_pk, service_sk = service_daily_key(day)
        owner_item = await self._get_item(owner_pk, owner_sk)
        service_item = await self._get_item(service_pk, service_sk)
        owner_used = _as_int(owner_item.get("tokens_used", 0)) if owner_item else 0
        service_used = _as_int(service_item.get("tokens_used", 0)) if service_item else 0
        return owner_used >= owner_daily_limit or service_used >= service_daily_limit

    async def daily_cannot_reserve(
        self,
        *,
        owner_key: str,
        tokens: int,
        now: datetime,
        owner_daily_limit: int,
        service_daily_limit: int,
    ) -> bool:
        if tokens <= 0:
            return False
        day = utc_day_start_epoch(now)
        owner_pk, owner_sk = owner_daily_key(owner_key, day)
        service_pk, service_sk = service_daily_key(day)
        owner_item = await self._get_item(owner_pk, owner_sk)
        service_item = await self._get_item(service_pk, service_sk)
        owner_used = _as_int(owner_item.get("tokens_used", 0)) if owner_item else 0
        service_used = _as_int(service_item.get("tokens_used", 0)) if service_item else 0
        return (
            owner_used + tokens > owner_daily_limit or service_used + tokens > service_daily_limit
        )

    async def _get_item(self, pk: str, sk: str) -> dict[str, object] | None:
        response = await self._call(
            "get_item",
            TableName=self._table,
            Key=self._key(pk, sk),
            ConsistentRead=True,
        )
        return self._decode(response.get("Item"))

    def _daily_token_claim_items(
        self,
        *,
        owner_key: str,
        tokens: int,
        now: datetime,
        owner_daily_limit: int,
        service_daily_limit: int,
    ) -> list[dict[str, object]]:
        day = utc_day_start_epoch(now)
        ttl = daily_ledger_ttl_epoch(day)
        owner_pk, owner_sk = owner_daily_key(owner_key, day)
        service_pk, service_sk = service_daily_key(day)
        claim = (
            "ADD tokens_used :tokens "
            f"SET record_type = :kind, {TTL_ATTRIBUTE} = :ttl, day_epoch = :day"
        )
        condition = (
            "(attribute_not_exists(tokens_used) AND :tokens <= :limit) OR tokens_used <= :ceiling"
        )
        values = {
            ":tokens": tokens,
            ":kind": "daily_tokens",
            ":ttl": ttl,
            ":day": day,
            ":ceiling": owner_daily_limit - tokens,
            ":limit": owner_daily_limit,
        }
        owner_update: dict[str, object] = {
            "Update": {
                "TableName": self._table,
                "Key": self._key(owner_pk, owner_sk),
                "UpdateExpression": claim,
                "ConditionExpression": condition,
                "ExpressionAttributeValues": self._values(values),
            }
        }
        service_update: dict[str, object] = {
            "Update": {
                "TableName": self._table,
                "Key": self._key(service_pk, service_sk),
                "UpdateExpression": claim,
                "ConditionExpression": condition,
                "ExpressionAttributeValues": self._values(
                    {
                        **values,
                        ":ceiling": service_daily_limit - tokens,
                        ":limit": service_daily_limit,
                    }
                ),
            }
        }
        return [owner_update, service_update]

    def _daily_token_refund_items(
        self, *, owner_key: str, refund: int, day_epoch: int
    ) -> list[dict[str, object]]:
        if refund <= 0:
            return []
        ttl = daily_ledger_ttl_epoch(day_epoch)
        owner_pk, owner_sk = owner_daily_key(owner_key, day_epoch)
        service_pk, service_sk = service_daily_key(day_epoch)
        adjust = f"ADD tokens_used :refund SET {TTL_ATTRIBUTE} = :ttl"
        values = {":refund": -refund, ":ttl": ttl, ":refund_abs": refund}
        return [
            {
                "Update": {
                    "TableName": self._table,
                    "Key": self._key(owner_pk, owner_sk),
                    "UpdateExpression": adjust,
                    "ConditionExpression": "tokens_used >= :refund_abs",
                    "ExpressionAttributeValues": self._values(values),
                }
            },
            {
                "Update": {
                    "TableName": self._table,
                    "Key": self._key(service_pk, service_sk),
                    "UpdateExpression": adjust,
                    "ConditionExpression": "tokens_used >= :refund_abs",
                    "ExpressionAttributeValues": self._values(values),
                }
            },
        ]

    async def reserve(
        self,
        *,
        question_id: UUID,
        topic_id: str,
        tokens: int,
        lease: Lease,
        operation_id: UUID,
        now: datetime,
        owner_daily_limit: int,
        service_daily_limit: int,
        lease_supplier: Callable[[], Lease] | None = None,
    ) -> Reservation:
        if tokens <= 0:
            raise ValueError("reservation must be positive")
        digest = sha256_hex(
            {"question_id": str(question_id), "topic_id": topic_id, "tokens": tokens}
        )
        prior_operation = await self._get_operation(operation_id)
        if prior_operation is not None:
            if prior_operation.get("input_hash") != digest:
                raise self._error(ErrorCode.IDEMPOTENCY_CONFLICT, "Operation identity was reused.")
            prior_payload = prior_operation.get("result_payload")
            if isinstance(prior_payload, str):
                return Reservation.model_validate_json(prior_payload)
            raise self._error(
                ErrorCode.DEPENDENCY_UNAVAILABLE, "Reservation result is unavailable."
            )
        key = self._key(f"QUESTION#{question_id}", "BUDGET")
        response = await self._call("get_item", TableName=self._table, Key=key, ConsistentRead=True)
        item = self._decode(response.get("Item"))
        if item is None:
            raise self._error(ErrorCode.BUDGET_EXCEEDED, "Question budget is unavailable.")
        budget = QuestionBudget.model_validate_json(str(item["payload"]))
        if budget.owner_key != lease.owner_key or budget.environment_id != lease.environment_id:
            raise self._error(ErrorCode.LEASE_LOST, "Budget belongs to another request.")
        if budget.state != "open" or budget.remaining_tokens < tokens:
            raise self._error(ErrorCode.BUDGET_EXCEEDED, "Question budget is exhausted.")
        charge_day = utc_day_start_epoch(now)
        reservation = Reservation(
            reservation_id=uuid4(),
            operation_id=operation_id,
            question_id=question_id,
            topic_id=topic_id,
            owner_key=lease.owner_key,
            environment_id=lease.environment_id,
            lease_id=lease.lease_id,
            holder_id=lease.holder_id,
            fence=lease.fence,
            reserved_tokens=tokens,
            state="reserved",
            created_at=now,
            hard_deadline_at=lease.last_renewed_at + timedelta(seconds=120),
            recover_after=max(lease.last_renewed_at + timedelta(seconds=120), lease.expires_at)
            + timedelta(seconds=35),
            daily_token_day_epoch=charge_day,
            version=1,
        )
        updated = budget.model_copy(
            update={
                "reserved_tokens": budget.reserved_tokens + tokens,
                "remaining_tokens": budget.remaining_tokens - tokens,
                "version": budget.version + 1,
            }
        )
        ticket = self._ticket(reservation)
        ops = [
            *self._daily_token_claim_items(
                owner_key=lease.owner_key,
                tokens=tokens,
                now=now,
                owner_daily_limit=owner_daily_limit,
                service_daily_limit=service_daily_limit,
            ),
            {
                "Update": {
                    "TableName": self._table,
                    "Key": key,
                    "UpdateExpression": (
                        "SET payload = :payload, remaining_tokens = :remaining, "
                        f"reserved_tokens = :reserved, version = :next REMOVE {TTL_ATTRIBUTE}"
                    ),
                    "ConditionExpression": (
                        "version = :old AND remaining_tokens >= :tokens AND expires_epoch > :now"
                    ),
                    "ExpressionAttributeValues": self._values(
                        {
                            ":payload": updated.model_dump_json(),
                            ":remaining": updated.remaining_tokens,
                            ":reserved": updated.reserved_tokens,
                            ":next": updated.version,
                            ":old": budget.version,
                            ":tokens": tokens,
                            ":now": self._epoch(now),
                        }
                    ),
                }
            },
            self._put_absent(
                f"QUESTION#{question_id}",
                f"RESERVATION#{reservation.reservation_id}",
                {
                    "record_type": "reservation",
                    "payload": reservation.model_dump_json(),
                    "state": "reserved",
                    "version": 1,
                    "owner_key": lease.owner_key,
                    "environment_id": lease.environment_id,
                    "lease_id": str(reservation.lease_id),
                    "holder_id": str(reservation.holder_id),
                    "fence": reservation.fence,
                    "expires_epoch": self._epoch(reservation.recover_after) + 86400,
                    "daily_token_day_epoch": charge_day,
                },
            ),
            *(
                [self._operation_ttl_remove(budget_open_operation_id, "budget_open")]
                if isinstance(budget_open_operation_id := item.get("budget_open_operation_id"), str)
                else []
            ),
            self._put_absent(
                f"RECOVERY#{ticket.bucket}",
                f"{question_id}#{reservation.reservation_id}",
                {
                    "record_type": "recovery_ticket",
                    "payload": ticket.model_dump_json(),
                    "due_epoch": self._epoch(ticket.due_at),
                    "version": ticket.version,
                },
            ),
            self._put_absent(
                f"OP#{operation_id}",
                "V1",
                {
                    "record_type": "operation",
                    "kind": "reserve",
                    "input_hash": digest,
                    "state": "completed",
                    "terminal_result_hash": sha256_hex(reservation),
                    "result_payload": reservation.model_dump_json(),
                    "expires_epoch": self._epoch(reservation.recover_after) + 86400,
                },
            ),
            self._lease_condition(lease, now),
        ]
        await self._transact(
            lambda attempt_now: self._transaction_items_at(ops, attempt_now),
            ErrorCode.BUDGET_EXCEEDED,
            now=now,
            lease=lease,
            lease_supplier=lease_supplier,
        )
        return reservation

    async def mark_started(
        self,
        reservation: Reservation,
        *,
        lease: Lease,
        operation_id: UUID,
        now: datetime,
        lease_supplier: Callable[[], Lease] | None = None,
    ) -> Reservation:
        digest = sha256_hex(
            {"reservation_id": str(reservation.reservation_id), "fence": lease.fence}
        )
        prior_operation = await self._get_operation(operation_id)
        if prior_operation is not None:
            if prior_operation.get("input_hash") != digest:
                raise self._error(ErrorCode.IDEMPOTENCY_CONFLICT, "Operation identity was reused.")
            response = await self._call(
                "get_item",
                TableName=self._table,
                Key=self._key(
                    f"QUESTION#{reservation.question_id}",
                    f"RESERVATION#{reservation.reservation_id}",
                ),
                ConsistentRead=True,
            )
            prior_item = self._decode(response.get("Item"))
            prior_payload = prior_item.get("payload") if prior_item else None
            if isinstance(prior_payload, str):
                return Reservation.model_validate_json(prior_payload)
            raise self._error(
                ErrorCode.DEPENDENCY_UNAVAILABLE, "Reservation result is unavailable."
            )
        started = reservation.model_copy(
            update={"state": "started", "started_at": now, "version": reservation.version + 1}
        )
        ticket = self._ticket(started)
        old_ticket = self._ticket(reservation)
        ops = [
            {
                "Update": {
                    "TableName": self._table,
                    "Key": self._key(
                        f"QUESTION#{reservation.question_id}",
                        f"RESERVATION#{reservation.reservation_id}",
                    ),
                    "UpdateExpression": (
                        "SET payload = :payload, #state = :started, version = :next, "
                        "mark_started_operation_id = :operation"
                    ),
                    "ConditionExpression": (
                        "#state = :reserved AND version = :old AND lease_id = :lease "
                        "AND holder_id = :holder AND fence = :fence"
                    ),
                    "ExpressionAttributeNames": {"#state": "state"},
                    "ExpressionAttributeValues": self._values(
                        {
                            ":payload": started.model_dump_json(),
                            ":started": "started",
                            ":reserved": "reserved",
                            ":next": started.version,
                            ":old": reservation.version,
                            ":lease": str(lease.lease_id),
                            ":holder": str(lease.holder_id),
                            ":fence": lease.fence,
                            ":operation": str(operation_id),
                        }
                    ),
                }
            },
            self._put_absent(
                f"OP#{operation_id}",
                "V1",
                {
                    "record_type": "operation",
                    "kind": "mark_started",
                    "input_hash": digest,
                    "result_payload": started.model_dump_json(),
                    "state": "completed",
                    "expires_epoch": self._epoch(started.recover_after) + 86400,
                },
            ),
            self._lease_condition(lease, now),
        ]
        if old_ticket.bucket == ticket.bucket:
            ops.append(
                {
                    "Put": {
                        "TableName": self._table,
                        "Item": self._encode(
                            {
                                "pk": f"RECOVERY#{ticket.bucket}",
                                "sk": f"{ticket.question_id}#{ticket.reservation_id}",
                                "record_type": "recovery_ticket",
                                "payload": ticket.model_dump_json(),
                                "due_epoch": self._epoch(ticket.due_at),
                                "version": ticket.version,
                            }
                        ),
                        "ConditionExpression": "version = :old",
                        "ExpressionAttributeValues": self._values({":old": old_ticket.version}),
                    }
                }
            )
        else:
            ops.extend(
                [
                    {
                        "Delete": {
                            "TableName": self._table,
                            "Key": self._key(
                                f"RECOVERY#{old_ticket.bucket}",
                                f"{old_ticket.question_id}#{old_ticket.reservation_id}",
                            ),
                            "ConditionExpression": "version = :old",
                            "ExpressionAttributeValues": self._values({":old": old_ticket.version}),
                        }
                    },
                    self._put_absent(
                        f"RECOVERY#{ticket.bucket}",
                        f"{ticket.question_id}#{ticket.reservation_id}",
                        {
                            "record_type": "recovery_ticket",
                            "payload": ticket.model_dump_json(),
                            "due_epoch": self._epoch(ticket.due_at),
                            "version": ticket.version,
                        },
                    ),
                ]
            )
        await self._transact(
            lambda attempt_now: self._transaction_items_at(ops, attempt_now),
            ErrorCode.LEASE_LOST,
            now=now,
            lease=lease,
            lease_supplier=lease_supplier,
            lease_margin_seconds=8,
        )
        return started

    async def settle(
        self,
        reservation: Reservation,
        *,
        charged_tokens: int | None,
        lease: Lease,
        operation_id: UUID,
        now: datetime,
        release: bool = False,
        lease_supplier: Callable[[], Lease] | None = None,
    ) -> None:
        # A shared terminalizer is used by normal settle and recovery to keep liability atomic.
        await self._terminalize(
            reservation,
            charged_tokens,
            lease=lease,
            operation_id=operation_id,
            now=now,
            recovery=False,
            released=release,
            lease_supplier=lease_supplier,
        )

    async def commit_completion(
        self,
        command: CompletionCommand,
        *,
        lease: Lease,
        now: datetime,
        operation_id: UUID,
        lease_supplier: Callable[[], Lease] | None = None,
    ) -> CompletionReceipt:
        input_hash = sha256_hex(command)
        prior_operation = await self._get_operation(operation_id)
        if prior_operation is not None:
            if prior_operation.get("input_hash") != input_hash:
                raise self._error(ErrorCode.IDEMPOTENCY_CONFLICT, "Operation identity was reused.")
            recovered = await self._completion_for_operation(command, prior_operation)
            if recovered is None:
                raise self._error(
                    ErrorCode.DEPENDENCY_UNAVAILABLE, "Completion result is unavailable."
                )
            return recovered
        self._validate_completion_bindings(command, lease, now)
        budget_response = await self._call(
            "get_item",
            TableName=self._table,
            Key=self._key(f"QUESTION#{command.question_id}", "BUDGET"),
            ConsistentRead=True,
        )
        budget_item = self._decode(budget_response.get("Item"))
        budget: QuestionBudget | None = None
        budget_open_operation_id: str | None = None
        if budget_item is not None:
            budget = QuestionBudget.model_validate_json(str(budget_item["payload"]))
            if budget.reserved_tokens:
                raise self._error(
                    ErrorCode.LEASE_LOST, "Question still has unresolved budget reservations."
                )
            operation_id_value = budget_item.get("budget_open_operation_id")
            if isinstance(operation_id_value, str):
                budget_open_operation_id = operation_id_value
        completion_id = uuid4()
        receipt = CompletionReceipt(
            completion_id=completion_id,
            question_id=command.question_id,
            committed_at=now,
            followup_id=command.followup.followup_id if command.followup else None,
            followup_revision=command.followup.revision if command.followup else None,
            answer_metadata_sha256=command.metadata_sha256,
        )
        ops: list[dict[str, object]] = [
            {
                "Update": {
                    "TableName": self._table,
                    "Key": self._key(f"QUESTION#{command.question_id}", "STATUS"),
                    "UpdateExpression": (
                        "SET #state = :completed, completion_id = :completion, "
                        f"answer_status = :status, {TTL_ATTRIBUTE} = :ttl"
                    ),
                    "ConditionExpression": (
                        "#state = :active AND lease_id = :lease AND holder_id = :holder "
                        "AND fence = :fence AND owner_key = :owner "
                        "AND environment_id = :site AND expires_epoch > :now"
                    ),
                    "ExpressionAttributeNames": {"#state": "state"},
                    "ExpressionAttributeValues": self._values(
                        {
                            ":completed": "completed",
                            ":active": "active",
                            ":completion": str(completion_id),
                            ":status": str(command.answer_status),
                            ":ttl": self._epoch(now) + 86400,
                            ":lease": str(lease.lease_id),
                            ":holder": str(lease.holder_id),
                            ":fence": lease.fence,
                            ":owner": command.owner_key,
                            ":site": command.environment_id,
                            ":now": self._epoch(now),
                        }
                    ),
                }
            },
            self._put_absent(
                f"QUESTION#{command.question_id}",
                "COMPLETION",
                {
                    "record_type": "completion",
                    "payload": receipt.model_dump_json(),
                    "completion_id": str(completion_id),
                    "metadata_sha256": command.metadata_sha256,
                    "expires_epoch": self._epoch(now) + 86400,
                    TTL_ATTRIBUTE: self._epoch(now) + 86400,
                },
            ),
            self._put_absent(
                f"OP#{operation_id}",
                "V1",
                {
                    "record_type": "operation",
                    "kind": "complete",
                    "input_hash": sha256_hex(command),
                    "terminal_result_hash": sha256_hex(receipt),
                    "state": "completed",
                    "expires_epoch": self._epoch(now) + 86400,
                    TTL_ATTRIBUTE: self._epoch(now) + 86400,
                },
            ),
            self._lease_condition(lease, now),
        ]
        if command.followup is not None:
            record = command.followup
            ops.append(
                self._put_absent(
                    f"PLAN#{record.followup_id}",
                    "V1",
                    {
                        "record_type": "plan",
                        "payload": record.model_dump_json(),
                        "owner_key": record.owner_key,
                        "environment_id": record.environment_id,
                        "expires_epoch": self._epoch(record.expires_at),
                        TTL_ATTRIBUTE: self._epoch(record.expires_at),
                    },
                )
            )
        if command.idempotency is not None:
            idem = command.idempotency
            ops.append(
                {
                    "Update": {
                        "TableName": self._table,
                        "Key": self._key(
                            f"IDEMPOTENCY#{idem.owner_key}#{idem.environment_id}", str(idem.key)
                        ),
                        "UpdateExpression": "SET #status = :completed, completion_id = :completion",
                        "ConditionExpression": "#status = :active AND question_id = :question",
                        "ExpressionAttributeNames": {"#status": "status"},
                        "ExpressionAttributeValues": self._values(
                            {
                                ":completed": "completed",
                                ":active": "active",
                                ":completion": str(completion_id),
                                ":question": str(command.question_id),
                            }
                        ),
                    }
                }
            )
        if budget is not None:
            closed_budget = budget.model_copy(
                update={"state": "closed", "version": budget.version + 1}
            )
            terminal_expires = self._epoch(now) + 86400
            ops.append(
                {
                    "Update": {
                        "TableName": self._table,
                        "Key": self._key(f"QUESTION#{command.question_id}", "BUDGET"),
                        "UpdateExpression": (
                            f"SET payload = :payload, version = :next, {TTL_ATTRIBUTE} = :ttl"
                        ),
                        "ConditionExpression": "version = :version AND reserved_tokens = :zero",
                        "ExpressionAttributeValues": self._values(
                            {
                                ":payload": closed_budget.model_dump_json(),
                                ":ttl": terminal_expires,
                                ":version": budget.version,
                                ":next": closed_budget.version,
                                ":zero": 0,
                            }
                        ),
                    }
                }
            )
            if budget_open_operation_id is not None:
                ops.append(
                    self._operation_ttl_update(
                        budget_open_operation_id, "budget_open", terminal_expires
                    )
                )
        try:
            await self._transact(
                lambda attempt_now: self._transaction_items_at(ops, attempt_now),
                ErrorCode.LEASE_LOST,
                now=now,
                lease=lease,
                lease_supplier=lease_supplier,
                lease_margin_seconds=8,
            )
        except StateFailure:
            recovered = await self._recover_completion(operation_id, command, input_hash)
            if recovered is not None:
                return recovered
            raise
        except Exception:
            recovered = await self._recover_completion(operation_id, command, input_hash)
            if recovered is not None:
                return recovered
            raise self._error(
                ErrorCode.DEPENDENCY_UNAVAILABLE, "State storage is unavailable."
            ) from None
        return receipt

    async def commit(
        self,
        command: CompletionCommand,
        *,
        lease: Lease,
        now: datetime,
        operation_id: UUID,
        lease_supplier: Callable[[], Lease] | None = None,
    ) -> CompletionReceipt:
        return await self.commit_completion(
            command,
            lease=lease,
            now=now,
            operation_id=operation_id,
            lease_supplier=lease_supplier,
        )

    async def _recover_completion(
        self, operation_id: UUID, command: CompletionCommand, input_hash: str
    ) -> CompletionReceipt | None:
        operation = await self._get_operation(operation_id)
        if operation is None:
            return None
        if operation.get("input_hash") != input_hash:
            raise self._error(ErrorCode.IDEMPOTENCY_CONFLICT, "Operation identity was reused.")
        return await self._completion_for_operation(command, operation)

    async def _completion_for_operation(
        self, command: CompletionCommand, operation: dict[str, object]
    ) -> CompletionReceipt | None:
        if operation.get("state") != "completed":
            return None
        response = await self._call(
            "get_item",
            TableName=self._table,
            Key=self._key(f"QUESTION#{command.question_id}", "COMPLETION"),
            ConsistentRead=True,
        )
        item = self._decode(response.get("Item"))
        if item is None or not isinstance(item.get("payload"), str):
            return None
        receipt = CompletionReceipt.model_validate_json(str(item["payload"]))
        if (
            receipt.question_id != command.question_id
            or receipt.answer_metadata_sha256 != command.metadata_sha256
            or operation.get("terminal_result_hash") != sha256_hex(receipt)
        ):
            return None
        return receipt

    def _validate_completion_bindings(
        self, command: CompletionCommand, lease: Lease, now: datetime
    ) -> None:
        if (
            command.question_id != lease.question_id
            or command.owner_key != lease.owner_key
            or command.environment_id != lease.environment_id
        ):
            raise self._error(ErrorCode.LEASE_LOST, "Request lease was lost.")
        record = command.followup
        if record is not None and (
            record.owner_key != command.owner_key
            or record.environment_id != command.environment_id
            or record.plan.question_id != command.question_id
            or record.plan.owner_key != command.owner_key
            or record.plan.environment_id != command.environment_id
            or self._epoch(record.expires_at) <= self._epoch(now)
        ):
            raise self._error(ErrorCode.INVALID_CONTINUATION, "Follow-up binding is invalid.")
        entry = command.idempotency
        if entry is not None and (
            entry.owner_key != command.owner_key
            or entry.environment_id != command.environment_id
            or entry.question_id != command.question_id
            or entry.status != "active"
        ):
            raise self._error(ErrorCode.IDEMPOTENCY_CONFLICT, "Request key binding is invalid.")

    async def reconcile(
        self,
        *,
        now: datetime,
        bucket: int,
        after: str | None = None,
        page_size: int = 100,
        question_id: UUID | None = None,
        reservation_id: UUID | None = None,
    ) -> RecoveryPage:
        if not 0 <= bucket < 128 or not 1 <= page_size <= 1000:
            raise ValueError("invalid recovery page")
        if (question_id is None) != (reservation_id is None):
            raise ValueError("reservation-scoped recovery requires question and reservation ids")
        if reservation_id is not None and after is not None:
            raise ValueError("reservation-scoped recovery does not accept a continuation key")
        key_condition = "pk = :pk"
        values = {":pk": f"RECOVERY#{bucket}"}
        if reservation_id is not None:
            key_condition += " AND sk = :sk"
            values[":sk"] = f"{question_id}#{reservation_id}"
        kwargs: dict[str, object] = {
            "TableName": self._table,
            "KeyConditionExpression": key_condition,
            "ExpressionAttributeValues": self._values(values),
            "Limit": page_size,
            "ConsistentRead": True,
        }
        if after:
            kwargs["ExclusiveStartKey"] = {"pk": {"S": f"RECOVERY#{bucket}"}, "sk": {"S": after}}
        response = await self._call("query", **kwargs)
        raw_items = response.get("Items", [])
        if not isinstance(raw_items, list):
            raw_items = []
        typed_items = cast(list[object], raw_items)
        records = [
            self._decode(cast(dict[object, object], value))
            for value in typed_items
            if isinstance(value, dict)
        ]
        due = [
            item
            for item in records
            if item and _as_int(item.get("due_epoch", 0)) <= self._epoch(now)
        ]
        errors: list[ErrorCode] = []
        terminalized = 0
        for item in due:
            # Each ticket is claimed by conditional version transitions in _terminalize.
            try:
                payload = item.get("payload")
                if isinstance(payload, str):
                    ticket = RecoveryTicket.model_validate_json(payload)
                    if reservation_id is not None and (
                        ticket.question_id != question_id or ticket.reservation_id != reservation_id
                    ):
                        continue
                    found = await self._call(
                        "get_item",
                        TableName=self._table,
                        Key=self._key(
                            f"QUESTION#{ticket.question_id}", f"RESERVATION#{ticket.reservation_id}"
                        ),
                        ConsistentRead=True,
                    )
                    raw = self._decode(found.get("Item"))
                    if raw and isinstance(raw.get("payload"), str):
                        payload = raw["payload"]
                        if isinstance(payload, str):
                            reservation = Reservation.model_validate_json(payload)
                        else:
                            continue
                        await self._terminalize(
                            reservation,
                            0 if reservation.state == "reserved" else None,
                            lease=None,
                            operation_id=uuid4(),
                            now=now,
                            recovery=True,
                        )
                        terminalized += 1
            except StateFailure as exc:
                if exc.code not in {ErrorCode.LEASE_LOST, ErrorCode.QUESTION_ACTIVE}:
                    errors.append(exc.code)
        last = response.get("LastEvaluatedKey")
        last_item = self._decode(last)
        next_after = str(last_item["sk"]) if last_item and "sk" in last_item else None
        return RecoveryPage(
            after=next_after, examined=len(records), terminalized=terminalized, errors=errors
        )

    async def publish_recovery_gauges(self, now: datetime) -> None:
        if self._metrics is None:
            return
        now_epoch = self._epoch(now)
        backlog = 0
        max_lag = 0.0
        for bucket in range(128):
            cursor: str | None = None
            while True:
                kwargs: dict[str, object] = {
                    "TableName": self._table,
                    "KeyConditionExpression": "pk = :pk",
                    "ExpressionAttributeValues": self._values({":pk": f"RECOVERY#{bucket}"}),
                    "ConsistentRead": True,
                }
                if cursor:
                    kwargs["ExclusiveStartKey"] = {
                        "pk": {"S": f"RECOVERY#{bucket}"},
                        "sk": {"S": cursor},
                    }
                response = await self._call("query", **kwargs)
                raw_items = response.get("Items", [])
                if not isinstance(raw_items, list):
                    raw_items = []
                for value in cast(list[object], raw_items):
                    if not isinstance(value, dict):
                        continue
                    item = self._decode(cast(dict[object, object], value))
                    if not item:
                        continue
                    due_epoch = _as_int(item.get("due_epoch", 0))
                    if due_epoch > now_epoch:
                        continue
                    backlog += 1
                    max_lag = max(max_lag, float(now_epoch - due_epoch))
                last = response.get("LastEvaluatedKey")
                last_item = self._decode(last)
                cursor = str(last_item["sk"]) if last_item and "sk" in last_item else None
                if cursor is None:
                    break
        emit_recovery_backlog(self._metrics, backlog)
        emit_recovery_lag_seconds(self._metrics, max_lag)

    async def _terminalize(
        self,
        reservation: Reservation,
        charged_tokens: int | None,
        *,
        lease: Lease | None,
        operation_id: UUID,
        now: datetime,
        recovery: bool,
        released: bool = False,
        lease_supplier: Callable[[], Lease] | None = None,
    ) -> None:
        current_response = await self._call(
            "get_item",
            TableName=self._table,
            Key=self._key(
                f"QUESTION#{reservation.question_id}",
                f"RESERVATION#{reservation.reservation_id}",
            ),
            ConsistentRead=True,
        )
        current_item = self._decode(current_response.get("Item"))
        current_payload = current_item.get("payload") if current_item is not None else None
        if current_item is None or not isinstance(current_payload, str):
            raise self._error(ErrorCode.LEASE_LOST, "Reservation is unavailable.")
        reservation = Reservation.model_validate_json(current_payload)
        if reservation.state in {"settled", "released", "unknown_charged"}:
            if released or reservation.state == "released":
                expected = 0
            elif charged_tokens is not None:
                expected = charged_tokens
            elif reservation.state == "unknown_charged":
                expected = reservation.reserved_tokens
            else:
                expected = reservation.charged_tokens
            if reservation.charged_tokens != expected:
                raise self._error(
                    ErrorCode.IDEMPOTENCY_CONFLICT,
                    "Reservation was already settled with different usage.",
                )
            return
        operation = await self._get_operation(operation_id)
        request_hash = sha256_hex(
            {"reservation_id": str(reservation.reservation_id), "charged": charged_tokens}
        )
        if operation is not None:
            if operation.get("input_hash") == request_hash:
                return
            raise self._error(ErrorCode.IDEMPOTENCY_CONFLICT, "Operation identity was reused.")
        budget_key = self._key(f"QUESTION#{reservation.question_id}", "BUDGET")
        response = await self._call(
            "get_item", TableName=self._table, Key=budget_key, ConsistentRead=True
        )
        raw_budget = self._decode(response.get("Item"))
        if raw_budget is None:
            raise self._error(ErrorCode.LEASE_LOST, "Question budget is unavailable.")
        budget = QuestionBudget.model_validate_json(str(raw_budget["payload"]))
        budget_open_operation_id = raw_budget.get("budget_open_operation_id")
        actual = (
            0
            if released
            else reservation.reserved_tokens
            if charged_tokens is None
            else charged_tokens
        )
        overflow = max(0, actual - reservation.reserved_tokens)
        refund = max(0, reservation.reserved_tokens - actual)
        state = (
            "released"
            if released
            else "unknown_charged"
            if charged_tokens is None
            else "released"
            if actual == 0
            else "settled"
        )
        updated_budget = budget.model_copy(
            update={
                "reserved_tokens": budget.reserved_tokens - reservation.reserved_tokens,
                "charged_tokens": budget.charged_tokens + actual,
                "remaining_tokens": 0 if overflow else budget.remaining_tokens + refund,
                "overflow_tokens": budget.overflow_tokens + overflow,
                "state": (
                    "closed"
                    if overflow
                    or (recovery and budget.reserved_tokens == reservation.reserved_tokens)
                    else budget.state
                ),
                "version": budget.version + 1,
            }
        )
        updated_reservation = reservation.model_copy(
            update={
                "charged_tokens": actual,
                "state": state,
                "version": reservation.version + 1,
            }
        )
        ticket = self._ticket(reservation)
        terminal_expires = self._epoch(now) + 86400
        budget_update = (
            "SET payload = :payload, reserved_tokens = :reserved, "
            "charged_tokens = :charged, remaining_tokens = :remaining, version = :next"
        )
        budget_values: dict[str, object] = {
            ":payload": updated_budget.model_dump_json(),
            ":reserved": updated_budget.reserved_tokens,
            ":charged": updated_budget.charged_tokens,
            ":remaining": updated_budget.remaining_tokens,
            ":next": updated_budget.version,
            ":old": budget.version,
            ":bound": reservation.reserved_tokens,
        }
        if updated_budget.reserved_tokens == 0:
            budget_update = f"{budget_update}, {TTL_ATTRIBUTE} = :budget_ttl"
            budget_values[":budget_ttl"] = terminal_expires
        ops: list[dict[str, object]] = [
            *self._daily_token_refund_items(
                owner_key=reservation.owner_key,
                refund=refund,
                day_epoch=reservation.daily_token_day_epoch
                or utc_day_start_epoch(reservation.created_at),
            ),
            {
                "Update": {
                    "TableName": self._table,
                    "Key": budget_key,
                    "UpdateExpression": budget_update,
                    "ConditionExpression": "version = :old AND reserved_tokens >= :bound",
                    "ExpressionAttributeValues": self._values(budget_values),
                }
            },
            {
                "Update": {
                    "TableName": self._table,
                    "Key": self._key(
                        f"QUESTION#{reservation.question_id}",
                        f"RESERVATION#{reservation.reservation_id}",
                    ),
                    "UpdateExpression": (
                        "SET payload = :payload, #state = :terminal, charged_tokens = :charged, "
                        f"version = :next, expires_epoch = :expires, {TTL_ATTRIBUTE} = :expires"
                    ),
                    "ConditionExpression": (
                        "version = :old AND #state IN (:started, :reserved) "
                        "AND lease_id = :lease AND holder_id = :holder AND fence = :fence"
                    ),
                    "ExpressionAttributeNames": {"#state": "state"},
                    "ExpressionAttributeValues": self._values(
                        {
                            ":payload": updated_reservation.model_dump_json(),
                            ":terminal": state,
                            ":started": "started",
                            ":reserved": "reserved",
                            ":charged": actual,
                            ":next": updated_reservation.version,
                            ":old": reservation.version,
                            ":lease": str(reservation.lease_id),
                            ":holder": str(reservation.holder_id),
                            ":fence": reservation.fence,
                            ":expires": terminal_expires,
                        }
                    ),
                }
            },
            {
                "Delete": {
                    "TableName": self._table,
                    "Key": self._key(
                        f"RECOVERY#{ticket.bucket}", f"{ticket.question_id}#{ticket.reservation_id}"
                    ),
                    "ConditionExpression": "version = :version",
                    "ExpressionAttributeValues": self._values({":version": ticket.version}),
                }
            },
            self._put_absent(
                f"OP#{operation_id}",
                "V1",
                {
                    "record_type": "operation",
                    "kind": "reconcile" if recovery else "settle",
                    "input_hash": sha256_hex(
                        {
                            "reservation_id": str(reservation.reservation_id),
                            "charged": charged_tokens,
                        }
                    ),
                    "terminal_result_hash": sha256_hex(updated_reservation),
                    "state": "completed",
                    "expires_epoch": terminal_expires,
                    TTL_ATTRIBUTE: terminal_expires,
                },
            ),
        ]
        if lease is not None:
            ops.append(self._lease_condition(lease, now))
        else:
            # Recovery may refund a never-started reservation only after its original lease expired.
            ops.append(
                {
                    "ConditionCheck": {
                        "TableName": self._table,
                        "Key": self._key(
                            f"LEASE#{reservation.owner_key}#{reservation.environment_id}", "ACTIVE"
                        ),
                        "ConditionExpression": (
                            "attribute_not_exists(pk) OR lease_id <> :lease "
                            "OR holder_id <> :holder OR fence <> :fence OR expires_epoch <= :now"
                        ),
                        "ExpressionAttributeValues": self._values(
                            {
                                ":lease": str(reservation.lease_id),
                                ":holder": str(reservation.holder_id),
                                ":fence": reservation.fence,
                                ":now": self._epoch(now),
                            }
                        ),
                    }
                }
            )
        ops.append(
            self._operation_ttl_update(reservation.operation_id, "reserve", terminal_expires)
        )
        if updated_budget.reserved_tokens == 0 and isinstance(budget_open_operation_id, str):
            ops.append(
                self._operation_ttl_update(
                    budget_open_operation_id, "budget_open", terminal_expires
                )
            )
        started_operation_id = current_item.get("mark_started_operation_id")
        if isinstance(started_operation_id, str):
            ops.append(
                self._operation_ttl_update(started_operation_id, "mark_started", terminal_expires)
            )
        await self._transact(
            lambda attempt_now: self._transaction_items_at(ops, attempt_now),
            ErrorCode.LEASE_LOST,
            now=now,
            lease=lease,
            lease_supplier=lease_supplier,
        )

    def _lease_condition(self, lease: Lease, now: datetime) -> dict[str, object]:
        return {
            "ConditionCheck": {
                "TableName": self._table,
                "Key": self._key(f"LEASE#{lease.owner_key}#{lease.environment_id}", "ACTIVE"),
                "ConditionExpression": (
                    "lease_id = :lease AND holder_id = :holder AND fence = :fence "
                    "AND question_id = :question AND expires_epoch > :now"
                ),
                "ExpressionAttributeValues": self._values(
                    {
                        ":lease": str(lease.lease_id),
                        ":holder": str(lease.holder_id),
                        ":fence": lease.fence,
                        ":question": str(lease.question_id),
                        ":now": self._epoch(now),
                    }
                ),
            }
        }

    def _put_absent(self, pk: str, sk: str, values: dict[str, object]) -> dict[str, object]:
        item = {"pk": pk, "sk": sk, **values}
        return {
            "Put": {
                "TableName": self._table,
                "Item": self._encode(item),
                "ConditionExpression": "attribute_not_exists(pk)",
            }
        }

    def _operation_ttl_update(
        self, operation_id: str | UUID, kind: str, expires_epoch: int
    ) -> dict[str, object]:
        return {
            "Update": {
                "TableName": self._table,
                "Key": self._key(f"OP#{operation_id}", "V1"),
                "UpdateExpression": f"SET {TTL_ATTRIBUTE} = :ttl",
                "ConditionExpression": "#state = :completed AND kind = :kind",
                "ExpressionAttributeNames": {"#state": "state"},
                "ExpressionAttributeValues": self._values(
                    {":ttl": expires_epoch, ":completed": "completed", ":kind": kind}
                ),
            }
        }

    def _operation_ttl_remove(self, operation_id: str | UUID, kind: str) -> dict[str, object]:
        return {
            "Update": {
                "TableName": self._table,
                "Key": self._key(f"OP#{operation_id}", "V1"),
                "UpdateExpression": f"REMOVE {TTL_ATTRIBUTE}",
                "ConditionExpression": "#state = :completed AND kind = :kind",
                "ExpressionAttributeNames": {"#state": "state"},
                "ExpressionAttributeValues": self._values(
                    {":completed": "completed", ":kind": kind}
                ),
            }
        }

    async def _transact(
        self,
        build_items: Callable[[datetime], Sequence[object]],
        conflict: ErrorCode,
        *,
        now: datetime,
        lease: Lease | None = None,
        lease_supplier: Callable[[], Lease] | None = None,
        lease_margin_seconds: int = 0,
    ) -> None:
        for attempt in range(2):
            try:
                async with self._io:
                    attempt_now = self._clock.now() if self._clock is not None else now
                    attempt_lease = lease_supplier() if lease_supplier is not None else lease
                    if attempt_lease is not None and attempt_lease.expires_at <= (
                        attempt_now + timedelta(seconds=lease_margin_seconds)
                    ):
                        raise self._error(
                            ErrorCode.LEASE_LOST, "Request lease is too close to expiry."
                        )
                    await asyncio.to_thread(
                        self._client.transact_write_items,
                        TransactItems=build_items(attempt_now),
                        ReturnConsumedCapacity="NONE",
                    )
                return
            except ClientError as exc:
                if self._transaction_conflict(exc) and attempt == 0:
                    await asyncio.sleep(0.05)
                    continue
                if self._transaction_condition_failed(exc):
                    raise self._error(
                        conflict, "State transaction condition was not met."
                    ) from None
                raise self._error(
                    ErrorCode.DEPENDENCY_UNAVAILABLE, "State storage is unavailable."
                ) from None

    def _transaction_items_at(self, items: Sequence[object], now: datetime) -> Sequence[object]:
        now_value = self._serializer.serialize(self._epoch(now))

        def rebuild(value: object) -> object:
            if isinstance(value, dict):
                return {
                    key: now_value if key == ":now" else rebuild(item)
                    for key, item in cast(dict[object, object], value).items()
                }
            if isinstance(value, list):
                return [rebuild(item) for item in cast(list[object], value)]
            return value

        return cast(Sequence[object], rebuild(list(items)))

    async def _call(self, method: str, **kwargs: object) -> dict[str, object]:
        async with self._io:
            if method == "get_item":
                result = await asyncio.to_thread(self._client.get_item, **kwargs)
            elif method == "put_item":
                result = await asyncio.to_thread(self._client.put_item, **kwargs)
            elif method == "update_item":
                result = await asyncio.to_thread(self._client.update_item, **kwargs)
            elif method == "query":
                result = await asyncio.to_thread(self._client.query, **kwargs)
            elif method == "transact_write_items":
                result = await asyncio.to_thread(self._client.transact_write_items, **kwargs)
            else:
                raise ValueError("unsupported DynamoDB operation")
        return result

    async def _get_operation(self, operation_id: UUID) -> dict[str, object] | None:
        response = await self._call(
            "get_item",
            TableName=self._table,
            Key=self._key(f"OP#{operation_id}", "V1"),
            ConsistentRead=True,
        )
        return self._decode(response.get("Item"))

    def _encode(self, item: dict[str, object]) -> dict[str, object]:
        return {key: self._serialize(value) for key, value in item.items()}

    def _values(self, values: Mapping[str, object]) -> dict[str, object]:
        return {key: self._serialize(value) for key, value in values.items()}

    def _serialize(self, value: object) -> object:
        return self._serializer.serialize(value)

    def _decode(self, raw: object) -> dict[str, object] | None:
        if not isinstance(raw, dict):
            return None
        try:
            decoded: dict[str, object] = {}
            typed_raw = cast(dict[object, object], raw)
            for key, value in typed_raw.items():
                if not isinstance(key, str):
                    return None
                decoded[key] = self._deserializer.deserialize(value)
            return decoded
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _key(pk: str, sk: str) -> dict[str, object]:
        return {"pk": {"S": pk}, "sk": {"S": sk}}

    @staticmethod
    def _epoch(value: datetime) -> int:
        if value.tzinfo is None:
            raise ValueError("state timestamps must be timezone-aware")
        return int(value.astimezone(UTC).timestamp())

    @staticmethod
    def _ticket(reservation: Reservation):
        from ai_soc.contracts.models import RecoveryTicket

        due = int(reservation.recover_after.timestamp())
        return RecoveryTicket(
            bucket=(due // 30) % 128,
            due_at=reservation.recover_after,
            question_id=reservation.question_id,
            reservation_id=reservation.reservation_id,
            version=reservation.version,
        )

    @staticmethod
    def _conditional(error: ClientError) -> bool:
        return DynamoState._error_code(error) == "ConditionalCheckFailedException"

    @staticmethod
    def _transaction_condition_failed(error: ClientError) -> bool:
        code = DynamoState._error_code(error)
        if code == "ConditionalCheckFailedException":
            return True
        if code != "TransactionCanceledException":
            return False
        return "ConditionalCheckFailed" in DynamoState._cancellation_codes(error)

    @staticmethod
    def _transaction_conflict(error: ClientError) -> bool:
        if DynamoState._error_code(error) != "TransactionCanceledException":
            return False
        codes = DynamoState._cancellation_codes(error)
        return (
            bool(codes)
            and "ConditionalCheckFailed" not in codes
            and codes <= {"TransactionConflict"}
        )

    @staticmethod
    def _cancellation_codes(error: ClientError) -> set[str]:
        response = cast(dict[str, object], error.response)
        reasons = response.get("CancellationReasons")
        if not isinstance(reasons, list):
            return set()
        codes: set[str] = set()
        for item in cast(list[object], reasons):
            if isinstance(item, dict):
                code = cast(dict[str, object], item).get("Code")
                if isinstance(code, str) and code not in {"", "None"}:
                    codes.add(code)
        return codes

    @staticmethod
    def _error_code(error: ClientError) -> str:
        response = cast(dict[str, object], error.response)
        detail = response.get("Error")
        if not isinstance(detail, dict):
            return ""
        code = cast(dict[str, object], detail).get("Code")
        return code if isinstance(code, str) else ""

    @staticmethod
    def _error(code: ErrorCode, message: str) -> StateFailure:
        return StateFailure(public_error(code, message, trace_id=str(uuid4())))
