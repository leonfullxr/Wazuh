"""Cross-replica fixed-slot admission for physical provider and indexer calls."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Mapping
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Literal, Protocol, cast
from uuid import UUID, uuid4

from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
from botocore.exceptions import ClientError

from ai_soc.contracts.errors import public_error
from ai_soc.contracts.models import (
    EmbeddingGrant,
    ErrorCode,
    ModelCountGrant,
    ReadOperationGrant,
    StageCapacityRejection,
)
from ai_soc.contracts.ports import (
    EmbeddingAdmissionStore,
    ModelCountAdmissionStore,
    ReadAdmissionStore,
)
from ai_soc.state.errors import StateFailure
from ai_soc.state.ttl import TTL_ATTRIBUTE

type ReadCall = Literal["mapping", "validate", "pit", "search", "probe"]
type ModelCall = Literal["count", "converse"]
type PhysicalCall = Literal[
    "mapping", "validate", "pit", "search", "probe", "count", "converse", "embedding"
]
type StageGrant = ReadOperationGrant | ModelCountGrant | EmbeddingGrant
type StageKind = Literal["read", "model-count", "embedding"]
type SlotDimension = Literal["service", "site", "question"]
type SlotKey = tuple[SlotDimension, str, int]


class StageDynamoClient(Protocol):
    def get_item(self, **kwargs: object) -> dict[str, object]: ...
    def transact_write_items(self, **kwargs: object) -> dict[str, object]: ...


class _Codec(Protocol):
    def serialize(self, value: object) -> object: ...
    def deserialize(self, value: object) -> object: ...


class _MemoryStageSlots:
    def __init__(
        self,
        kind: StageKind,
        *,
        service_capacity: int,
        site_capacity: int,
        seconds_by_call: Mapping[str, int],
    ) -> None:
        self.kind: StageKind = kind
        self.service_capacity = service_capacity
        self.site_capacity = site_capacity
        self.seconds_by_call = dict(seconds_by_call)
        self.lock = asyncio.Lock()
        self.slots: dict[SlotKey, _MemorySlot] = {}
        self.operations: dict[UUID, tuple[str, StageGrant, bool]] = {}

    async def acquire(
        self,
        *,
        environment_id: str,
        question_id: UUID,
        operation_id: UUID,
        call: PhysicalCall,
        now: datetime,
    ) -> StageGrant | StageCapacityRejection:
        _validate_time(now)
        _validate_call(self.kind, call)
        request_key = f"{self.kind}\0{environment_id}\0{question_id}\0{call}"
        now_epoch = int(now.timestamp())
        seconds = self.seconds_by_call[call]
        hard_deadline = now + timedelta(seconds=seconds)
        recover_after = hard_deadline + timedelta(seconds=35)
        async with self.lock:
            for prior_id, (_, prior_grant, _active) in tuple(self.operations.items()):
                if prior_grant.recover_after <= now:
                    del self.operations[prior_id]
            previous = self.operations.get(operation_id)
            if previous is not None:
                prior_key, grant, active = previous
                if prior_key != request_key or not active:
                    raise _failure(
                        ErrorCode.IDEMPOTENCY_CONFLICT,
                        "Stage operation identity was already used.",
                    )
                if grant.recover_after > now:
                    return grant

            if self.kind == "embedding":
                embedding_key: SlotKey = ("question", str(question_id), 1)
                embedding_slot = self.slots.get(embedding_key)
                if (
                    embedding_slot is not None
                    and embedding_slot.holder_id is not None
                    and embedding_slot.recover_after_epoch > now_epoch
                ):
                    return _rejection(question_id, operation_id, call)
                selected: list[SlotKey] = [embedding_key]
            else:
                selected = []
                dimensions: tuple[tuple[SlotDimension, str, int], ...] = (
                    ("service", "service", self.service_capacity),
                    ("site", environment_id, self.site_capacity),
                )
                for dimension, subject, capacity in dimensions:
                    candidate: SlotKey | None = None
                    for number in range(capacity):
                        key: SlotKey = (dimension, subject, number)
                        slot = self.slots.get(key)
                        if (
                            slot is None
                            or slot.holder_id is None
                            or slot.recover_after_epoch <= now_epoch
                        ):
                            candidate = key
                            break
                    if candidate is None:
                        return _rejection(question_id, operation_id, call)
                    selected.append(candidate)

            slot_states: list[_MemorySlot] = [
                self.slots.get(slot, _MemorySlot()) for slot in selected
            ]
            fence = max((slot.fence for slot in slot_states), default=0) + 1
            holder = uuid4()
            grant = _make_grant(
                kind=self.kind,
                environment_id=environment_id,
                question_id=question_id,
                operation_id=operation_id,
                call=call,
                holder_id=holder,
                fence=fence,
                acquired_at=now,
                hard_deadline=hard_deadline,
                recover_after=recover_after,
                service_slot=next((slot[2] for slot in selected if slot[0] == "service"), None),
                site_slot=next((slot[2] for slot in selected if slot[0] == "site"), None),
            )
            for slot_key, old in zip(selected, slot_states, strict=True):
                self.slots[slot_key] = _MemorySlot(
                    holder_id=holder,
                    fence=fence,
                    recover_after_epoch=int(recover_after.timestamp()),
                )
                if old.holder_id is not None:
                    old_operation = (
                        self.operations.get(old.operation_id) if old.operation_id else None
                    )
                    if old_operation is not None:
                        old_key, old_grant, _ = old_operation
                        self.operations[old_grant.operation_id] = (old_key, old_grant, False)
            self.operations[operation_id] = (request_key, grant, True)
            for slot_key in selected:
                slot = self.slots[slot_key]
                self.slots[slot_key] = _MemorySlot(
                    holder_id=slot.holder_id,
                    fence=slot.fence,
                    recover_after_epoch=slot.recover_after_epoch,
                    operation_id=operation_id,
                )
            return grant

    async def release(self, grant: StageGrant) -> None:
        async with self.lock:
            current = self.operations.get(grant.operation_id)
            if current is None:
                return
            request_key, recorded, active = current
            if not active or recorded.holder_id != grant.holder_id or recorded.fence != grant.fence:
                return
            self.operations[grant.operation_id] = (request_key, recorded, False)
            for slot_key, slot in tuple(self.slots.items()):
                if (
                    slot.operation_id == grant.operation_id
                    and slot.holder_id == grant.holder_id
                    and slot.fence == grant.fence
                ):
                    self.slots[slot_key] = _MemorySlot(
                        fence=slot.fence,
                        recover_after_epoch=0,
                    )


class _MemorySlot:
    __slots__ = ("holder_id", "fence", "recover_after_epoch", "operation_id")
    holder_id: UUID | None
    fence: int
    recover_after_epoch: int
    operation_id: UUID | None

    def __init__(
        self,
        *,
        holder_id: UUID | None = None,
        fence: int = 0,
        recover_after_epoch: int = 0,
        operation_id: UUID | None = None,
    ) -> None:
        self.holder_id = holder_id
        self.fence = fence
        self.recover_after_epoch = recover_after_epoch
        self.operation_id = operation_id


class MemoryReadAdmissionStore(ReadAdmissionStore):
    """Barrier-safe fixture mirror for the service20/site8 read pool."""

    def __init__(self) -> None:
        self._slots = _MemoryStageSlots(
            "read",
            service_capacity=20,
            site_capacity=8,
            seconds_by_call={
                name: 10 for name in ("mapping", "validate", "pit", "search", "probe")
            },
        )

    async def acquire(
        self,
        *,
        environment_id: str,
        question_id: UUID,
        operation_id: UUID,
        call: ReadCall,
        now: datetime,
    ) -> ReadOperationGrant | StageCapacityRejection:
        result = await self._slots.acquire(
            environment_id=environment_id,
            question_id=question_id,
            operation_id=operation_id,
            call=call,
            now=now,
        )
        return cast(ReadOperationGrant | StageCapacityRejection, result)

    async def release(self, grant: ReadOperationGrant) -> None:
        await self._slots.release(grant)


class MemoryModelCountAdmissionStore(ModelCountAdmissionStore):
    """Barrier-safe fixture mirror for the shared service8/site2 Count+Converse pool."""

    def __init__(self) -> None:
        self._slots = _MemoryStageSlots(
            "model-count",
            service_capacity=8,
            site_capacity=2,
            seconds_by_call={"count": 5, "converse": 30},
        )

    async def acquire(
        self,
        *,
        environment_id: str,
        question_id: UUID,
        operation_id: UUID,
        call: ModelCall,
        now: datetime,
    ) -> ModelCountGrant | StageCapacityRejection:
        result = await self._slots.acquire(
            environment_id=environment_id,
            question_id=question_id,
            operation_id=operation_id,
            call=call,
            now=now,
        )
        return cast(ModelCountGrant | StageCapacityRejection, result)

    async def release(self, grant: ModelCountGrant) -> None:
        await self._slots.release(grant)


class MemoryEmbeddingAdmissionStore(EmbeddingAdmissionStore):
    """Fixture permit that allows one in-flight embedding operation per question."""

    def __init__(self) -> None:
        self._slots = _MemoryStageSlots(
            "embedding", service_capacity=1, site_capacity=1, seconds_by_call={"embedding": 10}
        )

    async def acquire(
        self,
        *,
        environment_id: str,
        question_id: UUID,
        operation_id: UUID,
        now: datetime,
    ) -> EmbeddingGrant | StageCapacityRejection:
        result = await self._slots.acquire(
            environment_id=environment_id,
            question_id=question_id,
            operation_id=operation_id,
            call="embedding",
            now=now,
        )
        return cast(EmbeddingGrant | StageCapacityRejection, result)

    async def release(self, grant: EmbeddingGrant) -> None:
        await self._slots.release(grant)


class _DynamoStageSlots:
    def __init__(
        self,
        client: StageDynamoClient,
        table_name: str,
        kind: StageKind,
        *,
        service_capacity: int,
        site_capacity: int,
        seconds_by_call: Mapping[str, int],
    ) -> None:
        if not table_name:
            raise ValueError("stage admission table is required")
        self._client = client
        self._table = table_name
        self._kind: StageKind = kind
        self._service_capacity = service_capacity
        self._site_capacity = site_capacity
        self._seconds_by_call = dict(seconds_by_call)
        self._serializer = cast(_Codec, TypeSerializer())
        self._deserializer = cast(_Codec, TypeDeserializer())
        self._io = asyncio.Semaphore(4)

    async def acquire(
        self,
        *,
        environment_id: str,
        question_id: UUID,
        operation_id: UUID,
        call: PhysicalCall,
        now: datetime,
    ) -> StageGrant | StageCapacityRejection:
        _validate_time(now)
        _validate_call(self._kind, call)
        existing = await self._existing(operation_id, now)
        if existing is not None:
            grant, active = existing
            if (
                grant.question_id != question_id
                or grant.environment_id != environment_id
                or grant.call != call
            ):
                raise _failure(
                    ErrorCode.IDEMPOTENCY_CONFLICT, "Stage operation identity was reused."
                )
            if not active:
                raise _failure(ErrorCode.IDEMPOTENCY_CONFLICT, "Stage operation already completed.")
            return grant

        seconds = self._seconds_by_call[call]
        hard_deadline = now + timedelta(seconds=seconds)
        recover_after = hard_deadline + timedelta(seconds=35)
        holder = uuid4()
        attempts = 2 if self._kind == "embedding" else self._service_capacity + 1
        for attempt in range(attempts):
            if self._kind == "embedding":
                embedding_slot = await self._available("question", str(question_id), 1, now)
                if embedding_slot is None:
                    return _rejection(question_id, operation_id, call)
                slots = [embedding_slot]
            else:
                service = await self._available("service", "service", self._service_capacity, now)
                if service is None:
                    return _rejection(question_id, operation_id, call)
                site = await self._available("site", environment_id, self._site_capacity, now)
                if site is None:
                    return _rejection(question_id, operation_id, call)
                slots = [service, site]

            fence = max(slot.fence for slot in slots) + 1
            grant = _make_grant(
                kind=self._kind,
                environment_id=environment_id,
                question_id=question_id,
                operation_id=operation_id,
                call=call,
                holder_id=holder,
                fence=fence,
                acquired_at=now,
                hard_deadline=hard_deadline,
                recover_after=recover_after,
                service_slot=next(
                    (slot.number for slot in slots if slot.dimension == "service"), None
                ),
                site_slot=next((slot.number for slot in slots if slot.dimension == "site"), None),
            )
            actions = [self._slot_update(slot, grant, now) for slot in slots]
            actions.append(self._operation_put(grant, now))
            try:
                await self._invoke(
                    "transact_write_items",
                    TransactItems=actions,
                    ClientRequestToken=str(uuid4()),
                )
                return grant
            except ClientError as exc:
                existing = await self._existing(operation_id, now)
                if existing is not None:
                    prior, active = existing
                    if active and _same_operation(prior, grant):
                        return prior
                    if active:
                        raise _failure(
                            ErrorCode.IDEMPOTENCY_CONFLICT,
                            "Stage operation identity was reused.",
                        ) from None
                    raise _failure(
                        ErrorCode.IDEMPOTENCY_CONFLICT, "Stage operation already completed."
                    ) from None
                if not _conditional(exc):
                    raise _failure(
                        ErrorCode.DEPENDENCY_UNAVAILABLE, "Stage admission is unavailable."
                    ) from None
                if attempt + 1 == attempts:
                    return _rejection(question_id, operation_id, call)
            except StateFailure:
                existing = await self._existing(operation_id, now)
                if existing is not None:
                    prior, active = existing
                    if active and _same_operation(prior, grant):
                        return prior
                raise
        return _rejection(question_id, operation_id, call)

    async def release(self, grant: StageGrant) -> None:
        if isinstance(grant, EmbeddingGrant):
            slot_ids: list[SlotKey] = [("question", str(grant.question_id), 0)]
        else:
            slot_ids = [
                ("service", "service", _slot_number(grant.service_slot_id)),
                ("site", grant.environment_id, _slot_number(grant.site_slot_id)),
            ]
        actions = [self._release_update(slot, grant) for slot in slot_ids]
        actions.append(self._operation_release(grant))
        try:
            await self._invoke("transact_write_items", TransactItems=actions)
        except ClientError as exc:
            if not _conditional(exc):
                raise _failure(
                    ErrorCode.DEPENDENCY_UNAVAILABLE, "Stage admission is unavailable."
                ) from None

    async def _existing(self, operation_id: UUID, now: datetime) -> tuple[StageGrant, bool] | None:
        response = await self._invoke(
            "get_item",
            TableName=self._table,
            Key=self._key(f"STAGEOP#{operation_id}", "V1"),
            ConsistentRead=True,
        )
        item = self._decode(response.get("Item"))
        if item is None:
            return None
        if _int_field(item, "expires_epoch") <= int(now.timestamp()):
            return None
        payload = item.get("payload")
        if not isinstance(payload, str):
            raise _failure(ErrorCode.DEPENDENCY_UNAVAILABLE, "Stage operation record is malformed.")
        grant = _parse_grant(self._kind, payload)
        return grant, item.get("state") == "active"

    async def _available(
        self,
        dimension: SlotDimension,
        subject: str,
        capacity: int,
        now: datetime,
    ) -> _DynamoSlot | None:
        for number in range(1 if dimension == "question" else capacity):
            pk, sk = _slot_key(self._kind, dimension, subject, number)
            response = await self._invoke(
                "get_item",
                TableName=self._table,
                Key=self._key(pk, sk),
                ConsistentRead=True,
            )
            item = self._decode(response.get("Item"))
            if item is None:
                return _DynamoSlot(dimension, subject, number, 0, absent=True)
            fence = _int_field(item, "fence")
            if item.get("holder_id") is None or _int_field(item, "recover_after_epoch") <= int(
                now.timestamp()
            ):
                return _DynamoSlot(dimension, subject, number, fence, absent=False)
        return None

    def _slot_update(
        self, slot: _DynamoSlot, grant: StageGrant, now: datetime
    ) -> dict[str, object]:
        pk, sk = _slot_key(self._kind, slot.dimension, slot.subject, slot.number)
        values: dict[str, object] = {
            ":holder": str(grant.holder_id),
            ":fence": grant.fence,
            ":operation": str(grant.operation_id),
            ":question": str(grant.question_id),
            ":environment": grant.environment_id,
            ":call": grant.call,
            ":lease": int(grant.lease_expires_at.timestamp()),
            ":deadline": int(grant.hard_deadline_at.timestamp()),
            ":recover": int(grant.recover_after.timestamp()),
        }
        if slot.absent:
            condition = "attribute_not_exists(pk)"
        else:
            values[":now"] = int(now.timestamp())
            values[":previous"] = slot.fence
            condition = (
                "fence = :previous AND "
                "(attribute_not_exists(holder_id) OR recover_after_epoch <= :now)"
            )
        return {
            "Update": {
                "TableName": self._table,
                "Key": self._key(pk, sk),
                "UpdateExpression": (
                    "SET holder_id = :holder, fence = :fence, operation_id = :operation, "
                    "question_id = :question, environment_id = :environment, stage_call = :call, "
                    "lease_expires_epoch = :lease, hard_deadline_epoch = :deadline, "
                    "recover_after_epoch = :recover"
                ),
                "ConditionExpression": condition,
                "ExpressionAttributeValues": self._values(values),
            }
        }

    def _operation_put(self, grant: StageGrant, now: datetime) -> dict[str, object]:
        return {
            "Put": {
                "TableName": self._table,
                "Item": self._encode(
                    {
                        "pk": f"STAGEOP#{grant.operation_id}",
                        "sk": "V1",
                        "record_type": "stage_operation",
                        "payload": grant.model_dump_json(),
                        "state": "active",
                        "holder_id": str(grant.holder_id),
                        "fence": grant.fence,
                        "expires_epoch": int(grant.recover_after.timestamp()),
                        TTL_ATTRIBUTE: int(grant.recover_after.timestamp()),
                    }
                ),
                "ConditionExpression": "attribute_not_exists(pk) OR expires_epoch <= :now",
                "ExpressionAttributeValues": self._values({":now": int(now.timestamp())}),
            }
        }

    def _release_update(self, slot: SlotKey, grant: StageGrant) -> dict[str, object]:
        pk, sk = _slot_key(self._kind, *slot)
        return {
            "Update": {
                "TableName": self._table,
                "Key": self._key(pk, sk),
                "UpdateExpression": "SET released_epoch = :zero REMOVE holder_id",
                "ConditionExpression": (
                    "holder_id = :holder AND fence = :fence AND operation_id = :operation"
                ),
                "ExpressionAttributeValues": self._values(
                    {
                        ":zero": 0,
                        ":holder": str(grant.holder_id),
                        ":fence": grant.fence,
                        ":operation": str(grant.operation_id),
                    }
                ),
            }
        }

    def _operation_release(self, grant: StageGrant) -> dict[str, object]:
        return {
            "Update": {
                "TableName": self._table,
                "Key": self._key(f"STAGEOP#{grant.operation_id}", "V1"),
                "UpdateExpression": "SET #state = :released",
                "ConditionExpression": (
                    "holder_id = :holder AND fence = :fence AND #state = :active"
                ),
                "ExpressionAttributeNames": {"#state": "state"},
                "ExpressionAttributeValues": self._values(
                    {
                        ":holder": str(grant.holder_id),
                        ":fence": grant.fence,
                        ":released": "released",
                        ":active": "active",
                    }
                ),
            }
        }

    async def _invoke(self, method: str, **kwargs: object) -> dict[str, object]:
        async with self._io:
            try:
                if method == "get_item":
                    return await asyncio.to_thread(self._client.get_item, **kwargs)
                return await asyncio.to_thread(self._client.transact_write_items, **kwargs)
            except ClientError as exc:
                if _conditional(exc):
                    raise
                raise _failure(
                    ErrorCode.DEPENDENCY_UNAVAILABLE, "Stage admission is unavailable."
                ) from None
            except Exception:
                raise _failure(
                    ErrorCode.DEPENDENCY_UNAVAILABLE, "Stage admission is unavailable."
                ) from None

    def _key(self, pk: str, sk: str) -> dict[str, object]:
        return self._encode({"pk": pk, "sk": sk})

    def _encode(self, value: Mapping[str, object]) -> dict[str, object]:
        return {key: self._serializer.serialize(item) for key, item in value.items()}

    def _values(self, value: Mapping[str, object]) -> dict[str, object]:
        return {key: self._serializer.serialize(item) for key, item in value.items()}

    def _decode(self, value: object) -> dict[str, object] | None:
        if not isinstance(value, dict):
            return None
        return {
            str(key): self._deserializer.deserialize(item)
            for key, item in cast(dict[str, object], value).items()
        }


class DynamoReadAdmissionStore(ReadAdmissionStore):
    def __init__(self, client: StageDynamoClient, table_name: str) -> None:
        self._slots = _DynamoStageSlots(
            client,
            table_name,
            "read",
            service_capacity=20,
            site_capacity=8,
            seconds_by_call={
                name: 10 for name in ("mapping", "validate", "pit", "search", "probe")
            },
        )

    async def acquire(
        self,
        *,
        environment_id: str,
        question_id: UUID,
        operation_id: UUID,
        call: ReadCall,
        now: datetime,
    ) -> ReadOperationGrant | StageCapacityRejection:
        result = await self._slots.acquire(
            environment_id=environment_id,
            question_id=question_id,
            operation_id=operation_id,
            call=call,
            now=now,
        )
        return cast(ReadOperationGrant | StageCapacityRejection, result)

    async def release(self, grant: ReadOperationGrant) -> None:
        await self._slots.release(grant)


class DynamoModelCountAdmissionStore(ModelCountAdmissionStore):
    def __init__(self, client: StageDynamoClient, table_name: str) -> None:
        self._slots = _DynamoStageSlots(
            client,
            table_name,
            "model-count",
            service_capacity=8,
            site_capacity=2,
            seconds_by_call={"count": 5, "converse": 30},
        )

    async def acquire(
        self,
        *,
        environment_id: str,
        question_id: UUID,
        operation_id: UUID,
        call: ModelCall,
        now: datetime,
    ) -> ModelCountGrant | StageCapacityRejection:
        result = await self._slots.acquire(
            environment_id=environment_id,
            question_id=question_id,
            operation_id=operation_id,
            call=call,
            now=now,
        )
        return cast(ModelCountGrant | StageCapacityRejection, result)

    async def release(self, grant: ModelCountGrant) -> None:
        await self._slots.release(grant)


class DynamoEmbeddingAdmissionStore(EmbeddingAdmissionStore):
    def __init__(self, client: StageDynamoClient, table_name: str) -> None:
        self._slots = _DynamoStageSlots(
            client,
            table_name,
            "embedding",
            service_capacity=1,
            site_capacity=1,
            seconds_by_call={"embedding": 10},
        )

    async def acquire(
        self,
        *,
        environment_id: str,
        question_id: UUID,
        operation_id: UUID,
        now: datetime,
    ) -> EmbeddingGrant | StageCapacityRejection:
        result = await self._slots.acquire(
            environment_id=environment_id,
            question_id=question_id,
            operation_id=operation_id,
            call="embedding",
            now=now,
        )
        return cast(EmbeddingGrant | StageCapacityRejection, result)

    async def release(self, grant: EmbeddingGrant) -> None:
        await self._slots.release(grant)


class _DynamoSlot:
    __slots__ = ("dimension", "subject", "number", "fence", "absent")
    dimension: SlotDimension
    subject: str
    number: int
    fence: int
    absent: bool

    def __init__(
        self,
        dimension: SlotDimension,
        subject: str,
        number: int,
        fence: int,
        *,
        absent: bool = False,
    ) -> None:
        self.dimension = dimension
        self.subject = subject
        self.number = number
        self.fence = fence
        self.absent = absent


def _make_grant(
    *,
    kind: StageKind,
    environment_id: str,
    question_id: UUID,
    operation_id: UUID,
    call: PhysicalCall,
    holder_id: UUID,
    fence: int,
    acquired_at: datetime,
    hard_deadline: datetime,
    recover_after: datetime,
    service_slot: int | None,
    site_slot: int | None,
) -> StageGrant:
    values: dict[str, object] = {
        "question_id": question_id,
        "environment_id": environment_id,
        "operation_id": operation_id,
        "call": call,
        "holder_id": holder_id,
        "fence": fence,
        "acquired_at": acquired_at,
        "lease_expires_at": hard_deadline,
        "hard_deadline_at": hard_deadline,
        "recover_after": recover_after,
    }
    if kind == "embedding":
        return EmbeddingGrant.model_validate(values)
    site_key = hashlib.sha256(environment_id.encode("utf-8")).hexdigest()[:16]
    values["service_slot_id"] = f"{kind}:service:{service_slot:02d}"
    values["site_slot_id"] = f"{kind}:site:{site_key}:{site_slot:02d}"
    if kind == "read":
        return ReadOperationGrant.model_validate(values)
    return ModelCountGrant.model_validate(values)


def _parse_grant(kind: StageKind, payload: str) -> StageGrant:
    if kind == "read":
        return ReadOperationGrant.model_validate_json(payload)
    if kind == "model-count":
        return ModelCountGrant.model_validate_json(payload)
    return EmbeddingGrant.model_validate_json(payload)


def _same_operation(left: StageGrant, right: StageGrant) -> bool:
    return (
        left.operation_id == right.operation_id
        and left.question_id == right.question_id
        and left.environment_id == right.environment_id
        and left.call == right.call
    )


def _slot_key(
    kind: StageKind,
    dimension: SlotDimension,
    subject: str,
    number: int,
) -> tuple[str, str]:
    if dimension == "service":
        pk = f"STAGE#{kind}#SERVICE"
    elif dimension == "site":
        pk = f"STAGE#{kind}#SITE#{subject}"
    else:
        pk = f"STAGE#embedding#QUESTION#{subject}"
    return pk, f"SLOT#{number}"


def _slot_number(value: str) -> int:
    parts = value.split(":")
    if len(parts) not in {3, 4}:
        raise ValueError("stage grant contains an invalid slot identity")
    try:
        number = int(parts[-1])
        if number < 0:
            raise ValueError("negative slot")
        return number
    except ValueError as exc:
        raise ValueError("stage grant contains an invalid slot identity") from exc


def _rejection(question_id: UUID, operation_id: UUID, call: PhysicalCall) -> StageCapacityRejection:
    return StageCapacityRejection(question_id=question_id, operation_id=operation_id, call=call)


def _validate_call(kind: StageKind, call: PhysicalCall) -> None:
    valid = {
        "read": {"mapping", "validate", "pit", "search", "probe"},
        "model-count": {"count", "converse"},
        "embedding": {"embedding"},
    }[kind]
    if call not in valid:
        raise ValueError("physical call does not belong to this stage pool")


def _validate_time(now: datetime) -> None:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("stage admission time must be timezone-aware")


def _failure(code: ErrorCode, message: str) -> StateFailure:
    return StateFailure(public_error(code, message, trace_id=uuid4().hex))


def _conditional(error: ClientError) -> bool:
    response: object = error.response
    if not isinstance(response, dict):
        return False
    response_map = cast(Mapping[str, object], response)
    error_value: object = response_map.get("Error")
    if not isinstance(error_value, dict):
        return False
    code = cast(Mapping[str, object], error_value).get("Code")
    if code == "ConditionalCheckFailedException":
        return True
    if code != "TransactionCanceledException":
        return False
    reasons: object = response_map.get("CancellationReasons")
    if not isinstance(reasons, list):
        return False
    return any(
        isinstance(reason, dict)
        and cast(Mapping[str, object], reason).get("Code") == "ConditionalCheckFailed"
        for reason in cast(list[object], reasons)
    )


def _int_field(item: Mapping[str, object], key: str) -> int:
    value = item.get(key, 0)
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal, str)):
        return 0
    try:
        return int(value)
    except (ValueError, InvalidOperation, OverflowError):
        return 0
