"""Fixed-slot and fixed-minute admission stores for memory and DynamoDB."""

from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast
from uuid import UUID, uuid4

from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
from botocore.exceptions import ClientError

from ai_soc.contracts.errors import public_error
from ai_soc.contracts.models import AdmissionGrant, ErrorCode
from ai_soc.contracts.ports import AdmissionStore
from ai_soc.state.errors import StateFailure
from ai_soc.state.ttl import TTL_ATTRIBUTE
from ai_soc.telemetry.metrics import MetricExporter
from ai_soc.telemetry.operational import emit_admission_rejected


class AdmissionClient(Protocol):
    def get_item(self, **kwargs: object) -> dict[str, object]: ...
    def transact_write_items(self, **kwargs: object) -> dict[str, object]: ...
    def update_item(self, **kwargs: object) -> dict[str, object]: ...


class AttributeCodec(Protocol):
    def serialize(self, value: object) -> object: ...
    def deserialize(self, value: object) -> object: ...


class MemoryAdmissionStore(AdmissionStore):
    """Concurrent fixture admission with atomic slots and conservative rate counts."""

    def __init__(self, *, lease_seconds: int = 60, metrics: MetricExporter | None = None) -> None:
        if not 1 <= lease_seconds <= 60:
            raise ValueError("admission lease must be between 1 and 60 seconds")
        self._lease_seconds = lease_seconds
        self._metrics = metrics
        self._lock = asyncio.Lock()
        self._slots: dict[tuple[str, str], tuple[UUID, int, int]] = {}
        self._fences: dict[tuple[str, str], int] = {}
        self._rates: dict[tuple[str, str, str, int], int] = {}

    async def acquire(
        self,
        owner_key: str,
        environment_id: str,
        operation: str,
        question_id: UUID,
        now: datetime,
    ) -> AdmissionGrant:
        if operation not in {"ask", "page", "feedback", "semantic", "ingress"}:
            raise ValueError("unsupported admission operation")
        second = _epoch(now)
        minute = second // 60
        owner_limit, site_limit, slot_limits = _operation_limits(operation)
        owner_rate = ("owner", owner_key, operation, minute)
        site_rate = ("site", environment_id, operation, minute)
        ingress_rate = ("ingress", owner_key, "all", minute)
        service_semantic_rate = ("service", "global", "semantic", minute)
        count_ingress = operation in {"ingress", "page", "feedback"}
        async with self._lock:
            if (
                (operation != "ingress" and self._rates.get(owner_rate, 0) >= owner_limit)
                or (operation != "ingress" and self._rates.get(site_rate, 0) >= site_limit)
                or (count_ingress and self._rates.get(ingress_rate, 0) >= 240)
                or (operation == "semantic" and self._rates.get(service_semantic_rate, 0) >= 60)
            ):
                if self._metrics is not None:
                    emit_admission_rejected(self._metrics)
                raise _failure(ErrorCode.RATE_LIMITED, "The request rate limit was reached.")

            selected: list[tuple[str, str]] = []
            for dimension, capacity in slot_limits:
                found = None
                subject = _slot_subject(dimension, owner_key, environment_id)
                for number in range(capacity):
                    candidate = (dimension, f"{subject}#{number:04d}")
                    current = self._slots.get(candidate)
                    if current is None or current[2] <= second:
                        found = candidate
                        break
                if found is None:
                    if self._metrics is not None:
                        emit_admission_rejected(self._metrics)
                    raise _failure(ErrorCode.BUSY, "Service capacity is busy.")
                selected.append(found)

            holder = uuid4()
            expires = second + self._lease_seconds
            fences: list[int] = []
            for slot in selected:
                fence = self._fences.get(slot, 0) + 1
                self._fences[slot] = fence
                self._slots[slot] = (holder, fence, expires)
                fences.append(fence)
            if operation != "ingress":
                self._rates[owner_rate] = self._rates.get(owner_rate, 0) + 1
                self._rates[site_rate] = self._rates.get(site_rate, 0) + 1
            if count_ingress:
                self._rates[ingress_rate] = self._rates.get(ingress_rate, 0) + 1
            if operation == "semantic":
                self._rates[service_semantic_rate] = self._rates.get(service_semantic_rate, 0) + 1
            return AdmissionGrant(
                holder_id=holder,
                slot_ids=tuple(f"{dimension}/{subject}" for dimension, subject in selected),
                expires_at=now + timedelta(seconds=self._lease_seconds),
                fence=max(fences, default=1),
            )

    async def renew(self, grant: AdmissionGrant, now: datetime) -> AdmissionGrant:
        second = _epoch(now)
        async with self._lock:
            slots = [_parse_memory_slot(value) for value in grant.slot_ids]
            if any(
                (current := self._slots.get(slot)) is None
                or current[0] != grant.holder_id
                or current[2] <= second
                for slot in slots
            ):
                raise _failure(ErrorCode.BUSY, "Admission grant expired or was replaced.")
            expiry = second + self._lease_seconds
            for slot in slots:
                current = self._slots[slot]
                self._slots[slot] = (current[0], current[1], expiry)
            return grant.model_copy(
                update={"expires_at": now + timedelta(seconds=self._lease_seconds)}
            )

    async def release(self, grant: AdmissionGrant) -> None:
        async with self._lock:
            for value in grant.slot_ids:
                slot = _parse_memory_slot(value)
                current = self._slots.get(slot)
                if current is not None and current[0] == grant.holder_id:
                    del self._slots[slot]


class DynamoAdmissionStore(AdmissionStore):
    """Cross-replica fixed-slot admission using atomic DynamoDB transactions."""

    def __init__(
        self,
        client: AdmissionClient,
        table_name: str,
        *,
        lease_seconds: int = 60,
        metrics: MetricExporter | None = None,
    ) -> None:
        if not table_name or not 1 <= lease_seconds <= 60:
            raise ValueError("table and a 1..60 second admission lease are required")
        self._client = client
        self._table = table_name
        self._lease_seconds = lease_seconds
        self._metrics = metrics
        self._serializer = cast(AttributeCodec, TypeSerializer())
        self._deserializer = cast(AttributeCodec, TypeDeserializer())
        self._io = asyncio.Semaphore(4)

    async def acquire(
        self,
        owner_key: str,
        environment_id: str,
        operation: str,
        question_id: UUID,
        now: datetime,
    ) -> AdmissionGrant:
        if operation not in {"ask", "page", "feedback", "semantic", "ingress"}:
            raise ValueError("unsupported admission operation")
        second = _epoch(now)
        minute = second // 60
        owner_limit, site_limit, slot_limits = _operation_limits(operation)
        holder = uuid4()
        expires = second + self._lease_seconds
        for attempt in range(2):
            selected: list[tuple[str, str, int]] = []
            fences: list[int] = []
            for dimension, capacity in slot_limits:
                subject = _slot_subject(dimension, owner_key, environment_id)
                candidate = await self._available_slot(dimension, subject, capacity, second)
                if candidate is None:
                    self._reject_admission()
                    raise _failure(ErrorCode.BUSY, "Service capacity is busy.")
                number, old_fence = candidate
                selected.append((dimension, subject, number))
                fences.append(old_fence)
            grant_fence = max(fences, default=0) + 1
            transact: list[dict[str, object]] = []
            for dimension, subject, number in selected:
                pk, sk = _slot_key(dimension, subject, number)
                transact.append(
                    {
                        "Update": {
                            "TableName": self._table,
                            "Key": self._encode({"pk": pk, "sk": sk}),
                            "UpdateExpression": (
                                "SET holder_id = :holder, fence = :fence, expires_epoch = :expiry"
                            ),
                            "ConditionExpression": (
                                "attribute_not_exists(pk) OR expires_epoch <= :now"
                            ),
                            "ExpressionAttributeValues": self._values(
                                {
                                    ":now": second,
                                    ":holder": str(holder),
                                    ":fence": grant_fence,
                                    ":expiry": expires,
                                }
                            ),
                        }
                    }
                )
            if operation != "ingress":
                transact.extend(
                    self._rate_update("owner", owner_key, operation, minute, owner_limit)
                )
                transact.extend(
                    self._rate_update("site", environment_id, operation, minute, site_limit)
                )
            if operation in {"ingress", "page", "feedback"}:
                transact.extend(self._rate_update("ingress", owner_key, "all", minute, 240))
            if operation == "semantic":
                transact.extend(self._rate_update("service", "global", "semantic", minute, 60))
            try:
                await self._call(
                    "transact_write_items",
                    TransactItems=transact,
                    ClientRequestToken=str(uuid4()),
                )
            except ClientError as exc:
                if _conditional_failure(exc):
                    if _rate_failure(exc, slot_count=len(selected)):
                        self._reject_admission()
                        raise _failure(
                            ErrorCode.RATE_LIMITED, "The request rate limit was reached."
                        ) from None
                    if attempt == 0:
                        continue
                    self._reject_admission()
                    raise _failure(
                        ErrorCode.BUSY, "Service capacity or rate limit was reached."
                    ) from None
                raise _failure(
                    ErrorCode.DEPENDENCY_UNAVAILABLE, "Admission state is unavailable."
                ) from None
            slot_ids = tuple(
                f"{dimension}/{subject}/{number}" for dimension, subject, number in selected
            )
            return AdmissionGrant(
                holder_id=holder,
                slot_ids=slot_ids,
                expires_at=now + timedelta(seconds=self._lease_seconds),
                fence=grant_fence,
            )
        self._reject_admission()
        raise _failure(ErrorCode.BUSY, "Service capacity is busy.")

    def _reject_admission(self) -> None:
        if self._metrics is not None:
            emit_admission_rejected(self._metrics)

    async def renew(self, grant: AdmissionGrant, now: datetime) -> AdmissionGrant:
        second = _epoch(now)
        expiry = second + self._lease_seconds
        items: list[dict[str, object]] = []
        for value in grant.slot_ids:
            dimension, subject, number = _parse_dynamo_slot(value)
            pk, sk = _slot_key(dimension, subject, number)
            items.append(
                {
                    "Update": {
                        "TableName": self._table,
                        "Key": self._encode({"pk": pk, "sk": sk}),
                        "UpdateExpression": "SET expires_epoch = :expiry",
                        "ConditionExpression": "holder_id = :holder AND expires_epoch > :now",
                        "ExpressionAttributeValues": self._values(
                            {":expiry": expiry, ":holder": str(grant.holder_id), ":now": second}
                        ),
                    }
                }
            )
        if items:
            try:
                await self._call("transact_write_items", TransactItems=items)
            except ClientError as exc:
                if _conditional_failure(exc):
                    raise _failure(
                        ErrorCode.BUSY, "Admission grant expired or was replaced."
                    ) from None
                raise _failure(
                    ErrorCode.DEPENDENCY_UNAVAILABLE, "Admission state is unavailable."
                ) from None
        return grant.model_copy(update={"expires_at": now + timedelta(seconds=self._lease_seconds)})

    async def release(self, grant: AdmissionGrant) -> None:
        items: list[dict[str, object]] = []
        for value in grant.slot_ids:
            dimension, subject, number = _parse_dynamo_slot(value)
            pk, sk = _slot_key(dimension, subject, number)
            items.append(
                {
                    "Update": {
                        "TableName": self._table,
                        "Key": self._encode({"pk": pk, "sk": sk}),
                        "UpdateExpression": "SET expires_epoch = :zero REMOVE holder_id",
                        "ConditionExpression": "holder_id = :holder",
                        "ExpressionAttributeValues": self._values(
                            {":zero": 0, ":holder": str(grant.holder_id)}
                        ),
                    }
                }
            )
        if items:
            try:
                await self._call("transact_write_items", TransactItems=items)
            except ClientError as exc:
                if not _conditional_failure(exc):
                    raise _failure(
                        ErrorCode.DEPENDENCY_UNAVAILABLE, "Admission state is unavailable."
                    ) from None

    async def _available_slot(
        self, dimension: str, subject: str, capacity: int, now: int
    ) -> tuple[int, int] | None:
        for number in range(capacity):
            pk, sk = _slot_key(dimension, subject, number)
            response = await self._call(
                "get_item",
                TableName=self._table,
                Key=self._encode({"pk": pk, "sk": sk}),
                ConsistentRead=True,
            )
            item = self._decode(response.get("Item"))
            if item is None or _integer(item.get("expires_epoch")) <= now:
                return number, _integer(item.get("fence")) if item is not None else 0
        return None

    def _rate_update(
        self, dimension: str, subject: str, operation: str, minute: int, limit: int
    ) -> list[dict[str, object]]:
        digest = hashlib.sha256(subject.encode("utf-8")).hexdigest()
        pk, sk = f"RATE#{dimension}#{digest}", f"{minute}#{operation}"
        return [
            {
                "Update": {
                    "TableName": self._table,
                    "Key": self._encode({"pk": pk, "sk": sk}),
                    "UpdateExpression": (
                        "SET #count = if_not_exists(#count, :zero) + :one, "
                        f"expires_epoch = :ttl, {TTL_ATTRIBUTE} = :ttl"
                    ),
                    "ConditionExpression": "attribute_not_exists(#count) OR #count < :limit",
                    "ExpressionAttributeNames": {"#count": "count"},
                    "ExpressionAttributeValues": self._values(
                        {":zero": 0, ":one": 1, ":limit": limit, ":ttl": (minute + 2) * 60}
                    ),
                }
            }
        ]

    async def _call(self, method: str, **kwargs: object) -> dict[str, object]:
        async with self._io:
            try:
                if method == "get_item":
                    operation = self._client.get_item
                elif method == "transact_write_items":
                    operation = self._client.transact_write_items
                elif method == "update_item":
                    operation = self._client.update_item
                else:
                    raise ValueError("unsupported DynamoDB admission operation")
                result = await asyncio.wait_for(asyncio.to_thread(operation, **kwargs), timeout=5)
            except Exception as exc:
                raise _failure(
                    ErrorCode.DEPENDENCY_UNAVAILABLE, "Admission state is unavailable."
                ) from exc
        return result

    def _encode(self, item: dict[str, object]) -> dict[str, object]:
        return {key: self._serializer.serialize(value) for key, value in item.items()}

    def _values(self, item: dict[str, object]) -> dict[str, object]:
        return self._encode(item)

    def _decode(self, raw: object) -> dict[str, object] | None:
        if not isinstance(raw, dict):
            return None
        result: dict[str, object] = {}
        for key, value in cast(dict[object, object], raw).items():
            if isinstance(key, str):
                result[key] = self._deserializer.deserialize(value)
        return result


def _operation_limits(operation: str) -> tuple[int, int, tuple[tuple[str, int], ...]]:
    if operation == "ingress":
        return 240, 0, ()
    if operation == "ask":
        return 12, 120, (("SERVICE#questions", 32), ("SITE#questions", 4), ("OWNER#question", 1))
    if operation == "page":
        return 60, 600, (("SERVICE#reads", 20), ("SITE#reads", 8))
    if operation == "feedback":
        return 10, 100, ()
    return 6, 30, (("SERVICE#semantic", 60), ("SITE#semantic", 30))


def _slot_subject(dimension: str, owner: str, site: str) -> str:
    if dimension.startswith("SITE#"):
        value = site
    elif dimension.startswith("OWNER#"):
        value = f"{owner}#{site}"
    else:
        value = "global"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _slot_key(dimension: str, subject: str, number: int) -> tuple[str, str]:
    return f"ADMIT#{dimension}#{subject}", f"SLOT#{number:04d}"


def _parse_memory_slot(value: str) -> tuple[str, str]:
    dimension, number = value.split("/", 1)
    return dimension, number


def _parse_dynamo_slot(value: str) -> tuple[str, str, int]:
    dimension, subject, number = value.rsplit("/", 2)
    if not number.isdecimal():
        raise ValueError("invalid admission slot id")
    return dimension, subject, int(number)


def _epoch(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("admission time must be timezone-aware")
    return int(value.astimezone(UTC).timestamp())


def _integer(value: object) -> int:
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0


def _conditional_failure(error: ClientError) -> bool:
    response: object = error.response
    if not isinstance(response, dict):
        return False
    info = cast(dict[object, object], response).get("Error")
    if not isinstance(info, dict):
        return False
    code = cast(dict[object, object], info).get("Code")
    return code in {"TransactionCanceledException", "ConditionalCheckFailedException"}


def _rate_failure(error: ClientError, *, slot_count: int = 0) -> bool:
    response: object = error.response
    if not isinstance(response, dict):
        return False
    reasons = cast(dict[object, object], response).get("CancellationReasons")
    if not isinstance(reasons, list):
        return False
    typed_reasons = cast(list[object], reasons)
    for index, item in enumerate(typed_reasons):
        if index < slot_count:
            continue
        if (
            isinstance(item, dict)
            and cast(dict[object, object], item).get("Code") == "ConditionalCheckFailed"
        ):
            return True
    return False


def _failure(code: ErrorCode, message: str) -> StateFailure:
    return StateFailure(public_error(code, message, trace_id=uuid4().hex))
