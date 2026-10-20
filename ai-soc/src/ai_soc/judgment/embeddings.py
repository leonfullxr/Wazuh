"""Explicit, separately guardrailed Bedrock query/topic-card embedding API."""

from __future__ import annotations

import asyncio
import json
import math
from collections.abc import Callable
from typing import Protocol, cast
from uuid import uuid4

from ai_soc.contracts.models import (
    CallKind,
    ErrorCode,
    ExecutionContext,
    SemanticSuggestion,
    StageCapacityRejection,
)
from ai_soc.contracts.ports import (
    Clock,
    ContentCatalog,
    EmbeddingAdmissionStore,
    SemanticSuggester,
)
from ai_soc.judgment.bedrock import SystemClock

from .bedrock import PhysicalCallPool, ProviderFailure
from .capabilities import CapabilityError, EmbeddingCapability, validate_embedding_capability

MAX_EMBED_TEXTS = 64
MAX_EMBED_TEXT_BYTES = 2_048
MAX_EMBED_RESPONSE_BYTES = 2_097_152


class EmbeddingClient(Protocol):
    def invoke_model(self, **kwargs: object) -> dict[str, object]: ...


class BedrockEmbeddingProvider:
    """Embeds only caller supplied reviewed cards or one isolated query."""

    def __init__(
        self,
        client: EmbeddingClient,
        capability: EmbeddingCapability,
        *,
        pool: PhysicalCallPool | None = None,
    ) -> None:
        self._client = client
        self._capability = capability
        self._pool = pool or PhysicalCallPool(4, name="bedrock-embedding")

    @classmethod
    def from_boto3(cls, capability: EmbeddingCapability) -> BedrockEmbeddingProvider:
        import boto3
        from botocore.config import Config

        validated = validate_embedding_capability(capability)
        client_factory = cast(Callable[..., object], boto3.client)  # type: ignore[reportUnknownMemberType]
        client = client_factory(
            "bedrock-runtime",
            region_name=validated.region,
            config=Config(
                connect_timeout=3,
                read_timeout=10,
                retries={"total_max_attempts": 1, "mode": "standard"},
                max_pool_connections=4,
            ),
        )
        return cls(cast(EmbeddingClient, client), validated)

    async def embed(
        self,
        texts: tuple[str, ...],
        *,
        purpose: str,
        execution: ExecutionContext,
    ) -> tuple[tuple[float, ...], ...]:
        execution.cancel.raise_if_cancelled()
        capability = validate_embedding_capability(self._capability)
        if purpose == "search_query":
            purpose = "query"
        elif purpose == "search_document":
            purpose = "document"
        if purpose not in {"query", "document"}:
            raise CapabilityError("embedding purpose must explicitly be query or document")
        if not texts or len(texts) > MAX_EMBED_TEXTS:
            raise CapabilityError("embedding request text count is outside bounds")
        if purpose == "query" and len(texts) != 1:
            raise CapabilityError("query embedding accepts exactly one question")
        if any(
            not text.strip() or len(text.encode("utf-8")) > MAX_EMBED_TEXT_BYTES for text in texts
        ):
            raise CapabilityError("embedding text is empty or exceeds the input bound")
        body = _request_body(texts, purpose, capability)
        encoded_body = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(encoded_body) > capability.request_bytes:
            raise CapabilityError("embedding request exceeds the validated byte bound")
        args: dict[str, object] = {
            "modelId": capability.model_id,
            "body": encoded_body,
            "contentType": "application/json",
            "accept": "application/json",
            "guardrailIdentifier": capability.guardrail.identifier,
            "guardrailVersion": capability.guardrail.version,
        }
        try:
            response_value = await self._pool.run(
                lambda: self._client.invoke_model(**args),
                before_call=lambda: execution.calls.claim(CallKind.embedding),
            )
        except asyncio.CancelledError:
            raise
        except ProviderFailure:
            raise
        except Exception as exc:
            if _guardrail_blocked(exc):
                raise ProviderFailure("guardrail_blocked", retryable=False) from exc
            raise ProviderFailure("model_unavailable") from exc
        response = _mapping(response_value)
        raw_body = response.get("body") if response is not None else None
        try:
            read_method = getattr(raw_body, "read", None)
            if callable(read_method):
                decoded = cast(Callable[[int], bytes], read_method)(MAX_EMBED_RESPONSE_BYTES + 1)
            elif isinstance(raw_body, (bytes, str)):
                decoded = raw_body
            else:
                raise ProviderFailure("invalid_output", retryable=False)
            decoded_size = (
                len(decoded) if isinstance(decoded, bytes) else len(decoded.encode("utf-8"))
            )
            if decoded_size > MAX_EMBED_RESPONSE_BYTES:
                raise ProviderFailure("invalid_output", retryable=False)
            payload = cast(object, json.loads(decoded))
        except ProviderFailure:
            raise
        except (AttributeError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ProviderFailure("invalid_output", retryable=False) from exc
        vectors = _extract_vectors(payload, capability)
        if len(vectors) != len(texts):
            raise ProviderFailure("invalid_output", retryable=False)
        normalized = tuple(_normalize(vector, capability.dimensions) for vector in vectors)
        return normalized


class AdmittedSemanticSuggester:
    """Applies the question-scoped embedding permit before semantic provider work."""

    def __init__(
        self,
        suggester: SemanticSuggester,
        *,
        admission_store: EmbeddingAdmissionStore,
        clock: Clock | None = None,
    ) -> None:
        self._suggester = suggester
        self._admission_store = admission_store
        self._clock = clock or SystemClock()

    async def suggest(
        self,
        question: str,
        *,
        language: str,
        catalog: ContentCatalog,
        execution: ExecutionContext,
    ) -> SemanticSuggestion | None:
        execution.cancel.raise_if_cancelled()
        operation_id = uuid4()
        acquired = await self._admission_store.acquire(
            environment_id=execution.environment_id,
            question_id=execution.question_id,
            operation_id=operation_id,
            now=self._clock.now(),
        )
        if isinstance(acquired, StageCapacityRejection):
            if (
                acquired.question_id != execution.question_id
                or acquired.operation_id != operation_id
                or acquired.call != "embedding"
                or acquired.code is not ErrorCode.CAPACITY_LIMIT
                or acquired.outcome != "capacity"
            ):
                raise RuntimeError("embedding admission returned a rejection for another operation")
            return None
        if (
            acquired.question_id != execution.question_id
            or acquired.environment_id != execution.environment_id
            or acquired.operation_id != operation_id
            or acquired.call != "embedding"
        ):
            await self._admission_store.release(acquired)
            raise RuntimeError("embedding admission returned a grant for another operation")

        cancelled = False
        try:
            return await self._suggester.suggest(
                question,
                language=language,
                catalog=catalog,
                execution=execution,
            )
        except asyncio.CancelledError:
            # A cancelled semantic waiter cannot prove the provider's SDK thread stopped.
            # Keep the fence for recovery rather than releasing physical capacity early.
            cancelled = True
            raise
        finally:
            if not cancelled:
                await self._admission_store.release(acquired)


def _request_body(
    texts: tuple[str, ...], purpose: str, capability: EmbeddingCapability
) -> dict[str, object]:
    if capability.provider_mode == "titan_v2":
        if len(texts) != 1:
            raise CapabilityError("Titan v2 adapter sends one text per InvokeModel request")
        return {"inputText": texts[0], "dimensions": capability.dimensions, "normalize": True}
    cohere_mode = capability.query_mode if purpose == "query" else capability.document_mode
    return {"texts": list(texts), "input_type": cohere_mode, "truncate": "NONE"}


def _extract_vectors(payload: object, capability: EmbeddingCapability) -> list[list[object]]:
    payload_data = _mapping(payload)
    if payload_data is None:
        raise ProviderFailure("invalid_output", retryable=False)
    if capability.provider_mode == "titan_v2":
        values = payload_data.get("embedding")
        if not isinstance(values, list):
            raise ProviderFailure("invalid_output", retryable=False)
        return [cast(list[object], values)]
    values = payload_data.get("embeddings")
    values_data = _mapping(values)
    if values_data is not None:
        values = values_data.get("float")
    if not isinstance(values, list):
        raise ProviderFailure("invalid_output", retryable=False)
    vectors: list[list[object]] = []
    for raw_vector in cast(list[object], values):
        if not isinstance(raw_vector, list):
            raise ProviderFailure("invalid_output", retryable=False)
        vectors.append(cast(list[object], raw_vector))
    return vectors


def _normalize(vector: list[object], dimensions: int) -> tuple[float, ...]:
    if len(vector) != dimensions:
        raise ProviderFailure("invalid_output", retryable=False)
    converted: list[float] = []
    for item in vector:
        if (
            isinstance(item, bool)
            or not isinstance(item, (int, float))
            or not math.isfinite(float(item))
        ):
            raise ProviderFailure("invalid_output", retryable=False)
        converted.append(float(item))
    norm = math.sqrt(sum(value * value for value in converted))
    if norm == 0:
        raise ProviderFailure("invalid_output", retryable=False)
    return tuple(value / norm for value in converted)


def _mapping(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    raw_mapping = cast(dict[object, object], value)
    if any(not isinstance(key, str) for key in raw_mapping):
        return None
    return cast(dict[str, object], raw_mapping)


def _guardrail_blocked(error: Exception) -> bool:
    response = _mapping(cast(object, getattr(error, "response", None)))
    if response is None:
        return False
    error_data = _mapping(response.get("Error"))
    code = error_data.get("Code") if error_data is not None else None
    return isinstance(code, str) and "guardrail" in code.casefold()
