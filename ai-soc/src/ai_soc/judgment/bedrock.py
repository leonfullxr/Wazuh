"""Bounded, buffered Bedrock Converse and CountTokens adapter."""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import time
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Literal, Protocol, cast
from uuid import UUID, uuid4

from ai_soc.content.finding_catalog import validate_topic_context
from ai_soc.contracts.models import (
    CallKind,
    ExecutionContext,
    JudgmentRequest,
    ModelCapability,
    ModelCountGrant,
    RawJudgment,
    StageCapacityRejection,
    TokenUsage,
)
from ai_soc.contracts.ports import Clock, ModelCountAdmissionStore

from .capabilities import CapabilityError, validate_guardrail, validate_model_capability


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic(self) -> float:
        return time.monotonic()


_OUTPUT_INSTRUCTIONS = (
    'Return only UTF-8 JSON: {"schema_version":"1","findings":[]}. '
    "Each finding has finding_id, kind, template_id, evidence_ids, and bindings. "
    "Each binding maps a required binding ID to {evidence_id,field}. Never return prose."
)


class BedrockClient(Protocol):
    def count_tokens(self, **kwargs: object) -> dict[str, object]: ...
    def converse(self, **kwargs: object) -> dict[str, object]: ...


class ProviderFailure(RuntimeError):
    """Sanitized failure classification for one provider stage."""

    def __init__(self, state: str, *, retryable: bool = True) -> None:
        super().__init__(state)
        self.state = state
        self.retryable = retryable


class PhysicalCallPool:
    """Non-waiting bounded executor whose slots outlive cancelled awaiters."""

    def __init__(self, capacity: int = 4, *, name: str = "bedrock") -> None:
        if capacity < 1:
            raise ValueError("capacity must be positive")
        self._slots = threading.BoundedSemaphore(capacity)
        self._executor = ThreadPoolExecutor(max_workers=capacity, thread_name_prefix=name)

    async def run(
        self,
        call: Callable[[], object],
        *,
        before_call: Callable[[], None] | None = None,
        on_complete: Callable[[], Awaitable[None]] | None = None,
    ) -> object:
        if not self._slots.acquire(blocking=False):
            if on_complete is not None:
                await on_complete()
            raise ProviderFailure("capacity_limited", retryable=True)
        loop = asyncio.get_running_loop()
        completion = loop.create_future()
        completion.add_done_callback(lambda done: None if done.cancelled() else done.exception())

        async def release_permit() -> None:
            try:
                if on_complete is not None:
                    await on_complete()
                if not completion.done():
                    completion.set_result(None)
            except BaseException as exc:
                if not completion.done():
                    completion.set_exception(exc)

        def schedule_release() -> None:
            loop.create_task(release_permit())

        try:

            def invoke() -> object:
                if before_call is not None:
                    try:
                        before_call()
                    except Exception as exc:
                        raise ProviderFailure("capacity_limited", retryable=True) from exc
                return call()

            future = self._executor.submit(invoke)
        except BaseException:
            self._slots.release()
            if on_complete is not None:
                await on_complete()
            raise

        def completed(_: object) -> None:
            self._slots.release()
            try:
                loop.call_soon_threadsafe(schedule_release)
            except RuntimeError:
                # An event loop can only close after its owning task has ended.
                # Keep release best-effort if a caller closes it during shutdown.
                pass

        future.add_done_callback(lambda _: completed(None))
        wrapped = asyncio.wrap_future(future)
        try:
            result = await asyncio.shield(wrapped)
            await asyncio.shield(completion)
            return result
        except asyncio.CancelledError:
            # shield prevents cancellation of the asyncio wrapper; callback above
            # releases the local slot and shared permit only when the SDK returns.
            raise


class BedrockJudgmentProvider:
    """Implements only CountTokens and non-streaming, tool-free Converse."""

    def __init__(
        self,
        client: BedrockClient,
        *,
        count_client: BedrockClient | None = None,
        pool: PhysicalCallPool | None = None,
        count_pool: PhysicalCallPool | None = None,
        admission_store: ModelCountAdmissionStore,
        clock: Clock | None = None,
    ) -> None:
        self._client = client
        self._count_client = count_client or client
        self._pool = pool or PhysicalCallPool(4, name="bedrock-converse")
        self._count_pool = count_pool or PhysicalCallPool(4, name="bedrock-count")
        self._admission_store = admission_store
        self._clock = clock or SystemClock()

    @classmethod
    def from_boto3(
        cls,
        model: ModelCapability,
        *,
        admission_store: ModelCountAdmissionStore,
        clock: Clock | None = None,
    ) -> BedrockJudgmentProvider:
        """Create a regional client with the required finite SDK transport limits."""
        import boto3
        from botocore.config import Config

        capability = validate_model_capability(model)
        client_factory = cast(Callable[..., object], boto3.client)  # type: ignore[reportUnknownMemberType]
        common = {"region_name": capability.region}
        converse = client_factory(
            "bedrock-runtime",
            **common,
            config=Config(
                connect_timeout=3,
                read_timeout=27,
                retries={"total_max_attempts": 1, "mode": "standard"},
                max_pool_connections=4,
            ),
        )
        counter = client_factory(
            "bedrock-runtime",
            **common,
            config=Config(
                connect_timeout=3,
                read_timeout=5,
                retries={"total_max_attempts": 1, "mode": "standard"},
                max_pool_connections=4,
            ),
        )
        return cls(
            cast(BedrockClient, converse),
            count_client=cast(BedrockClient, counter),
            admission_store=admission_store,
            clock=clock,
        )

    @staticmethod
    def _prompt(
        request: JudgmentRequest,
    ) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        validate_model_capability(request.model)
        validate_guardrail(request.guardrail)
        if (
            request.topic_id != request.evidence.topic_id
            or request.topic_id != request.topic_pack.topic_id
        ):
            raise CapabilityError("judgment request contains cross-topic context")
        if not request.question.strip():
            raise CapabilityError("original question must be bound before provider invocation")
        if request.topic_pack.content_sha != request.evidence.content_sha:
            raise CapabilityError("topic pack and evidence content revisions differ")
        if request.max_output_tokens > request.model.max_output_tokens:
            raise CapabilityError("requested output exceeds selected model capability")
        if not request.finding_templates:
            raise CapabilityError("judgment request carries no approved finding template catalog")
        try:
            topic_text = validate_topic_context(request.topic_pack, request.finding_templates)
        except (TypeError, ValueError) as error:
            raise CapabilityError(
                "judgment request finding template catalog is invalid or oversized"
            ) from error

        system: list[dict[str, object]] = [
            {"text": request.standing_rules + "\n" + _OUTPUT_INSTRUCTIONS}
        ]
        cache_enabled = (
            request.model.cache_min_tokens > 0 and request.model.cache_max_checkpoints >= 2
        )
        if cache_enabled:
            system.append({"cachePoint": {"type": "default", "ttl": request.model.cache_ttl}})
        system.append({"text": topic_text})
        if cache_enabled:
            system.append({"cachePoint": {"type": "default", "ttl": request.model.cache_ttl}})
        evidence_json = request.evidence.model_dump_json(exclude_none=False)
        question_text = "UNTRUSTED ORIGINAL QUESTION DATA:\n" + json.dumps(
            request.question, ensure_ascii=False
        )
        user = [
            {"text": "UNTRUSTED TOPIC EVIDENCE DATA:\n" + evidence_json},
            {
                "guardContent": {
                    # guard_content: harmful-content and other policies on the question only;
                    # see AWS contextual grounding qualifiers (read 2026-10-07).
                    "text": {"text": question_text, "qualifiers": ["guard_content"]},
                }
            },
        ]
        messages: list[dict[str, object]] = [{"role": "user", "content": user}]
        return system, messages

    @staticmethod
    def bind_question(request: JudgmentRequest, question: str) -> JudgmentRequest:
        """Bind the planner's original question before count and invocation."""
        if not question.strip() or len(question.encode("utf-8")) > 16_384:
            raise CapabilityError("original question is empty or exceeds its contract bound")
        return request.model_copy(update={"question": question})

    @staticmethod
    def _count_input(request: JudgmentRequest) -> dict[str, object]:
        system, messages = BedrockJudgmentProvider._prompt(request)
        return {
            "modelId": request.model.count_tokens_model_id,
            "input": {"converse": {"system": system, "messages": messages}},
        }

    async def count(self, request: JudgmentRequest, *, execution: ExecutionContext) -> int:
        execution.cancel.raise_if_cancelled()
        _validate_execution_binding(request, execution)
        args = self._count_input(request)
        operation_id = uuid4()
        acquired = await self._admission_store.acquire(
            environment_id=execution.environment_id,
            question_id=execution.question_id,
            operation_id=operation_id,
            call="count",
            now=self._clock.now(),
        )
        try:
            grant = require_model_count_grant(acquired, execution, operation_id, "count")
            execution.cancel.raise_if_cancelled()
        except BaseException:
            if isinstance(acquired, ModelCountGrant):
                await self._admission_store.release(acquired)
            raise
        try:
            response_value = await self._count_pool.run(
                lambda: self._count_client.count_tokens(**args),
                before_call=lambda: execution.calls.claim(CallKind.COUNT),
                on_complete=lambda: self._admission_store.release(grant),
            )
        except asyncio.CancelledError:
            raise
        except ProviderFailure:
            raise
        except Exception as exc:
            raise ProviderFailure("token_count_unavailable") from exc
        response = _mapping(response_value)
        if response is None:
            raise ProviderFailure("token_count_unavailable", retryable=False)
        count = response.get("inputTokens")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ProviderFailure("token_count_unavailable", retryable=False)
        return count

    async def converse(
        self, request: JudgmentRequest, *, execution: ExecutionContext
    ) -> RawJudgment:
        execution.cancel.raise_if_cancelled()
        _validate_execution_binding(request, execution)
        system, messages = self._prompt(request)
        args: dict[str, object] = {
            "modelId": request.model.id,
            "system": system,
            "messages": messages,
            "inferenceConfig": {"maxTokens": request.max_output_tokens, "temperature": 0},
            "guardrailConfig": {
                "guardrailIdentifier": request.guardrail.identifier,
                "guardrailVersion": request.guardrail.version,
            },
        }
        if request.effort is not None:
            if request.effort not in request.model.efforts:
                raise CapabilityError("selected effort is not supported by model")
            if request.model.effort_transport != "additionalModelRequestFields":
                raise CapabilityError("selected effort has no supported transport")
            args["additionalModelRequestFields"] = request.model.effort_parameters[request.effort]
        operation_id = uuid4()
        acquired = await self._admission_store.acquire(
            environment_id=execution.environment_id,
            question_id=execution.question_id,
            operation_id=operation_id,
            call="converse",
            now=self._clock.now(),
        )
        try:
            grant = require_model_count_grant(acquired, execution, operation_id, "converse")
            execution.cancel.raise_if_cancelled()
        except BaseException:
            if isinstance(acquired, ModelCountGrant):
                await self._admission_store.release(acquired)
            raise
        try:
            response_value = await self._pool.run(
                lambda: self._client.converse(**args),
                before_call=lambda: execution.calls.claim(CallKind.converse),
                on_complete=lambda: self._admission_store.release(grant),
            )
        except asyncio.CancelledError:
            raise
        except ProviderFailure:
            raise
        except Exception as exc:
            if _guardrail_exception(exc):
                raise ProviderFailure("guardrail_blocked", retryable=False) from exc
            raise ProviderFailure("model_unavailable") from exc
        response = _mapping(response_value)
        if response is None:
            raise ProviderFailure("model_unavailable")
        output = response.get("output")
        output_data = _mapping(output)
        message = output_data.get("message") if output_data is not None else None
        message_data = _mapping(message)
        content = message_data.get("content") if message_data is not None else None
        stop_reason = response.get("stopReason")
        if not isinstance(stop_reason, str):
            raise ProviderFailure("model_unavailable")
        intervened = _response_guardrail_intervened(response)
        if not isinstance(content, list):
            content = []
        text_parts: list[str] = []
        for raw_part in cast(list[object], content):
            part = _mapping(raw_part)
            if part is None:
                continue
            text_value = part.get("text")
            if isinstance(text_value, str):
                text_parts.append(text_value)
        if intervened or stop_reason in {"content_filtered", "guardrail_intervened"}:
            usage = _normalize_usage(response.get("usage"), request)
            request_id = _mapping(response.get("ResponseMetadata"))
            request_id_value = request_id.get("RequestId", "") if request_id is not None else ""
            digest = hashlib.sha256(
                (request_id_value if isinstance(request_id_value, str) else "").encode()
            ).hexdigest()[:24]
            return RawJudgment(
                text=text_parts[0] if len(text_parts) == 1 else "",
                stop_reason=stop_reason,
                guardrail_intervened=True,
                usage=usage,
                provider_request_id=digest,
            )
        usage = _normalize_usage(response.get("usage"), request)
        request_id = _mapping(response.get("ResponseMetadata"))
        request_id_value = request_id.get("RequestId", "") if request_id is not None else ""
        digest = hashlib.sha256(
            (request_id_value if isinstance(request_id_value, str) else "").encode()
        ).hexdigest()[:24]
        return RawJudgment(
            text=text_parts[0] if len(text_parts) == 1 else "",
            stop_reason=stop_reason,
            guardrail_intervened=intervened,
            usage=usage,
            provider_request_id=digest,
        )


def _guardrail_exception(error: Exception) -> bool:
    response = _mapping(getattr(error, "response", None))
    if response is None:
        return False
    code = _mapping(response.get("Error"))
    code_value = code.get("Code", "") if code is not None else ""
    return isinstance(code_value, str) and "guardrail" in code_value.casefold()


def _response_guardrail_intervened(response: dict[str, object]) -> bool:
    if response.get("stopReason") == "guardrail_intervened":
        return True
    trace = _mapping(response.get("trace"))
    guardrail = _mapping(trace.get("guardrail")) if trace is not None else None
    if guardrail is not None:
        return guardrail.get("action") == "INTERVENED"
    return False


def _normalize_usage(raw: object, request: JudgmentRequest) -> TokenUsage | None:
    usage_data = _mapping(raw)
    if usage_data is None:
        return None
    names = ("inputTokens", "outputTokens", "cacheReadInputTokens", "cacheWriteInputTokens")
    values: list[int] = []
    for name in names:
        value = usage_data.get(name, 0)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            return None
        values.append(value)
    fresh, output, cache_read, cache_write = values
    if request.reservation_id is None:
        return None
    return TokenUsage(
        topic_id=request.topic_id,
        input_tokens=fresh,
        output_tokens=output,
        cache_read_input_tokens=cache_read,
        cache_write_input_tokens=cache_write,
        total_input_tokens=fresh + cache_read + cache_write,
        reserved_tokens=request.reserved_tokens,
        reservation_id=request.reservation_id,
    )


def _mapping(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    raw_mapping = cast(dict[object, object], value)
    if any(not isinstance(key, str) for key in raw_mapping):
        return None
    return cast(dict[str, object], raw_mapping)


def require_model_count_grant(
    grant: ModelCountGrant | StageCapacityRejection,
    execution: ExecutionContext,
    operation_id: UUID,
    call: Literal["count", "converse"],
) -> ModelCountGrant:
    failure_state = "token_count_unavailable" if call == "count" else "model_unavailable"
    if isinstance(grant, StageCapacityRejection):
        if (
            grant.question_id != execution.question_id
            or grant.operation_id != operation_id
            or grant.call != call
        ):
            raise ProviderFailure(failure_state, retryable=False)
        raise ProviderFailure("capacity_limited", retryable=True)
    if (
        grant.question_id != execution.question_id
        or grant.environment_id != execution.environment_id
        or grant.operation_id != operation_id
        or grant.call != call
    ):
        raise ProviderFailure(failure_state, retryable=False)
    return grant


def _validate_execution_binding(request: JudgmentRequest, execution: ExecutionContext) -> None:
    if (
        request.question_id != execution.question_id
        or request.evidence.environment_id != execution.environment_id
    ):
        raise CapabilityError("judgment request and execution context are not bound together")
