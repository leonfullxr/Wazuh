"""Independent G058 semantic-provider admission cases for the provider adapter."""

from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import uuid4

import boto3
import pytest
from admission_fakes import FakeStageAdmissionStore
from botocore.client import BaseClient
from botocore.stub import Stubber
from case_binding import (
    assert_fixture_matches_all_variants,
    canonical_acceptance_ids,
    canonical_fixture_sha256,
)

from ai_soc.contracts.models import (
    AdmissionGrant,
    CallKind,
    ExecutionContext,
    GuardrailPin,
    SemanticSuggestion,
    StageCapacityRejection,
    TraceContext,
)
from ai_soc.contracts.ports import ContentCatalog
from ai_soc.judgment.bedrock import ProviderFailure
from ai_soc.judgment.capabilities import CapabilityError, EmbeddingCapability
from ai_soc.judgment.embeddings import (
    AdmittedSemanticSuggester,
    BedrockEmbeddingProvider,
    EmbeddingClient,
)
from ai_soc.state.stage_admission import MemoryEmbeddingAdmissionStore

NOW = datetime(2026, 1, 1, tzinfo=UTC)
EMBEDDING_ADMISSION_FIXTURE = Path(__file__).parent / "data" / "embedding_admission_cases.json"


def _assert_g058_fixture(variant: str, assertions: list[str]) -> None:
    assert_fixture_matches_all_variants(
        "B4-G058.embedding-admission.private", EMBEDDING_ADMISSION_FIXTURE
    )
    parsed: object = json.loads(EMBEDDING_ADMISSION_FIXTURE.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict) or not isinstance(parsed.get("cases"), list):
        raise AssertionError("G058 fixture must contain case rows")
    rows = cast(list[object], parsed["cases"])
    for row in rows:
        if isinstance(row, dict) and row.get("variant") == variant:
            if row.get("assertions") != assertions:
                raise AssertionError(f"G058 {variant} fixture assertions changed")
            return
    raise AssertionError(f"G058 fixture has no {variant} variant")


class NeverCancelled:
    def is_cancelled(self) -> bool:
        return False

    def raise_if_cancelled(self) -> None:
        return None

    async def wait(self) -> None:
        await asyncio.Future()


class AttemptLedger:
    def __init__(self) -> None:
        self.attempts: list[CallKind] = []

    def claim(self, kind: CallKind) -> None:
        self.attempts.append(kind)


class InvokeClient:
    def __init__(self, body: bytes | None = None, error: Exception | None = None) -> None:
        self.body = body
        self.error = error
        self.calls: list[dict[str, object]] = []

    def invoke_model(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        if self.body is None:
            raise AssertionError("fixture response body was not configured")
        return {"body": self.body, "contentType": "application/json"}


class ProviderSuggester:
    def __init__(self, provider: BedrockEmbeddingProvider) -> None:
        self.provider = provider
        self.calls = 0

    async def suggest(
        self,
        question: str,
        *,
        language: str,
        catalog: ContentCatalog,
        execution: ExecutionContext,
    ) -> SemanticSuggestion | None:
        del language, catalog
        self.calls += 1
        await self.provider.embed((question,), purpose="query", execution=execution)
        return SemanticSuggestion(
            topic_id="ldap",
            score=0.9,
            margin=0.1,
            model_id="fixture",
            qualifies=True,
            near_threshold=False,
        )


def _suggestion_inputs(ledger: AttemptLedger) -> tuple[str, str, ContentCatalog, ExecutionContext]:
    return "ldap timeout", "en", cast(ContentCatalog, object()), _execution(ledger)


def _capability() -> EmbeddingCapability:
    return EmbeddingCapability(
        model_id="amazon.titan-embed-text-v2:0",
        region="us-east-1",
        resource_arns=(
            "arn:aws:bedrock:us-east-1:123456789012:foundation-model/amazon.titan-embed-text-v2:0",
        ),
        dimensions=3,
        purpose="topic_cards",
        normalization="l2",
        provider_mode="titan_v2",
        query_mode="single_text",
        document_mode="single_text",
        guardrail=GuardrailPin(identifier="embed-gr", version="2"),
        source_vpce="vpce-0123456789abcdef0",
        request_bytes=65_536,
        max_tokens=512,
        max_calls_per_question=1,
        requests_per_minute=30,
        validated_at=NOW,
        primary_doc_url="https://docs.aws.amazon.com/bedrock/latest/userguide/titan-embedding-models.html",
        validated=True,
    )


def _execution(ledger: AttemptLedger) -> ExecutionContext:
    return ExecutionContext(
        question_id=uuid4(),
        operation="semantic",
        owner_key="1" * 64,
        environment_id="alpha",
        deadline_at=NOW,
        cancel=NeverCancelled(),  # type: ignore[arg-type]
        calls=ledger,  # type: ignore[arg-type]
        admission=AdmissionGrant(
            holder_id=uuid4(), slot_ids=("semantic",), expires_at=NOW, fence=1
        ),
        trace_context=TraceContext(trace_id="1" * 32, span_id="2" * 16, trace_flags=1),
    )


@pytest.mark.asyncio
async def test_g058_exact_invoke_model_request_is_one_counted_transport_attempt() -> None:
    capability = _capability()
    client_factory = cast(Callable[..., BaseClient], boto3.client)  # type: ignore[reportUnknownMemberType]
    client = client_factory(
        "bedrock-runtime",
        region_name="us-east-1",
        aws_access_key_id="offline-fixture",
        aws_secret_access_key="offline-fixture-only",
    )
    ledger = AttemptLedger()
    expected_body = json.dumps(
        {"inputText": "ldap timeout", "dimensions": 3, "normalize": True},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    expected_request = {
        "modelId": capability.model_id,
        "body": expected_body,
        "contentType": "application/json",
        "accept": "application/json",
        "guardrailIdentifier": "embed-gr",
        "guardrailVersion": "2",
    }
    with Stubber(client) as stubber:
        stubber.add_response(  # type: ignore[reportUnknownMemberType]  # botocore ships partial stubs.
            "invoke_model",
            {"body": b'{"embedding":[3,4,0]}', "contentType": "application/json"},
            expected_request,
        )
        vectors = await BedrockEmbeddingProvider(
            client=cast(EmbeddingClient, client),
            capability=capability,
        ).embed(("ldap timeout",), purpose="query", execution=_execution(ledger))
        stubber.assert_no_pending_responses()

    assert vectors[0] == pytest.approx((0.6, 0.8, 0.0))
    assert ledger.attempts == [CallKind.embedding]


@pytest.mark.asyncio
async def test_g058_missing_exact_request_is_rejected_before_sdk_transport() -> None:
    client = InvokeClient(body=b'{"embedding":[1,0,0]}')
    with pytest.raises(CapabilityError, match="text count"):
        await BedrockEmbeddingProvider(client, _capability()).embed(
            (), purpose="query", execution=_execution(AttemptLedger())
        )
    assert client.calls == []


@pytest.mark.parametrize(
    ("capability", "message"),
    [
        pytest.param(
            replace(_capability(), validated=False),
            "not passed live validation",
            id="QA-014.resolution-disabled-capability",
        ),
        pytest.param(
            replace(_capability(), provider_mode="future-provider"),
            "unsupported embedding provider mode",
            id="QA-014.resolution-unsupported-provider",
        ),
    ],
)
@pytest.mark.asyncio
async def test_g058_disabled_or_unsupported_capability_never_reaches_sdk(
    capability: EmbeddingCapability, message: str
) -> None:
    client = InvokeClient(body=b'{"embedding":[1,0,0]}')
    with pytest.raises(CapabilityError, match=message):
        await BedrockEmbeddingProvider(client, capability).embed(
            ("ldap timeout",), purpose="query", execution=_execution(AttemptLedger())
        )
    assert client.calls == []


@pytest.mark.asyncio
async def test_g058_boto_config_and_timeout_are_single_attempt() -> None:
    capability = _capability()
    client = InvokeClient(error=TimeoutError("synthetic read timeout"))
    captured: list[tuple[str, dict[str, object]]] = []

    def factory(service_name: str, **kwargs: object) -> InvokeClient:
        captured.append((service_name, kwargs))
        return client

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(boto3, "client", factory)
    try:
        provider = BedrockEmbeddingProvider.from_boto3(capability)
        config = captured[0][1]["config"]
        assert captured[0][0] == "bedrock-runtime"
        assert captured[0][1]["region_name"] == capability.region
        assert config.connect_timeout == 3  # type: ignore[union-attr]
        assert config.read_timeout == 10  # type: ignore[union-attr]
        assert config.retries == {"total_max_attempts": 1, "mode": "standard"}  # type: ignore[union-attr]
        with pytest.raises(ProviderFailure, match="model_unavailable"):
            await provider.embed(
                ("ldap timeout",), purpose="query", execution=_execution(AttemptLedger())
            )
    finally:
        monkeypatch.undo()

    assert len(client.calls) == 1


@pytest.mark.parametrize(
    "token",
    [
        pytest.param("NaN", id="QA-014.resolution-nan-vector"),
        pytest.param("Infinity", id="QA-014.resolution-infinite-vector"),
    ],
)
@pytest.mark.asyncio
async def test_g058_nonfinite_embedding_vectors_are_rejected(token: str) -> None:
    client = InvokeClient(body=f'{{"embedding":[{token},0,0]}}'.encode("ascii"))
    with pytest.raises(ProviderFailure, match="invalid_output"):
        await BedrockEmbeddingProvider(client, _capability()).embed(
            ("ldap timeout",), purpose="query", execution=_execution(AttemptLedger())
        )
    assert len(client.calls) == 1


@pytest.mark.asyncio
@pytest.mark.case_id("B4-G058.embedding-admission.private")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G058.embedding-admission.private"))
@pytest.mark.variant("boundary")
@pytest.mark.fixture_sha256(
    canonical_fixture_sha256("B4-G058.embedding-admission.private", "boundary")
)
async def test_embedding_grant_stays_fenced_after_sdk_waiter_cancellation() -> None:
    _assert_g058_fixture(
        "boundary",
        [
            "cancelled SDK waiter retains the fenced embedding grant through physical "
            "call completion"
        ],
    )
    started = threading.Event()
    finish_call = threading.Event()
    physically_finished = threading.Event()

    class BlockingInvokeClient:
        def invoke_model(self, **kwargs: object) -> dict[str, object]:
            started.set()
            if not finish_call.wait(timeout=2):
                raise TimeoutError("test physical call barrier timed out")
            physically_finished.set()
            return {"body": b'{"embedding":[1,0,0]}'}

    store = FakeStageAdmissionStore()
    ledger = AttemptLedger()
    provider = BedrockEmbeddingProvider(BlockingInvokeClient(), _capability())
    base = ProviderSuggester(provider)
    suggester = AdmittedSemanticSuggester(base, admission_store=store)
    question, language, catalog, execution = _suggestion_inputs(ledger)
    task = asyncio.create_task(
        suggester.suggest(question, language=language, catalog=catalog, execution=execution)
    )
    assert await asyncio.to_thread(started.wait, 1)
    assert ledger.attempts == [CallKind.embedding]
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert store.released == []

    finish_call.set()
    assert await asyncio.to_thread(physically_finished.wait, 1)
    assert store.released == []
    assert store.grants[0].question_id == execution.question_id
    assert base.calls == 1


@pytest.mark.asyncio
@pytest.mark.case_id("B4-G058.embedding-admission.private")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G058.embedding-admission.private"))
@pytest.mark.variant("negative")
@pytest.mark.fixture_sha256(
    canonical_fixture_sha256("B4-G058.embedding-admission.private", "negative")
)
async def test_embedding_capacity_rejection_abstains_before_provider_or_ledger() -> None:
    _assert_g058_fixture(
        "negative",
        [
            "typed capacity rejection returns no suggestion",
            "provider and ledger remain untouched",
        ],
    )
    store = FakeStageAdmissionStore()
    store.reject = True
    ledger = AttemptLedger()
    client = InvokeClient(body=b'{"embedding":[1,0,0]}')
    provider = BedrockEmbeddingProvider(client, _capability())
    base = ProviderSuggester(provider)
    suggester = AdmittedSemanticSuggester(base, admission_store=store)
    question, language, catalog, execution = _suggestion_inputs(ledger)

    result = await suggester.suggest(
        question, language=language, catalog=catalog, execution=execution
    )

    assert result is None
    assert base.calls == 0
    assert client.calls == []
    assert ledger.attempts == []
    assert store.released == []


@pytest.mark.asyncio
@pytest.mark.case_id("B4-G058.embedding-admission.private")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G058.embedding-admission.private"))
@pytest.mark.variant("positive")
@pytest.mark.fixture_sha256(
    canonical_fixture_sha256("B4-G058.embedding-admission.private", "positive")
)
async def test_b5_embedding_fixture_store_releases_completed_semantic_grant() -> None:
    _assert_g058_fixture(
        "positive",
        [
            "one embedding grant",
            "one provider ledger claim",
            "exact grant release after completion",
        ],
    )
    store = MemoryEmbeddingAdmissionStore()
    ledger = AttemptLedger()
    execution = _execution(ledger)
    provider = BedrockEmbeddingProvider(InvokeClient(body=b'{"embedding":[1,0,0]}'), _capability())
    base = ProviderSuggester(provider)
    suggester = AdmittedSemanticSuggester(base, admission_store=store)

    result = await suggester.suggest(
        "ldap timeout", language="en", catalog=cast(ContentCatalog, object()), execution=execution
    )
    assert result is not None
    assert ledger.attempts == [CallKind.embedding]

    acquired = await store.acquire(
        environment_id=execution.environment_id,
        question_id=execution.question_id,
        operation_id=uuid4(),
        now=datetime.now(UTC),
    )
    assert not isinstance(acquired, StageCapacityRejection)
    await store.release(acquired)


@pytest.mark.asyncio
@pytest.mark.case_id("B4-G058.embedding-admission.private")
@pytest.mark.acceptance(*canonical_acceptance_ids("B4-G058.embedding-admission.private"))
@pytest.mark.variant("failure")
@pytest.mark.fixture_sha256(
    canonical_fixture_sha256("B4-G058.embedding-admission.private", "failure")
)
async def test_provider_failure_propagates_and_releases_completed_grant() -> None:
    _assert_g058_fixture(
        "failure",
        [
            "unexpected provider failure propagates",
            "completed failed call releases its exact grant",
        ],
    )
    store = FakeStageAdmissionStore()
    ledger = AttemptLedger()
    client = InvokeClient(error=TimeoutError("synthetic embedding timeout"))
    provider = BedrockEmbeddingProvider(client, _capability())
    suggester = AdmittedSemanticSuggester(ProviderSuggester(provider), admission_store=store)

    with pytest.raises(ProviderFailure, match="model_unavailable"):
        await suggester.suggest(
            "ldap timeout",
            language="en",
            catalog=cast(ContentCatalog, object()),
            execution=_execution(ledger),
        )

    assert len(client.calls) == 1
    assert ledger.attempts == [CallKind.embedding]
    assert store.released == store.grants
    assert len(store.released) == 1
    assert store.released[0] is store.grants[0]
