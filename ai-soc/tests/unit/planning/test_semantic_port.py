import asyncio
import hashlib
import io
import json
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import boto3
import pytest
from botocore.config import Config
from botocore.response import StreamingBody
from botocore.stub import Stubber
from support import make_catalog

from ai_soc.contracts.canonical import canonical_bytes
from ai_soc.contracts.models import (
    AdmissionGrant,
    CallKind,
    ContentId,
    EmbeddingGrant,
    EmbeddingManifest,
    ExecutionContext,
    GuardrailPin,
    StageCapacityRejection,
    TraceContext,
)
from ai_soc.contracts.ports import EmbeddingAdmissionStore, EmbeddingProvider, SemanticSuggester
from ai_soc.judgment.capabilities import EmbeddingCapability
from ai_soc.judgment.embeddings import AdmittedSemanticSuggester, BedrockEmbeddingProvider
from ai_soc.planning.semantic import (
    EmbeddingSemanticSuggester,
    SemanticIndex,
    SemanticProviderBinding,
)


class _Cancel:
    def is_cancelled(self) -> bool:
        return False

    def raise_if_cancelled(self) -> None:
        return None

    async def wait(self) -> None:
        await asyncio.Future()


class _Ledger:
    def __init__(self) -> None:
        self.attempts: list[CallKind] = []

    def claim(self, kind: CallKind) -> None:
        self.attempts.append(kind)


class _EmbeddingAdmission(EmbeddingAdmissionStore):
    def __init__(self) -> None:
        self.grants: list[EmbeddingGrant] = []
        self.released: list[EmbeddingGrant] = []
        self.acquire_calls = 0

    async def acquire(
        self,
        *,
        environment_id: ContentId,
        question_id: UUID,
        operation_id: UUID,
        now: datetime,
    ) -> EmbeddingGrant | StageCapacityRejection:
        self.acquire_calls += 1
        grant = EmbeddingGrant(
            question_id=question_id,
            environment_id=environment_id,
            operation_id=operation_id,
            holder_id=uuid4(),
            fence=1,
            acquired_at=now,
            lease_expires_at=now + timedelta(seconds=5),
            hard_deadline_at=now + timedelta(seconds=10),
            recover_after=now + timedelta(seconds=45),
        )
        self.grants.append(grant)
        return grant

    async def release(self, grant: EmbeddingGrant) -> None:
        self.released.append(grant)


class _Embedding:
    def __init__(self, result: tuple[tuple[float, ...], ...]) -> None:
        self.result = result
        self.calls = 0
        self.purposes: list[str] = []

    async def embed(
        self,
        texts: tuple[str, ...],
        *,
        purpose: str,
        execution: ExecutionContext,
    ) -> tuple[tuple[float, ...], ...]:
        assert texts == ("Tell me about directory login",)
        assert execution.operation == "semantic"
        self.calls += 1
        self.purposes.append(purpose)
        return self.result


class _FailingEmbedding(_Embedding):
    async def embed(
        self,
        texts: tuple[str, ...],
        *,
        purpose: str,
        execution: ExecutionContext,
    ) -> tuple[tuple[float, ...], ...]:
        assert texts == ("Tell me about directory login",)
        assert execution.operation == "semantic"
        self.calls += 1
        self.purposes.append(purpose)
        raise RuntimeError("embedding adapter failure")


class _RejectingEmbeddingAdmission(_EmbeddingAdmission):
    async def acquire(
        self,
        *,
        environment_id: ContentId,
        question_id: UUID,
        operation_id: UUID,
        now: datetime,
    ) -> StageCapacityRejection:
        self.acquire_calls += 1
        return StageCapacityRejection(
            question_id=question_id,
            operation_id=operation_id,
            call="embedding",
        )


class _ObservedEmbeddingClient:
    def __init__(self, client) -> None:
        self.client = client
        self.attempts = 0

    def invoke_model(self, **kwargs: object) -> dict[str, object]:
        self.attempts += 1
        return self.client.invoke_model(**kwargs)


def _execution(calls: _Ledger | None = None) -> ExecutionContext:
    now = datetime(2026, 9, 30, 12, tzinfo=UTC)
    return ExecutionContext(
        question_id=uuid4(),
        operation="semantic",
        owner_key="6" * 64,
        environment_id="alpha",
        deadline_at=now,
        cancel=_Cancel(),
        calls=calls or _Ledger(),
        admission=AdmissionGrant(holder_id=uuid4(), slot_ids=(), expires_at=now, fence=1),
        trace_context=TraceContext(trace_id="1" * 32, span_id="2" * 16, trace_flags=1),
    )


def _manifest(card_vectors: dict[str, tuple[float, ...]]) -> EmbeddingManifest:
    vector_sha = hashlib.sha256(
        canonical_bytes(
            {topic_id: list(card_vectors[topic_id]) for topic_id in sorted(card_vectors)}
        )
    ).hexdigest()
    return EmbeddingManifest(
        model_id="fixture-embed",
        region="us-east-1",
        dimensions=2,
        purpose="topic_cards",
        normalization="l2",
        corpus_sha256="3" * 64,
        vector_sha256=vector_sha,
        golden_sha256="5" * 64,
        threshold=0.8,
        minimum_margin=0.1,
        selection_report_path="reports/selection.json",
    )


def _binding() -> SemanticProviderBinding:
    return SemanticProviderBinding(
        model_id="fixture-embed",
        dimensions=2,
        purpose="topic_cards",
        normalization="l2",
        query_mode="single_text",
        document_mode="single_text",
    )


def _titan_capability() -> EmbeddingCapability:
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
        guardrail=GuardrailPin(identifier="embedding-gr", version="2"),
        source_vpce="vpce-0123456789abcdef0",
        request_bytes=65_536,
        max_tokens=512,
        max_calls_per_question=1,
        requests_per_minute=30,
        validated_at=datetime(2026, 9, 30, 12, tzinfo=UTC),
        primary_doc_url="https://docs.aws.amazon.com/bedrock/latest/userguide/titan-embedding-models.html",
        validated=True,
    )


def test_async_port_uses_typed_result_and_never_runs_after_deterministic_match() -> None:
    provider = _Embedding(((1.0, 0.0),))
    vectors = {"ldap": (1.0, 0.0), "dns": (0.0, 1.0)}
    index = SemanticIndex(_manifest(vectors), vectors, "single_text", "single_text")
    suggester = EmbeddingSemanticSuggester(index, provider, provider_binding=_binding())
    catalog = make_catalog()

    suggestion = asyncio.run(
        suggester.suggest(
            "Tell me about directory login",
            language="en",
            catalog=catalog,
            execution=_execution(),
        )
    )
    assert suggestion is not None
    assert suggestion.topic_id == "ldap"
    assert suggestion.qualifies
    assert suggestion.model_id == "fixture-embed"
    assert provider.calls == 1 and provider.purposes == ["query"]

    no_suggestion = asyncio.run(
        suggester.suggest(
            "Show LDAP alerts",
            language="en",
            catalog=catalog,
            execution=_execution(),
        )
    )
    assert no_suggestion is None
    assert provider.calls == 1


def test_disabled_semantic_index_is_distinct_from_a_missing_port() -> None:
    provider: EmbeddingProvider = _Embedding(((1.0, 0.0),))
    vectors = {"ldap": (1.0, 0.0)}
    index = SemanticIndex(_manifest(vectors), vectors, "query", "document", enabled=False)
    suggestion = asyncio.run(
        EmbeddingSemanticSuggester(index, provider, provider_binding=_binding()).suggest(
            "Tell me about directory login",
            language="en",
            catalog=make_catalog(),
            execution=_execution(),
        )
    )
    assert suggestion is None
    assert isinstance(provider, _Embedding)
    assert provider.calls == 0


def test_unexpected_embedding_failure_propagates_instead_of_becoming_abstention() -> None:
    provider = _FailingEmbedding(())
    vectors = {"ldap": (1.0, 0.0)}
    ranker: SemanticSuggester = EmbeddingSemanticSuggester(
        SemanticIndex(_manifest(vectors), vectors, "query", "document"),
        provider,
        provider_binding=_binding(),
    )
    admission = _EmbeddingAdmission()
    suggester = AdmittedSemanticSuggester(ranker, admission_store=admission)

    with pytest.raises(RuntimeError, match="embedding adapter failure"):
        asyncio.run(
            suggester.suggest(
                "Tell me about directory login",
                language="en",
                catalog=make_catalog(),
                execution=_execution(),
            )
        )

    assert provider.calls == 1
    assert provider.purposes == ["query"]
    assert admission.acquire_calls == 1
    assert admission.released == admission.grants


def test_async_port_returns_tie_as_nonqualifying_near_threshold_suggestion() -> None:
    provider = _Embedding(((0.7071067811865476, 0.7071067811865476),))
    vectors = {"dns": (0.0, 1.0), "ldap": (1.0, 0.0)}
    manifest = _manifest(vectors).model_copy(update={"threshold": 0.7, "minimum_margin": 0.1})
    suggestion = asyncio.run(
        EmbeddingSemanticSuggester(
            SemanticIndex(manifest, vectors, "query", "document"),
            provider,
            provider_binding=_binding(),
        ).suggest(
            "Tell me about directory login",
            language="en",
            catalog=make_catalog(),
            execution=_execution(),
        )
    )
    assert suggestion is not None
    assert not suggestion.qualifies and suggestion.near_threshold
    assert suggestion.margin == 0.0


def test_async_port_abstains_on_missing_vector_and_marks_low_score_nonqualifying() -> None:
    vectors = {"ldap": (1.0, 0.0)}
    index = SemanticIndex(_manifest(vectors), vectors, "query", "document")
    empty = asyncio.run(
        EmbeddingSemanticSuggester(index, _Embedding(()), provider_binding=_binding()).suggest(
            "Tell me about directory login",
            language="en",
            catalog=make_catalog(),
            execution=_execution(),
        )
    )
    assert empty is None

    low_score = asyncio.run(
        EmbeddingSemanticSuggester(
            index,
            _Embedding(((0.0, 1.0),)),
            provider_binding=_binding(),
        ).suggest(
            "Tell me about directory login",
            language="en",
            catalog=make_catalog(),
            execution=_execution(),
        )
    )
    assert low_score is not None
    assert low_score.topic_id == "ldap"
    assert low_score.score == 0.0
    assert not low_score.qualifies and not low_score.near_threshold


def test_semantic_index_rejects_vector_hash_and_provider_capability_mismatches() -> None:
    vectors = {"ldap": (1.0, 0.0)}
    manifest = _manifest(vectors)
    with pytest.raises(ValueError, match="vector hash"):
        SemanticIndex(manifest, {"ldap": (0.0, 1.0)}, "query", "document")
    provider = _Embedding(((1.0, 0.0),))
    index = SemanticIndex(manifest, vectors, "query", "document")
    with pytest.raises(ValueError, match="manifest hash"):
        SemanticIndex(manifest, vectors, "query", "document", manifest_sha256="9" * 64)
    bad_binding = SemanticProviderBinding(
        model_id="different-model",
        dimensions=2,
        purpose="topic_cards",
        normalization="l2",
        query_mode="single_text",
        document_mode="single_text",
    )
    with pytest.raises(ValueError, match="does not match"):
        EmbeddingSemanticSuggester(index, provider, provider_binding=bad_binding)


@pytest.mark.asyncio
async def test_real_bedrock_embedding_adapter_feeds_bilingual_semantic_ranking() -> None:
    capability = _titan_capability()
    model_id = capability.model_id
    vectors = {"ldap": (1.0, 0.0, 0.0), "dns": (0.0, 1.0, 0.0)}
    manifest = EmbeddingManifest(
        model_id=model_id,
        region="us-east-1",
        dimensions=3,
        purpose="topic_cards",
        normalization="l2",
        corpus_sha256="3" * 64,
        vector_sha256=hashlib.sha256(
            canonical_bytes({topic_id: list(vectors[topic_id]) for topic_id in sorted(vectors)})
        ).hexdigest(),
        golden_sha256="5" * 64,
        threshold=0.8,
        minimum_margin=0.1,
        selection_report_path="reports/selection.json",
    )
    client = boto3.client(
        "bedrock-runtime",
        region_name="us-east-1",
        aws_access_key_id="fixture-key",
        aws_secret_access_key="fixture-secret",
        config=Config(connect_timeout=3, read_timeout=10, retries={"total_max_attempts": 1}),
    )
    query = "Tell me about directory login"
    expected_body = json.dumps(
        {"inputText": query, "dimensions": 3, "normalize": True},
        separators=(",", ":"),
    ).encode()
    response_body = json.dumps({"embedding": [1.0, 0.0, 0.0]}).encode()
    with Stubber(client) as stubber:
        stubber.add_response(
            "invoke_model",
            {
                "body": StreamingBody(io.BytesIO(response_body), len(response_body)),
                "contentType": "application/json",
            },
            {
                "modelId": model_id,
                "body": expected_body,
                "contentType": "application/json",
                "accept": "application/json",
                "guardrailIdentifier": "embedding-gr",
                "guardrailVersion": "2",
            },
        )
        ledger = _Ledger()
        admission_store = _EmbeddingAdmission()
        provider = BedrockEmbeddingProvider(client, capability)
        binding = SemanticProviderBinding(
            model_id=capability.model_id,
            dimensions=capability.dimensions,
            purpose="topic_cards",
            normalization="l2",
            query_mode=capability.query_mode,
            document_mode=capability.document_mode,
        )
        ranker = EmbeddingSemanticSuggester(
            SemanticIndex(manifest, vectors, "query", "document"),
            provider,
            provider_binding=binding,
        )
        suggester = AdmittedSemanticSuggester(ranker, admission_store=admission_store)
        suggestion = await suggester.suggest(
            query,
            language="en",
            catalog=make_catalog(),
            execution=ExecutionContext(
                question_id=uuid4(),
                operation="semantic",
                owner_key="6" * 64,
                environment_id="alpha",
                deadline_at=datetime(2026, 9, 30, 12, tzinfo=UTC),
                cancel=_Cancel(),
                calls=ledger,
                admission=AdmissionGrant(
                    holder_id=uuid4(),
                    slot_ids=(),
                    expires_at=datetime(2026, 9, 30, 12, tzinfo=UTC),
                    fence=1,
                ),
                trace_context=TraceContext(trace_id="1" * 32, span_id="2" * 16, trace_flags=1),
            ),
        )
        assert suggestion is not None
        assert suggestion.topic_id == "ldap" and suggestion.qualifies
        assert suggestion.model_id == model_id
        assert ledger.attempts == [CallKind.embedding]
        assert admission_store.acquire_calls == 1
        assert len(admission_store.grants) == 1
        assert admission_store.released == admission_store.grants
        stubber.assert_no_pending_responses()


@pytest.mark.asyncio
async def test_embedding_capacity_rejection_abstains_before_ranker_or_provider_work() -> None:
    capability = _titan_capability()
    model_id = capability.model_id
    client = boto3.client(
        "bedrock-runtime",
        region_name="us-east-1",
        aws_access_key_id="fixture-key",
        aws_secret_access_key="fixture-secret",
        config=Config(connect_timeout=3, read_timeout=10, retries={"total_max_attempts": 1}),
    )
    observed_client = _ObservedEmbeddingClient(client)
    vectors = {"ldap": (1.0, 0.0, 0.0)}
    provider = BedrockEmbeddingProvider(observed_client, capability)
    ranker = EmbeddingSemanticSuggester(
        SemanticIndex(
            _manifest(vectors).model_copy(update={"dimensions": 3, "model_id": model_id}),
            # The fixture vectors stay independent while matching the exact SDK capability.
            vectors,
            "query",
            "document",
        ),
        provider,
        provider_binding=SemanticProviderBinding(
            model_id=model_id,
            dimensions=3,
            purpose="topic_cards",
            normalization="l2",
            query_mode="single_text",
            document_mode="single_text",
        ),
    )
    admission = _RejectingEmbeddingAdmission()
    suggester = AdmittedSemanticSuggester(ranker, admission_store=admission)

    ledger = _Ledger()
    execution = _execution(ledger)
    query = "Tell me about directory login"
    expected_body = json.dumps(
        {"inputText": query, "dimensions": 3, "normalize": True},
        separators=(",", ":"),
    ).encode()
    response_body = json.dumps({"embedding": [1.0, 0.0, 0.0]}).encode()
    with Stubber(client) as stubber:
        stubber.add_response(
            "invoke_model",
            {
                "body": StreamingBody(io.BytesIO(response_body), len(response_body)),
                "contentType": "application/json",
            },
            {
                "modelId": model_id,
                "body": expected_body,
                "contentType": "application/json",
                "accept": "application/json",
                "guardrailIdentifier": "embedding-gr",
                "guardrailVersion": "2",
            },
        )
        result = await suggester.suggest(
            query,
            language="en",
            catalog=make_catalog(),
            execution=execution,
        )

    assert result is None
    assert admission.acquire_calls == 1
    assert admission.grants == []
    assert admission.released == []
    assert observed_client.attempts == 0
    assert ledger.attempts == []
