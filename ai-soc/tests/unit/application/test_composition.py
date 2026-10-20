from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import cast
from uuid import uuid4

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import TypeAdapter
from starlette.applications import Starlette
from starlette.testclient import TestClient

from ai_soc.application.composition import (
    SocRuntime,
    _JudgmentProviderAdapter,
    compose_soc,
    compose_stage_admission_adapters,
    compose_state_adapters,
)
from ai_soc.config import ServiceConfig
from ai_soc.content.catalog import ContentCatalog
from ai_soc.contracts.coverage import case_fixture_bindings, validate_case_fixture_bindings
from ai_soc.contracts.models import (
    AuthorizedSite,
    BuildProvenance,
    CueCatalog,
    Effort,
    ExecutionContext,
    HTTPSUrl,
    IndexFamily,
    JudgmentRequest,
    ModelCapability,
    RawJudgment,
    SemanticSuggestion,
    SiteConfig,
    TemplateId,
    Visibility,
)
from ai_soc.contracts.ports import (
    ContentCatalog as ContentCatalogPort,
)
from ai_soc.contracts.ports import (
    EmbeddingAdmissionStore,
    ModelCountAdmissionStore,
)
from ai_soc.feedback.sqs import SqsClient as FeedbackSqsClient
from ai_soc.identity.alb import AlbAssertionVerifier, McpBearerVerifier
from ai_soc.judgment.embeddings import AdmittedSemanticSuggester
from ai_soc.mcp.server import VerifiedRequestContext
from ai_soc.query.compiler import default_profile
from ai_soc.query.indexer import WazuhIndexer
from ai_soc.state.admission import DynamoAdmissionStore, MemoryAdmissionStore
from ai_soc.state.dynamodb import DynamoClient, DynamoState
from ai_soc.state.feedback_control import FeedbackControlPool
from ai_soc.state.memory import MemoryState
from ai_soc.state.stage_admission import (
    DynamoEmbeddingAdmissionStore,
    DynamoModelCountAdmissionStore,
    DynamoReadAdmissionStore,
    MemoryEmbeddingAdmissionStore,
    MemoryModelCountAdmissionStore,
    MemoryReadAdmissionStore,
)
from ai_soc.telemetry.audit_delivery import SqsClient as AuditSqsClient
from ai_soc.telemetry.metrics import FixtureMetricExporter
from ai_soc.telemetry.tracing import FixtureSpanExporter


class _Dynamo:
    def get_item(self, **kwargs: object) -> dict[str, object]:
        return {}

    def put_item(self, **kwargs: object) -> dict[str, object]:
        return {}

    def update_item(self, **kwargs: object) -> dict[str, object]:
        return {}

    def transact_write_items(self, **kwargs: object) -> dict[str, object]:
        return {}

    def query(self, **kwargs: object) -> dict[str, object]:
        return {}


class _FailingDynamo(_Dynamo):
    def __init__(self) -> None:
        self.get_requests: list[dict[str, object]] = []

    def get_item(self, **kwargs: object) -> dict[str, object]:
        self.get_requests.append(kwargs)
        raise OSError("fixture DynamoDB unavailable")


NOW = datetime(2026, 10, 3, 12, tzinfo=UTC)
_LIVE_COMPOSITION_FIXTURE = Path(__file__).parent / "data" / "live_composition_cases.json"
_MCP_IDENTITY_FIXTURE = Path(__file__).parent / "data" / "mcp_identity_barrier_cases.json"
_MCP_IDENTITY_FIXTURE_SHA256 = "e021d6d8b6b48e6e40cd23037cad966bd340cec0ba00a5e813aea2d2faa697b5"
_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_CASE_CATALOG = json.loads((_REPOSITORY_ROOT / "docs/case_catalog.json").read_text())
_FREEZE = json.loads((_REPOSITORY_ROOT / "contracts/v1/freeze.json").read_text())
validate_case_fixture_bindings(_CASE_CATALOG, _FREEZE["case_fixture_bindings_sha256"])
_B5_G042_FIXTURE_HASH = case_fixture_bindings(_CASE_CATALOG)["B5-G042.composition.private"]


def _assert_g042_fixture_binding(variant: str) -> None:
    expected_hashes = _B5_G042_FIXTURE_HASH[variant]
    assert len(expected_hashes) == 1
    assert sha256(_LIVE_COMPOSITION_FIXTURE.read_bytes()).hexdigest() == expected_hashes[0]


class _Clock:
    def now(self) -> datetime:
        return NOW

    def monotonic(self) -> float:
        return 0.0


class _Readiness:
    def ready(self) -> bool:
        return True


class _Kms:
    def sign(self, **kwargs: object) -> dict[str, object]:
        return {}


class _Sqs:
    def send_message(self, *, QueueUrl: str, MessageBody: str) -> dict[str, object]:
        return {"MessageId": "fixture-message"}


class _JudgmentProvider:
    async def count(self, request: JudgmentRequest, *, execution: ExecutionContext) -> int:
        raise AssertionError("judgment provider must remain lazy during composition")

    async def converse(
        self, request: JudgmentRequest, *, execution: ExecutionContext
    ) -> RawJudgment:
        raise AssertionError("judgment provider must remain lazy during composition")


class _SemanticSuggester:
    async def suggest(
        self,
        question: str,
        *,
        language: str,
        catalog: ContentCatalogPort,
        execution: ExecutionContext,
    ) -> SemanticSuggestion | None:
        raise AssertionError("semantic suggester must remain lazy during composition")


def _unexpected_key(key_id: str) -> str:
    raise AssertionError("identity key resolution must remain lazy during composition")


def _unexpected_transport(site: AuthorizedSite) -> httpx.AsyncClient:
    raise AssertionError("transport must remain lazy during composition")


def _site() -> SiteConfig:
    return SiteConfig(
        environment_id="alpha",
        label="Alpha",
        enabled=True,
        indexer_origin="https://alpha.private.example.test",
        private_network_ref="fixture-alpha",
        jwt_issuer="soc-alpha",
        jwt_audience="wazuh-alpha",
        kms_signing_key_arn="arn:aws:kms:us-east-1:123456789012:key/alpha",
        ca_secret_arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:alpha",
        ca_secret_version="fixture-version",
        ca_sha256="a" * 64,
        group_role_map={"soc": ("analyst",)},
        role_visibility={"analyst": Visibility.full},
        allowed_index_patterns={IndexFamily.alerts: ("wazuh-alerts-alpha-*",)},
        mapping_profile="wazuh-v4-fixture",
        policy_version="policy-1",
        pit_supported=True,
        allowed_templates=(TemplateId.alerts_rows_v1,),
        dls_attestation_version="dls-1",
        composite_role_visibility={"analyst": Visibility.full},
    )


def _model() -> ModelCapability:
    return ModelCapability(
        id="fixture-model",
        label="Fixture model",
        region="us-east-1",
        resource_arns=("arn:aws:bedrock:us-east-1:123456789012:inference-profile/fixture",),
        context_tokens=8192,
        max_output_tokens=1024,
        count_tokens_model_id="fixture-count-model",
        efforts=(Effort.low,),
        effort_transport="none",
        effort_parameters={Effort.low: {}},
        output_strategy="strict_json_messages",
        count_strategy="count_tokens_converse",
        count_contract_sha256="b" * 64,
        cache_min_tokens=0,
        cache_max_checkpoints=0,
        cache_ttl="5m",
        validated_at=NOW,
        primary_doc_url=cast(
            HTTPSUrl,
            TypeAdapter(HTTPSUrl).validate_python("https://docs.example.test/model"),
        ),
    )


def _provenance() -> BuildProvenance:
    return BuildProvenance(
        service_sha="a" * 40,
        content_repository="https://example.test/soc-content",
        content_sha="b" * 40,
        pack_sha256="c" * 64,
        image_digest="sha256:" + "d" * 64,
        docs_origin="https://docs.example.test",
        docs_manifest_sha256="e" * 64,
    )


def test_fixture_composition_uses_equivalent_memory_state_and_admission() -> None:
    state, admission = compose_state_adapters("fixture", client=None, table_name=None)

    assert isinstance(state, MemoryState)
    assert isinstance(admission, MemoryAdmissionStore)


@pytest.mark.acceptance("G042")
@pytest.mark.case_id("B5-G042.composition.private")
@pytest.mark.variant("positive")
@pytest.mark.fixture_sha256(_B5_G042_FIXTURE_HASH["positive"][0])
def test_dynamo_composition_pairs_state_and_admission_on_explicit_table() -> None:
    _assert_g042_fixture_binding("positive")
    fixture = cast(dict[str, object], json.loads(_LIVE_COMPOSITION_FIXTURE.read_text()))
    assert fixture["mode"] == "live"
    positive = cast(dict[str, object], fixture["positive"])
    table_name = cast(str, positive["table_name"])
    client = _Dynamo()
    state, admission = compose_state_adapters("live", client=client, table_name=table_name)

    assert isinstance(state, DynamoState)
    assert state._table == table_name
    assert isinstance(admission, DynamoAdmissionStore)


@pytest.mark.acceptance("G042")
@pytest.mark.case_id("B5-G042.composition.private")
@pytest.mark.variant("boundary")
@pytest.mark.fixture_sha256(_B5_G042_FIXTURE_HASH["boundary"][0])
def test_two_live_compositions_share_the_configured_durable_followup_table() -> None:
    _assert_g042_fixture_binding("boundary")
    fixture = cast(dict[str, object], json.loads(_LIVE_COMPOSITION_FIXTURE.read_text()))
    boundary = cast(dict[str, object], fixture["boundary"])
    assert fixture["mode"] == "live"
    assert boundary["replicas"] == 2
    table_name = cast(str, boundary["table_name"])
    client = _Dynamo()

    replica_a, _ = compose_state_adapters("live", client=client, table_name=table_name)
    replica_b, _ = compose_state_adapters("live", client=client, table_name=table_name)

    assert isinstance(replica_a, DynamoState)
    assert isinstance(replica_b, DynamoState)
    assert replica_a is not replica_b
    assert replica_a._client is client
    assert replica_b._client is client
    assert replica_a._table == replica_b._table == table_name


@pytest.mark.asyncio
@pytest.mark.acceptance("G042")
@pytest.mark.case_id("B5-G042.composition.private")
@pytest.mark.variant("failure")
@pytest.mark.fixture_sha256(_B5_G042_FIXTURE_HASH["failure"][0])
async def test_live_followup_read_failure_propagates_without_memory_fallback() -> None:
    _assert_g042_fixture_binding("failure")
    fixture = cast(dict[str, object], json.loads(_LIVE_COMPOSITION_FIXTURE.read_text()))
    failure = cast(dict[str, object], fixture["failure"])
    table_name = cast(str, failure["table_name"])
    error_message = cast(str, failure["error_message"])
    client = _FailingDynamo()
    state, _ = compose_state_adapters("live", client=client, table_name=table_name)
    assert isinstance(state, DynamoState)

    with pytest.raises(OSError, match=error_message):
        await state.load_plan(
            uuid4(),
            owner_key="a" * 64,
            environment_id="alpha",
            revision=1,
            policy_hash="b" * 64,
            content_sha="c" * 40,
            now=NOW,
        )

    assert len(client.get_requests) == 1
    assert client.get_requests[0]["TableName"] == table_name
    assert client.get_requests[0]["ConsistentRead"] is True


def test_stage_admission_composition_pairs_all_physical_pools() -> None:
    fixture = compose_stage_admission_adapters("fixture", client=None, table_name=None)
    assert isinstance(fixture.reads, MemoryReadAdmissionStore)
    assert isinstance(fixture.model_count, MemoryModelCountAdmissionStore)
    assert isinstance(fixture.embeddings, MemoryEmbeddingAdmissionStore)

    durable = compose_stage_admission_adapters(
        "live", client=cast(DynamoClient, _Dynamo()), table_name="soc-live-state"
    )
    assert isinstance(durable.reads, DynamoReadAdmissionStore)
    assert isinstance(durable.model_count, DynamoModelCountAdmissionStore)
    assert isinstance(durable.embeddings, DynamoEmbeddingAdmissionStore)

    with pytest.raises(ValueError, match="live mode requires explicit DynamoDB stage admission"):
        compose_stage_admission_adapters("live", client=None, table_name=None)


@pytest.mark.acceptance("G042")
@pytest.mark.case_id("B5-G042.composition.private")
@pytest.mark.variant("negative")
@pytest.mark.fixture_sha256(_B5_G042_FIXTURE_HASH["negative"][0])
def test_live_composition_fails_closed_without_durable_state_and_admission() -> None:
    _assert_g042_fixture_binding("negative")
    fixture = cast(dict[str, object], json.loads(_LIVE_COMPOSITION_FIXTURE.read_text()))
    negative = cast(dict[str, object], fixture["negative"])
    assert negative == {"client_present": False, "table_present": False}
    with pytest.raises(ValueError, match="live mode requires explicit DynamoDB"):
        compose_state_adapters("live", client=None, table_name=None)

    with pytest.raises(ValueError, match="must be supplied together"):
        compose_state_adapters("live", client=cast(DynamoClient, _Dynamo()), table_name=None)


def _compose_fixture_runtime(
    mcp_key_resolver: Callable[[str], str | bytes] = _unexpected_key,
    identity_now: Callable[[], datetime] | None = None,
    state_client: DynamoClient | None = None,
    state_table: str | None = None,
) -> SocRuntime:
    site = _site()
    config = ServiceConfig(
        mode="fixture",
        guardrail_identifier="fixture-guardrail",
        guardrail_version="1",
        sites=(site,),
        models=(_model(),),
    )
    provenance = _provenance()
    catalog = ContentCatalog(
        provenance,
        CueCatalog(version="1", sha256="f" * 64, cues=[], aliases=[], ambiguities=[]),
        (),
        (),
    )
    clock = _Clock()
    kms = _Kms()
    sqs = cast(AuditSqsClient, _Sqs())
    feedback_sqs = cast(FeedbackSqsClient, _Sqs())
    alb = AlbAssertionVerifier(
        region="us-east-1",
        signer_arn="arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/soc/fixture",
        issuer="https://issuer.example.test",
        client_id="soc-client",
        groups_claim="groups",
        key_resolver=_unexpected_key,
        now=clock.now,
    )
    mcp = McpBearerVerifier(
        issuer="https://issuer.example.test",
        resource="https://soc.example.test/mcp",
        jwks_uri="https://issuer.example.test/.well-known/jwks.json",
        key_resolver=mcp_key_resolver,
        now=identity_now or clock.now,
        allowed_origins=frozenset({"https://soc.example.test"}),
    )

    def judgment_factory(admission: ModelCountAdmissionStore) -> _JudgmentProvider:
        if state_client is None:
            return _judgment_factory(admission)
        assert isinstance(admission, DynamoModelCountAdmissionStore)
        return _JudgmentProvider()

    def semantic_factory(admission: EmbeddingAdmissionStore) -> AdmittedSemanticSuggester:
        if state_client is None:
            return _semantic_factory(admission)
        assert isinstance(admission, DynamoEmbeddingAdmissionStore)
        return AdmittedSemanticSuggester(_SemanticSuggester(), admission_store=admission)

    runtime = compose_soc(
        config,
        clock=clock,
        catalog=catalog,
        state_client=state_client,
        state_table=state_table if state_client is not None else None,
        kms=kms,
        indexer_key_ids={"alpha": "fixture-key"},
        transport_for=_unexpected_transport,
        mapping_profiles={"wazuh-v4-fixture": default_profile()},
        cursor_cipher=None,
        judgment_provider_factory=judgment_factory,
        audit_client=sqs,
        audit_queue_url="https://sqs.us-east-1.amazonaws.com/123456789012/audit",
        feedback_client=feedback_sqs,
        feedback_queue_url="https://sqs.us-east-1.amazonaws.com/123456789012/feedback",
        span_exporter=FixtureSpanExporter(),
        metric_exporter=FixtureMetricExporter(),
        receipt_keys={"fixture": b"k" * 32},
        current_receipt_key="fixture",
        csrf_secret=b"s" * 32,
        browser_origin="https://soc.example.test",
        alb_verifier=alb,
        mcp_verifier=mcp,
        readiness=_Readiness(),
        standing_rules="fixture standing rules",
        mcp_issuer_url="https://issuer.example.test",
        mcp_resource_url="https://soc.example.test/mcp",
        semantic_suggester_factory=semantic_factory,
    )

    return runtime


def test_composition_builds_the_real_fixture_runtime_without_ambient_clients() -> None:
    runtime = _compose_fixture_runtime()

    assert isinstance(runtime.rest, Starlette)
    assert isinstance(runtime.mcp, VerifiedRequestContext)
    assert isinstance(runtime.application.plans, MemoryState)
    assert isinstance(runtime.application.fetches, WazuhIndexer)
    assert isinstance(runtime.application.fetches._read_admission, MemoryReadAdmissionStore)
    provider_adapter = cast(_JudgmentProviderAdapter, runtime.application.judgment_provider)
    assert isinstance(provider_adapter.provider, _JudgmentProvider)
    assert isinstance(runtime.application.semantic_suggester, AdmittedSemanticSuggester)
    assert isinstance(runtime.application.semantic_suggester._suggester, _SemanticSuggester)
    assert isinstance(
        runtime.application.semantic_suggester._admission_store, MemoryEmbeddingAdmissionStore
    )
    assert isinstance(runtime.application.admissions, MemoryAdmissionStore)
    assert runtime.application.question_admission is runtime.application.plans
    assert runtime.application.leases is runtime.application.plans
    assert runtime.application.budgets is runtime.application.plans
    assert runtime.application.completions is runtime.application.plans
    assert runtime.feedback_control_pool is None
    runtime.close_feedback_control()


def test_dynamo_composition_shares_owned_feedback_pool_with_state() -> None:
    runtime = _compose_fixture_runtime(
        state_client=cast(DynamoClient, _Dynamo()), state_table="fixture-state"
    )
    pool = runtime.feedback_control_pool
    assert pool is not None
    assert isinstance(runtime.application.feedback_store, DynamoState)
    assert runtime.application.feedback_store._feedback_control_pool is pool
    runtime.close_feedback_control()
    assert pool._closed


def test_composition_closes_feedback_pool_after_later_construction_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ai_soc.application.composition as composition

    pool = FeedbackControlPool()
    closed: list[bool] = []
    close = pool.close

    def track_close() -> None:
        closed.append(True)
        close()

    monkeypatch.setattr(pool, "close", track_close)
    monkeypatch.setattr(composition, "FeedbackControlPool", lambda: pool)

    def fail_adapter_construction(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("fixture adapter construction failure")

    monkeypatch.setattr(composition, "compose_state_adapters", fail_adapter_construction)
    with pytest.raises(RuntimeError, match="fixture adapter construction failure"):
        _compose_fixture_runtime(
            state_client=cast(DynamoClient, _Dynamo()), state_table="fixture-state"
        )
    assert closed == [True]
    assert pool._closed


def _mcp_token(private_key: str, *, audience: str, scope: str, groups: list[str]) -> str:
    now = datetime.now(UTC)
    claims = {
        "iss": "https://issuer.example.test",
        "sub": "fixture-analyst",
        "aud": audience,
        "scope": scope,
        "groups": groups,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()) - 5,
        "exp": int(now.timestamp()) + 3600,
    }
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "fixture-key"})


def _mcp_request(client: TestClient, token: str, *, origin: str) -> httpx.Response:
    return client.post(
        "/mcp",
        headers={
            "Authorization": f"Bearer {token}",
            "Origin": origin,
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "soc-composition-fixture", "version": "1"},
            },
        },
    )


def _identity_fixture() -> dict[str, object]:
    return cast(dict[str, object], json.loads(_MCP_IDENTITY_FIXTURE.read_text()))


@pytest.mark.acceptance("GMCP")
@pytest.mark.case_id("B5-GMCP.composed-identity.private")
@pytest.mark.variant("positive")
@pytest.mark.fixture_sha256(_MCP_IDENTITY_FIXTURE_SHA256)
def test_composed_mcp_accepts_the_exact_resource_audience_and_scope() -> None:
    fixture = _identity_fixture()
    positive = cast(dict[str, object], fixture["positive"])
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    runtime = _compose_fixture_runtime(lambda key_id: public_pem, lambda: datetime.now(UTC))
    token = _mcp_token(
        private_pem,
        audience=cast(str, positive["audience"]),
        scope=cast(str, positive["scope"]),
        groups=cast(list[str], positive["groups"]),
    )

    with TestClient(runtime.mcp, base_url="https://soc.example.test") as client:
        response = _mcp_request(client, token, origin=cast(str, positive["origin"]))

    assert response.status_code == positive["status"], response.text
    assert response.json()["result"]["serverInfo"]["name"] == "AI SOC"


@pytest.mark.acceptance("GMCP")
@pytest.mark.case_id("B5-GMCP.composed-identity.private")
@pytest.mark.variant("negative")
@pytest.mark.fixture_sha256(_MCP_IDENTITY_FIXTURE_SHA256)
def test_composed_mcp_rejects_audience_scope_and_origin_before_dispatch() -> None:
    fixture = _identity_fixture()
    for case in cast(list[dict[str, object]], fixture["negative"]):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        public_pem = (
            private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
        runtime = _compose_fixture_runtime(
            lambda key_id, pem=public_pem: pem, lambda: datetime.now(UTC)
        )
        token = _mcp_token(
            private_pem,
            audience=cast(str, case["audience"]),
            scope=cast(str, case["scope"]),
            groups=["soc"],
        )

        with TestClient(runtime.mcp, base_url="https://soc.example.test") as client:
            response = _mcp_request(client, token, origin=cast(str, case["origin"]))

        assert response.status_code == case["status"]
        assert response.json()["code"] == case["code"]
        assert "MCP-IDENTITY-PRIVATE-KEY-CANARY" not in response.text
        if response.status_code == 401:
            assert "oauth-protected-resource/mcp" in response.headers["www-authenticate"]
        else:
            assert "www-authenticate" not in response.headers


@pytest.mark.acceptance("GMCP")
@pytest.mark.case_id("B5-GMCP.composed-identity.private")
@pytest.mark.variant("boundary")
@pytest.mark.fixture_sha256(_MCP_IDENTITY_FIXTURE_SHA256)
def test_composed_mcp_accepts_the_exact_128_group_boundary() -> None:
    fixture = _identity_fixture()
    boundary = cast(dict[str, object], fixture["boundary"])
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    runtime = _compose_fixture_runtime(lambda key_id: public_pem, lambda: datetime.now(UTC))
    token = _mcp_token(
        private_pem,
        audience="https://soc.example.test/mcp",
        scope="soc:ask",
        groups=[f"group-{index:03}" for index in range(cast(int, boundary["group_count"]))],
    )

    with TestClient(runtime.mcp, base_url="https://soc.example.test") as client:
        response = _mcp_request(client, token, origin="https://soc.example.test")

    assert response.status_code == boundary["status"], response.text


@pytest.mark.acceptance("GMCP")
@pytest.mark.case_id("B5-GMCP.composed-identity.private")
@pytest.mark.variant("failure")
@pytest.mark.fixture_sha256(_MCP_IDENTITY_FIXTURE_SHA256)
def test_composed_mcp_sanitizes_a_key_resolver_failure() -> None:
    fixture = _identity_fixture()
    failure = cast(dict[str, object], fixture["failure"])
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    sentinel = cast(str, failure["key_resolver_error"])

    def unavailable_key(_: str) -> str:
        raise RuntimeError(sentinel)

    runtime = _compose_fixture_runtime(unavailable_key, lambda: datetime.now(UTC))
    token = _mcp_token(
        private_pem,
        audience="https://soc.example.test/mcp",
        scope="soc:ask",
        groups=["soc"],
    )
    with TestClient(runtime.mcp, base_url="https://soc.example.test") as client:
        response = _mcp_request(client, token, origin="https://soc.example.test")

    assert response.status_code == failure["status"]
    assert response.json()["code"] == failure["code"]
    assert sentinel not in response.text


def _judgment_factory(admission: ModelCountAdmissionStore) -> _JudgmentProvider:
    assert isinstance(admission, MemoryModelCountAdmissionStore)
    return _JudgmentProvider()


def _semantic_factory(admission: EmbeddingAdmissionStore) -> AdmittedSemanticSuggester:
    assert isinstance(admission, MemoryEmbeddingAdmissionStore)
    return AdmittedSemanticSuggester(_SemanticSuggester(), admission_store=admission)
