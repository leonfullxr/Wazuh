from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Literal, NotRequired, TypedDict, cast
from uuid import UUID, uuid4

import httpx
import pytest
from conftest import DynamoFixture
from fastapi.testclient import TestClient
from pydantic import SecretStr

from ai_soc.api.app import CSRF_COOKIE, create_app
from ai_soc.api.csrf import CsrfTokens
from ai_soc.contracts.canonical import owner_key
from ai_soc.contracts.models import (
    AdmissionGrant,
    AuthorizedSite,
    CallKind,
    CursorPayload,
    ErrorCode,
    ExecutionContext,
    FetchResult,
    FetchSpec,
    HTTPSUrl,
    IndexerCredential,
    IndexFamily,
    PageRequest,
    ResolvedWindow,
    SiteConfig,
    SnapshotKind,
    SnapshotRef,
    TemplateId,
    TraceContext,
    VerifiedPrincipal,
    Visibility,
)
from ai_soc.identity.policy import MappedSitePolicy, SiteAuthorizationError
from ai_soc.query.compiler import default_profile
from ai_soc.query.cursors import CursorCipher
from ai_soc.query.indexer import WazuhIndexer
from ai_soc.state.stage_admission import (
    DynamoReadAdmissionStore,
    MemoryReadAdmissionStore,
    StageDynamoClient,
)

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
FIXTURE_PATH = Path(__file__).parent / "data/query_resource_cases.json"
FIXTURE_SHA256 = "f7c790610c4267872ac109458a2bea1660306ab306c5baf3ad2876483bb9ef9f"
NO_REUSE_FIXTURE_SHA256 = "21718df15af9bad38c8a6c3fa555c423a02d8c134a61370490403a4cd30f4527"


def test_local_indexer_standin_fetches_through_authenticated_rest_app() -> None:
    """LOCAL-ONLY: a login-gated page request reaches the real indexer adapter."""
    principal = _principal()
    site = _authorized_site()
    now = NOW
    cipher = CursorCipher(keys={"current": b"k" * 32}, current_key_id="current", now=lambda: now)
    cursor = cipher.seal(
        CursorPayload(
            key_id="current",
            owner_key=principal.owner_key,
            environment_id="alpha",
            policy_hash=site.policy_hash,
            content_sha="c" * 40,
            question_id=uuid4(),
            topic_id="topic-alerts",
            fetch_id="fetch-page-smoke",
            template_id=TemplateId.alerts_rows_v1,
            filters=[],
            window=_fetch(0).window,
            projection_hash="d" * 64,
            sort_values=["2026-09-30T11:00:00Z", "alerts", "physical-row-001"],
            pit_id="local-pit",
            snapshot=SnapshotRef(
                kind=SnapshotKind.pit,
                key="e" * 64,
                at=now,
                expires_at=now + timedelta(minutes=4),
            ),
            page_size=1,
            expires_at=now + timedelta(minutes=4),
        )
    )
    state = ProtocolState("positive")
    server, thread, origin = _server(state)
    transport = httpx.AsyncClient(base_url=origin, trust_env=False, follow_redirects=False)
    indexer = WazuhIndexer(
        TokenBroker(),
        MemoryReadAdmissionStore(),
        lambda _site: transport,
        profiles={"wazuh-v4-fixture": default_profile("wazuh-v4-fixture")},
        clock=lambda: now,
        content_sha="c" * 40,
        cursor_cipher=cipher,
    )

    class Identity:
        async def verify(self, *, headers: object, edge: str) -> VerifiedPrincipal:
            assert edge == "browser"
            return principal

    class Application:
        async def page(self, request: PageRequest, verified: VerifiedPrincipal) -> FetchResult:
            assert verified.owner_key == principal.owner_key
            execution, _ = _execution(verified, operation="page")
            return await indexer.page(
                request.cursor,
                principal=verified,
                site=site,
                execution=execution,
            )

    class Clock:
        def now(self) -> datetime:
            return now

    class Readiness:
        def ready(self) -> bool:
            return True

    csrf = CsrfTokens(b"r" * 32, origin="https://soc.example.test")
    cookie, token = csrf.issue(
        owner_key=principal.owner_key,
        assertion_expires_at=principal.expires_at,
        now=now,
    )
    app = create_app(Application(), Identity(), csrf, Clock(), Readiness())  # type: ignore[arg-type]
    client = TestClient(app, base_url="https://soc.example.test")
    try:
        response = client.post(
            "/v1/fetches/page",
            json={"environment_id": "alpha", "cursor": cursor},
            headers={"Origin": "https://soc.example.test", "X-SOC-CSRF": token},
            cookies={CSRF_COOKIE: cookie},
        )
        assert response.status_code == 200, response.text
        assert response.json()["rows"]
        assert len(state.requests) == 1
        assert state.requests[0][0:2] == ("POST", "/_search")
        assert state.requests[0][2]["authorization"] == "Bearer b3-local-analyst-token"
    finally:
        import asyncio

        asyncio.run(transport.aclose())
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class Scenario(TypedDict):
    topic_ids: list[str]
    response_mode: str
    response_bytes: int
    expected_http_attempts: int
    expected_state: str
    expected_response_bytes: NotRequired[int]
    expected_error: NotRequired[str]


class IsolationStep(TypedDict):
    principal: str
    authorization: str
    policy_version: str


class IsolationScenario(TypedDict):
    steps: list[IsolationStep]
    expected_outcomes: list[str]
    expected_record_ids: list[str]
    expected_broker_principals: list[str]
    expected_http_attempts: int
    expected_error_codes: list[str | None]
    expected_physical_requests: list[str]


class CallLedger:
    def __init__(self) -> None:
        self.claimed: list[CallKind] = []

    def claim(self, kind: CallKind) -> None:
        self.claimed.append(kind)


class TokenBroker:
    async def issue(
        self,
        principal: VerifiedPrincipal,
        site: AuthorizedSite,
        *,
        execution: ExecutionContext,
    ) -> IndexerCredential:
        assert site.config.environment_id == execution.environment_id == "alpha"
        assert principal.owner_key == execution.owner_key
        return IndexerCredential(
            bearer_token=SecretStr("b3-local-analyst-token"),
            expires_at=NOW + timedelta(minutes=5),
            key_id="local-fixture-key",
        )


class IsolationBroker:
    def __init__(self) -> None:
        self.issued: list[tuple[str, str, str]] = []

    async def issue(
        self,
        principal: VerifiedPrincipal,
        site: AuthorizedSite,
        *,
        execution: ExecutionContext,
    ) -> IndexerCredential:
        assert principal.owner_key == execution.owner_key
        assert site.config.environment_id == execution.environment_id == "alpha"
        issue_number = sum(subject == principal.sub for subject, _, _ in self.issued) + 1
        policy_version = site.config.policy_version
        self.issued.append((principal.sub, site.policy_hash, policy_version))
        return IndexerCredential(
            bearer_token=SecretStr(f"{principal.sub}:{issue_number}:{policy_version}"),
            expires_at=NOW + timedelta(minutes=5),
            key_id=f"local-{principal.sub}-{issue_number}",
        )


class ProtocolState:
    def __init__(self, response_mode: str) -> None:
        self.response_mode = response_mode
        self.requests: list[tuple[str, str, dict[str, str], bytes]] = []
        self.response_sizes: list[int] = []
        self.declared_response_sizes: list[int | None] = []
        self.lock = threading.Lock()

    def record(self, method: str, path: str, headers: dict[str, str], body: bytes) -> None:
        with self.lock:
            self.requests.append((method, path, headers, body))

    def record_response(self, size: int, declared_size: int | None) -> None:
        with self.lock:
            self.response_sizes.append(size)
            self.declared_response_sizes.append(declared_size)


def _principal(
    subject: str = "analyst-query-resource-fixture",
    groups: tuple[str, ...] = ("soc-alpha",),
) -> VerifiedPrincipal:
    issuer = "https://identity.example.test"
    return VerifiedPrincipal(
        issuer=cast(HTTPSUrl, issuer),
        sub=subject,
        owner_key=owner_key(issuer, subject),
        groups=groups,
        edge="fixture",
        authenticated_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        assertion_hash="a" * 64,
    )


def _site_config() -> SiteConfig:
    return SiteConfig(
        environment_id="alpha",
        label="alpha local protocol fixture",
        enabled=True,
        indexer_origin="https://alpha.private.example.test",
        private_network_ref="fixture-private-alpha",
        jwt_issuer="soc-alpha",
        jwt_audience="wazuh-alpha",
        kms_signing_key_arn="arn:aws:kms:us-east-1:123456789012:key/fixture-alpha",
        ca_secret_arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:fixture-alpha",
        ca_secret_version="fixture-version",
        ca_sha256="b" * 64,
        group_role_map={"soc-alpha": ("analyst_read",)},
        role_visibility={"analyst_read": Visibility.full},
        allowed_index_patterns={IndexFamily.alerts: ("wazuh-alerts-alpha-*",)},
        mapping_profile="wazuh-v4-fixture",
        policy_version="fixture-policy-v1",
        pit_supported=False,
        allowed_templates=tuple(TemplateId),
        dls_attestation_version="fixture-attestation-v1",
        composite_role_visibility={"analyst_read": Visibility.full},
    )


def _authorized_site() -> AuthorizedSite:
    return MappedSitePolicy((_site_config(),), now=lambda: NOW).authorize(_principal(), "alpha")


def _execution(
    principal: VerifiedPrincipal,
    question_id: UUID | None = None,
    *,
    operation: Literal["ask", "page", "feedback", "semantic"] = "ask",
) -> tuple[ExecutionContext, CallLedger]:
    ledger = CallLedger()
    execution = ExecutionContext(
        question_id=question_id or uuid4(),
        operation=operation,
        owner_key=principal.owner_key,
        environment_id="alpha",
        deadline_at=NOW + timedelta(minutes=5),
        cancel=_NeverCancelled(),
        calls=ledger,
        admission=AdmissionGrant(
            holder_id=uuid4(),
            slot_ids=("fixture-owner",),
            expires_at=NOW + timedelta(minutes=5),
            fence=1,
        ),
        trace_context=TraceContext(trace_id="1" * 32, span_id="2" * 16, trace_flags=1),
    )
    return execution, ledger


class _NeverCancelled:
    def is_cancelled(self) -> bool:
        return False

    def raise_if_cancelled(self) -> None:
        return None

    async def wait(self) -> None:
        return None


def _fetch(number: int) -> FetchSpec:
    return FetchSpec(
        fetch_id=f"fetch-{number:02d}",
        template_id=TemplateId.alerts_rows_v1,
        window=ResolvedWindow(
            start=NOW - timedelta(days=1),
            end=NOW,
            semantics="rolling",
            source_text="last 24 hours",
            timezone="UTC",
            anchor_at=NOW,
        ),
        filters=[],
        page_size=1,
    )


def _response_body(mode: str, request_number: int, size: int) -> bytes:
    if mode in {"exact_empty", "oversize_empty"}:
        payload = json.dumps(
            {"hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}},
            separators=(",", ":"),
        ).encode()
        if mode == "oversize_empty":
            return payload
        exact_size = size
        return payload + b" " * (exact_size - len(payload))
    payload = {
        "hits": {
            "total": {"value": 1, "relation": "eq"},
            "hits": [
                {
                    "_index": "wazuh-alerts-alpha-2026.09.30",
                    "_id": f"physical-row-{request_number:03d}",
                    "_source": {
                        "@timestamp": "2026-09-30T11:00:00Z",
                        "agent": {"id": "007", "name": "alpha-agent"},
                        "rule": {"id": "5710", "level": 5, "groups": ["auth"]},
                        "data": {"srcip": "192.0.2.10", "dstip": "192.0.2.8"},
                    },
                }
            ],
        }
    }
    return json.dumps(payload, separators=(",", ":")).encode()


def _server(state: ProtocolState) -> tuple[ThreadingHTTPServer, threading.Thread, str]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:
            length = int(self.headers.get("content-length", "0"))
            body = self.rfile.read(length)
            headers = {key.lower(): value for key, value in self.headers.items()}
            state.record("POST", self.path, headers, body)
            if self.path.endswith("/_validate/query"):
                if state.response_mode == "validation_503":
                    self._write(503, b'{"error":"local unavailable"}')
                else:
                    self._write(200, b'{"valid":true}')
                return
            if self.path.endswith("/_search"):
                request_number = len(state.requests)
                response = _response_body(state.response_mode, request_number, 2_097_152)
                if state.response_mode == "oversize_chunked":
                    self._write_chunked(200, response)
                    return
                declared_size = 2_097_153 if state.response_mode == "oversize_empty" else None
                self._write(200, response, declared_size=declared_size)
                return
            self._write(404, b'{"error":"not found"}')

        def _write(self, status: int, body: bytes, *, declared_size: int | None = None) -> None:
            actual_declared_size = len(body) if declared_size is None else declared_size
            state.record_response(len(body), actual_declared_size)
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(actual_declared_size))
            self.send_header("content-encoding", "identity")
            self.end_headers()
            self.wfile.write(body)

        def _write_chunked(self, status: int, body: bytes) -> None:
            state.record_response(len(body), None)
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-encoding", "identity")
            self.send_header("transfer-encoding", "chunked")
            self.end_headers()
            for offset in range(0, len(body), 64):
                chunk = body[offset : offset + 64]
                self.wfile.write(f"{len(chunk):X}\r\n".encode() + chunk + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")

        def log_message(self, format: str, *args: object) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(
        target=server.serve_forever, name="b3-query-local-protocol", daemon=True
    )
    thread.start()
    host, port = cast(tuple[str, int], server.server_address)
    return server, thread, f"http://{host}:{port}"


class IsolationProtocolState:
    def __init__(self, variant: str) -> None:
        self.variant = variant
        self.requests: list[tuple[str, str, bytes]] = []
        self.lock = threading.Lock()

    def record(self, path: str, token: str, body: bytes) -> None:
        with self.lock:
            self.requests.append((path, token, body))


def _isolation_server(
    state: IsolationProtocolState,
) -> tuple[ThreadingHTTPServer, threading.Thread, str]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:
            length = int(self.headers.get("content-length", "0"))
            body = self.rfile.read(length)
            token = self.headers.get("authorization", "").removeprefix("Bearer ")
            state.record(self.path, token, body)
            subject = token.split(":", maxsplit=1)[0]
            if self.path.endswith("/_validate/query"):
                self._write(200, b'{"valid":true}')
                return
            if self.path.endswith("/_search") and state.variant == "failure" and subject == "bob":
                self._write(403, b'{"error":"analyst scope denied"}')
                return
            if self.path.endswith("/_search"):
                parts = token.split(":", maxsplit=2)
                if len(parts) != 3:
                    self._write(401, b'{"error":"invalid local token"}')
                    return
                _, _, policy_version = parts
                record_id = f"{subject}-{policy_version}-private-row"
                payload = {
                    "hits": {
                        "total": {"value": 1, "relation": "eq"},
                        "hits": [
                            {
                                "_index": "wazuh-alerts-alpha-2026.09.30",
                                "_id": record_id,
                                "_source": {
                                    "@timestamp": "2026-09-30T11:00:00Z",
                                    "agent": {"id": "007", "name": f"{subject}-agent"},
                                    "rule": {"id": "5710", "level": 5, "groups": ["auth"]},
                                    "data": {"srcip": "192.0.2.10", "dstip": "192.0.2.8"},
                                },
                            }
                        ],
                    }
                }
                self._write(
                    200,
                    json.dumps(payload, separators=(",", ":")).encode(),
                )
                return
            self._write(404, b'{"error":"not found"}')

        def _write(self, status: int, body: bytes) -> None:
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.send_header("content-encoding", "identity")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(
        target=server.serve_forever, name="b3-query-isolation-protocol", daemon=True
    )
    thread.start()
    host, port = cast(tuple[str, int], server.server_address)
    return server, thread, f"http://{host}:{port}"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "variant",
    [
        pytest.param(
            variant,
            marks=[
                pytest.mark.acceptance("G027"),
                pytest.mark.case_id("B3-G027.query-resource-component"),
                pytest.mark.variant(variant),
                pytest.mark.fixture_sha256(FIXTURE_SHA256),
            ],
        )
        for variant in ("positive", "boundary", "negative", "failure")
    ],
)
async def test_local_indexer_protocol_enforces_resource_bounds_and_no_32_topic_cutoff(
    dynamo_fixture: DynamoFixture, variant: str
) -> None:
    fixture_bytes = FIXTURE_PATH.read_bytes()
    digest = hashlib.sha256(fixture_bytes).hexdigest()
    if FIXTURE_SHA256:
        assert digest == FIXTURE_SHA256
    fixture = cast(dict[str, object], json.loads(fixture_bytes))
    scenarios = cast(dict[str, Scenario], fixture["cases"])
    scenario = scenarios[variant]
    principal = _principal()
    site = _authorized_site()
    transaction_start = sum(
        operation == "TransactWriteItems" for operation, _ in dynamo_fixture.calls
    )
    state = ProtocolState(scenario["response_mode"])
    server, thread, origin = _server(state)
    client = httpx.AsyncClient(base_url=origin, trust_env=False, follow_redirects=False)
    execution, call_ledger = _execution(principal)
    indexer = WazuhIndexer(
        TokenBroker(),
        DynamoReadAdmissionStore(
            cast(StageDynamoClient, dynamo_fixture.clients[0]), dynamo_fixture.table
        ),
        lambda _site, active_client=client: active_client,
        profiles={"wazuh-v4-fixture": default_profile("wazuh-v4-fixture")},
        clock=lambda: NOW,
        content_sha="c" * 40,
        response_bytes=scenario["response_bytes"],
    )
    outputs: list[FetchResult] = []
    try:
        for number, topic in enumerate(scenario["topic_ids"]):
            result = await indexer.execute(
                _fetch(number),
                topic_id=topic,
                question_id=execution.question_id,
                principal=principal,
                site=site,
                execution=execution,
            )
            outputs.append(result)

        assert len(state.requests) == scenario["expected_http_attempts"]
        assert all(method == "POST" for method, _, _, _ in state.requests)
        assert all(
            headers.get("authorization") == "Bearer b3-local-analyst-token"
            and headers.get("accept-encoding") == "identity"
            for _, _, headers, _ in state.requests
        )
        assert all(
            path.endswith("/_validate/query") or path.endswith("/_search")
            for _, path, _, _ in state.requests
        )
        assert len(call_ledger.claimed) == scenario["expected_http_attempts"]
        assert [result.topic_id for result in outputs] == scenario["topic_ids"]
        assert {str(result.state) for result in outputs} == {scenario["expected_state"]}

        if variant == "positive":
            assert len(outputs) == 40
            assert all(
                result.rows and result.count is not None and result.count.value == 1
                for result in outputs
            )
            assert all(
                "query" in json.loads(body)
                for _, path, _, body in state.requests
                if path.endswith("/_validate/query")
            )
        elif variant == "boundary":
            expected_size = scenario.get("expected_response_bytes")
            assert expected_size is not None
            assert state.response_sizes[-1] == expected_size
            assert outputs[0].count is not None and outputs[0].count.value == 0
        elif variant == "negative":
            expected_size = scenario.get("expected_response_bytes")
            expected_error = scenario.get("expected_error")
            assert expected_size is not None and expected_error is not None
            assert state.declared_response_sizes[-1] == expected_size
            assert outputs[0].error is not None
            assert outputs[0].error.code == ErrorCode(expected_error)
        else:
            expected_error = scenario.get("expected_error")
            assert expected_error is not None
            assert [path.endswith("/_validate/query") for _, path, _, _ in state.requests] == [True]
            assert outputs[0].error is not None
            assert outputs[0].error.code == ErrorCode(expected_error)

        transactions = [
            params
            for operation, params in dynamo_fixture.calls
            if operation == "TransactWriteItems"
        ]
        expected_transactions = scenario["expected_http_attempts"] * 2
        assert len(transactions) - transaction_start == expected_transactions
        assert all(params["TransactItems"] for params in transactions[transaction_start:])
    finally:
        await client.aclose()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


@pytest.mark.asyncio
async def test_streamed_chunked_response_without_content_length_is_bounded(
    dynamo_fixture: DynamoFixture,
) -> None:
    principal = _principal()
    site = _authorized_site()
    transaction_start = sum(
        operation == "TransactWriteItems" for operation, _ in dynamo_fixture.calls
    )
    state = ProtocolState("oversize_chunked")
    server, thread, origin = _server(state)
    client = httpx.AsyncClient(base_url=origin, trust_env=False, follow_redirects=False)
    execution, call_ledger = _execution(principal)
    indexer = WazuhIndexer(
        TokenBroker(),
        DynamoReadAdmissionStore(
            cast(StageDynamoClient, dynamo_fixture.clients[0]), dynamo_fixture.table
        ),
        lambda _site, active_client=client: active_client,
        profiles={"wazuh-v4-fixture": default_profile("wazuh-v4-fixture")},
        clock=lambda: NOW,
        content_sha="c" * 40,
        response_bytes=128,
    )
    try:
        result = await indexer.execute(
            _fetch(0),
            topic_id="topic-chunked-oversize",
            question_id=execution.question_id,
            principal=principal,
            site=site,
            execution=execution,
        )

        assert str(result.state) == "unavailable"
        assert result.error is not None and result.error.code == ErrorCode.EVIDENCE_LIMIT
        assert [path.endswith("/_validate/query") for _, path, _, _ in state.requests] == [
            True,
            False,
        ]
        assert len(call_ledger.claimed) == 2
        assert state.response_sizes[-1] > 128
        assert state.declared_response_sizes[-1] is None
        transactions = [
            params
            for operation, params in dynamo_fixture.calls
            if operation == "TransactWriteItems"
        ]
        assert len(transactions) - transaction_start == 4
    finally:
        await client.aclose()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "variant",
    [
        pytest.param(
            variant,
            marks=[
                pytest.mark.acceptance("GN01"),
                pytest.mark.case_id("B3-GN01.query-no-result-reuse.local-protocol"),
                pytest.mark.variant(variant),
                pytest.mark.fixture_sha256(NO_REUSE_FIXTURE_SHA256),
            ],
        )
        for variant in ("positive", "negative", "boundary", "failure")
    ],
)
async def test_local_indexer_reauthorizes_same_question_without_reusing_analyst_results(
    dynamo_fixture: DynamoFixture,
    variant: str,
) -> None:
    fixture_path = Path(__file__).parent / "data/query_no_reuse_cases.json"
    fixture_bytes = fixture_path.read_bytes()
    digest = hashlib.sha256(fixture_bytes).hexdigest()
    assert digest == NO_REUSE_FIXTURE_SHA256
    fixture = cast(dict[str, object], json.loads(fixture_bytes))
    principal_data = cast(dict[str, object], fixture["principals"])
    scenarios = cast(dict[str, IsolationScenario], fixture["variants"])
    scenario = scenarios[variant]
    question_id = uuid4()
    fetch = _fetch(0)
    config = _site_config()
    state = IsolationProtocolState(variant)
    server, thread, origin = _isolation_server(state)
    client = httpx.AsyncClient(base_url=origin, trust_env=False, follow_redirects=False)
    broker = IsolationBroker()
    indexer = WazuhIndexer(
        broker,
        DynamoReadAdmissionStore(
            cast(StageDynamoClient, dynamo_fixture.clients[0]), dynamo_fixture.table
        ),
        lambda _site, active_client=client: active_client,
        profiles={"wazuh-v4-fixture": default_profile("wazuh-v4-fixture")},
        clock=lambda: NOW,
        content_sha="c" * 40,
    )
    transaction_start = sum(
        operation == "TransactWriteItems" for operation, _ in dynamo_fixture.calls
    )
    outcomes: list[str] = []
    record_ids: list[str] = []
    error_codes: list[str | None] = []
    observed_question_ids: list[UUID] = []
    try:
        for step in scenario["steps"]:
            principal_fixture = cast(dict[str, object], principal_data[step["principal"]])
            principal = _principal(
                cast(str, principal_fixture["subject"]),
                tuple(cast(list[str], principal_fixture["groups"])),
            )
            active_config = config.model_copy(
                update={
                    "policy_version": step["policy_version"],
                    "dls_attestation_version": f"fixture-attestation-{step['policy_version']}",
                }
            )
            policy = MappedSitePolicy((active_config,), now=lambda: NOW)
            if step["authorization"] == "deny":
                with pytest.raises(SiteAuthorizationError) as denial:
                    policy.authorize(principal, "alpha")
                outcomes.append("site_denied")
                error_codes.append(denial.value.code.value)
                continue

            authorized = policy.authorize(principal, "alpha")
            execution, _ = _execution(principal, question_id)
            observed_question_ids.append(execution.question_id)
            result = await indexer.execute(
                fetch,
                topic_id="ldap",
                question_id=question_id,
                principal=principal,
                site=authorized,
                execution=execution,
            )
            outcomes.append(str(result.state))
            error_codes.append(str(result.error.code) if result.error is not None else None)
            record_ids.extend(
                row.record_ref.record_id for row in result.rows if row.record_ref is not None
            )
            assert result.scope.environment_id == "alpha"
            assert result.scope.policy_hash == authorized.policy_hash

        assert observed_question_ids == [question_id] * len(observed_question_ids)
        assert outcomes == scenario["expected_outcomes"]
        assert record_ids == scenario["expected_record_ids"]
        assert error_codes == scenario["expected_error_codes"]
        assert [subject for subject, _, _ in broker.issued] == scenario[
            "expected_broker_principals"
        ]
        assert len(state.requests) == scenario["expected_http_attempts"]
        actual_physical_requests = [
            f"{token.split(':', maxsplit=1)[0]}."
            f"{'validate' if path.endswith('/_validate/query') else 'search'}"
            for path, token, _ in state.requests
        ]
        assert actual_physical_requests == scenario["expected_physical_requests"]
        assert all(
            path.endswith("/_validate/query") or path.endswith("/_search")
            for path, _, _ in state.requests
        )
        for phase in ("validate", "search"):
            phase_bodies = [
                body
                for path, _, body in state.requests
                if path.endswith(f"/_{phase if phase == 'search' else 'validate/query'}")
            ]
            if phase_bodies:
                assert len(set(phase_bodies)) == 1
        transactions = [
            params
            for operation, params in dynamo_fixture.calls
            if operation == "TransactWriteItems"
        ]
        assert len(transactions) - transaction_start == scenario["expected_http_attempts"] * 2

        if variant == "positive":
            alice_tokens = [token for _, token, _ in state.requests if token.startswith("alice:")]
            assert alice_tokens[:2] == [alice_tokens[0]] * 2
            assert alice_tokens[2:] == [alice_tokens[2]] * 2
            assert alice_tokens[0] != alice_tokens[2]
            assert record_ids[0] != record_ids[1]
            assert record_ids[2] == record_ids[0]
        elif variant == "boundary":
            assert len({policy_hash for _, policy_hash, _ in broker.issued}) == 2
            assert [version for _, _, version in broker.issued] == ["policy-v1", "policy-v2"]
        elif variant == "failure":
            assert outcomes[-1] == "denied"
            assert error_codes[-1] == ErrorCode.INDEXER_DENIED.value
            assert len(record_ids) == 1
    finally:
        await client.aclose()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()
