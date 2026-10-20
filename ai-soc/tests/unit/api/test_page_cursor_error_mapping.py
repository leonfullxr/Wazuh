"""Route-level cursor failure mapping for REST page and MCP soc_page."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from ai_soc.api.app import CSRF_COOKIE, create_app
from ai_soc.api.csrf import CsrfTokens
from ai_soc.contracts.errors import status_for
from ai_soc.contracts.models import (
    AdmissionGrant,
    ErrorCode,
    ExecutionContext,
    FetchResult,
    FetchSpec,
    FieldId,
    Filter,
    PageRequest,
    ResolvedWindow,
    TemplateId,
    TraceContext,
    VerifiedPrincipal,
)
from ai_soc.identity.policy import MappedSitePolicy
from ai_soc.mcp.server import create_mcp_app
from ai_soc.query.compiler import compile_fetch, default_profile
from ai_soc.query.cursors import CursorCipher
from tests.unit.mcp.test_server import Identity as McpFixtureIdentity
from tests.unit.query.conftest import NOW, Cancellation, Ledger, make_principal, make_site
from tests.unit.query.test_indexer_cursor import RecordingReadAdmission, hit, make_indexer


@pytest.fixture
def principal() -> VerifiedPrincipal:
    return make_principal()


@pytest.fixture
def site():
    config = make_site()
    authorized = MappedSitePolicy((config,), now=lambda: NOW).authorize(make_principal(), "alpha")
    return config, authorized


@pytest.fixture
def window() -> ResolvedWindow:
    return ResolvedWindow(
        start=NOW - timedelta(days=1),
        end=NOW,
        semantics="rolling",
        source_text="last 24 hours",
        timezone="UTC",
        anchor_at=NOW,
    )


@pytest.fixture
def fetch(window: ResolvedWindow) -> FetchSpec:
    return FetchSpec(
        fetch_id="fetch_alerts",
        template_id=TemplateId.alerts_rows_v1,
        window=window,
        filters=[Filter(field=FieldId.agent_id, op="eq", value="007")],
        page_size=2,
    )


@pytest.fixture
def execution(principal: VerifiedPrincipal) -> ExecutionContext:
    return ExecutionContext(
        question_id=uuid4(),
        operation="ask",
        owner_key=principal.owner_key,
        environment_id="alpha",
        deadline_at=NOW + timedelta(seconds=30),
        cancel=Cancellation(),
        calls=Ledger(),
        admission=AdmissionGrant(
            holder_id=uuid4(),
            slot_ids=("alpha-owner",),
            expires_at=NOW + timedelta(seconds=30),
            fence=1,
        ),
        trace_context=TraceContext(trace_id="1" * 32, span_id="1" * 16, trace_flags=1),
    )


@pytest.fixture
def cursor_cipher():
    return CursorCipher(keys={"key-1": b"k" * 32}, current_key_id="key-1", now=lambda: NOW)


@pytest.fixture
def mapping_profile():
    return default_profile("wazuh-v4-fixture")


class FixedClock:
    def now(self) -> datetime:
        return datetime(2026, 9, 30, 12, 0, tzinfo=UTC)


class BrowserIdentity:
    def __init__(self, principal: VerifiedPrincipal) -> None:
        self.principal = principal

    async def verify(self, *, headers: object, edge: str) -> VerifiedPrincipal:
        assert edge == "browser"
        return self.principal


class IndexerPageApplication:
    def __init__(self, indexer, policy: MappedSitePolicy) -> None:
        self._indexer = indexer
        self._policy = policy

    async def page(self, request: PageRequest, principal: VerifiedPrincipal) -> FetchResult:
        site = self._policy.authorize(principal, request.environment_id)
        execution = ExecutionContext(
            question_id=uuid4(),
            operation="page",
            owner_key=principal.owner_key,
            environment_id=request.environment_id,
            deadline_at=NOW + timedelta(seconds=30),
            cancel=Cancellation(),
            calls=Ledger(),
            admission=None,
            trace_context=TraceContext(trace_id="1" * 32, span_id="1" * 16, trace_flags=1),
        )
        return await self._indexer.page(
            request.cursor,
            principal=principal,
            site=site,
            execution=execution,
        )


def _csrf_headers(csrf: CsrfTokens, owner_key_value: str) -> dict[str, str]:
    cookie, token = csrf.issue(
        owner_key=owner_key_value,
        assertion_expires_at=NOW + timedelta(minutes=5),
        now=NOW,
    )
    return {
        "x-amzn-oidc-data": "fixture-token",
        "x-soc-csrf": token,
        "Origin": "https://soc.example.test",
        "Cookie": f"{CSRF_COOKIE}={cookie}",
    }


def _sealed_cursor(
    site,
    fetch,
    principal,
    execution,
    mapping_profile,
    cursor_cipher,
    handler,
    *,
    admission=None,
) -> tuple[str, IndexerPageApplication]:
    indexer, _, _, _ = make_indexer(
        site, mapping_profile, cursor_cipher, handler, admission=admission
    )
    compiled = compile_fetch(fetch, site[1], mapping_profile)
    first = indexer._result(
        {
            "hits": {
                "total": {"value": 2, "relation": "eq"},
                "hits": [hit("row-1", "2026-09-30T11:00:00Z")],
            }
        },
        compiled,
        fetch,
        "ldap",
        execution.question_id,
        site[1],
        pit_id="route-test-pit",
        profile=mapping_profile,
        principal=principal,
    )
    assert first.next_cursor is not None
    policy = MappedSitePolicy((site[0],), now=lambda: NOW)
    return first.next_cursor, IndexerPageApplication(indexer, policy)


@pytest.mark.parametrize(
    ("search_status", "expected_code"),
    [(403, ErrorCode.SITE_DENIED), (504, ErrorCode.INDEXER_UNAVAILABLE)],
)
def test_rest_page_preserves_indexer_cursor_error_codes(
    site,
    fetch,
    principal,
    execution,
    mapping_profile,
    cursor_cipher,
    search_status,
    expected_code,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/_validate/query"):
            return httpx.Response(200, json={"valid": True})
        return httpx.Response(search_status, json={"error": "synthetic"})

    cursor, application = _sealed_cursor(
        site, fetch, principal, execution, mapping_profile, cursor_cipher, handler
    )
    csrf = CsrfTokens(b"k" * 32, origin="https://soc.example.test")
    app = create_app(
        application,
        BrowserIdentity(principal),
        csrf,
        FixedClock(),
        type("Ready", (), {"ready": lambda self: True})(),
    )
    client = TestClient(app, base_url="https://soc.example.test")
    response = client.post(
        "/v1/fetches/page",
        headers=_csrf_headers(csrf, principal.owner_key),
        json={"environment_id": "alpha", "cursor": cursor},
    )
    assert response.status_code == status_for(expected_code)
    assert response.json()["code"] == expected_code.value


def test_rest_page_read_admission_rejection_maps_to_capacity_limit(
    site,
    fetch,
    principal,
    execution,
    mapping_profile,
    cursor_cipher,
) -> None:
    admission = RecordingReadAdmission(reject_calls=frozenset({("alpha", "search")}))

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/_validate/query"):
            return httpx.Response(200, json={"valid": True})
        return httpx.Response(200, json={"hits": {"total": 2, "hits": []}})

    cursor, application = _sealed_cursor(
        site,
        fetch,
        principal,
        execution,
        mapping_profile,
        cursor_cipher,
        handler,
        admission=admission,
    )
    csrf = CsrfTokens(b"k" * 32, origin="https://soc.example.test")
    app = create_app(
        application,
        BrowserIdentity(principal),
        csrf,
        FixedClock(),
        type("Ready", (), {"ready": lambda self: True})(),
    )
    client = TestClient(app, base_url="https://soc.example.test")
    response = client.post(
        "/v1/fetches/page",
        headers=_csrf_headers(csrf, principal.owner_key),
        json={"environment_id": "alpha", "cursor": cursor},
    )
    assert response.status_code == status_for(ErrorCode.CAPACITY_LIMIT)
    assert response.json()["code"] == ErrorCode.CAPACITY_LIMIT.value


def _mcp_headers() -> dict[str, str]:
    return {
        "Authorization": "Bearer good-token",
        "Origin": "https://soc.example.test",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }


def _mcp_initialize(client: TestClient):
    return client.post(
        "/mcp",
        headers=_mcp_headers(),
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "soc-fixture", "version": "1"},
            },
        },
    )


class CursorFailurePageApplication:
    def __init__(self, code: ErrorCode) -> None:
        self.code = code

    async def page(self, request: PageRequest, principal: VerifiedPrincipal) -> FetchResult:
        from ai_soc.query.cursors import CursorError

        raise CursorError(self.code)


@pytest.mark.parametrize(
    "expected_code",
    [
        ErrorCode.SITE_DENIED,
        ErrorCode.INDEXER_UNAVAILABLE,
        ErrorCode.CAPACITY_LIMIT,
    ],
)
def test_mcp_soc_page_preserves_cursor_error_codes(expected_code: ErrorCode) -> None:
    app = create_mcp_app(
        CursorFailurePageApplication(expected_code),
        McpFixtureIdentity(),
        issuer_url="https://issuer.example.test",
        resource_url="https://soc.example.test/mcp",
    )
    with TestClient(app, base_url="https://soc.example.test") as client:
        initialized = _mcp_initialize(client)
        assert initialized.status_code == 200
        response = client.post(
            "/mcp",
            headers=_mcp_headers(),
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "soc_page",
                    "arguments": {
                        "request": {"environment_id": "alpha", "cursor": "opaque-cursor"}
                    },
                },
            },
        )
    assert response.status_code == 200
    body = response.json()["result"]
    assert body["isError"] is True
    text = body["content"][0]["text"]
    prefix = "Error executing tool soc_page: "
    assert text.startswith(prefix)
    payload = json.loads(text.removeprefix(prefix))
    assert payload["code"] == expected_code.value
    assert status_for(expected_code) in (403, 429, 503)
