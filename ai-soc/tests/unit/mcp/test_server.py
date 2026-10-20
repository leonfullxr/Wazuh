from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from ai_soc.application.errors import ServiceFailure
from ai_soc.contracts.errors import public_error
from ai_soc.contracts.models import (
    Answer,
    AnswerStatus,
    BuildProvenance,
    ErrorCode,
    VerifiedPrincipal,
)
from ai_soc.mcp.server import create_mcp_app
from ai_soc.query.cursors import CursorCipher

_SURFACE_BYTES = Path(__file__).with_name("data").joinpath("gmcp_surface_cases.json").read_bytes()
_SURFACE_SHA256 = "ef4539658672e3f3ad7dfc54d67d92aeea054300c37e873a24831c365727467b"
assert hashlib.sha256(_SURFACE_BYTES).hexdigest() == _SURFACE_SHA256
_SURFACE = json.loads(_SURFACE_BYTES)


class Identity:
    def __init__(self) -> None:
        self.calls = 0

    async def verify(self, *, headers: object, edge: str) -> VerifiedPrincipal:
        self.calls += 1
        assert edge == "mcp"
        assert isinstance(headers, dict)
        if headers.get("authorization") != "Bearer good-token":
            raise ServiceFailure(
                public_error(
                    ErrorCode.AUTH_INVALID,
                    "Authentication could not be verified.",
                    trace_id="a" * 32,
                )
            )
        return VerifiedPrincipal(
            issuer="https://issuer.example.test",
            sub="analyst-mcp",
            owner_key="b" * 64,
            groups=("soc",),
            edge="mcp",
            authenticated_at=datetime(2026, 9, 30, tzinfo=UTC),
            expires_at=datetime(2030, 9, 30, 0, 5, tzinfo=UTC),
            assertion_hash="c" * 64,
        )


class Application:
    def __init__(self) -> None:
        self.ask_principal: VerifiedPrincipal | None = None

    async def ask(self, request, principal, *, idempotency_key=None) -> Answer:
        self.ask_principal = principal
        return Answer(
            question_id=uuid4(),
            environment_id=request.environment_id,
            language="en",
            status=AnswerStatus.answered,
            blocks=[],
            left_out=[],
            provenance=BuildProvenance(
                service_sha="a" * 40,
                content_repository="https://example.test/soc-content",
                content_sha="b" * 40,
                pack_sha256="c" * 64,
                image_digest="sha256:" + "d" * 64,
                docs_origin="https://docs.example.test",
                docs_manifest_sha256="e" * 64,
            ),
            trace_id="f" * 32,
            feedback_receipt="opaque-receipt",
        )

    async def page(self, request, principal):
        raise AssertionError("page should not run in this test")

    async def feedback(self, request, principal):
        raise AssertionError("feedback should not run in this test")


def client() -> tuple[TestClient, Identity, Application]:
    identity = Identity()
    application = Application()
    app = create_mcp_app(
        application,
        identity,
        issuer_url="https://issuer.example.test",
        resource_url="https://soc.example.test/mcp",
    )
    return TestClient(app, base_url="https://soc.example.test"), identity, application


def headers(token: str = "good-token") -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Origin": "https://soc.example.test",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }


def test_mcp_sdk_rejects_cookie_only_and_unknown_routes_before_work() -> None:
    client_, identity, _ = client()
    unauthorized = client_.post(
        "/mcp",
        headers={"Origin": "https://soc.example.test", "Content-Type": "application/json"},
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    missing = client_.get("/not-mcp")

    assert unauthorized.status_code == 401
    assert "oauth-protected-resource/mcp" in unauthorized.headers["www-authenticate"]
    assert missing.status_code == 404
    assert identity.calls == 0


def test_mcp_rejects_trailing_and_encoded_path_aliases_before_authentication() -> None:
    client_, identity, _ = client()

    trailing = client_.post(
        "/mcp/",
        headers=headers(),
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    encoded = client_.post(
        "/%6dcp",
        headers=headers(),
        json={"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {}},
    )

    assert trailing.status_code == encoded.status_code == 404
    assert identity.calls == 0


def test_mcp_rejects_disallowed_origin_before_tool_dispatch() -> None:
    client_, identity, application = client()
    origin = _SURFACE["cases"]["negative"]["disallowed_origin"]
    request_headers = {**headers(), "Origin": origin}
    with client_:
        response = client_.post(
            "/mcp",
            headers=request_headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "origin-fixture", "version": "1"},
                },
            },
        )

    assert response.status_code == _SURFACE["cases"]["negative"]["origin_status"]
    assert identity.calls == 2
    assert application.ask_principal is None


def test_mcp_negotiates_latest_version_for_unsupported_client_version() -> None:
    client_, _, application = client()
    version = _SURFACE["cases"]["positive"]["unsupported_protocol_version"]
    with client_:
        response = client_.post(
            "/mcp",
            headers=headers(),
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": version,
                    "capabilities": {},
                    "clientInfo": {"name": "version-fixture", "version": "1"},
                },
            },
        )

    assert response.status_code == 200
    assert (
        response.json()["result"]["protocolVersion"]
        == _SURFACE["cases"]["positive"]["negotiated_protocol_version"]
    )
    assert application.ask_principal is None


def test_mcp_sdk_enforces_the_bounded_request_body_before_tool_dispatch() -> None:
    client_, _, application = client()
    response = client_.post("/mcp", headers=headers(), content=b" " * 65_537)

    assert response.status_code == 413
    assert application.ask_principal is None


@pytest.mark.acceptance("GMCP")
@pytest.mark.case_id("B5-GMCP.protocol-surface")
@pytest.mark.variant("boundary")
@pytest.mark.fixture_sha256(_SURFACE_SHA256)
@pytest.mark.acceptance("GMCP")
@pytest.mark.case_id("B5-GMCP.protocol-surface")
@pytest.mark.variant("boundary")
@pytest.mark.fixture_sha256(_SURFACE_SHA256)
def test_mcp_sdk_accepts_exact_body_limit_and_rejects_one_byte_over() -> None:
    case = _SURFACE["cases"]["boundary"]
    client_, _, application = client()
    initialize = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "limit-fixture", "version": "1"},
            },
        },
        separators=(",", ":"),
    ).encode("utf-8")
    assert len(initialize) < case["request_limit_bytes"]
    exact = initialize + b" " * (case["request_limit_bytes"] - len(initialize))
    over = exact + b" "

    with client_:
        accepted = client_.post("/mcp", headers=headers(), content=exact)
        rejected = client_.post("/mcp", headers=headers(), content=over)

    assert accepted.status_code == case["expected_status"]
    assert rejected.status_code == case["over_limit_status"]
    assert application.ask_principal is None


def test_mcp_uses_sdk_streamable_http_and_lists_only_fixed_tools() -> None:
    client_, identity, application = client()
    with client_:
        initialized = client_.post(
            "/mcp",
            headers=headers(),
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
        listing = client_.post(
            "/mcp",
            headers=headers(),
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        call = client_.post(
            "/mcp",
            headers=headers(),
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "soc_ask",
                    "arguments": {
                        "request": {"question": "show alerts", "environment_id": "alpha"}
                    },
                },
            },
        )

    assert initialized.status_code == 200
    assert listing.status_code == 200
    assert call.status_code == 200
    result = listing.json()["result"]["tools"]
    assert {tool["name"] for tool in result} == {"soc_ask", "soc_page", "soc_feedback"}
    assert (
        "context"
        not in next(tool for tool in result if tool["name"] == "soc_ask")["inputSchema"][
            "properties"
        ]
    )
    call_result = call.json()["result"]
    assert call_result["structuredContent"]["status"] == "answered"
    assert application.ask_principal is not None
    assert application.ask_principal.edge == "mcp"
    assert identity.calls >= 4


class CursorPageApplication(Application):
    async def page(self, request, principal):
        cipher = CursorCipher(
            keys={"old-key": b"o" * 32},
            current_key_id="old-key",
            now=lambda: datetime(2026, 9, 30, tzinfo=UTC),
        )
        cipher.open(
            request.cursor,
            owner_key=principal.owner_key,
            environment_id=request.environment_id,
            policy_hash="a" * 64,
            content_sha="b" * 40,
        )
        raise AssertionError("cursor open should have failed")


def test_soc_page_malformed_cursor_surfaces_bad_request() -> None:
    client_, identity, _ = client()
    app = create_mcp_app(
        CursorPageApplication(),
        identity,
        issuer_url="https://issuer.example.test",
        resource_url="https://soc.example.test/mcp",
    )
    client_ = TestClient(app, base_url="https://soc.example.test")
    with client_:
        client_.post(
            "/mcp",
            headers=headers(),
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
        response = client_.post(
            "/mcp",
            headers=headers(),
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "soc_page",
                    "arguments": {"request": {"environment_id": "alpha", "cursor": "v1.old-key.a"}},
                },
            },
        )
    assert response.status_code == 200
    body = response.json()
    assert body["result"]["isError"] is True
    assert "BAD_REQUEST" in body["result"]["content"][0]["text"]


def test_protected_resource_metadata_is_available_without_bearer_token() -> None:
    client_, identity, _ = client()
    response = client_.get("/.well-known/oauth-protected-resource/mcp")

    assert response.status_code == 200
    assert response.json()["resource"] == "https://soc.example.test/mcp"
    assert response.json()["scopes_supported"] == ["soc:ask"]
    assert identity.calls == 0
