"""E1: MCP marks host evidence as untrusted via server instructions only."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from fastapi.testclient import TestClient

from ai_soc.contracts.models import Answer, AnswerStatus, BuildProvenance
from ai_soc.mcp.server import create_mcp_app


class Identity:
    async def verify(self, *, headers: object, edge: str):
        from ai_soc.contracts.models import VerifiedPrincipal

        assert isinstance(headers, dict)
        assert headers.get("authorization") == "Bearer good-token"
        return VerifiedPrincipal(
            issuer="https://issuer.example.test",
            sub="analyst",
            owner_key="b" * 64,
            groups=("soc",),
            edge="mcp",
            authenticated_at=datetime(2026, 9, 30, tzinfo=UTC),
            expires_at=datetime(2030, 9, 30, tzinfo=UTC),
            assertion_hash="c" * 64,
        )


class Application:
    async def ask(self, request, principal, *, idempotency_key=None) -> Answer:
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
        raise AssertionError("unused")

    async def feedback(self, request, principal):
        raise AssertionError("unused")


def test_mcp_instructions_and_structured_output_match_frozen_answer_shape() -> None:
    app = create_mcp_app(
        Application(),
        Identity(),
        issuer_url="https://issuer.example.test",
        resource_url="https://soc.example.test/mcp",
    )
    client = TestClient(app, base_url="https://soc.example.test")
    headers = {
        "Authorization": "Bearer good-token",
        "Origin": "https://soc.example.test",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    with client:
        init = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "e1", "version": "1"},
                },
            },
        )
        call = client.post(
            "/mcp",
            headers=headers,
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
    assert init.status_code == call.status_code == 200
    instructions = init.json()["result"]["instructions"]
    assert "verified evidence" not in instructions.casefold()
    assert "untrusted" in instructions.casefold()
    structured = call.json()["result"]["structuredContent"]
    assert structured["status"] == "answered"
    assert "answer" not in structured and "untrusted_evidence" not in structured
