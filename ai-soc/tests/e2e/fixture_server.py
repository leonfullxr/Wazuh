"""Loopback-only browser fixture serving the real REST/MCP adapters and UI build."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.types import Receive, Scope, Send

from ai_soc.api.app import create_app
from ai_soc.api.csrf import CsrfTokens
from ai_soc.application.errors import ServiceFailure
from ai_soc.contracts.errors import public_error
from ai_soc.contracts.models import (
    Answer,
    BootstrapResponse,
    BuildProvenance,
    ErrorCode,
    FeedbackQueued,
    FeedbackRequest,
    FetchResult,
    ModelCapabilityPublic,
    PageRequest,
    PublicLimits,
    SitePublic,
    VerifiedPrincipal,
)
from ai_soc.mcp.server import create_mcp_app

ORIGIN = os.environ.get("SOC_FIXTURE_ORIGIN", "http://127.0.0.1:8765")
NOW = datetime(2026, 9, 30, 12, tzinfo=UTC)
UI_DIST = Path(__file__).resolve().parents[2] / "ui/dist"
ASK_CALLS = 0
G053_TESTS = Path(__file__).resolve().parents[1] / "unit" / "application"
sys.path.insert(0, str(G053_TESTS))

from test_fenced_completion import (  # noqa: E402
    G035_FIXTURE_BYTES,
    G053_TOKEN_FIXTURE_BYTES,
    _assert_application_mixed_access_case,
    _g053_provider_input,
)

G053_FIXTURE = json.loads(G053_TOKEN_FIXTURE_BYTES)


def assert_g053_response_is_sanitized(serialized: str) -> None:
    assert G053_FIXTURE["hostile_first_token"] not in serialized, (
        "raw provider first token escaped the validated answer boundary"
    )
    assert "PRIVATE-CONVERSE-TIMEOUT:" not in serialized, (
        "private provider transport detail escaped the answer boundary"
    )


def provenance() -> BuildProvenance:
    return BuildProvenance(
        service_sha="a" * 40,
        content_repository="https://fixture.example.test/soc-content",
        content_sha="b" * 40,
        pack_sha256="c" * 64,
        image_digest="sha256:" + "d" * 64,
        docs_origin="https://docs.example.test",
        docs_manifest_sha256="e" * 64,
    )


class Clock:
    def now(self) -> datetime:
        return NOW


class Identity:
    async def verify(self, *, headers: Mapping[str, str], edge: str) -> VerifiedPrincipal:
        expected = "Bearer fixture-mcp-token" if edge == "mcp" else "fixture-browser-token"
        supplied = (
            headers.get("authorization", "")
            if edge == "mcp"
            else headers.get("x-soc-fixture-token", "")
        )
        if supplied != expected:
            raise ServiceFailure(
                public_error(
                    ErrorCode.AUTH_INVALID,
                    "Authentication could not be verified.",
                    trace_id="f" * 32,
                )
            )
        return VerifiedPrincipal(
            issuer="https://issuer.fixture.example.test",
            sub="fixture-analyst",
            owner_key="f" * 64,
            groups=("soc",),
            edge="fixture",
            authenticated_at=NOW,
            expires_at=datetime(2030, 9, 30, 12, tzinfo=UTC),
            assertion_hash="2" * 64,
        )


class Application:
    mutate_drop_evidence: bool = False
    mutate_raw_provider_token: bool = False

    async def bootstrap(self, principal: VerifiedPrincipal) -> BootstrapResponse:
        return BootstrapResponse(
            sites=[SitePublic(id="alpha", label="Synthetic Alpha")],
            models=[
                ModelCapabilityPublic(
                    id="fixture-model",
                    label="Fixture model",
                    efforts=[],
                    context_tokens=4096,
                    max_output_tokens=512,
                )
            ],
            provenance=provenance(),
            mode="fixture",
            limits=PublicLimits(
                question_bytes=16384,
                page_size=50,
                window_days=90,
                request_bytes=65536,
                plan_bytes=131072,
            ),
        )

    async def ask(
        self,
        request: object,
        principal: VerifiedPrincipal,
        *,
        idempotency_key: UUID | None = None,
    ) -> Answer:
        global ASK_CALLS
        ASK_CALLS += 1
        if principal.owner_key != "f" * 64:
            raise AssertionError("fixture identity does not match the composed test analyst")
        fixture = json.loads(G053_TOKEN_FIXTURE_BYTES)
        question = getattr(request, "question", "")
        variant = next(
            (
                name
                for name in ("positive", "negative", "boundary", "failure")
                if f"g053:{name}" in question
            ),
            "negative",
        )
        raw_text, failure_detail = _g053_provider_input(fixture, fixture["cases"][variant])
        mixed_case = json.loads(G035_FIXTURE_BYTES)["cases"]["positive"]
        answer = await _assert_application_mixed_access_case(
            mixed_case,
            raw_text=raw_text,
            failure_detail=failure_detail,
        )
        if self.mutate_drop_evidence:
            answer = answer.model_copy(
                update={
                    "blocks": [
                        block.model_copy(update={"tables": []})
                        if block.topic_id == "vpn"
                        else block
                        for block in answer.blocks
                    ]
                }
            )
        if self.mutate_raw_provider_token:
            mutated_blocks = []
            for block in answer.blocks:
                if block.topic_id == "vpn" and block.judgment.sentences:
                    sentences = list(block.judgment.sentences)
                    sentences[0] = sentences[0].model_copy(
                        update={"text": fixture["hostile_first_token"]}
                    )
                    judgment = block.judgment.model_copy(update={"sentences": sentences})
                    block = block.model_copy(update={"judgment": judgment})
                mutated_blocks.append(block)
            answer = answer.model_copy(update={"blocks": mutated_blocks})
        return answer

    async def page(self, request: PageRequest, principal: VerifiedPrincipal) -> FetchResult:
        raise AssertionError("the browser fixture has no paginated fixture data")

    async def feedback(
        self, request: FeedbackRequest, principal: VerifiedPrincipal
    ) -> FeedbackQueued:
        return FeedbackQueued(feedback_id=uuid4(), status="queued")


identity = Identity()
application = Application()
rest_app = create_app(
    application,
    identity,
    CsrfTokens(b"fixture-only-csrf-secret-32-bytes!!", origin=ORIGIN),
    Clock(),
    type("Ready", (), {"ready": lambda self: True})(),
)
rest_app.add_api_route(
    "/__fixture/counters",
    lambda: JSONResponse({"ask_calls": ASK_CALLS}),
    methods=["GET"],
)
if not UI_DIST.is_dir():
    raise RuntimeError("build ui/dist before starting the real-route E2E fixture")
rest_app.mount("/", StaticFiles(directory=UI_DIST, html=True), name="fixture-ui")
mcp_app = create_mcp_app(
    application,
    identity,
    issuer_url="https://issuer.fixture.example.test",
    resource_url=f"{ORIGIN}/mcp",
)


async def app(scope: Scope, receive: Receive, send: Send) -> None:
    """Dispatch MCP requests without rewriting the path expected by the SDK."""
    if scope["type"] == "lifespan":
        await mcp_app(scope, receive, send)
        return
    path = str(scope.get("path", ""))
    if path == "/mcp" or path.startswith("/.well-known/oauth-protected-resource"):
        await mcp_app(scope, receive, send)
    else:
        await rest_app(scope, receive, send)
