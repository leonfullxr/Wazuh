from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from starlette.applications import Starlette

from ai_soc.application.errors import ServiceFailure
from ai_soc.contracts.errors import public_error
from ai_soc.contracts.models import (
    Answer,
    AnswerStatus,
    BuildProvenance,
    DomainError,
    ErrorCode,
    FeedbackQueued,
    FetchResult,
    FetchScope,
    FetchState,
    IndexFamily,
    ResolvedWindow,
    SnapshotKind,
    SnapshotRef,
    TemplateId,
    VerifiedPrincipal,
    Visibility,
)
from ai_soc.mcp.server import VerifiedRequestContext, create_mcp_app

_SURFACE_BYTES = Path(__file__).with_name("data").joinpath("gmcp_surface_cases.json").read_bytes()
_SURFACE_SHA256 = "ef4539658672e3f3ad7dfc54d67d92aeea054300c37e873a24831c365727467b"
assert hashlib.sha256(_SURFACE_BYTES).hexdigest() == _SURFACE_SHA256
_SURFACE = json.loads(_SURFACE_BYTES)

NOW = datetime(2026, 9, 30, 12, tzinfo=UTC)


class Identity:
    async def verify(self, *, headers: object, edge: str) -> VerifiedPrincipal:
        assert edge == "mcp"
        assert isinstance(headers, dict)
        assert headers.get("authorization") == "Bearer official-client-token"
        return VerifiedPrincipal(
            issuer="https://issuer.example.test",
            sub="analyst-mcp",
            owner_key="b" * 64,
            groups=("soc",),
            edge="mcp",
            authenticated_at=NOW,
            expires_at=datetime(2030, 9, 30, 0, 5, tzinfo=UTC),
            assertion_hash="c" * 64,
        )


class Application:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def ask(self, request, principal, *, idempotency_key: UUID | None = None) -> Answer:
        self.calls.append("ask")
        return Answer(
            question_id=uuid4(),
            environment_id=request.environment_id,
            language="en",
            status=AnswerStatus.answered,
            blocks=[],
            left_out=[],
            provenance=_provenance(),
            trace_id="f" * 32,
            feedback_receipt="opaque-receipt",
        )

    async def page(self, request, principal) -> FetchResult:
        self.calls.append("page")
        window = ResolvedWindow(
            start=NOW - timedelta(days=1),
            end=NOW,
            semantics="absolute",
            source_text="fixture window",
            timezone="UTC",
            anchor_at=NOW,
        )
        return FetchResult(
            fetch_id="alerts",
            topic_id="ldap",
            state=FetchState.unavailable,
            scope=FetchScope(
                environment_id=request.environment_id,
                template_id=TemplateId.alerts_rows_v1,
                index_family=IndexFamily.alerts,
                filters=[],
                visibility=Visibility.full,
                policy_hash="1" * 63 + "2",
                snapshot=SnapshotKind.first_page_only,
                displayed_rows=0,
            ),
            window=window,
            columns=[],
            rows=[],
            checks=[],
            snapshot=SnapshotRef(kind=SnapshotKind.first_page_only, key="2" * 64, at=NOW),
            items=[],
            error=DomainError(
                code=ErrorCode.INDEXER_UNAVAILABLE,
                message="Synthetic fixture result.",
                retryable=True,
                trace_id="0" * 32,
                details={},
            ),
        )

    async def feedback(self, request, principal) -> FeedbackQueued:
        self.calls.append("feedback")
        return FeedbackQueued(feedback_id=uuid4(), status="queued")


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


@pytest.mark.asyncio
async def test_official_mcp_client_initializes_lists_and_calls_all_fixed_tools() -> None:
    identity = Identity()
    application = Application()
    app = create_mcp_app(
        application,
        identity,
        issuer_url="https://issuer.example.test",
        resource_url="https://soc.example.test/mcp",
    )

    sdk_app = cast(Starlette, cast(VerifiedRequestContext, app)._app)
    async with sdk_app.router.lifespan_context(sdk_app):
        async with httpx.AsyncClient(
            base_url="https://soc.example.test",
            transport=httpx.ASGITransport(app=app),
            headers={
                "Authorization": "Bearer official-client-token",
                "Origin": "https://soc.example.test",
            },
        ) as http_client:
            async with streamable_http_client(
                "https://soc.example.test/mcp", http_client=http_client
            ) as (read_stream, write_stream, _get_session_id):
                async with ClientSession(read_stream, write_stream) as session:
                    initialized = await session.initialize()
                    tools = await session.list_tools()
                    ask_result = await session.call_tool(
                        "soc_ask",
                        {
                            "request": {"question": "show alerts", "environment_id": "alpha"},
                            "idempotency_key": None,
                        },
                    )
                    page_result = await session.call_tool(
                        "soc_page",
                        {"request": {"environment_id": "alpha", "cursor": "opaque-cursor"}},
                    )
                    feedback_result = await session.call_tool(
                        "soc_feedback",
                        {
                            "request": {
                                "question_id": "11111111-1111-4111-8111-111111111111",
                                "environment_id": "alpha",
                                "feedback_receipt": "opaque-receipt",
                                "kind": "wrong",
                            }
                        },
                    )

    assert initialized.protocolVersion == "2025-11-25"
    assert {item.name for item in tools.tools} == {"soc_ask", "soc_page", "soc_feedback"}
    assert ask_result.structuredContent["status"] == "answered"
    assert page_result.structuredContent["state"] == "unavailable"
    assert feedback_result.structuredContent is not None, repr(feedback_result)
    assert feedback_result.structuredContent["status"] == "queued"
    assert application.calls == ["ask", "page", "feedback"]


class MultiIdentity:
    def __init__(self, tokens: list[str], owner_keys: list[str]) -> None:
        self.owners = dict(zip(tokens, owner_keys, strict=True))
        self.calls: list[str] = []

    async def verify(self, *, headers: object, edge: str) -> VerifiedPrincipal:
        assert edge == "mcp"
        assert isinstance(headers, dict)
        token = headers.get("authorization")
        self.calls.append(str(token))
        owner = self.owners.get(str(token))
        if owner is None:
            raise ServiceFailure(
                public_error(
                    ErrorCode.AUTH_INVALID,
                    "Authentication could not be verified.",
                    trace_id="8" * 32,
                )
            )
        return VerifiedPrincipal(
            issuer="https://issuer.example.test",
            sub=f"analyst-{owner[0]}",
            owner_key=owner,
            groups=("soc",),
            edge="mcp",
            authenticated_at=NOW,
            expires_at=datetime(2030, 9, 30, 0, 5, tzinfo=UTC),
            assertion_hash="c" * 64,
        )


class OwnerApplication(Application):
    def __init__(self) -> None:
        super().__init__()
        self.owners: list[str] = []

    async def ask(self, request, principal, *, idempotency_key: UUID | None = None) -> Answer:
        self.calls.append("ask")
        self.owners.append(principal.owner_key)
        return Answer(
            question_id=uuid4(),
            environment_id=request.environment_id,
            language="en",
            status=AnswerStatus.answered,
            blocks=[],
            left_out=[],
            provenance=_provenance(),
            trace_id="f" * 32,
            feedback_receipt=f"receipt:{principal.owner_key[:8]}",
        )


@pytest.mark.asyncio
@pytest.mark.acceptance("GMCP")
@pytest.mark.case_id("B5-GMCP.protocol-surface")
@pytest.mark.variant("positive")
@pytest.mark.fixture_sha256(_SURFACE_SHA256)
async def test_official_client_keeps_verified_owner_context_isolated() -> None:
    case = _SURFACE["cases"]["positive"]
    identity = MultiIdentity(case["owner_tokens"], case["owner_keys"])
    application = OwnerApplication()
    app = create_mcp_app(
        application,
        identity,
        issuer_url="https://issuer.example.test",
        resource_url="https://soc.example.test/mcp",
    )
    sdk_app = cast(Starlette, cast(VerifiedRequestContext, app)._app)
    async with sdk_app.router.lifespan_context(sdk_app):
        for token, owner in zip(case["owner_tokens"], case["owner_keys"], strict=True):
            async with httpx.AsyncClient(
                base_url="https://soc.example.test",
                transport=httpx.ASGITransport(app=app),
                headers={"Authorization": token, "Origin": "https://soc.example.test"},
            ) as http_client:
                async with streamable_http_client(
                    "https://soc.example.test/mcp", http_client=http_client
                ) as (read_stream, write_stream, _get_session_id):
                    async with ClientSession(read_stream, write_stream) as session:
                        initialized = await session.initialize()
                        listing = await session.list_tools()
                        result = await session.call_tool("soc_ask", {"request": case["request"]})
                        assert result.structuredContent is not None
                        page_result = await session.call_tool(
                            "soc_page",
                            {"request": {"environment_id": "alpha", "cursor": "owner-cursor"}},
                        )
                        feedback_result = await session.call_tool(
                            "soc_feedback",
                            {
                                "request": {
                                    "question_id": result.structuredContent["question_id"],
                                    "environment_id": "alpha",
                                    "feedback_receipt": result.structuredContent[
                                        "feedback_receipt"
                                    ],
                                    "kind": "wrong",
                                }
                            },
                        )
            assert {item.name for item in listing.tools} == set(case["expected_tools"])
            assert initialized.protocolVersion == "2025-11-25"
            assert result.structuredContent is not None
            assert result.structuredContent["feedback_receipt"] == f"receipt:{owner[:8]}"
            assert page_result.structuredContent is not None
            assert page_result.structuredContent["state"] == "unavailable"
            assert feedback_result.structuredContent is not None
            assert feedback_result.structuredContent["status"] == "queued"

        async with httpx.AsyncClient(
            base_url="https://soc.example.test",
            transport=httpx.ASGITransport(app=app),
            headers={
                "Authorization": case["owner_tokens"][0],
                "Origin": "https://soc.example.test",
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            },
        ) as http_client:
            negotiated = await http_client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": case["unsupported_protocol_version"],
                        "capabilities": {},
                        "clientInfo": {"name": "version-fixture", "version": "1"},
                    },
                },
            )
        assert negotiated.status_code == 200
        assert negotiated.json()["result"]["protocolVersion"] == case["negotiated_protocol_version"]

    assert application.owners == case["owner_keys"]
    assert identity.calls
    assert application.calls == ["ask", "page", "feedback"] * len(case["owner_keys"])


@pytest.mark.asyncio
@pytest.mark.acceptance("GMCP")
@pytest.mark.case_id("B5-GMCP.protocol-surface")
@pytest.mark.variant("failure")
@pytest.mark.fixture_sha256(_SURFACE_SHA256)
async def test_official_client_surfaces_typed_failure_without_provider_text() -> None:
    case = _SURFACE["cases"]["failure"]

    class FailingApplication(OwnerApplication):
        async def ask(self, request, principal, *, idempotency_key: UUID | None = None) -> Answer:
            raise ServiceFailure(
                public_error(
                    ErrorCode(case["error_code"]),
                    case["public_message"],
                    trace_id="9" * 32,
                )
            )

    application = FailingApplication()
    identity = MultiIdentity(["Bearer owner-alpha"], ["a" * 64])
    app = create_mcp_app(
        application,
        identity,
        issuer_url="https://issuer.example.test",
        resource_url="https://soc.example.test/mcp",
    )
    sdk_app = cast(Starlette, cast(VerifiedRequestContext, app)._app)
    async with sdk_app.router.lifespan_context(sdk_app):
        async with httpx.AsyncClient(
            base_url="https://soc.example.test",
            transport=httpx.ASGITransport(app=app),
            headers={
                "Authorization": "Bearer owner-alpha",
                "Origin": "https://soc.example.test",
            },
        ) as http_client:
            async with streamable_http_client(
                "https://soc.example.test/mcp", http_client=http_client
            ) as (read_stream, write_stream, _get_session_id):
                async with ClientSession(read_stream, write_stream) as session:
                    result = await session.call_tool(
                        "soc_ask", {"request": _SURFACE["cases"]["positive"]["request"]}
                    )

    serialized = json.dumps(
        {
            "content": [item.model_dump(mode="json") for item in result.content],
            "structured": result.structuredContent,
        },
        sort_keys=True,
    )
    assert result.isError
    assert case["error_code"] in serialized
    assert case["public_message"] in serialized
    assert case["hostile_provider_sentinel"] not in serialized


@pytest.mark.asyncio
@pytest.mark.acceptance("GMCP")
@pytest.mark.case_id("B5-GMCP.protocol-surface")
@pytest.mark.variant("negative")
@pytest.mark.fixture_sha256(_SURFACE_SHA256)
async def test_official_client_invalid_bearer_is_rejected_before_application_work() -> None:
    identity = MultiIdentity(["Bearer owner-alpha"], ["a" * 64])
    application = OwnerApplication()
    app = create_mcp_app(
        application,
        identity,
        issuer_url="https://issuer.example.test",
        resource_url="https://soc.example.test/mcp",
    )
    sdk_app = cast(Starlette, cast(VerifiedRequestContext, app)._app)
    negative = _SURFACE["cases"]["negative"]
    responses: list[httpx.Response] = []
    origin_response: httpx.Response | None = None

    async def capture(response: httpx.Response) -> None:
        responses.append(response)

    async with sdk_app.router.lifespan_context(sdk_app):
        async with httpx.AsyncClient(
            base_url="https://soc.example.test",
            transport=httpx.ASGITransport(app=app),
            headers={
                "Authorization": _SURFACE["cases"]["negative"]["authorization"],
                "Origin": "https://soc.example.test",
            },
            event_hooks={"response": [capture]},
        ) as http_client:
            with pytest.raises(BaseExceptionGroup):
                async with streamable_http_client(
                    "https://soc.example.test/mcp", http_client=http_client
                ) as (read_stream, write_stream, _get_session_id):
                    async with ClientSession(read_stream, write_stream) as session:
                        await session.initialize()
            origin_response = await http_client.post(
                "/mcp",
                headers={
                    "Authorization": "Bearer owner-alpha",
                    "Origin": negative["disallowed_origin"],
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {"name": "origin-fixture", "version": "1"},
                    },
                },
            )

    assert responses and responses[0].status_code == negative["expected_status"]
    assert negative["challenge_path"] in responses[0].headers["www-authenticate"]
    assert origin_response is not None
    assert origin_response.status_code == negative["origin_status"]
    assert application.calls == []
