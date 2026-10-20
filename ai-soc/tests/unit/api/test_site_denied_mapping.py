from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from ai_soc.api.app import create_app
from ai_soc.api.csrf import CsrfTokens
from ai_soc.application.service import ApplicationService
from ai_soc.contracts.errors import status_for
from ai_soc.contracts.models import (
    Answer,
    AskRequest,
    ErrorCode,
    IndexFamily,
    SiteConfig,
    TemplateId,
    TraceContext,
    VerifiedPrincipal,
    Visibility,
)
from ai_soc.identity.policy import MappedSitePolicy
from ai_soc.mcp.server import create_mcp_app
from ai_soc.state.memory import MemoryState
from ai_soc.telemetry.audit_delivery import AuditUnavailable

NOW = datetime(2026, 9, 30, 12, tzinfo=UTC)


class FixedClock:
    def now(self) -> datetime:
        return NOW


class Identity:
    def __init__(self, principal: VerifiedPrincipal) -> None:
        self.principal = principal

    async def verify(self, *, headers: object, edge: str) -> VerifiedPrincipal:
        assert edge in {"browser", "mcp"}
        return self.principal


def _service() -> ApplicationService:
    return ApplicationService(
        clock=FixedClock(),  # type: ignore[arg-type]
        catalog=object(),  # type: ignore[arg-type]
        planner=object(),  # type: ignore[arg-type]
        site_policy=MappedSitePolicy((_site(),), now=lambda: NOW),
        plans=object(),  # type: ignore[arg-type]
        admissions=object(),  # type: ignore[arg-type]
        question_admission=object(),  # type: ignore[arg-type]
        leases=object(),  # type: ignore[arg-type]
        budgets=object(),  # type: ignore[arg-type]
        completions=object(),  # type: ignore[arg-type]
        fetches=object(),  # type: ignore[arg-type]
        playbooks=object(),  # type: ignore[arg-type]
        judgment_engine=object(),  # type: ignore[arg-type]
        judgment_provider=object(),  # type: ignore[arg-type]
        finding_validator=object(),  # type: ignore[arg-type]
        telemetry=None,
        feedback_sink=object(),  # type: ignore[arg-type]
        feedback_store=MemoryState(),
        receipts=object(),  # type: ignore[arg-type]
        runtime=object(),  # type: ignore[arg-type]
        models=(),
    )


def _denied_principal() -> VerifiedPrincipal:
    return VerifiedPrincipal(
        issuer="https://issuer.example.test",
        sub="analyst-1",
        owner_key="a" * 64,
        groups=("unmapped-group",),
        edge="fixture",
        authenticated_at=NOW,
        expires_at=datetime(2030, 9, 30, 0, 5, tzinfo=UTC),
        assertion_hash="b" * 64,
    )


def _site() -> SiteConfig:
    return SiteConfig(
        environment_id="alpha",
        label="Alpha Sensitive Label",
        enabled=True,
        indexer_origin="https://alpha.private.example.test",
        private_network_ref="vpn-alpha",
        jwt_issuer="soc-alpha",
        jwt_audience="wazuh-alpha",
        kms_signing_key_arn="arn:aws:kms:us-east-1:123456789012:key/alpha",
        ca_secret_arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:alpha",
        ca_secret_version="version-alpha",
        ca_sha256="b" * 64,
        group_role_map={"authorized-group": ("analyst_read",)},
        role_visibility={"analyst_read": Visibility.full},
        allowed_index_patterns={IndexFamily.alerts: ("wazuh-alerts-alpha-*",)},
        mapping_profile="wazuh-v4-fixture",
        policy_version="policy-1",
        pit_supported=True,
        allowed_templates=tuple(TemplateId),
        dls_attestation_version="dls-7",
        composite_role_visibility={"analyst_read": Visibility.full},
    )


def _csrf_headers(csrf: CsrfTokens, principal: VerifiedPrincipal) -> dict[str, str]:
    cookie, token = csrf.issue(
        owner_key=principal.owner_key,
        assertion_expires_at=principal.expires_at,
        now=NOW,
    )
    return {
        "x-amzn-oidc-data": "fixture-token",
        "x-soc-csrf": token,
        "Origin": "https://soc.example.test",
        "Cookie": f"__Host-soc-csrf={cookie}",
    }


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


def test_rest_unauthorized_site_is_sanitized_site_denied() -> None:
    principal = _denied_principal()
    csrf = CsrfTokens(b"k" * 32, origin="https://soc.example.test")
    app = create_app(
        _service(),
        Identity(principal),
        csrf,
        FixedClock(),
        type("Ready", (), {"ready": lambda self: True})(),
    )

    response = TestClient(app, base_url="https://soc.example.test").post(
        "/v1/fetches/page",
        headers=_csrf_headers(csrf, principal),
        json={"environment_id": "alpha", "cursor": "opaque-cursor"},
    )

    assert response.status_code == 403 == status_for(ErrorCode.SITE_DENIED)
    assert response.json()["code"] == ErrorCode.SITE_DENIED.value
    assert response.json()["message"] == "Access to this site is denied."
    assert "alpha" not in response.text.casefold()


def test_mcp_unauthorized_site_is_sanitized_site_denied() -> None:
    app = create_mcp_app(
        _service(),
        Identity(_denied_principal()),
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

    result = response.json()["result"]
    assert result["isError"] is True
    text = result["content"][0]["text"]
    prefix = "Error executing tool soc_page: "
    assert text.startswith(prefix)
    error = json.loads(text.removeprefix(prefix))
    assert error["code"] == ErrorCode.SITE_DENIED.value
    assert status_for(ErrorCode(error["code"])) == 403
    assert error["message"] == "Access to this site is denied."
    assert "alpha" not in response.text.casefold()


async def _raise_audit_unavailable(
    _self: ApplicationService,
    _request: AskRequest,
    _principal: VerifiedPrincipal,
    *,
    idempotency_key: UUID | None,
    trace_context: TraceContext,
) -> Answer:
    raise AuditUnavailable("private SQS queue details")


def test_rest_audit_ack_failure_is_sanitized_audit_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ApplicationService, "_ask_impl", _raise_audit_unavailable)
    principal = _denied_principal().model_copy(update={"groups": ("authorized-group",)})
    csrf = CsrfTokens(b"k" * 32, origin="https://soc.example.test")
    app = create_app(
        _service(),
        Identity(principal),
        csrf,
        FixedClock(),
        type("Ready", (), {"ready": lambda self: True})(),
    )

    response = TestClient(app, base_url="https://soc.example.test").post(
        "/v1/questions",
        headers=_csrf_headers(csrf, principal),
        json={"environment_id": "alpha", "question": "Check alerts"},
    )

    assert response.status_code == 503 == status_for(ErrorCode.AUDIT_UNAVAILABLE)
    assert response.json()["code"] == ErrorCode.AUDIT_UNAVAILABLE.value
    assert response.json()["message"] == "The audit service is temporarily unavailable."
    assert "private SQS" not in response.text


def test_mcp_audit_ack_failure_is_sanitized_audit_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ApplicationService, "_ask_impl", _raise_audit_unavailable)
    principal = _denied_principal().model_copy(update={"groups": ("authorized-group",)})
    app = create_mcp_app(
        _service(),
        Identity(principal),
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
                    "name": "soc_ask",
                    "arguments": {
                        "request": {"environment_id": "alpha", "question": "Check alerts"}
                    },
                },
            },
        )

    result = response.json()["result"]
    assert result["isError"] is True
    text = result["content"][0]["text"]
    prefix = "Error executing tool soc_ask: "
    assert text.startswith(prefix)
    error = json.loads(text.removeprefix(prefix))
    assert error["code"] == ErrorCode.AUDIT_UNAVAILABLE.value
    assert status_for(ErrorCode(error["code"])) == 503
    assert error["message"] == "The audit service is temporarily unavailable."
    assert "private SQS" not in response.text
