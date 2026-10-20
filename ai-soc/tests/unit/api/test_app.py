from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import TypeAdapter

from ai_soc.api.app import CSRF_COOKIE, MAX_REQUEST_BYTES, SECURITY_HEADERS, create_app
from ai_soc.api.csrf import CsrfTokens
from ai_soc.contracts.errors import public_error
from ai_soc.contracts.models import (
    Answer,
    AnswerStatus,
    BootstrapResponse,
    BuildProvenance,
    ErrorCode,
    FeedbackQueued,
    FeedbackRequest,
    FetchResult,
    HTTPSUrl,
    PageRequest,
    PublicLimits,
    SitePublic,
    VerifiedPrincipal,
)
from ai_soc.identity.alb import IdentityError
from ai_soc.query.cursors import CursorCipher
from ai_soc.state.errors import StateFailure

_ROUTE_CASE_FIXTURE = Path(__file__).parent / "data" / "route_security_cases.json"
_ROUTE_CASE_SHA256 = hashlib.sha256(_ROUTE_CASE_FIXTURE.read_bytes()).hexdigest()


def route_case() -> dict[str, object]:
    return cast(dict[str, object], json.loads(_ROUTE_CASE_FIXTURE.read_text(encoding="utf-8")))


class FixedClock:
    def now(self) -> datetime:
        return datetime(2026, 9, 30, tzinfo=UTC)


class Identity:
    def __init__(self) -> None:
        self.calls = 0

    async def verify(self, *, headers: object, edge: str) -> VerifiedPrincipal:
        self.calls += 1
        assert edge == "browser"
        return VerifiedPrincipal(
            issuer=TypeAdapter[HTTPSUrl](HTTPSUrl).validate_python("https://issuer.example.test"),
            sub="analyst-1",
            owner_key="a" * 64,
            groups=("soc",),
            edge="fixture",
            authenticated_at=datetime(2026, 9, 30, tzinfo=UTC),
            expires_at=datetime(2026, 9, 30, 0, 5, tzinfo=UTC),
            assertion_hash="b" * 64,
        )


class Application:
    def __init__(self) -> None:
        self.ask_calls = 0

    async def bootstrap(self, principal: VerifiedPrincipal) -> BootstrapResponse:
        return BootstrapResponse(
            sites=[SitePublic(id="alpha", label="Alpha")],
            models=[],
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
        self.ask_calls += 1
        return Answer(
            question_id=uuid4(),
            environment_id="alpha",
            language="en",
            status=AnswerStatus.answered,
            blocks=[],
            left_out=[],
            provenance=provenance(),
            trace_id="f" * 32,
            feedback_receipt="opaque-receipt",
        )

    async def page(self, request: PageRequest, principal: VerifiedPrincipal) -> FetchResult:
        raise NotImplementedError

    async def feedback(
        self, request: FeedbackRequest, principal: VerifiedPrincipal
    ) -> FeedbackQueued:
        raise NotImplementedError


class Ready:
    def ready(self) -> bool:
        return True


def client() -> tuple[TestClient, Application, Identity, CsrfTokens]:
    app_service = Application()
    identity = Identity()
    csrf = CsrfTokens(b"k" * 32, origin="https://soc.example.test")
    app = create_app(app_service, identity, csrf, FixedClock(), Ready())
    return TestClient(app, base_url="https://soc.example.test"), app_service, identity, csrf


def csrf_headers(csrf: CsrfTokens) -> tuple[dict[str, str], dict[str, str]]:
    cookie, token = csrf.issue(
        owner_key="a" * 64,
        assertion_expires_at=datetime(2026, 9, 30, 0, 5, tzinfo=UTC),
        now=datetime(2026, 9, 30, tzinfo=UTC),
    )
    return {"X-SOC-CSRF": token, "Origin": "https://soc.example.test"}, {CSRF_COOKIE: cookie}


def provenance() -> BuildProvenance:
    return BuildProvenance(
        service_sha="a" * 40,
        content_repository="https://example.test/soc-content",
        content_sha="b" * 40,
        pack_sha256="c" * 64,
        image_digest="sha256:" + "d" * 64,
        docs_origin="https://docs.example.test",
        docs_manifest_sha256="e" * 64,
    )


def test_health_and_unknown_routes_do_not_start_identity_work() -> None:
    client_, _, identity, _ = client()

    assert client_.get("/health/live").json() == {"status": "ok"}
    assert client_.get("/v1/not-a-route").status_code == 404
    assert identity.calls == 0


def test_question_requires_valid_csrf_and_maps_schema_errors() -> None:
    client_, application, identity, csrf = client()
    headers, cookies = csrf_headers(csrf)
    denied = client_.post(
        "/v1/questions",
        json={"question": "show alerts", "environment_id": "alpha"},
        headers={**headers, "X-SOC-CSRF": "invalid"},
        cookies=cookies,
    )
    assert denied.status_code == 403
    assert application.ask_calls == 0

    invalid = client_.post(
        "/v1/questions",
        json={"question": "show alerts", "environment_id": "alpha", "extra": True},
        headers=headers,
        cookies=cookies,
    )
    assert invalid.status_code == 422
    assert application.ask_calls == 0
    assert identity.calls == 2


@pytest.mark.acceptance()
@pytest.mark.case_id("B5-API.ingress-component")
@pytest.mark.variant("failure")
@pytest.mark.fixture_sha256(_ROUTE_CASE_SHA256)
def test_malformed_json_is_bad_request_before_application_work() -> None:
    fixture = route_case()
    security = cast(dict[str, object], fixture["security"])
    expected = cast(dict[str, object], fixture["expected"])
    client_, application, _, csrf = client()
    headers, cookies = csrf_headers(csrf)
    response = client_.post(
        "/v1/questions",
        content=str(security["malformed_json"]).encode(),
        headers={**headers, "Content-Type": "application/json"},
        cookies=cookies,
    )

    assert response.status_code == security["malformed_status"]
    assert response.json()["code"] == security["malformed_code"]
    assert application.ask_calls == expected["denied_application_calls"]


@pytest.mark.acceptance()
@pytest.mark.case_id("B5-API.ingress-component")
@pytest.mark.variant("boundary")
@pytest.mark.fixture_sha256(_ROUTE_CASE_SHA256)
def test_request_body_accepts_exact_limit_and_rejects_one_byte_over() -> None:
    fixture = route_case()
    security = cast(dict[str, object], fixture["security"])
    expected = cast(dict[str, object], fixture["expected"])
    assert MAX_REQUEST_BYTES == security["body_limit_bytes"]
    client_, application, _, csrf = client()
    headers, cookies = csrf_headers(csrf)
    request = json.dumps(fixture["request"], separators=(",", ":")).encode()
    exact = request + b" " * (MAX_REQUEST_BYTES - len(request))
    accepted = client_.post(
        "/v1/questions",
        content=exact,
        headers={**headers, "Content-Type": "application/json"},
        cookies=cookies,
    )
    oversized = client_.post(
        "/v1/questions",
        content=exact + b" ",
        headers={**headers, "Content-Type": "application/json"},
        cookies=cookies,
    )

    assert accepted.status_code == expected["boundary_accepted_status"]
    assert oversized.status_code == security["oversize_status"]
    assert oversized.json()["code"] == security["oversize_code"]
    assert application.ask_calls == expected["boundary_application_calls"]


@pytest.mark.acceptance()
@pytest.mark.case_id("B5-API.ingress-component")
@pytest.mark.variant("positive")
@pytest.mark.fixture_sha256(_ROUTE_CASE_SHA256)
def test_question_route_returns_typed_answer_and_honors_idempotency_key() -> None:
    fixture = route_case()
    request = cast(dict[str, object], fixture["request"])
    expected = cast(dict[str, object], fixture["expected"])
    client_, application, _, csrf = client()
    headers, cookies = csrf_headers(csrf)
    key = str(uuid4())
    response = client_.post(
        "/v1/questions",
        json=request,
        headers={**headers, "Idempotency-Key": key},
        cookies=cookies,
    )

    assert response.status_code == expected["success_status"]
    assert response.json()["status"] == expected["answer_status"]
    assert application.ask_calls == 1


@pytest.mark.acceptance()
@pytest.mark.case_id("B5-API.ingress-component")
@pytest.mark.variant("negative")
@pytest.mark.fixture_sha256(_ROUTE_CASE_SHA256)
def test_question_route_rejects_wrong_origin_and_missing_nonce_before_application() -> None:
    fixture = route_case()
    security = cast(dict[str, object], fixture["security"])
    expected = cast(dict[str, object], fixture["expected"])
    request = cast(dict[str, object], fixture["request"])
    client_, application, _, csrf = client()
    headers, cookies = csrf_headers(csrf)

    foreign_origin = client_.post(
        "/v1/questions",
        json=request,
        headers={**headers, "Origin": str(security["foreign_origin"])},
        cookies=cookies,
    )
    missing_nonce = client_.post(
        "/v1/questions",
        json=request,
        headers={"Origin": str(security["allowed_origin"])},
        cookies=cookies,
    )

    assert foreign_origin.status_code == expected["denied_status"]
    assert missing_nonce.status_code == expected["denied_status"]
    assert security["invalid_csrf_status"] == expected["denied_status"]
    assert application.ask_calls == expected["denied_application_calls"]


def test_state_admission_error_maps_to_sanitized_http_domain_error() -> None:
    class RateLimitedApplication(Application):
        async def ask(self, request, principal, *, idempotency_key=None) -> Answer:
            raise StateFailure(
                public_error(
                    ErrorCode.RATE_LIMITED,
                    "The request rate limit was reached.",
                    trace_id="a" * 32,
                    retryable=True,
                )
            )

    identity = Identity()
    csrf = CsrfTokens(b"k" * 32, origin="https://soc.example.test")
    app = create_app(RateLimitedApplication(), identity, csrf, FixedClock(), Ready())
    client_ = TestClient(app, base_url="https://soc.example.test")
    headers, cookies = csrf_headers(csrf)

    response = client_.post(
        "/v1/questions",
        json={"question": "show alerts", "environment_id": "alpha"},
        headers=headers,
        cookies=cookies,
    )

    assert response.status_code == 429
    assert response.json()["code"] == "RATE_LIMITED"
    assert response.headers["retry-after"] == "60"


def test_bootstrap_issues_one_shared_signed_cookie_and_header_value() -> None:
    client_, _, _, _ = client()
    response = client_.get("/v1/bootstrap", headers={"Authorization": "fixture"})

    assert response.status_code == 200
    token = response.json()["csrf_token"]
    assert response.cookies[CSRF_COOKIE] == token
    set_cookie = response.headers["set-cookie"]
    assert "HttpOnly" in set_cookie
    assert "Secure" in set_cookie
    assert "SameSite=strict" in set_cookie


def test_mutation_requires_matching_csrf_header_and_cookie() -> None:
    client_, app_service, _, _ = client()
    bootstrap = client_.get("/v1/bootstrap", headers={"Authorization": "fixture"})
    cookie = bootstrap.cookies[CSRF_COOKIE]
    token = bootstrap.json()["csrf_token"]
    headers = {"Origin": "https://soc.example.test", "X-SOC-CSRF": token}

    accepted = client_.post(
        "/v1/questions",
        json={"question": "show alerts", "environment_id": "alpha"},
        headers=headers,
        cookies={CSRF_COOKIE: cookie},
    )
    rejected = client_.post(
        "/v1/questions",
        json={"question": "show alerts", "environment_id": "alpha"},
        headers={**headers, "X-SOC-CSRF": "altered"},
        cookies={CSRF_COOKIE: cookie},
    )
    client_.cookies.delete(CSRF_COOKIE)
    missing_cookie = client_.post(
        "/v1/questions",
        json={"question": "show alerts", "environment_id": "alpha"},
        headers=headers,
    )

    assert accepted.status_code == 200
    assert rejected.status_code == 403
    assert missing_cookie.status_code == 403
    assert app_service.ask_calls == 1


def test_expired_browser_assertion_returns_auth_expired() -> None:
    from datetime import timedelta

    from cryptography.hazmat.primitives.asymmetric import ec

    from tests.unit.identity.test_verifiers import NOW, _alb_token, _alb_verifier

    private = ec.generate_private_key(ec.SECP256R1())
    verifier = _alb_verifier(private.public_key())
    expired = _alb_token(
        private,
        header_overrides={"exp": int((NOW - timedelta(seconds=30)).timestamp())},
    )

    class AlbIdentity:
        async def verify(self, *, headers: object, edge: str) -> VerifiedPrincipal:
            assert edge == "browser"
            mapping = dict(headers) if isinstance(headers, dict) else {}
            token = next(
                (value for key, value in mapping.items() if key.lower() == "x-amzn-oidc-data"),
                "",
            )
            if not token:
                raise IdentityError(ErrorCode.AUTH_REQUIRED)
            return verifier.verify(token)

    csrf = CsrfTokens(b"k" * 32, origin="https://soc.example.test")
    app = create_app(Application(), AlbIdentity(), csrf, FixedClock(), Ready())
    response = TestClient(app, base_url="https://soc.example.test").get(
        "/v1/bootstrap",
        headers={"x-amzn-oidc-data": expired},
    )
    assert response.status_code == 401
    assert response.json()["code"] == ErrorCode.AUTH_EXPIRED.value


class CursorPageApplication(Application):
    async def page(self, request: PageRequest, principal: VerifiedPrincipal) -> FetchResult:
        cipher = CursorCipher(
            keys={"old-key": b"o" * 32},
            current_key_id="old-key",
            now=FixedClock().now,
        )
        cipher.open(
            request.cursor,
            owner_key=principal.owner_key,
            environment_id=request.environment_id,
            policy_hash="a" * 64,
            content_sha="b" * 40,
        )
        raise AssertionError("cursor open should have failed")


def test_page_malformed_cursor_returns_bad_request() -> None:
    test_client, _, _, csrf = client()
    cookie, token = csrf.issue(
        owner_key="a" * 64,
        assertion_expires_at=datetime(2026, 9, 30, 0, 5, tzinfo=UTC),
        now=FixedClock().now(),
    )
    app = create_app(CursorPageApplication(), Identity(), csrf, FixedClock(), Ready())
    test_client = TestClient(app, base_url="https://soc.example.test")
    response = test_client.post(
        "/v1/fetches/page",
        headers={
            "x-amzn-oidc-data": "fixture-token",
            "x-soc-csrf": token,
            "Origin": "https://soc.example.test",
            "Cookie": f"{CSRF_COOKIE}={cookie}",
        },
        json={"environment_id": "alpha", "cursor": "v1.old-key.a"},
    )
    assert response.status_code == 400
    assert response.json()["code"] == ErrorCode.BAD_REQUEST.value


def test_security_headers_are_applied_to_api_responses() -> None:
    test_client, _, _, _ = client()
    response = test_client.get("/health/live")
    assert response.status_code == 200
    for name, value in SECURITY_HEADERS.items():
        assert response.headers.get(name) == value
