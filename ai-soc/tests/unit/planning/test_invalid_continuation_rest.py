"""REST ingress maps invalid continuation to 422 before application work."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from fastapi.testclient import TestClient
from support import FixedClock, make_catalog, make_principal

from ai_soc.api.app import CSRF_COOKIE, create_app
from ai_soc.api.csrf import CsrfTokens
from ai_soc.application.service import invalid_continuation_failure
from ai_soc.contracts.models import (
    Answer,
    AskRequest,
    BootstrapResponse,
    BuildProvenance,
    ErrorCode,
    FollowupRecord,
    LeftOut,
    LeftOutReason,
    PublicLimits,
    SitePublic,
    VerifiedPrincipal,
)
from ai_soc.planning.followups import InvalidContinuation
from ai_soc.planning.parser import DeterministicPlanner

POLICY_HASH = "a" * 64


class FixedClockApi:
    def now(self) -> datetime:
        return datetime(2026, 9, 30, 12, tzinfo=UTC)


class Identity:
    def __init__(self, principal: VerifiedPrincipal) -> None:
        self._principal = principal

    async def verify(self, *, headers: object, edge: str) -> VerifiedPrincipal:
        return self._principal


class Ready:
    def ready(self) -> bool:
        return True


class PlannerApplication:
    def __init__(self, planner: DeterministicPlanner, record: FollowupRecord) -> None:
        self.planner = planner
        self.record = record
        self.ask_calls = 0
        self.indexer_calls = 0

    async def bootstrap(self, principal: VerifiedPrincipal) -> BootstrapResponse:
        return BootstrapResponse(
            sites=[SitePublic(id="alpha", label="Alpha")],
            models=[],
            provenance=BuildProvenance(
                service_sha="a" * 40,
                content_repository="https://example.test/content",
                content_sha="1" * 40,
                pack_sha256="2" * 64,
                image_digest="sha256:" + "3" * 64,
                docs_origin="https://docs.example.test",
                docs_manifest_sha256="4" * 64,
            ),
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
        request: AskRequest,
        principal: VerifiedPrincipal,
        *,
        idempotency_key: object = None,
    ) -> Answer:
        self.ask_calls += 1
        try:
            self.planner.plan(
                request,
                principal,
                self.record,
                policy_hash=POLICY_HASH,
                clock=FixedClock(),
            )
        except InvalidContinuation as exc:
            raise invalid_continuation_failure() from exc

    async def page(self, *args: object, **kwargs: object) -> object:
        raise NotImplementedError

    async def feedback(self, *args: object, **kwargs: object) -> object:
        raise NotImplementedError


def _csrf_headers(
    csrf: CsrfTokens, principal: VerifiedPrincipal, clock: FixedClockApi
) -> tuple[dict[str, str], dict[str, str]]:
    now = clock.now()
    cookie, token = csrf.issue(
        owner_key=principal.owner_key,
        assertion_expires_at=principal.expires_at,
        now=now,
    )
    return {"X-SOC-CSRF": token, "Origin": "https://soc.example.test"}, {CSRF_COOKIE: cookie}


def test_invalid_continuation_returns_422_before_application_answer() -> None:
    principal = make_principal()
    catalog = make_catalog(("ldap", "dns"))
    planner = DeterministicPlanner(catalog)
    original = planner.plan(
        AskRequest(question="LDAP is failing", environment_id="alpha", timezone="UTC"),
        principal,
        None,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )
    assert original.kind == "planned"
    record = FollowupRecord(
        followup_id=uuid4(),
        owner_key=principal.owner_key,
        environment_id="alpha",
        revision=1,
        plan=original.plan,
        answered_topic_ids=[],
        leftout_topic_ids=["ldap"],
        leftout_stages=[
            LeftOut(
                topic_id="ldap",
                stage="judgment",
                reason=LeftOutReason.capacity_limited,
                retryable=True,
            ),
        ],
        created_at=datetime(2026, 9, 30, 12, tzinfo=UTC),
        expires_at=datetime(2026, 10, 1, 12, tzinfo=UTC),
    )
    application = PlannerApplication(planner, record)
    clock = FixedClockApi()
    csrf = CsrfTokens(b"k" * 32, origin="https://soc.example.test")
    client = TestClient(
        create_app(application, Identity(principal), csrf, clock, Ready()),
        base_url="https://soc.example.test",
    )
    headers, cookies = _csrf_headers(csrf, principal, clock)
    client.cookies.update(cookies)
    body = {
        "question": "continue the left-out judgments",
        "environment_id": "alpha",
        "timezone": "UTC",
        "followup_id": str(record.followup_id),
        "followup_revision": record.revision,
        "continue_topic_ids": ["dns"],
    }
    response = client.post(
        "/v1/questions",
        json=body,
        headers={**headers, "Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert response.json()["code"] == ErrorCode.INVALID_CONTINUATION.value
    assert application.ask_calls == 1
