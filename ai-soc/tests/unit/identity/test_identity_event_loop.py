from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from ai_soc.contracts.models import (
    AdmissionGrant,
    CallKind,
    ExecutionContext,
    TraceContext,
    VerifiedPrincipal,
)
from ai_soc.identity.alb import McpBearerVerifier
from ai_soc.identity.broker import KmsIndexerTokenBroker
from ai_soc.identity.policy import MappedSitePolicy
from ai_soc.identity.verifier import RouteIdentityVerifier
from tests.unit.identity.test_policy_broker_ca import make_site, principal

NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)


class SlowAlb:
    def verify(self, _token: str) -> VerifiedPrincipal:
        time.sleep(0.2)
        return principal()


@pytest.mark.asyncio
async def test_route_identity_verify_offloads_blocking_work() -> None:
    mcp = McpBearerVerifier(
        issuer="https://id.example.test",
        resource="https://soc.example.test/mcp",
        jwks_uri="https://id.example.test/.well-known/jwks.json",
        key_resolver=lambda _kid: object(),
        now=lambda: NOW,
        allowed_origins=frozenset({"https://soc.example.test"}),
    )
    verifier = RouteIdentityVerifier(SlowAlb(), mcp)

    async def ticker() -> float:
        await asyncio.sleep(0.05)
        return time.monotonic()

    started = time.monotonic()
    _, tick_at = await asyncio.gather(
        verifier.verify(headers={"x-amzn-oidc-data": "token"}, edge="browser"),
        ticker(),
    )
    assert tick_at - started < 0.15


@pytest.mark.asyncio
async def test_kms_broker_issue_offloads_signing() -> None:
    class SlowKms:
        def sign(self, **_: object) -> dict[str, bytes]:
            time.sleep(0.2)
            return {"Signature": b"\x01" * 256}

    class Cancellation:
        def raise_if_cancelled(self) -> None:
            return None

    class Ledger:
        def claim(self, _kind: CallKind) -> None:
            return None

    verified = principal(expires=NOW + timedelta(minutes=10))
    authorized = MappedSitePolicy([make_site("alpha")]).authorize(verified, "alpha")
    execution = ExecutionContext(
        question_id=uuid4(),
        operation="page",
        owner_key=verified.owner_key,
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
        trace_context=TraceContext(trace_id="3" * 32, span_id="3" * 16, trace_flags=1),
    )
    broker = KmsIndexerTokenBroker(SlowKms(), key_ids={"alpha": "alpha-key-v4"}, now=lambda: NOW)

    async def ticker() -> float:
        await asyncio.sleep(0.05)
        return time.monotonic()

    started = time.monotonic()
    _, tick_at = await asyncio.gather(
        broker.issue(verified, authorized, execution=execution),
        ticker(),
    )
    assert tick_at - started < 0.15
