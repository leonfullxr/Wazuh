from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ai_soc.contracts.models import ErrorCode
from ai_soc.identity.alb import AlbAssertionVerifier, IdentityError, McpBearerVerifier
from ai_soc.judgment.bedrock import SystemClock
from ai_soc.state.errors import StateFailure
from ai_soc.state.memory import MemoryState

NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)
ISSUER = "https://id.example.test"
ALB_SIGNER = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/soc/abc"
RESOURCE = "https://soc.example.test/mcp"


class AdvancingClock:
    def __init__(self, start: datetime) -> None:
        self._now = start

    def now(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta) -> None:
        self._now += delta


@pytest.fixture
def signing_key() -> tuple[object, object]:
    return ec.generate_private_key(ec.SECP256R1()), rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )


def test_live_clock_advances_for_alb_and_mcp_tokens(signing_key: tuple[object, object]) -> None:
    alb_private, mcp_private = signing_key
    clock = AdvancingClock(NOW)
    alb = AlbAssertionVerifier(
        region="us-east-1",
        signer_arn=ALB_SIGNER,
        issuer=ISSUER,
        client_id="browser-client",
        groups_claim="groups",
        key_resolver=lambda kid: alb_private.public_key(),  # type: ignore[union-attr]
        now=clock.now,
    )
    mcp = McpBearerVerifier(
        issuer=ISSUER,
        resource=RESOURCE,
        jwks_uri=f"{ISSUER}/.well-known/jwks.json",
        key_resolver=lambda kid: mcp_private.public_key(),  # type: ignore[union-attr]
        now=clock.now,
        allowed_origins=frozenset({"https://soc.example.test"}),
    )
    alb_token = jwt.encode(
        {"sub": "analyst", "groups": ["soc"]},
        alb_private,  # type: ignore[arg-type]
        algorithm="ES256",
        headers={
            "kid": "alb-kid",
            "signer": ALB_SIGNER,
            "iss": ISSUER,
            "client": "browser-client",
            "exp": int((NOW + timedelta(minutes=1)).timestamp()),
        },
    )
    mcp_token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": RESOURCE,
            "sub": "analyst",
            "groups": ["soc"],
            "scope": "soc:ask",
            "exp": int((NOW + timedelta(minutes=1)).timestamp()),
            "nbf": int((NOW - timedelta(seconds=1)).timestamp()),
        },
        mcp_private,  # type: ignore[arg-type]
        algorithm="RS256",
        headers={"kid": "mcp-kid"},
    )
    alb.verify(alb_token)
    mcp.verify(mcp_token, origin="https://soc.example.test")
    clock.advance(timedelta(minutes=2))
    with pytest.raises(IdentityError) as alb_error:
        alb.verify(alb_token)
    assert alb_error.value.code == ErrorCode.AUTH_EXPIRED
    with pytest.raises(IdentityError) as mcp_error:
        mcp.verify(mcp_token, origin="https://soc.example.test")
    assert mcp_error.value.code == ErrorCode.AUTH_EXPIRED


def test_wall_clock_now_and_monotonic_move_forward() -> None:
    clock = SystemClock()
    first = clock.now()
    second = clock.now()
    assert second >= first
    assert clock.monotonic() <= clock.monotonic()


@pytest.mark.asyncio
async def test_lease_expires_when_clock_advances() -> None:
    clock = AdvancingClock(NOW)
    store = MemoryState(lease_seconds=30)
    owner = "0" * 64
    lease = await store.acquire_lease(
        owner_key=owner,
        environment_id="alpha",
        question_id=uuid4(),
        holder_id=uuid4(),
        now=clock.now(),
    )
    assert lease.expires_at > clock.now()
    clock.advance(timedelta(seconds=31))
    with pytest.raises(StateFailure):
        await store.renew_lease(lease, now=clock.now())
