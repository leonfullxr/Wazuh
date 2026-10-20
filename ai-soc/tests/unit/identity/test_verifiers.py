from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ai_soc.contracts.models import ErrorCode
from ai_soc.identity.alb import AlbAssertionVerifier, IdentityError, McpBearerVerifier
from ai_soc.identity.verifier import RouteIdentityVerifier

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
ISSUER = "https://id.example.test"
ALB_SIGNER = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/soc/abc"
OTHER_ALB_SIGNER = "arn:aws:elasticloadbalancing:us-east-1:999999999999:loadbalancer/app/evil/xyz"
RESOURCE = "https://soc.example.test/mcp"


@pytest.fixture
def signing_key():
    return ec.generate_private_key(ec.SECP256R1()), rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )


def _alb_header(**overrides: object) -> dict[str, object]:
    header: dict[str, object] = {
        "signer": ALB_SIGNER,
        "iss": ISSUER,
        "client": "browser-client",
        "exp": int((NOW + timedelta(minutes=5)).timestamp()),
    }
    header.update(overrides)
    return header


def _alb_token(
    private,
    *,
    header_overrides: dict[str, object] | None = None,
    **payload_overrides: object,
) -> str:
    claims: dict[str, object] = {
        "sub": "analyst-007",
        "groups": ["soc-alpha"],
    }
    claims.update(payload_overrides)
    header = _alb_header(**(header_overrides or {}))
    return jwt.encode(claims, private, algorithm="ES256", headers={"kid": "alb-kid-1", **header})


def _alb_verifier(public):
    return AlbAssertionVerifier(
        region="us-east-1",
        signer_arn=ALB_SIGNER,
        issuer=ISSUER,
        client_id="browser-client",
        groups_claim="groups",
        key_resolver=lambda kid: public if kid == "alb-kid-1" else pytest.fail("unexpected kid"),
        now=lambda: NOW,
    )


def _mcp_token(private, **overrides: object) -> str:
    claims: dict[str, object] = {
        "iss": ISSUER,
        "aud": RESOURCE,
        "sub": "analyst-007",
        "groups": ["soc-alpha"],
        "scope": "soc:ask",
        "exp": int((NOW + timedelta(minutes=5)).timestamp()),
        "nbf": int((NOW - timedelta(seconds=1)).timestamp()),
    }
    claims.update(overrides)
    return jwt.encode(claims, private, algorithm="RS256", headers={"kid": "mcp-kid-1"})


def _mcp_verifier(public):
    return McpBearerVerifier(
        issuer=ISSUER,
        resource=RESOURCE,
        jwks_uri="https://id.example.test/.well-known/jwks.json",
        key_resolver=lambda kid: public if kid == "mcp-kid-1" else pytest.fail("unexpected kid"),
        now=lambda: NOW,
        allowed_origins=frozenset({"https://soc.example.test"}),
    )


def test_alb_assertion_is_validated_and_owner_is_stable(signing_key):
    private, _ = signing_key
    verifier = _alb_verifier(private.public_key())
    principal = verifier.verify(_alb_token(private))
    assert principal.edge == "browser"
    assert principal.sub == "analyst-007"
    assert principal.groups == ("soc-alpha",)
    assert principal.owner_key == verifier.verify(_alb_token(private)).owner_key
    assert principal.expires_at == NOW + timedelta(minutes=5)


@pytest.mark.parametrize(
    "header_changes, payload_changes, expected",
    [
        (
            {"signer": OTHER_ALB_SIGNER},
            {
                "iss": ISSUER,
                "signer": ALB_SIGNER,
                "client": "browser-client",
            },
            ErrorCode.AUTH_INVALID,
        ),
        ({"iss": "https://attacker.example"}, {}, ErrorCode.AUTH_INVALID),
        ({"client": "other-client"}, {}, ErrorCode.AUTH_INVALID),
        ({}, {"groups": None}, ErrorCode.AUTH_INVALID),
        (
            {"exp": int((NOW - timedelta(seconds=1)).timestamp())},
            {},
            ErrorCode.AUTH_EXPIRED,
        ),
    ],
)
def test_alb_rejects_wrong_header_claims_and_expiry(
    signing_key, header_changes, payload_changes, expected
):
    private, _ = signing_key
    public = private.public_key()
    with pytest.raises(IdentityError) as error:
        _alb_verifier(public).verify(
            _alb_token(private, header_overrides=header_changes, **payload_changes)
        )
    assert error.value.code == expected


def test_alb_ignores_spoofed_signer_in_payload_when_header_is_valid(signing_key):
    private, _ = signing_key
    verifier = _alb_verifier(private.public_key())
    token = _alb_token(
        private,
        signer=OTHER_ALB_SIGNER,
        iss=ISSUER,
        client="browser-client",
    )
    principal = verifier.verify(token)
    assert principal.sub == "analyst-007"


def test_alb_rejects_jku_oversized_and_bad_signatures(signing_key):
    private, _ = signing_key
    public = private.public_key()
    verifier = _alb_verifier(public)
    forged_header = jwt.encode(
        {"sub": "alice", "groups": ["soc-alpha"]},
        private,
        algorithm="ES256",
        headers={
            "kid": "alb-kid-1",
            "jku": "https://evil.example/keys",
            **_alb_header(),
        },
    )
    with pytest.raises(IdentityError):
        verifier.verify(forged_header)
    with pytest.raises(IdentityError):
        verifier.verify("x" * 16_385)
    with pytest.raises(IdentityError):
        verifier.verify(_alb_token(private).rsplit(".", 1)[0] + ".AA")


def test_alb_requires_es256_and_uses_regional_key_origin(signing_key):
    _, mcp_private = signing_key
    wrong_algorithm = jwt.encode(
        {"sub": "analyst-007", "groups": ["soc-alpha"]},
        mcp_private,
        algorithm="RS256",
        headers={"kid": "alb-kid-1", **_alb_header()},
    )
    verifier = _alb_verifier(mcp_private.public_key())
    assert verifier.key_origin == "https://public-keys.auth.elb.us-east-1.amazonaws.com/"
    with pytest.raises(IdentityError):
        verifier.verify(wrong_algorithm)


def test_mcp_bearer_is_independent_resource_scoped_and_origin_checked(signing_key):
    _, private = signing_key
    public = private.public_key()
    verifier = _mcp_verifier(public)
    principal = verifier.verify(_mcp_token(private), origin="https://soc.example.test")
    assert principal.edge == "mcp"
    assert principal.owner_key
    assert verifier.verify(_mcp_token(private), origin=None).sub == principal.sub
    with pytest.raises(IdentityError) as error:
        verifier.verify(_mcp_token(private, aud="https://other.example/mcp"))
    assert error.value.code == ErrorCode.AUTH_INVALID
    with pytest.raises(IdentityError):
        verifier.verify(_mcp_token(private, aud=["https://other.example/mcp", "account"]))
    verifier.verify(_mcp_token(private, aud=[RESOURCE, "account"]))
    with pytest.raises(IdentityError) as error:
        verifier.verify(_mcp_token(private, scope="profile"))
    assert error.value.code == ErrorCode.SCOPE_DENIED
    with pytest.raises(IdentityError) as error:
        verifier.verify(_mcp_token(private), origin="https://evil.example")
    assert error.value.code == ErrorCode.ORIGIN_DENIED


def test_browser_assertion_and_cookie_cannot_authenticate_mcp(signing_key):
    alb_private, mcp_private = signing_key
    route = RouteIdentityVerifier(
        _alb_verifier(alb_private.public_key()), _mcp_verifier(mcp_private.public_key())
    )
    with pytest.raises(IdentityError) as error:
        import asyncio

        asyncio.run(route.verify(headers={"cookie": "session=anything"}, edge="mcp"))
    assert error.value.code == ErrorCode.AUTH_REQUIRED
    with pytest.raises(IdentityError):
        import asyncio

        asyncio.run(
            route.verify(
                headers={"x-amzn-oidc-data": _alb_token(alb_private)},
                edge="mcp",
            )
        )
    with pytest.raises(IdentityError):
        import asyncio

        asyncio.run(
            route.verify(
                headers={"authorization": "Bearer " + _mcp_token(mcp_private)},
                edge="browser",
            )
        )
