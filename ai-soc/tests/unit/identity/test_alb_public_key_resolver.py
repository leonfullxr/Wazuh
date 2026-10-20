from __future__ import annotations

import ssl
import time
from urllib.parse import urlparse

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ai_soc.identity.alb import (
    AlbAssertionVerifier,
    AlbPublicKeyResolver,
    IdentityError,
    build_alb_public_key_resolver,
    regional_alb_public_key_origin,
)
from tests.unit.identity.test_verifiers import ALB_SIGNER, ISSUER, NOW, _alb_token

REGION = "us-east-1"
ORIGIN = regional_alb_public_key_origin(REGION)
ORIGIN_HOST = urlparse(ORIGIN).hostname


def _alb_private_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


class StubKeys:
    def __init__(self) -> None:
        self.keys: dict[str, bytes] = {}
        self.fetch_count = 0
        self.delay_seconds = 0.0
        self.oversize = False
        self.redirect_to: str | None = None
        self.max_key_bytes = 8192

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.host != ORIGIN_HOST:
            return httpx.Response(403, request=request)
        self.fetch_count += 1
        if self.delay_seconds:
            time.sleep(self.delay_seconds)
        if self.redirect_to is not None:
            return httpx.Response(302, headers={"location": self.redirect_to}, request=request)
        kid = request.url.path.removeprefix("/")
        body = self.keys.get(kid)
        if body is None:
            return httpx.Response(404, request=request)
        payload = b"x" * (self.max_key_bytes + 1) if self.oversize else body
        return httpx.Response(200, content=payload, request=request)


def _resolver(stub: StubKeys, **resolver_kwargs: object):
    client = httpx.Client(
        base_url=ORIGIN,
        transport=httpx.MockTransport(stub.handler),
        follow_redirects=False,
        trust_env=False,
        timeout=httpx.Timeout(1.0, connect=1.0),
    )
    return build_alb_public_key_resolver(
        REGION,
        http_client=client,
        unknown_kid_cooldown_seconds=0.5,
        cache_ttl_seconds=60.0,
        **resolver_kwargs,
    )


def test_regional_origin_is_pinned() -> None:
    assert regional_alb_public_key_origin("us-east-1") == (
        "https://public-keys.auth.elb.us-east-1.amazonaws.com/"
    )
    assert regional_alb_public_key_origin("cn-northwest-1").endswith("amazonaws.com.cn/")


def test_resolver_fetches_key_by_kid() -> None:
    private = _alb_private_key()
    pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    stub = StubKeys()
    stub.keys["kid-alpha"] = pem
    resolver = _resolver(stub)
    assert resolver("kid-alpha") == pem
    assert stub.fetch_count == 1
    assert resolver("kid-alpha") == pem
    assert stub.fetch_count == 1


def test_resolver_refetches_unknown_kid_after_rotation() -> None:
    private = _alb_private_key()
    pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    stub = StubKeys()
    resolver = _resolver(stub)
    with pytest.raises(IdentityError):
        resolver("kid-missing")
    assert stub.fetch_count == 1
    with pytest.raises(IdentityError):
        resolver("kid-missing")
    assert stub.fetch_count == 1
    time.sleep(0.6)
    stub.keys["kid-missing"] = pem
    assert resolver("kid-missing") == pem


def test_resolver_rejects_oversize_timeout_and_redirect() -> None:
    private = _alb_private_key()
    pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    stub = StubKeys()
    stub.keys["kid-alpha"] = pem
    resolver = _resolver(stub, max_key_bytes=32)
    stub.oversize = True
    with pytest.raises(IdentityError):
        resolver("kid-alpha")
    stub.oversize = False
    stub.delay_seconds = 2.0
    with pytest.raises(IdentityError):
        resolver("kid-alpha")
    stub.delay_seconds = 0.0
    stub.redirect_to = "https://evil.example.test/key.pem"
    with pytest.raises(IdentityError):
        resolver("kid-alpha")


def test_resolver_rejects_unpinned_request_origin() -> None:
    pem = b"pem-bytes"

    def permissive_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=pem, request=request)

    evil_client = httpx.Client(
        base_url="https://evil.example.test/",
        transport=httpx.MockTransport(permissive_handler),
        follow_redirects=False,
    )
    resolver = build_alb_public_key_resolver(REGION, http_client=evil_client)
    with pytest.raises(IdentityError):
        resolver("kid-alpha")


def test_build_alb_public_key_resolver_production_client_is_pinned() -> None:
    resolver = build_alb_public_key_resolver(REGION)
    assert isinstance(resolver, AlbPublicKeyResolver)
    client = resolver._client
    assert f"{client.base_url}" == ORIGIN
    assert client.follow_redirects is False
    assert client.timeout.connect == 5.0
    pool = client._transport._pool
    assert pool._ssl_context is not None
    context = pool._ssl_context
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_resolver_wires_into_alb_verifier() -> None:
    private = _alb_private_key()
    pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    stub = StubKeys()
    stub.keys["alb-kid-1"] = pem
    resolver = _resolver(stub)
    verifier = AlbAssertionVerifier(
        region=REGION,
        signer_arn=ALB_SIGNER,
        issuer=ISSUER,
        client_id="browser-client",
        groups_claim="groups",
        key_resolver=resolver,
        now=lambda: NOW,
    )
    principal = verifier.verify(_alb_token(private))
    assert principal.sub == "analyst-007"


def test_resolver_rejects_invalid_kid_format() -> None:
    client = httpx.Client(
        base_url=ORIGIN,
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b"pem")),
    )
    resolver = build_alb_public_key_resolver(REGION, http_client=client)
    with pytest.raises(IdentityError):
        resolver("../etc/passwd")
