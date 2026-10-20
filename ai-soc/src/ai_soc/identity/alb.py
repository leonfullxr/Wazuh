"""Verification of ALB-signed OIDC assertions and independent MCP access tokens."""

from __future__ import annotations

import hashlib
import re
import ssl
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast
from urllib.parse import urlparse

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwt import InvalidTokenError
from pydantic import HttpUrl

from ai_soc.contracts.canonical import owner_key as make_owner_key
from ai_soc.contracts.models import ErrorCode, VerifiedPrincipal


class IdentityError(ValueError):
    """Sanitized authentication failure; messages never contain token material."""

    def __init__(self, code: ErrorCode = ErrorCode.AUTH_INVALID) -> None:
        self.code = code
        super().__init__(code.value)


KeyMaterial = str | bytes | RSAPublicKey | EllipticCurvePublicKey


class PublicKeyResolver(Protocol):
    def __call__(self, key_id: str) -> KeyMaterial: ...


_REGION_RE = re.compile(r"[a-z]{2}(?:-gov)?-[a-z]+(?:-[a-z]+)*-\d")
_KID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def regional_alb_public_key_origin(region: str) -> str:
    """Pinned HTTPS origin for AWS regional ALB OIDC verification keys."""
    if not _REGION_RE.fullmatch(region):
        raise ValueError("invalid AWS region")
    suffix = "amazonaws.com.cn" if region.startswith("cn-") else "amazonaws.com"
    return f"https://public-keys.auth.elb.{region}.{suffix}/"


@dataclass(slots=True)
class AlbPublicKeyResolver:
    """Fetch ES256 ALB verification keys from the regional origin only."""

    _client: httpx.Client
    _origin_host: str
    _max_key_bytes: int
    _cache_ttl_seconds: float
    _cache_max_entries: int
    _unknown_kid_cooldown_seconds: float
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _cache: OrderedDict[str, tuple[bytes, float]] = field(
        default_factory=OrderedDict[str, tuple[bytes, float]]
    )
    _cooldown_until: dict[str, float] = field(default_factory=dict[str, float])

    def __call__(self, key_id: str) -> str | bytes:
        if not _KID_RE.fullmatch(key_id):
            raise IdentityError()
        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(key_id)
            if cached is not None and cached[1] > now:
                return cached[0]
            if cached is not None:
                del self._cache[key_id]
            cooldown = self._cooldown_until.get(key_id)
            if cooldown is not None and cooldown > now:
                raise IdentityError()
        try:
            response = self._client.get(
                f"/{key_id}",
                timeout=self._client.timeout,
            )
        except httpx.HTTPError:
            raise IdentityError() from None
        if response.status_code != 200:
            with self._lock:
                self._cooldown_until[key_id] = now + self._unknown_kid_cooldown_seconds
            raise IdentityError()
        if response.request.url.host != self._origin_host or response.url.host != self._origin_host:
            raise IdentityError()
        body = response.content
        if len(body) == 0 or len(body) > self._max_key_bytes:
            raise IdentityError()
        with self._lock:
            self._cooldown_until.pop(key_id, None)
            self._cache[key_id] = (body, now + self._cache_ttl_seconds)
            self._cache.move_to_end(key_id)
            while len(self._cache) > self._cache_max_entries:
                self._cache.popitem(last=False)
        return body


def build_alb_public_key_resolver(
    region: str,
    *,
    https_proxy: str | None = None,
    ca_bundle_path: str | None = None,
    static_public_key_pem: str | None = None,
    timeout_seconds: float = 5.0,
    max_key_bytes: int = 8192,
    cache_ttl_seconds: float = 3600.0,
    cache_max_entries: int = 32,
    unknown_kid_cooldown_seconds: float = 1.0,
    http_client: httpx.Client | None = None,
) -> PublicKeyResolver:
    """Build a production ALB key resolver for live composition (region only required).

    Pass ``http_client`` only in tests; live callers rely on the pinned regional origin,
    system trust store, and optional in-VPC ``https_proxy``.
    """
    if static_public_key_pem:

        def _static_resolver(key_id: str) -> str | bytes:
            if key_id != "alb-kid-1":
                raise IdentityError()
            return static_public_key_pem.encode()

        return _static_resolver
    origin = regional_alb_public_key_origin(region)
    parsed = urlparse(origin)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("ALB key origin must be HTTPS")
    origin_host = parsed.hostname
    if http_client is None:
        timeout = httpx.Timeout(timeout_seconds, connect=timeout_seconds)
        verify = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        if ca_bundle_path:
            verify.load_verify_locations(cafile=ca_bundle_path)
        http_client = httpx.Client(
            base_url=origin,
            verify=verify,
            follow_redirects=False,
            trust_env=False,
            proxy=https_proxy,
            timeout=timeout,
            limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
        )
    elif cast(httpx.URL | None, http_client.base_url) is None:
        raise ValueError("http_client requires a base_url")
    return AlbPublicKeyResolver(
        _client=http_client,
        _origin_host=origin_host,
        _max_key_bytes=max_key_bytes,
        _cache_ttl_seconds=cache_ttl_seconds,
        _cache_max_entries=cache_max_entries,
        _unknown_kid_cooldown_seconds=unknown_kid_cooldown_seconds,
    )


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("identity clock must be timezone-aware")
    return value.astimezone(UTC)


def _token_header(token: str, *, max_bytes: int, algorithm: str) -> dict[str, object]:
    if len(token.encode("utf-8")) > max_bytes or token.count(".") != 2:
        raise IdentityError()
    try:
        header = jwt.get_unverified_header(token)
    except (InvalidTokenError, TypeError, ValueError) as exc:
        raise IdentityError() from exc
    if header.get("alg") != algorithm or not isinstance(header.get("kid"), str):
        raise IdentityError()
    if any(k in header for k in ("jku", "x5u", "jwk", "crit")):
        raise IdentityError()
    return header


def _groups(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise IdentityError()
    raw_groups = cast(list[object], value)
    if not raw_groups or len(raw_groups) > 128:
        raise IdentityError()
    groups: list[str] = []
    for group in raw_groups:
        if not isinstance(group, str) or not group or len(group.encode()) > 256:
            raise IdentityError()
        groups.append(group)
    if len(set(groups)) != len(groups):
        raise IdentityError()
    return tuple(sorted(groups))


class AlbAssertionVerifier:
    """Verify `x-amzn-oidc-data` using an injected AWS regional-key resolver."""

    def __init__(
        self,
        *,
        region: str,
        signer_arn: str,
        issuer: str,
        client_id: str,
        groups_claim: str,
        key_resolver: PublicKeyResolver,
        now: Callable[[], datetime],
        max_token_bytes: int = 16_384,
        clock_skew: timedelta = timedelta(seconds=30),
    ) -> None:
        if not _REGION_RE.fullmatch(region):
            raise ValueError("invalid AWS region")
        if not signer_arn.startswith("arn:") or not issuer.startswith("https://") or not client_id:
            raise ValueError("ALB identity configuration is incomplete")
        self.region = region
        self.signer_arn = signer_arn
        self.issuer = issuer
        self.client_id = client_id
        self.groups_claim = groups_claim
        self.key_resolver = key_resolver
        self.now = now
        self.max_token_bytes = max_token_bytes
        self.clock_skew = clock_skew

    @property
    def key_origin(self) -> str:
        return regional_alb_public_key_origin(self.region)

    def verify(self, token: str) -> VerifiedPrincipal:
        header = _token_header(token, max_bytes=self.max_token_bytes, algorithm="ES256")
        kid = str(header["kid"])
        if not _KID_RE.fullmatch(kid):
            raise IdentityError()
        try:
            public_key = self.key_resolver(kid)
            claims = jwt.decode(
                token,
                public_key,
                algorithms=["ES256"],
                options={
                    "verify_aud": False,
                    "verify_exp": False,
                    "verify_nbf": False,
                    "require": ["sub"],
                },
            )
        except IdentityError:
            raise
        except Exception as exc:
            raise IdentityError() from exc
        now = _utc(self.now())
        expiry = _validate_alb_signed_header(
            header,
            signer_arn=self.signer_arn,
            issuer=self.issuer,
            client_id=self.client_id,
            now=now,
            clock_skew=self.clock_skew,
        )
        if claims.get("exp") is not None:
            _validate_time_claims(claims, now, self.clock_skew)
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject or len(subject.encode()) > 1024:
            raise IdentityError()
        groups = _groups(claims.get(self.groups_claim))
        issuer_url = HttpUrl(self.issuer)
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        return VerifiedPrincipal(
            issuer=issuer_url,
            sub=subject,
            owner_key=make_owner_key(self.issuer, subject),
            groups=groups,
            edge="browser",
            authenticated_at=now,
            expires_at=expiry,
            assertion_hash=digest,
        )


class McpBearerVerifier:
    """Separate OAuth resource-token verifier; ALB assertions/cookies cannot enter."""

    def __init__(
        self,
        *,
        issuer: str,
        resource: str,
        jwks_uri: str,
        key_resolver: PublicKeyResolver,
        now: Callable[[], datetime],
        allowed_origins: frozenset[str],
        required_scope: str = "soc:ask",
        max_token_bytes: int = 16_384,
        clock_skew: timedelta = timedelta(seconds=30),
    ) -> None:
        parsed = urlparse(jwks_uri)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or not parsed.path
            or parsed.path == "/"
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("JWKS URI must be a pinned HTTPS URL with host and path")
        if not issuer.startswith("https://") or not resource.startswith("https://"):
            raise ValueError("MCP issuer and resource must use HTTPS")
        self.issuer = issuer
        self.resource = resource
        self.jwks_uri = jwks_uri
        self.key_resolver = key_resolver
        self.now = now
        self.allowed_origins = allowed_origins
        self.required_scope = required_scope
        self.max_token_bytes = max_token_bytes
        self.clock_skew = clock_skew

    def verify(self, token: str, *, origin: str | None = None) -> VerifiedPrincipal:
        if origin is not None and origin not in self.allowed_origins:
            raise IdentityError(ErrorCode.ORIGIN_DENIED)
        header = _token_header(token, max_bytes=self.max_token_bytes, algorithm="RS256")
        try:
            key = self.key_resolver(str(header["kid"]))
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                issuer=self.issuer,
                audience=self.resource,
                options={
                    "verify_exp": False,
                    "verify_nbf": False,
                    "require": ["exp", "iss", "sub", "aud"],
                },
            )
        except Exception as exc:
            raise IdentityError() from exc
        now = _utc(self.now())
        _validate_time_claims(claims, now, self.clock_skew)
        expiry_raw = claims.get("exp")
        if isinstance(expiry_raw, bool) or not isinstance(expiry_raw, (int, float)):
            raise IdentityError()
        expiry = datetime.fromtimestamp(float(expiry_raw), UTC)
        if expiry <= now:
            raise IdentityError(ErrorCode.AUTH_EXPIRED)
        scopes = claims.get("scope", "")
        if not isinstance(scopes, str) or self.required_scope not in scopes.split():
            raise IdentityError(ErrorCode.SCOPE_DENIED)
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject or len(subject.encode()) > 1024:
            raise IdentityError()
        groups_claim = claims.get("groups")
        groups = _groups(groups_claim)
        return VerifiedPrincipal(
            issuer=HttpUrl(self.issuer),
            sub=subject,
            owner_key=make_owner_key(self.issuer, subject),
            groups=groups,
            edge="mcp",
            authenticated_at=now,
            expires_at=expiry,
            assertion_hash=hashlib.sha256(token.encode("ascii")).hexdigest(),
        )


def bearer_from_headers(headers: Mapping[str, str]) -> str:
    value = next((v for k, v in headers.items() if k.lower() == "authorization"), "")
    prefix, sep, token = value.partition(" ")
    if not sep or prefix.lower() != "bearer" or not token or " " in token:
        raise IdentityError(ErrorCode.AUTH_REQUIRED)
    return token


def protected_resource_metadata(resource: str, issuer: str) -> dict[str, object]:
    """Build the fixed RFC 9728 metadata document without dynamic discovery."""
    if not resource.startswith("https://") or not issuer.startswith("https://"):
        raise ValueError("protected resource metadata requires HTTPS URLs")
    return {
        "resource": resource,
        "authorization_servers": [issuer],
        "scopes_supported": ["soc:ask"],
        "bearer_methods_supported": ["header"],
    }


def _validate_alb_signed_header(
    header: Mapping[str, object],
    *,
    signer_arn: str,
    issuer: str,
    client_id: str,
    now: datetime,
    clock_skew: timedelta,
) -> datetime:
    """ALB binds identity in the signed JWT header; payload carries IdP userinfo only."""
    if header.get("signer") != signer_arn:
        raise IdentityError()
    if header.get("iss") != issuer:
        raise IdentityError()
    if header.get("client") != client_id:
        raise IdentityError()
    exp = header.get("exp")
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        raise IdentityError()
    expiry = datetime.fromtimestamp(float(exp), UTC)
    if expiry <= now - clock_skew:
        raise IdentityError(ErrorCode.AUTH_EXPIRED)
    if expiry <= now or expiry > now + timedelta(hours=24):
        raise IdentityError(ErrorCode.AUTH_EXPIRED if expiry <= now else ErrorCode.AUTH_INVALID)
    return expiry


def _validate_time_claims(claims: Mapping[str, object], now: datetime, skew: timedelta) -> None:
    exp = claims.get("exp")
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        raise IdentityError()
    if datetime.fromtimestamp(float(exp), UTC) <= now - skew:
        raise IdentityError(ErrorCode.AUTH_EXPIRED)
    nbf = claims.get("nbf")
    if nbf is not None:
        if isinstance(nbf, bool) or not isinstance(nbf, (int, float)):
            raise IdentityError()
        if datetime.fromtimestamp(float(nbf), UTC) > now + skew:
            raise IdentityError()
