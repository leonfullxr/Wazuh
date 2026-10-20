"""Pinned HTTPS key material resolvers for ALB and MCP verification."""

from __future__ import annotations

import json
import os
import ssl
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import cast
from urllib.parse import urlparse

import httpx
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from ai_soc.identity.alb import (
    KeyMaterial,
    PublicKeyResolver,
    build_alb_public_key_resolver,
)


def _alb_https_proxy() -> str | None:
    value = os.environ.get("SOC_ALB_PUBLIC_KEY_HTTPS_PROXY", "").strip()
    return value or None


def _mcp_jwks_https_proxy() -> str | None:
    value = os.environ.get("SOC_MCP_JWKS_HTTPS_PROXY", "").strip()
    return value or None


def _verify_context(ca_bundle_path: str | None) -> ssl.SSLContext:
    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    if ca_bundle_path:
        context.load_verify_locations(cafile=ca_bundle_path)
    return context


def alb_key_resolver(region: str, *, ca_bundle_path: str | None = None) -> PublicKeyResolver:
    return build_alb_public_key_resolver(
        region,
        https_proxy=_alb_https_proxy(),
        ca_bundle_path=ca_bundle_path,
    )


@dataclass(slots=True)
class _JwksPublicKeyResolver:
    _client: httpx.Client
    _origin_host: str
    _jwks_path: str
    _cache_ttl_seconds: float
    _cache_max_entries: int
    _global_refresh_cooldown_seconds: float
    _unknown_kid_map_max_entries: int
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _refresh_cv: threading.Condition = field(init=False, repr=False)
    _refreshing: bool = False
    _refresh_generation: int = 0
    _refresh_error_generation: int | None = None
    _cache: OrderedDict[str, tuple[KeyMaterial, float]] = field(
        default_factory=OrderedDict[str, tuple[KeyMaterial, float]]
    )
    _jwks_material: dict[str, KeyMaterial] = field(default_factory=dict[str, KeyMaterial])
    _jwks_fetched_at: float = 0.0
    _last_refresh_at: float = 0.0
    _unknown_kid_until: OrderedDict[str, float] = field(default_factory=OrderedDict[str, float])

    def __post_init__(self) -> None:
        object.__setattr__(self, "_refresh_cv", threading.Condition(self._lock))

    def __call__(self, key_id: str) -> KeyMaterial:
        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(key_id)
            if cached is not None and cached[1] > now:
                return cached[0]
            if cached is not None:
                del self._cache[key_id]
            reject_until = self._unknown_kid_until.get(key_id)
            if reject_until is not None:
                if reject_until > now:
                    raise ValueError("requested signing key is unavailable")
                del self._unknown_kid_until[key_id]

        material = self._resolve(key_id, now=now)
        with self._lock:
            self._unknown_kid_until.pop(key_id, None)
            cache_expires_at = min(
                time.monotonic() + self._cache_ttl_seconds,
                self._jwks_fetched_at + self._cache_ttl_seconds,
            )
            self._cache[key_id] = (material, cache_expires_at)
            self._cache.move_to_end(key_id)
            while len(self._cache) > self._cache_max_entries:
                self._cache.popitem(last=False)
        return material

    def _resolve(self, key_id: str, *, now: float) -> KeyMaterial:
        snapshot = self._shared_refresh(now=now)
        material = snapshot.get(key_id)
        if material is None:
            with self._lock:
                self._mark_unknown(key_id, now=now)
            raise ValueError("requested signing key is unavailable")
        return material

    def _shared_refresh(self, *, now: float) -> dict[str, KeyMaterial]:
        with self._refresh_cv:
            while True:
                now = time.monotonic()
                jwks_fresh = (
                    self._jwks_fetched_at > 0
                    and now - self._jwks_fetched_at < self._cache_ttl_seconds
                )
                if jwks_fresh:
                    return dict(self._jwks_material)
                if self._refreshing:
                    generation = self._refresh_generation
                    self._refresh_cv.wait(timeout=self._client.timeout.read)
                    if self._refresh_error_generation == generation:
                        raise ValueError("requested signing key is unavailable")
                    continue
                refresh_allowed = (
                    now - self._last_refresh_at >= self._global_refresh_cooldown_seconds
                )
                if not refresh_allowed:
                    if self._jwks_fetched_at > 0 and now - self._jwks_fetched_at < (
                        self._cache_ttl_seconds
                    ):
                        return dict(self._jwks_material)
                    raise ValueError("requested signing key is unavailable")
                self._refreshing = True
                self._refresh_generation += 1
                generation = self._refresh_generation
                self._last_refresh_at = now
                break
        try:
            material = self._fetch_jwks()
        except Exception:
            with self._refresh_cv:
                self._refresh_error_generation = generation
                self._refreshing = False
                self._refresh_cv.notify_all()
            raise ValueError("requested signing key is unavailable") from None
        with self._refresh_cv:
            self._jwks_material = material
            fetched_at = time.monotonic()
            self._jwks_fetched_at = fetched_at
            self._last_refresh_at = fetched_at
            self._refreshing = False
            self._refresh_cv.notify_all()
            return dict(material)

    def _mark_unknown(self, key_id: str, *, now: float) -> None:
        until = now + self._global_refresh_cooldown_seconds
        self._unknown_kid_until[key_id] = until
        self._unknown_kid_until.move_to_end(key_id)
        while len(self._unknown_kid_until) > self._unknown_kid_map_max_entries:
            self._unknown_kid_until.popitem(last=False)

    def _fetch_jwks(self) -> dict[str, KeyMaterial]:
        try:
            response = self._client.get(self._jwks_path, timeout=self._client.timeout)
        except httpx.HTTPError as exc:
            raise ValueError("requested signing key is unavailable") from exc
        if response.status_code != 200:
            raise ValueError("requested signing key is unavailable")
        if response.request.url.host != self._origin_host or response.url.host != self._origin_host:
            raise ValueError("requested signing key is unavailable")
        payload: object = json.loads(response.text)
        if not isinstance(payload, dict):
            raise ValueError("JWKS payload is invalid")
        keys = cast(dict[str, object], payload).get("keys")
        if not isinstance(keys, list):
            raise ValueError("JWKS payload is invalid")
        material_by_kid: dict[str, KeyMaterial] = {}
        for raw_entry in cast(list[object], keys):
            if not isinstance(raw_entry, dict):
                continue
            entry = cast(dict[str, object], raw_entry)
            kid = entry.get("kid")
            if not isinstance(kid, str) or not kid:
                continue
            if entry.get("kty") == "RSA" and isinstance(entry.get("n"), str):
                from jwt.algorithms import RSAAlgorithm

                # pyjwt types from_jwk as private-or-public; pinned JWKS entries are public keys.
                material_by_kid[kid] = cast(RSAPublicKey, RSAAlgorithm.from_jwk(json.dumps(entry)))
            elif entry.get("kty") == "EC" and isinstance(entry.get("x"), str):
                from jwt.algorithms import ECAlgorithm

                material_by_kid[kid] = cast(
                    EllipticCurvePublicKey, ECAlgorithm.from_jwk(json.dumps(entry))
                )
        return material_by_kid


def _validate_jwks_uri(jwks_uri: str) -> tuple[str, str, str]:
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
    origin_host = parsed.hostname
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    return base_url, origin_host, parsed.path


def mcp_key_resolver(jwks_uri: str, *, ca_bundle_path: str | None = None) -> PublicKeyResolver:
    base_url, origin_host, jwks_path = _validate_jwks_uri(jwks_uri)
    timeout = httpx.Timeout(5.0, connect=5.0)
    client = httpx.Client(
        base_url=base_url,
        verify=_verify_context(ca_bundle_path),
        follow_redirects=False,
        trust_env=False,
        proxy=_mcp_jwks_https_proxy(),
        timeout=timeout,
        limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
    )
    return _JwksPublicKeyResolver(
        _client=client,
        _origin_host=origin_host,
        _jwks_path=jwks_path,
        _cache_ttl_seconds=300.0,
        _cache_max_entries=32,
        _global_refresh_cooldown_seconds=5.0,
        _unknown_kid_map_max_entries=256,
    )
