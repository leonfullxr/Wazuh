from __future__ import annotations

import json
import threading
import time

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from ai_soc.live.keys import _JwksPublicKeyResolver, mcp_key_resolver


def _resolver_with_mock_transport() -> tuple[_JwksPublicKeyResolver, dict[str, int]]:
    counts = {"fetch": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "kc.lab"
        assert request.url.path == "/realms/soc/protocol/openid-connect/certs"
        counts["fetch"] += 1
        return httpx.Response(200, json={"keys": []})

    client = httpx.Client(
        base_url="https://kc.lab",
        transport=httpx.MockTransport(handler),
    )
    resolver = _JwksPublicKeyResolver(
        _client=client,
        _origin_host="kc.lab",
        _jwks_path="/realms/soc/protocol/openid-connect/certs",
        _cache_ttl_seconds=300.0,
        _cache_max_entries=32,
        _global_refresh_cooldown_seconds=5.0,
        _unknown_kid_map_max_entries=256,
    )
    return resolver, counts


def test_mcp_key_resolver_accepts_keycloak_jwks_path() -> None:
    uri = "https://kc.lab/realms/soc/protocol/openid-connect/certs"
    resolver = mcp_key_resolver(uri)
    assert resolver is not None


def test_unknown_kids_trigger_at_most_one_fetch_per_window() -> None:
    resolver, counts = _resolver_with_mock_transport()
    for index in range(20):
        with pytest.raises(ValueError, match="unavailable"):
            resolver(f"unknown-{index}")
    assert counts["fetch"] == 1


def test_concurrent_valid_kids_share_one_inflight_refresh() -> None:
    counts = {"fetch": 0}
    gate = threading.Event()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    first_key = {**public_jwk, "kid": "kid-a", "alg": "RS256", "use": "sig"}
    rotated_key = {**public_jwk, "kid": "kid-b", "alg": "RS256", "use": "sig"}

    def handler(request: httpx.Request) -> httpx.Response:
        counts["fetch"] += 1
        fetch_number = counts["fetch"]
        if fetch_number == 1:
            gate.wait(timeout=2.0)
        return httpx.Response(200, json={"keys": [first_key if fetch_number == 1 else rotated_key]})

    client = httpx.Client(
        base_url="https://kc.lab",
        transport=httpx.MockTransport(handler),
    )
    resolver = _JwksPublicKeyResolver(
        _client=client,
        _origin_host="kc.lab",
        _jwks_path="/realms/soc/protocol/openid-connect/certs",
        _cache_ttl_seconds=300.0,
        _cache_max_entries=32,
        _global_refresh_cooldown_seconds=5.0,
        _unknown_kid_map_max_entries=256,
    )
    resolved: list[str | bytes] = []

    def worker() -> None:
        resolved.append(resolver("kid-a"))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    time.sleep(0.05)
    assert counts["fetch"] == 1
    gate.set()
    for thread in threads:
        thread.join(timeout=2.0)
    assert counts["fetch"] == 1
    assert len(resolved) == 8
    resolver._jwks_fetched_at = time.monotonic() - 301.0
    resolver._last_refresh_at = time.monotonic() - 6.0
    assert resolver("kid-b") is not None
    assert counts["fetch"] == 2


def test_expired_jwks_refresh_failure_rejects_old_key_for_waiters() -> None:
    fetch_started = threading.Event()
    finish_fetch = threading.Event()
    counts = {"fetch": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        counts["fetch"] += 1
        fetch_started.set()
        finish_fetch.wait(timeout=2.0)
        return httpx.Response(503)

    client = httpx.Client(base_url="https://kc.lab", transport=httpx.MockTransport(handler))
    resolver = _JwksPublicKeyResolver(
        _client=client,
        _origin_host="kc.lab",
        _jwks_path="/realms/soc/protocol/openid-connect/certs",
        _cache_ttl_seconds=0.05,
        _cache_max_entries=32,
        _global_refresh_cooldown_seconds=5.0,
        _unknown_kid_map_max_entries=256,
    )
    old_material = "expired-public-key"
    expired_at = time.monotonic() - 0.1
    resolver._jwks_material = {"kid-old": old_material}
    resolver._jwks_fetched_at = expired_at
    resolver._last_refresh_at = time.monotonic() - 6.0
    resolver._cache["kid-old"] = (old_material, expired_at)
    failures: list[str] = []

    def worker() -> None:
        try:
            resolver("kid-old")
        except ValueError as exc:
            failures.append(str(exc))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    assert fetch_started.wait(timeout=1.0)
    time.sleep(0.02)
    finish_fetch.set()
    for thread in threads:
        thread.join(timeout=1.0)

    assert counts["fetch"] == 1
    assert failures == [
        "requested signing key is unavailable",
        "requested signing key is unavailable",
    ]


def test_cached_key_cannot_outlive_its_jwks_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    monotonic = [1000.0]

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    client = httpx.Client(base_url="https://kc.lab", transport=httpx.MockTransport(handler))
    resolver = _JwksPublicKeyResolver(
        _client=client,
        _origin_host="kc.lab",
        _jwks_path="/realms/soc/protocol/openid-connect/certs",
        _cache_ttl_seconds=300.0,
        _cache_max_entries=32,
        _global_refresh_cooldown_seconds=5.0,
        _unknown_kid_map_max_entries=256,
    )
    resolver._jwks_material = {"kid-a": "snapshot-key"}
    resolver._jwks_fetched_at = 1000.0
    resolver._last_refresh_at = 1000.0
    monkeypatch.setattr("ai_soc.live.keys.time.monotonic", lambda: monotonic[0])

    monotonic[0] = 1299.0
    assert resolver("kid-a") == "snapshot-key"
    monotonic[0] = 1301.0
    with pytest.raises(ValueError, match="unavailable"):
        resolver("kid-a")
