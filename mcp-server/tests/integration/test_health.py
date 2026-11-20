"""
Liveness vs readiness tests.

/health must stay 200 while the process is up even when Wazuh is unreachable -
otherwise a SIEM outage fails the container healthcheck and restart-loops a live
server. /ready is where dependency health is reported.
"""

import os

import pytest

os.environ.setdefault("WAZUH_HOST", "localhost")
os.environ.setdefault("WAZUH_USER", "test")
os.environ.setdefault("WAZUH_PASS", "test")
os.environ.setdefault("AUTH_MODE", "none")

import httpx  # noqa: E402

from wazuh_mcp import server as mcp_server  # noqa: E402
from wazuh_mcp.security import memory_manager


def _client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=mcp_server.app), base_url="http://testserver")


@pytest.fixture(autouse=True)
def _fresh_readiness(monkeypatch):
    # Each test stubs dependencies differently; don't let a cached /ready result leak across
    monkeypatch.setattr(mcp_server.state, "_ready_cache", None)


@pytest.mark.asyncio
async def test_health_is_liveness_and_ignores_wazuh(monkeypatch):
    # Even if the Wazuh manager call would fail, liveness stays healthy.
    async def boom():
        raise RuntimeError("wazuh down")

    monkeypatch.setattr(mcp_server.state.wazuh_client, "get_manager_info", boom)
    async with _client() as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "healthy"
    assert body["version"]
    # Liveness must not include dependency status.
    assert "services" not in body


@pytest.mark.asyncio
async def test_ready_reports_dependency_failure_as_503(monkeypatch):
    async def boom():
        raise RuntimeError("wazuh down")

    # /ready uses the uncached ping_manager probe so a fresh outage isn't cache-masked.
    monkeypatch.setattr(mcp_server.state.wazuh_client, "ping_manager", boom)
    async with _client() as client:
        resp = await client.get("/ready")
    assert resp.status_code == 503
    assert resp.json()["services"]["wazuh_manager"] == "unhealthy"


@pytest.mark.asyncio
async def test_ready_healthy_when_manager_reachable(monkeypatch):
    async def ok():
        return {"data": {"affected_items": [{"version": "4.14.7"}]}}

    monkeypatch.setattr(mcp_server.state.wazuh_client, "ping_manager", ok)
    # No indexer configured in the test client -> indexer_status not_configured (healthy overall).
    monkeypatch.setattr(mcp_server.state.wazuh_client, "_indexer_client", None)
    async with _client() as client:
        resp = await client.get("/ready")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


@pytest.mark.asyncio
async def test_ready_flood_probes_wazuh_once(monkeypatch):
    # /ready is unauthenticated and not rate limited; a flood must not turn into a flood of
    # Manager API calls eating the budget real tool calls share.
    calls = []

    async def ping():
        calls.append(1)
        return {}

    monkeypatch.setattr(mcp_server.state.wazuh_client, "ping_manager", ping)
    monkeypatch.setattr(mcp_server.state.wazuh_client, "_indexer_client", None)
    async with _client() as client:
        import asyncio

        responses = await asyncio.gather(*(client.get("/ready") for _ in range(50)))
    assert {r.status_code for r in responses} == {200}
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_ready_degrades_over_memory_limit(monkeypatch):
    async def ping():
        return {}

    monkeypatch.setattr(mcp_server.state.wazuh_client, "ping_manager", ping)
    monkeypatch.setattr(mcp_server.state.wazuh_client, "_indexer_client", None)
    monkeypatch.setattr(memory_manager, "check_memory_usage", lambda: False)
    async with _client() as client:
        resp = await client.get("/ready")
    assert resp.status_code == 503
    assert resp.json()["services"]["memory"] == "over_limit"


@pytest.mark.asyncio
async def test_redis_scan_failure_then_recovery(monkeypatch):
    from unittest.mock import AsyncMock

    from wazuh_mcp.session_store import RedisSessionStore

    store = RedisSessionStore("redis://example.invalid")
    store._initialized = True
    scan = AsyncMock(side_effect=[(2, ["mcp:session:a"]), OSError("private-host"), (0, [])])
    store._redis = AsyncMock(scan=scan)
    monkeypatch.setattr(mcp_server.state, "_session_store", store)
    monkeypatch.setattr(mcp_server.state.wazuh_client, "ping_manager", AsyncMock(return_value={}))
    monkeypatch.setattr(mcp_server.state.wazuh_client, "_indexer_client", None)
    async with _client() as client:
        failed = await client.get("/ready")
        assert failed.status_code == 503 and "private-host" not in failed.text
        assert (await client.get("/ready")).status_code == 503
        assert (await client.get("/health")).status_code == 200
        monkeypatch.setattr(mcp_server.state, "_ready_cache", None)
        ready = await client.get("/ready")
        assert ready.status_code == 200 and ready.json()["metrics"]["total_sessions"] == 0
    assert scan.await_count == 3
    store._redis.get.assert_not_called()


@pytest.mark.asyncio
async def test_redis_count_initialization_and_cancellation(monkeypatch):
    import asyncio
    from unittest.mock import AsyncMock

    from wazuh_mcp.session_store import RedisSessionStore, SessionStoreUnavailable

    store = RedisSessionStore("redis://example.invalid")
    monkeypatch.setattr(store, "_ensure_initialized", AsyncMock(side_effect=OSError("unavailable")))
    with pytest.raises(SessionStoreUnavailable):
        await store.count()
    monkeypatch.setattr(store, "_ensure_initialized", AsyncMock(side_effect=asyncio.CancelledError))
    with pytest.raises(asyncio.CancelledError):
        await store.count()


@pytest.mark.asyncio
async def test_redis_live_store():
    """Run against a designated ephemeral CI database when provided."""
    import uuid

    from wazuh_mcp.session_store import RedisSessionStore

    url = os.environ.get("MCP_TEST_REDIS_URL")
    if not url:
        pytest.skip("Set MCP_TEST_REDIS_URL to a disposable Redis test database")
    key = str(uuid.uuid4())
    store = RedisSessionStore(url)
    try:
        first = {"principal": "fixture", "state": "initial"}
        second = {"principal": "fixture", "state": "updated"}
        assert await store.set(key, first)
        assert await store.count() >= 1
        assert await store.compare_and_swap(key, first, second)
        assert not await store.compare_and_swap(key, first, None)
        assert await store.get(key) == second
        assert await store.compare_and_swap(key, second, None)
        assert not await store.compare_and_swap(key, second, first)
        assert await store.get(key) is None
    finally:
        await store.delete(key)
        await store.close()


@pytest.mark.asyncio
async def test_restricted_readiness_omits_topology(monkeypatch):
    from unittest.mock import AsyncMock

    monkeypatch.setattr(mcp_server.state, "cluster_policy", object())
    monkeypatch.setattr(mcp_server.state.wazuh_client, "ping_manager", AsyncMock(return_value={}))
    async with _client() as client:
        assert "clusters" not in (await client.get("/ready")).json()


@pytest.mark.asyncio
async def test_stalled_redis_probe_is_cached_at_completion(monkeypatch):
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from wazuh_mcp import session_store
    from wazuh_mcp.server import ops

    store = session_store.RedisSessionStore("redis://example.invalid")
    store._initialized = True
    clock = [20.0]

    async def stalled(**kwargs):
        clock[0] += 5
        await asyncio.Event().wait()

    real_timeout = asyncio.timeout
    monkeypatch.setattr(session_store, "asyncio", SimpleNamespace(timeout=lambda _: real_timeout(.01)))
    monkeypatch.setattr(ops, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    store._redis = AsyncMock()
    store._redis.scan.side_effect = stalled
    monkeypatch.setattr(mcp_server.state, "_session_store", store)
    monkeypatch.setattr(mcp_server.state, "_ready_lock", asyncio.Lock())
    monkeypatch.setattr(mcp_server.state.wazuh_client, "ping_manager", AsyncMock(return_value={}))
    async with _client() as client:
        results = await asyncio.gather(*(client.get("/ready") for _ in range(3)))
    assert {r.status_code for r in results} == {503}
    assert store._redis.scan.await_count == 1
