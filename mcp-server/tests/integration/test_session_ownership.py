import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from wazuh_mcp.server.sessions import MCPSession, SessionManager, SessionNotFound
from wazuh_mcp.session_store import InMemorySessionStore, RedisSessionStore


class RedisStub:
    def __init__(self):
        self.data = {}
        self.writes = 0

    async def get(self, key):
        return self.data.get(key)

    async def set(self, key, data, *, ex):
        assert ex > 0
        self.data[key] = data
        self.writes += 1

    async def eval(self, script, numkeys, key, expected, replacement, ttl):
        if self.data.get(key) != expected:
            return 0
        self.writes += 1
        if replacement:
            self.data[key] = replacement
        else:
            del self.data[key]
        return 1


@pytest.fixture(params=["memory", "redis"])
def store(request):
    if request.param == "memory":
        return InMemorySessionStore()
    store = RedisSessionStore("redis://stub")
    store._initialized = True
    store._redis = RedisStub()
    return store


@pytest.mark.asyncio
async def test_ownership_roundtrip_and_foreign_expired_is_read_only(store):
    first, second = SessionManager(store), SessionManager(store)
    session = MCPSession("id")
    session.owner = {"version": 1, "family": "api_key", "subject": "same:id"}
    await first.set("id", session)
    original = await store.get("id")
    writes = getattr(getattr(store, "_redis", None), "writes", None)
    foreign = {"version": 1, "family": "bearer_jwt", "subject": "same:id"}
    with pytest.raises(SessionNotFound):
        await second.owned("id", foreign)
    assert await store.get("id") == original
    assert getattr(getattr(store, "_redis", None), "writes", None) == writes
    assert (await second.owned("id", dict(session.owner))).owner == session.owner
    expired = await second.get("id")
    expired.last_activity = datetime.now(timezone.utc) - timedelta(hours=2)
    await first.set("id", expired)
    before = await store.get("id")
    with pytest.raises(SessionNotFound):
        await second.owned("id", foreign, delete=True)
    assert await store.get("id") == before
    with pytest.raises(SessionNotFound):
        await first.owned("id", session.owner)
    assert await store.get("id") is None


@pytest.mark.asyncio
async def test_ownerless_and_unknown_rejected(store):
    manager = SessionManager(store)
    session = MCPSession("ownerless")
    await manager.set(session.session_id, session)
    for session_id in ("ownerless", "missing"):
        with pytest.raises(SessionNotFound):
            await manager.owned(session_id, {"version": 1, "family": "authless"})


@pytest.mark.asyncio
async def test_delete_racing_update_never_recreates(store):
    first, second = SessionManager(store), SessionManager(store)
    session = MCPSession("race")
    session.owner = {"version": 1, "family": "authless"}
    await first.set("race", session)
    result = await asyncio.gather(
        first.owned("race", session.owner, delete=True), second.owned("race", session.owner), return_exceptions=True
    )
    assert any(isinstance(item, SessionNotFound) for item in result)
    assert await store.get("race") is None


@pytest.mark.asyncio
async def test_public_routes_hide_foreign_session_and_preserve_stateless(monkeypatch):
    from types import SimpleNamespace

    import httpx

    from wazuh_mcp import server
    from wazuh_mcp.server import state, transport

    manager = SessionManager(InMemorySessionStore())
    monkeypatch.setattr(state, "sessions", manager)
    monkeypatch.setattr(state, "_session_store", manager._store)
    owner = {"version": 1, "family": "api_key", "subject": "alice"}
    session = MCPSession("private")
    session.owner = owner
    await manager.set("private", session)
    before = await manager._store.get("private")

    async def authenticate(request, authorization):
        name = "alice" if authorization == "Bearer alice" else "bob"
        return SimpleNamespace(
            owner={"version": 1, "family": "api_key", "subject": name},
            api_key_id=name,
            scopes=["wazuh:read"],
            has_scope=lambda scope: scope == "wazuh:read",
        )

    monkeypatch.setattr(transport, "_authenticate", authenticate)
    headers = {"Authorization": "Bearer bob", "MCP-Session-Id": "private"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app), base_url="http://testserver") as client:
        for path in ("/", "/mcp"):
            assert (await client.get(path, headers={**headers, "Accept": "text/event-stream"})).status_code == 404
            assert (
                await client.post(path, headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
            ).status_code == 404
            assert (await client.delete(path, headers=headers)).status_code == 404
        assert await manager._store.get("private") == before
        modern = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}},
        }
        response = await client.post(
            "/mcp",
            headers={**headers, "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "server/discover"},
            json=modern,
        )
        assert response.status_code == 200
        assert "mcp-session-id" not in response.headers
        assert (await client.delete("/mcp", headers={**headers, "Authorization": "Bearer alice"})).status_code == 204


@pytest.mark.asyncio
async def test_two_managers_retry_simultaneous_updates_without_changing_owner():
    class ContendedStore(InMemorySessionStore):
        def __init__(self):
            super().__init__()
            self.arrived = 0
            self.both_arrived = asyncio.Event()

        async def compare_and_swap(self, session_id, expected, replacement):
            if self.arrived < 2:
                self.arrived += 1
                if self.arrived == 2:
                    self.both_arrived.set()
                await self.both_arrived.wait()
            return await super().compare_and_swap(session_id, expected, replacement)

    store = ContendedStore()
    first, second = SessionManager(store), SessionManager(store)
    session = MCPSession("race-updates")
    session.owner = {"version": 1, "family": "authless"}
    await first.set(session.session_id, session)
    updated = await asyncio.wait_for(asyncio.gather(first.owned(session.session_id, session.owner), second.owned(session.session_id, session.owner)), 2)
    assert all(item.owner == session.owner for item in updated)
    assert (await store.get(session.session_id))["owner"] == session.owner


@pytest.mark.asyncio
async def test_delayed_update_cannot_restore_deleted_record():
    class InterleavedStore(InMemorySessionStore):
        def __init__(self):
            super().__init__()
            self.update_waiting = asyncio.Event()
            self.release_update = asyncio.Event()

        async def compare_and_swap(self, session_id, expected, replacement):
            if replacement is not None:
                self.update_waiting.set()
                await self.release_update.wait()
            return await super().compare_and_swap(session_id, expected, replacement)

    store = InterleavedStore()
    first, second = SessionManager(store), SessionManager(store)
    session = MCPSession("race-delete")
    session.owner = {"version": 1, "family": "authless"}
    await first.set(session.session_id, session)
    update = asyncio.create_task(first.owned(session.session_id, session.owner))
    await asyncio.wait_for(store.update_waiting.wait(), 2)
    await second.owned(session.session_id, session.owner, delete=True)
    store.release_update.set()
    with pytest.raises(SessionNotFound):
        await update
    assert await store.get(session.session_id) is None


@pytest.mark.asyncio
async def test_store_backend_concurrent_updates_and_delete_do_not_resurrect(store, monkeypatch):
    first, second = SessionManager(store), SessionManager(store)
    session = MCPSession("both-backends")
    session.owner = {"version": 1, "family": "authless"}
    await first.set(session.session_id, session)
    original = store.compare_and_swap
    arrived = asyncio.Event()
    release = asyncio.Event()
    paused = False

    async def interleaved(session_id, expected, replacement):
        nonlocal paused
        if replacement is not None and not paused:
            paused = True
            arrived.set()
            await release.wait()
        return await original(session_id, expected, replacement)

    monkeypatch.setattr(store, "compare_and_swap", interleaved)
    pending = asyncio.create_task(first.owned(session.session_id, session.owner))
    await asyncio.wait_for(arrived.wait(), 2)
    await second.owned(session.session_id, session.owner, delete=True)
    release.set()
    with pytest.raises(SessionNotFound):
        await pending
    assert await store.get(session.session_id) is None
