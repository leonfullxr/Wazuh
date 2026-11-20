import json
import os
from datetime import datetime, timezone

import httpx
import pytest
from cryptography.fernet import Fernet

os.environ.setdefault("AUTH_MODE", "none")

from wazuh_mcp.server.product_tools import InvestigationContext, evidence, execute, render, timeline  # noqa: E402


class Indexer:
    ccs_prefix = ""
    base_url = "https://indexer"

    def __init__(self, handler):
        self.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    async def _ensure_initialized(self):
        pass


class Manager:
    def __init__(self):
        self.client = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200, stream=Stream({"data": {"total_failed_items": 0, "affected_items": [{"status": "active"}]}})
                )
            )
        )
        self.token = "token"
        self.config = type("Config", (), {"base_url": "https://manager"})()


class Stream(httpx.AsyncByteStream):
    def __init__(self, body):
        self.body = json.dumps(body).encode()

    async def __aiter__(self):
        yield self.body


def fixture():
    records = {
        "a": {"timestamp": "2026-01-01T00:30:00Z", "rule": {"id": "1"}},
        "b": {"timestamp": "2026-01-01T00:30:00Z", "rule": {"id": "2"}},
    }
    state = {"uuid": "original", "allow": True, "body": None}

    def response(body):
        return httpx.Response(200, stream=Stream(body))

    def handler(request):
        if request.url.path.endswith("/_search"):
            state["body"] = json.loads(request.content)
            return response(
                {
                    "hits": {
                        "total": {"value": 2, "relation": "eq"},
                        "hits": [
                            {
                                "_index": "wazuh-alerts-2026.01.01",
                                "_id": key,
                                "_source": records[key],
                                "sort": ["2026-01-01T00:30:00Z", key],
                            }
                            for key in ("b", "a")
                        ],
                    }
                }
            )
        if request.url.path.endswith("/_settings"):
            return response({"wazuh-alerts-2026.01.01": {"settings": {"index": {"uuid": state["uuid"]}}}})
        key = request.url.path.rsplit("/", 1)[-1]
        return response({"_source": records[key]})

    async def authorize(owner, cluster):
        return state["allow"]

    ctx = InvestigationContext(
        "one", "revision", "alice", Indexer(handler), Manager(), (Fernet.generate_key(),), "event.id", authorize
    )
    return ctx, state, records


@pytest.mark.asyncio
async def test_timeline_lookup_revocation_revision_and_rendering():
    ctx, state, records = fixture()
    args = {"agent_id": "7", "from": "2026-01-01T00:00:00Z", "to": "2026-01-01T01:00:00Z"}
    data = await timeline(ctx, args)
    assert [e["rule_id"] for e in data["events"]] == ["1", "2"]
    assert data["sources"]["alerts"] == {"status": "complete", "matched": 2, "returned": 2, "truncated": False}
    assert state["body"]["_source"] and state["body"]["sort"][-1] == {"event.id": "desc"}
    rendered = render(data)
    assert json.loads(rendered["content"][1]["text"]) == rendered["structuredContent"]
    ref = data["events"][0]["evidence_ref"]
    assert (await evidence(ctx, ref))["status"] == "available"
    records["a"]["rule"]["id"] = "changed"
    assert (await evidence(ctx, ref))["status"] == "unavailable"
    state["allow"] = False
    assert (await evidence(ctx, ref))["status"] == "unavailable"
    state["allow"] = True
    state["uuid"] = "recreated"
    assert (await evidence(ctx, ref))["status"] == "unavailable"
    await ctx.indexer.client.aclose()
    await ctx.manager.client.aclose()


@pytest.mark.asyncio
async def test_saved_query_and_bounds():
    ctx, state, _ = fixture()
    args = {"agent_id": "7", "from": "2026-01-01T00:00:00Z", "to": "2026-01-01T01:00:00Z"}
    saved = {"saved_investigation_login": {"version": "1", "rule_groups": ["authentication_failed"]}}
    data = await execute(ctx, "saved_investigation_login", args, saved)
    assert data["query"]["version"] == "1"
    assert {"terms": {"rule.groups": ["authentication_failed"]}} in state["body"]["query"]["bool"]["filter"]
    with pytest.raises(ValueError):
        await timeline(ctx, {**args, "limit": 51})
    with pytest.raises(ValueError):
        await timeline(ctx, {**args, "query": "*"})
    with pytest.raises(ValueError):
        await timeline(ctx, {**args, "to": "2026-01-03T00:00:00Z"})
    await ctx.indexer.client.aclose()
    await ctx.manager.client.aclose()


@pytest.mark.asyncio
async def test_http_discovery_and_call(monkeypatch):
    from unittest.mock import AsyncMock

    from wazuh_mcp import server
    from wazuh_mcp.auth import AuthToken
    from wazuh_mcp.clusters import ClusterRegistry
    from wazuh_mcp.server.product_tools import ProductConfig

    ctx, _, _ = fixture()
    ctx.manager._indexer_client = ctx.indexer
    config = ProductConfig(ctx.keys, ctx.tie_breaker, {})
    monkeypatch.setattr(server.state, "investigation_config", config)
    monkeypatch.setattr(
        server.state.config, "ENABLED_TOOLS", {"investigate_agent_timeline", "get_investigation_evidence"}
    )
    monkeypatch.setattr(server.state, "cluster_registry", ClusterRegistry({"one": ctx.manager}, "one", False))
    token = AuthToken(
        token="t",
        api_key_id="a",
        created_at=datetime.now(timezone.utc),
        scopes=["wazuh:read"],
        owner={"version": 1, "family": "api_key", "subject": "a"},
    )
    monkeypatch.setattr(server.http_security, "verify_authentication", AsyncMock(return_value=token))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app), base_url="http://testserver") as client:
        init = await client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"},
                },
            },
        )
        headers = {"MCP-Session-Id": init.headers["MCP-Session-Id"]}

        async def call(method, params):
            response = await client.post(
                "/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 2, "method": method, "params": params}
            )
            return response.json()["result"]

        listed = await call("tools/list", {})
        assert "investigate_agent_timeline" in [tool["name"] for tool in listed["tools"]]
        result = await call(
            "tools/call",
            {
                "name": "investigate_agent_timeline",
                "arguments": {"agent_id": "7", "from": "2026-01-01T00:00:00Z", "to": "2026-01-01T01:00:00Z"},
            },
        )
        assert result["structuredContent"]["sources"]["alerts"]["status"] == "complete"
        assert json.loads(result["content"][1]["text"]) == result["structuredContent"]
    await ctx.indexer.client.aclose()
    await ctx.manager.client.aclose()


@pytest.mark.asyncio
async def test_evidence_replica_owner_and_key_rotation():
    from dataclasses import replace

    ctx, _, _ = fixture()
    args = {"agent_id": "7", "from": "2026-01-01T00:00:00Z", "to": "2026-01-01T01:00:00Z"}
    result = await timeline(ctx, args)
    ref = result["events"][0]["evidence_ref"]
    second = replace(ctx, keys=(Fernet.generate_key(), *ctx.keys))
    assert (await evidence(second, ref))["status"] == "available"
    assert (await evidence(replace(second, owner="bob"), ref))["status"] == "unavailable"
    assert (await evidence(replace(second, cluster="two"), ref))["status"] == "unavailable"
    assert (await evidence(replace(second, cluster_revision="new"), ref))["status"] == "unavailable"
    assert (await evidence(replace(second, keys=(Fernet.generate_key(),)), ref))["status"] == "unavailable"
    import time

    token = Fernet(ctx.keys[0]).decrypt(ref[3:].encode())
    expired = "ev_" + Fernet(ctx.keys[0]).encrypt_at_time(token, int(time.time()) - 901).decode()
    assert (await evidence(second, expired))["status"] == "unavailable"
    await ctx.indexer.client.aclose()
    await ctx.manager.client.aclose()


@pytest.mark.asyncio
async def test_unavailable_search_and_empty_search():
    ctx, _, _ = fixture()

    async def unavailable(request):
        return httpx.Response(503)

    await ctx.indexer.client.aclose()
    ctx.indexer.client = httpx.AsyncClient(transport=httpx.MockTransport(unavailable))
    args = {"agent_id": "7", "from": "2026-01-01T00:00:00Z", "to": "2026-01-01T01:00:00Z"}
    result = await timeline(ctx, args)
    assert result["sources"]["alerts"]["status"] == "unavailable"
    assert result["sources"]["agent_status"]["status"] == "available"
    await ctx.indexer.client.aclose()
    ctx.indexer.client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, stream=Stream({"hits": {"total": 0, "hits": []}}))
        )
    )
    result = await timeline(ctx, args)
    assert result["sources"]["alerts"] == {"status": "complete", "matched": 0, "returned": 0, "truncated": False}
    await ctx.indexer.client.aclose()
    await ctx.manager.client.aclose()


def test_configuration_validation(tmp_path):
    from wazuh_mcp.server.product_tools import load_config

    path = tmp_path / "investigations.json"
    path.write_text('{"tie_breaker":"event.id","tie_breaker_verified":true,"saved":{}}')
    key = Fernet.generate_key().decode()
    assert load_config(str(path), key).tie_breaker == "event.id"
    with pytest.raises(ValueError):
        load_config(str(path), None)
    path.write_text('{"tie_breaker":"event.id","tie_breaker_verified":true,"saved":{},"saved":{}}')
    with pytest.raises(ValueError):
        load_config(str(path), key)


@pytest.mark.asyncio
async def test_saved_queries_match_underlying_filters():
    ctx, state, _ = fixture()
    args = {"agent_id": "7", "from": "2026-01-01T00:00:00Z", "to": "2026-01-01T01:00:00Z", "limit": 2}
    definitions = {
        "saved_investigation_login": {"version": "1", "rule_groups": ["authentication_failed"]},
        "saved_investigation_privilege": {"version": "2", "rule_groups": ["privilege_escalation"]},
    }
    for name, definition in definitions.items():
        saved = await execute(ctx, name, args, definitions)
        saved_body = state["body"]
        direct = await timeline(ctx, args, query={"terms": {"rule.groups": definition["rule_groups"]}})
        assert saved_body == state["body"]
        assert saved["sources"]["alerts"] == direct["sources"]["alerts"]
        assert [x["rule_id"] for x in saved["events"]] == [x["rule_id"] for x in direct["events"]]
    with pytest.raises(ValueError):
        await execute(ctx, "saved_investigation_login", {"agent_id": "7"}, definitions)
    with pytest.raises(ValueError):
        await timeline(ctx, {"from": args["from"], "to": args["to"]})
    await ctx.indexer.client.aclose()
    await ctx.manager.client.aclose()


@pytest.mark.asyncio
async def test_response_budget_and_timeout(monkeypatch):
    import asyncio

    import wazuh_mcp.server.product_tools as module

    ctx, _, _ = fixture()
    args = {"agent_id": "7", "from": "2026-01-01T00:00:00Z", "to": "2026-01-01T01:00:00Z"}
    await ctx.indexer.client.aclose()
    ctx.indexer.client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, headers={"Content-Encoding": "gzip"}, stream=Stream({}))
        )
    )
    data = await timeline(ctx, args)
    assert data["sources"]["alerts"]["status"] == "unavailable"
    await ctx.indexer.client.aclose()

    async def slow(request):
        await asyncio.Event().wait()

    ctx.indexer.client = httpx.AsyncClient(transport=httpx.MockTransport(slow))
    monkeypatch.setattr(module, "DEADLINE_SECONDS", 0.01)
    data = await timeline(ctx, args)
    assert data["sources"]["alerts"]["status"] == "unavailable"
    assert data["sources"]["agent_status"]["status"] == "available"
    await ctx.indexer.client.aclose()
    await ctx.manager.client.aclose()


@pytest.mark.asyncio
async def test_fifty_event_response_size():
    ctx, _, _ = fixture()
    await ctx.indexer.client.aclose()

    def handler(request):
        if request.url.path.endswith("/_settings"):
            return httpx.Response(
                200, stream=Stream({"wazuh-alerts-2026.01.01": {"settings": {"index": {"uuid": "u"}}}})
            )
        rows = [
            {
                "_index": "wazuh-alerts-2026.01.01",
                "_id": str(i),
                "_source": {"timestamp": "2026-01-01T00:30:00Z", "rule": {"id": str(i)}},
                "sort": ["2026-01-01T00:30:00Z", i],
            }
            for i in reversed(range(50))
        ]
        return httpx.Response(200, stream=Stream({"hits": {"total": 50, "hits": rows}}))

    ctx.indexer.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    result = await timeline(ctx, {"agent_id": "7", "from": "2026-01-01T00:00:00Z", "to": "2026-01-01T01:00:00Z"})
    assert len(result["events"]) == 50
    response = render(result)
    assert len(json.dumps(response).encode()) < 100_000
    await ctx.indexer.client.aclose()
    await ctx.manager.client.aclose()


def test_analysis_profiles_and_disabled_registration():
    from wazuh_mcp.toolsets import resolve_enabled_tools

    registered = frozenset({"investigate_agent_timeline", "get_investigation_evidence", "saved_investigation_login"})
    assert registered <= resolve_enabled_tools("analysis", None, "triage", registered)
    assert not (registered & resolve_enabled_tools("all", None, "compliance", registered))
    assert "saved_investigation_login" not in resolve_enabled_tools(
        "analysis", "saved_investigation_login", None, registered
    )
    with pytest.raises(ValueError):
        resolve_enabled_tools("analysis", "saved_investigation_unknown", None, registered)


def test_render_budget_counts_both_representations():
    from wazuh_mcp.server.product_tools import MAX_RESPONSE_BYTES

    result = {
        "events": [{"at": "x" * 50_000, "evidence_ref": str(i)} for i in range(5)],
        "sources": {"alerts": {"status": "complete", "returned": 5, "truncated": False}},
    }
    response = render(result)
    assert len(json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode()) <= MAX_RESPONSE_BYTES
    assert len(response["structuredContent"]["events"]) < 5
    assert response["structuredContent"]["sources"]["alerts"]["status"] == "partial"
    assert json.loads(response["content"][1]["text"]) == response["structuredContent"]


def test_catalog_schemas_are_isolated():
    from wazuh_mcp.server.product_tools import catalog

    saved = {"saved_investigation_login": {"version": "1", "rule_groups": ["authentication_failed"]}}
    first = catalog(saved)
    first[0]["inputSchema"]["properties"]["agent_id"]["type"] = "integer"
    first[0]["inputSchema"]["properties"]["cluster_id"]["description"] = "private"
    first[2]["inputSchema"]["properties"]["limit"]["maximum"] = 1
    second = catalog(saved)
    assert first[2]["inputSchema"]["properties"]["agent_id"]["type"] == "string"
    assert second[0]["inputSchema"]["properties"]["agent_id"]["type"] == "string"
    assert "description" not in second[0]["inputSchema"]["properties"]["cluster_id"]
    assert second[2]["inputSchema"]["properties"]["limit"]["maximum"] == 50


@pytest.mark.asyncio
@pytest.mark.parametrize("auth_status,retry_status", [(200, 200), (401, None), (200, 401)])
async def test_manager_expired_token_refresh_is_bounded(auth_status, retry_status):
    import asyncio

    ctx, _, _ = fixture()
    await ctx.manager.client.aclose()
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path, request.headers.get("authorization")))
        if request.url.path.endswith("/authenticate"):
            return httpx.Response(auth_status, stream=Stream({"data": {"token": "fresh"}}))
        status = 401 if request.headers["authorization"] == "Bearer stale" else retry_status
        return httpx.Response(
            status, stream=Stream({"data": {"total_failed_items": 0, "affected_items": [{"status": "active"}]}})
        )

    ctx.manager.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ctx.manager.token = "stale"
    ctx.manager._auth_lock = asyncio.Lock()
    ctx.manager.config.wazuh_user = "user"
    ctx.manager.config.wazuh_pass = "pass"
    result = await timeline(ctx, {"agent_id": "7"})
    assert result["sources"]["agent_status"]["status"] == ("available" if retry_status == 200 else "unavailable")
    assert [x[0] for x in calls] == (["GET", "POST", "GET"] if retry_status else ["GET", "POST"])
    assert calls[0][2] == "Bearer stale"
    if retry_status:
        assert calls[-1][2] == "Bearer fresh"
    await ctx.indexer.client.aclose()
    await ctx.manager.client.aclose()


@pytest.mark.asyncio
async def test_manager_auth_budget_and_cancellation(monkeypatch):
    import asyncio

    import wazuh_mcp.server.product_tools as module

    ctx, _, _ = fixture()
    await ctx.manager.client.aclose()
    ctx.manager.token = "stale"
    ctx.manager._auth_lock = asyncio.Lock()
    ctx.manager.config.wazuh_user = "user"
    ctx.manager.config.wazuh_pass = "pass"
    started = asyncio.Event()

    async def handler(request):
        if request.method == "POST":
            started.set()
            await asyncio.Event().wait()
        return httpx.Response(401, stream=Stream({}))

    ctx.manager.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(module, "DEADLINE_SECONDS", 0.01)
    result = await timeline(ctx, {"agent_id": "7"})
    assert result["sources"]["agent_status"]["status"] == "unavailable"
    ctx.manager.token = "stale"
    started.clear()
    task = asyncio.create_task(timeline(ctx, {"agent_id": "7"}))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await ctx.indexer.client.aclose()
    await ctx.manager.client.aclose()


@pytest.mark.asyncio
async def test_concurrent_expired_tokens_share_refresh():
    import asyncio

    ctx, _, _ = fixture()
    await ctx.manager.client.aclose()
    ctx.manager.token = "stale"
    ctx.manager._auth_lock = asyncio.Lock()
    ctx.manager.config.wazuh_user = "user"
    ctx.manager.config.wazuh_pass = "pass"
    both_stale = asyncio.Event()
    stale_count = 0
    auth_count = 0

    async def handler(request):
        nonlocal stale_count, auth_count
        if request.method == "POST":
            auth_count += 1
            return httpx.Response(200, stream=Stream({"data": {"token": "fresh"}}))
        if request.headers["authorization"] == "Bearer stale":
            stale_count += 1
            if stale_count == 2:
                both_stale.set()
            await both_stale.wait()
            return httpx.Response(401, stream=Stream({}))
        return httpx.Response(
            200, stream=Stream({"data": {"total_failed_items": 0, "affected_items": [{"status": "active"}]}})
        )

    ctx.manager.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    results = await asyncio.gather(timeline(ctx, {"agent_id": "7"}), timeline(ctx, {"agent_id": "7"}))
    assert auth_count == 1 and stale_count == 2
    assert all(r["sources"]["agent_status"]["status"] == "available" for r in results)
    await ctx.indexer.client.aclose()
    await ctx.manager.client.aclose()


@pytest.mark.asyncio
async def test_manager_auth_reply_respects_total_budget(monkeypatch):
    import asyncio

    import wazuh_mcp.server.product_tools as module

    ctx, _, _ = fixture()
    await ctx.manager.client.aclose()
    ctx.manager.token = "stale"
    ctx.manager._auth_lock = asyncio.Lock()
    ctx.manager.config.wazuh_user = "user"
    ctx.manager.config.wazuh_pass = "pass"
    calls = []

    def handler(request):
        calls.append(request.method)
        if request.method == "POST":
            return httpx.Response(200, stream=Stream({"data": {"token": "x" * 2000}}))
        return httpx.Response(401, stream=Stream({}))

    ctx.manager.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(module, "MAX_BACKEND_BYTES", 1000)
    result = await timeline(ctx, {"agent_id": "7"})
    assert result["sources"]["agent_status"]["status"] == "unavailable"
    assert calls == ["GET", "POST"]
    assert ctx.manager.token is None
    await ctx.indexer.client.aclose()
    await ctx.manager.client.aclose()
