"""Offline HTTP workflow for both MCP protocol eras and renewed authorization."""
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from cryptography.fernet import Fernet

from wazuh_mcp import server
from wazuh_mcp.auth import AuthToken
from wazuh_mcp.clusters import ClusterRegistry
from wazuh_mcp.server.cluster_policy import ClusterPolicy, Rule
from wazuh_mcp.server.product_tools import ProductConfig


class Body(httpx.AsyncByteStream):
    def __init__(self, value):
        self.value = json.dumps(value).encode()

    async def __aiter__(self):
        yield self.value


def response(value):
    return httpx.Response(200, stream=Body(value))


@pytest.mark.asyncio
@pytest.mark.parametrize("modern", [False, True], ids=["legacy", "modern"])
async def test_investigation_http_workflow(monkeypatch, modern):
    document = {"timestamp": "2026-01-01T00:30:00Z", "rule": {"id": "5710", "groups": ["authentication_failed"]}}
    requests = []

    def indexer_handler(request):
        requests.append((request.url.path, json.loads(request.content) if request.content else None))
        if request.url.path.endswith("/_search"):
            return response({"hits": {"total": {"value": 1, "relation": "eq"}, "hits": [{
                "_index": "wazuh-alerts-2026.01.01", "_id": "event-1", "_source": document,
                "sort": ["2026-01-01T00:30:00Z", "event-1"]}]}})
        if request.url.path.endswith("/_settings"):
            return response({"wazuh-alerts-2026.01.01": {"settings": {"index": {"uuid": "fixture-index"}}}})
        return response({"_source": document})

    class Indexer:
        ccs_prefix = ""
        base_url = "https://indexer.invalid"
        client = httpx.AsyncClient(transport=httpx.MockTransport(indexer_handler))

        async def _ensure_initialized(self):
            pass

    indexer = Indexer()
    manager = SimpleNamespace(
        client=httpx.AsyncClient(transport=httpx.MockTransport(lambda _: response({"data": {
            "total_failed_items": 0, "affected_items": [{"id": "007", "status": "active"}]}}))),
        token="fixture", config=SimpleNamespace(base_url="https://manager.invalid"), _indexer_client=indexer,
    )
    saved_name = "saved_investigation_login"
    saved = {saved_name: {"version": "1", "rule_groups": ["authentication_failed"]}}
    monkeypatch.setattr(server.state, "investigation_config", ProductConfig((Fernet.generate_key(),), "event.id", saved))
    monkeypatch.setattr(server.state.config, "ENABLED_TOOLS", {"investigate_agent_timeline", "get_investigation_evidence", saved_name})
    monkeypatch.setattr(server.state, "cluster_registry", ClusterRegistry({"one": manager}, "one", False))
    allow = Rule("api_key", "analyst", None, "one", frozenset({"wazuh:read"}), frozenset())
    monkeypatch.setattr(server.state, "cluster_policy", ClusterPolicy((allow,)))
    token = AuthToken(token="fixture", api_key_id="analyst", created_at=datetime.now(timezone.utc),
                      scopes=["wazuh:read"], owner={"version": 1, "family": "api_key", "subject": "analyst"})
    monkeypatch.setattr(server.http_security, "verify_authentication", AsyncMock(return_value=token))
    args = {"agent_id": "7", "from": "2026-01-01T00:00:00Z", "to": "2026-01-01T01:00:00Z", "cluster_id": "one"}
    headers = {}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app), base_url="http://testserver") as client:
        if not modern:
            init = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "text-client", "version": "1"}}})
            assert init.status_code == 200
            headers["MCP-Session-Id"] = init.headers["MCP-Session-Id"]

        async def call(method, params):
            params = dict(params)
            request_headers = dict(headers)
            if modern:
                params["_meta"] = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                   "io.modelcontextprotocol/clientInfo": {"name": "text-client", "version": "1"},
                                   "io.modelcontextprotocol/clientCapabilities": {}}
                request_headers.update({"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": method})
                if method == "tools/call":
                    request_headers["Mcp-Name"] = params["name"]
            result = await client.post("/mcp", headers=request_headers,
                                       json={"jsonrpc": "2.0", "id": 2, "method": method, "params": params})
            assert result.status_code == 200, result.text
            return result.json()["result"]

        async def tool(name, arguments):
            return await call("tools/call", {"name": name, "arguments": arguments})

        try:
            names = {item["name"] for item in (await call("tools/list", {}))["tools"]}
            assert {"investigate_agent_timeline", "get_investigation_evidence", saved_name} <= names
            timeline = await tool("investigate_agent_timeline", args)
            structured = timeline["structuredContent"]
            assert json.loads(timeline["content"][1]["text"]) == structured
            assert structured["sources"]["alerts"]["status"] == "complete"
            assert structured["events"][0]["rule_id"] == "5710"
            ref = structured["events"][0]["evidence_ref"]
            found = await tool("get_investigation_evidence", {"cluster_id": "one", "evidence_ref": ref})
            assert found["structuredContent"]["status"] == "available"
            assert json.loads(found["content"][1]["text"]) == found["structuredContent"]
            result = await tool(saved_name, args)
            assert result["structuredContent"]["query"]["version"] == "1"
            assert any(
                body and {"terms": {"rule.groups": ["authentication_failed"]}} in body.get("query", {}).get("bool", {}).get("filter", [])
                for _, body in requests)
            monkeypatch.setattr(server.state, "cluster_policy", ClusterPolicy(()))
            before = len(requests)
            denied = await tool("get_investigation_evidence", {"cluster_id": "one", "evidence_ref": ref})
            assert denied["structuredContent"] == {"status": "unavailable"}
            assert len(requests) == before
            monkeypatch.setattr(server.state, "cluster_policy", ClusterPolicy((allow,)))
            token.scopes.clear()
            denied = await tool("get_investigation_evidence", {"cluster_id": "one", "evidence_ref": ref})
            assert denied["structuredContent"] == {"status": "unavailable"}
            assert len(requests) == before
        finally:
            await indexer.client.aclose()
            await manager.client.aclose()
