"""
RBAC scope-enforcement tests at the tool-dispatch boundary.

handle_tools_call is the sole executor for every tool on every transport, so this
is where the read/write boundary must hold. These tests drive it directly (rather
than re-implementing the check) so a regression in the server's own gate is caught.
"""

from datetime import datetime, timezone

import pytest

from wazuh_mcp import server as mcp_server
from wazuh_mcp.auth import AuthToken
from wazuh_mcp.clusters import ClusterRegistry
from wazuh_mcp.server.sessions import MCPSession
from wazuh_mcp.server.tool_calls import handle_tools_call
from wazuh_mcp.server.tool_policy import WRITE_SCOPE_TOOLS


def _session(scopes):
    session = MCPSession("test-session", None)
    session.authenticated = True
    session._auth_token = AuthToken(
        token="t", api_key_id="tester", created_at=datetime.now(timezone.utc), scopes=scopes
    )
    return session


class _StubClient:
    """Records every active-response / tool call instead of hitting Wazuh."""

    def __init__(self):
        self.calls = []

    async def _record(self, name, **kw):
        self.calls.append((name, kw))
        return {"data": {"affected_items": [], "total_affected_items": 0, "total_failed_items": 0, "failed_items": []}}

    async def block_ip(self, *a, **k):
        return await self._record("block_ip", args=a, kwargs=k)

    async def isolate_host(self, *a, **k):
        return await self._record("isolate_host", args=a, kwargs=k)


@pytest.fixture(autouse=True)
def _stub_cluster(monkeypatch):
    stub = _StubClient()
    monkeypatch.setattr(mcp_server.state, "cluster_registry", ClusterRegistry({"default": stub}, "default", False))
    return stub


class TestReadTokenDeniedWriteTools:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool", sorted(WRITE_SCOPE_TOOLS))
    async def test_every_write_tool_denied_to_read_token(self, tool, _stub_cluster):
        session = _session(["wazuh:read"])
        result = await handle_tools_call({"name": tool, "arguments": {}}, session)
        # A tool execution error (visible to the model), and nothing reached Wazuh
        assert result["isError"] is True
        assert "Insufficient permissions" in result["content"][0]["text"]
        assert _stub_cluster.calls == []

    @pytest.mark.asyncio
    async def test_write_tool_denied_when_no_token(self):
        session = MCPSession("s", None)
        session._auth_token = None
        result = await handle_tools_call({"name": "wazuh_block_ip", "arguments": {"ip_address": "1.2.3.4"}}, session)
        assert result["isError"] is True
        assert "Insufficient permissions" in result["content"][0]["text"]

    @pytest.mark.asyncio
    async def test_read_tool_allowed_for_read_token(self):
        session = _session(["wazuh:read"])
        # get_wazuh_alerts is read-scoped - should not raise on the scope gate.
        result = await handle_tools_call({"name": "list_wazuh_clusters", "arguments": {}}, session)
        assert result["isError"] is False


class TestWriteTokenAllowedAndAudited:
    @pytest.mark.asyncio
    async def test_write_token_dispatches_and_audits(self, _stub_cluster, caplog):
        session = _session(["wazuh:read", "wazuh:write"])
        with caplog.at_level("WARNING", logger="wazuh_mcp.audit"):
            result = await handle_tools_call(
                {"name": "wazuh_block_ip", "arguments": {"ip_address": "10.0.0.9"}}, session
            )
        assert result["isError"] is False
        # Reached the client.
        assert any(name == "block_ip" for name, _ in _stub_cluster.calls)
        # Audit record for the destructive op was emitted with the tool name.
        audit_lines = [r.getMessage() for r in caplog.records if r.name == "wazuh_mcp.audit"]
        assert any("wazuh_block_ip" in line for line in audit_lines), audit_lines


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


@pytest.mark.asyncio
@pytest.mark.parametrize("scopes", [None, [], ["wazuh:write"], ["unknown"]])
async def test_read_access_denied_before_registry(monkeypatch, scopes):
    class Registry:
        def get(self, cluster_id):
            pytest.fail("denied request reached registry")

        multi_cluster = False

    monkeypatch.setattr(mcp_server.state, "cluster_registry", Registry())
    session = _session(scopes) if scopes is not None else MCPSession("missing", None)
    handlers = mcp_server.handlers
    assert await handlers.handle_resources_list({}, session) == {"resources": []}
    assert await handlers.handle_resources_templates_list({}, session) == {"resourceTemplates": []}
    listed = await mcp_server.tool_catalog.handle_tools_list({}, session)
    assert all(t["name"] in WRITE_SCOPE_TOOLS for t in listed["tools"])
    result = await handle_tools_call({"name": "get_wazuh_alerts", "arguments": {"cluster_id": "bad"}}, session)
    assert result["isError"] and "Insufficient permissions" in result["content"][0]["text"]
    for uri in ("wazuh://manager/info", "wazuh://agents/1/info", "wazuh://nope", "bad", None):
        request = mcp_server.jsonrpc.MCPRequest(jsonrpc="2.0", id=1, method="resources/read", params={"uri": uri})
        response = await mcp_server.dispatch.process_mcp_request(request, session)
        assert response.error["code"] == -32002
        assert response.error["message"] == "Resource not found"


@pytest.mark.asyncio
@pytest.mark.parametrize("scopes", [["wazuh:read"], ["wazuh:read", "wazuh:write"]])
async def test_read_discovery_and_unknown_uri(scopes):
    session = _session(scopes)
    assert len((await mcp_server.handlers.handle_resources_list({}, session))["resources"]) == 6
    assert len((await mcp_server.handlers.handle_resources_templates_list({}, session))["resourceTemplates"]) == 3
    listed = await mcp_server.tool_catalog.handle_tools_list({}, session)
    assert any(t["name"] == "get_wazuh_alerts" for t in listed["tools"])
    request = mcp_server.jsonrpc.MCPRequest(jsonrpc="2.0", id=1, method="resources/read", params={"uri": "wazuh://nope"})
    assert (await mcp_server.dispatch.process_mcp_request(request, session)).error["code"] == -32002


@pytest.mark.asyncio
@pytest.mark.parametrize("modern", [False, True])
async def test_http_reads_use_current_grant(monkeypatch, modern, _stub_cluster):
    from unittest.mock import AsyncMock

    import httpx

    token = _session(["wazuh:read"])._auth_token
    token.owner = {"version": 1, "family": "api_key", "subject": "tester"}
    monkeypatch.setattr(mcp_server.http_security, "verify_authentication", AsyncMock(return_value=token))
    _stub_cluster.get_manager_info = AsyncMock(return_value={"data": {}})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=mcp_server.app), base_url="http://testserver") as client:
        headers = {}
        if not modern:
            init = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}})
            headers["MCP-Session-Id"] = init.headers["MCP-Session-Id"]

        async def call(method, params=None):
            params = dict(params or {})
            local_headers = dict(headers)
            if modern:
                params["_meta"] = {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1"}, "io.modelcontextprotocol/clientCapabilities": {}}
                local_headers.update({"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": method})
                if method == "resources/read":
                    local_headers["Mcp-Name"] = params["uri"]
            response = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": method, "params": params}, headers=local_headers)
            assert response.status_code == 200
            return response.json()

        allowed = await call("resources/read", {"uri": "wazuh://manager/info"})
        assert "contents" in allowed["result"]
        token.scopes = []
        denied = await call("resources/read", {"uri": "wazuh://manager/info"})
        assert denied["error"]["code"] == -32002
        listed = await call("resources/list")
        assert listed["result"]["resources"] == []
        if modern:
            assert listed["result"]["resultType"] == "complete"
        assert _stub_cluster.get_manager_info.await_count == 1
