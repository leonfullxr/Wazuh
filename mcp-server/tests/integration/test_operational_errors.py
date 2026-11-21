"""Reviewed operational failures stay visible to the MCP client.

Unexpected exceptions stay generic (see test_output_redaction.py). Messages this
server wrote — a missing agent, a refused active response — are SafeToolError
and have to come back as the tool error text.
"""

from datetime import datetime, timezone

import pytest

from wazuh_mcp import server
from wazuh_mcp.api.wazuh_client import WazuhClient
from wazuh_mcp.auth import AuthToken
from wazuh_mcp.clusters import ClusterRegistry
from wazuh_mcp.config import WazuhConfig
from wazuh_mcp.security import SafeToolError
from wazuh_mcp.server.sessions import MCPSession
from wazuh_mcp.server.tool_calls import handle_tools_call


def _session() -> MCPSession:
    session = MCPSession("operational", None)
    session._auth_token = AuthToken(
        token="t",
        api_key_id="tester",
        created_at=datetime.now(timezone.utc),
        scopes=["wazuh:read", "wazuh:write"],
    )
    return session


def _client() -> WazuhClient:
    return WazuhClient(WazuhConfig(wazuh_host="10.9.9.9", wazuh_user="u", wazuh_pass="p"))


@pytest.mark.asyncio
async def test_missing_agent_is_reported_to_the_client(monkeypatch):
    client = _client()

    async def no_agent(method, endpoint, **kwargs):
        return {"data": {"affected_items": [], "total_affected_items": 0, "total_failed_items": 0, "failed_items": []}}

    client._request = no_agent
    monkeypatch.setattr(server.state, "cluster_registry", ClusterRegistry({"default": client}, "default", False))

    result = await handle_tools_call(
        {"name": "check_agent_health", "arguments": {"agent_id": "999"}}, _session()
    )

    assert result["isError"] is True
    assert result["content"][0]["text"] == "Agent 999 not found"


@pytest.mark.asyncio
async def test_block_without_a_target_names_the_requirement(monkeypatch):
    client = _client()
    monkeypatch.setattr(server.state, "cluster_registry", ClusterRegistry({"default": client}, "default", False))

    result = await handle_tools_call(
        {"name": "wazuh_block_ip", "arguments": {"ip_address": "203.0.113.50"}}, _session()
    )

    text = result["content"][0]["text"]
    assert result["isError"] is True
    assert "explicit target" in text
    assert "Tool execution failed" not in text


def test_operational_error_is_a_value_error_subclass():
    with pytest.raises(ValueError) as caught:
        from wazuh_mcp.api.wazuh_client import _operational_error

        _operational_error("Agent 001 not found")
    assert isinstance(caught.value, SafeToolError)
    assert str(caught.value) == "Agent 001 not found"
