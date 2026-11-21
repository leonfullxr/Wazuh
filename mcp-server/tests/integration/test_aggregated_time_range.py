"""get_alerts_aggregated accepts the time_range shorthand the other alert tools use."""

from datetime import datetime, timezone

import pytest

from wazuh_mcp import server
from wazuh_mcp.auth import AuthToken
from wazuh_mcp.clusters import ClusterRegistry
from wazuh_mcp.server.sessions import MCPSession
from wazuh_mcp.server.tool_calls import handle_tools_call


def _session() -> MCPSession:
    session = MCPSession("agg", None)
    session._auth_token = AuthToken(
        token="t", api_key_id="tester", created_at=datetime.now(timezone.utc), scopes=["wazuh:read"]
    )
    return session


class _Client:
    def __init__(self):
        self.calls = []

    async def get_alerts_aggregated(self, **kwargs):
        self.calls.append(kwargs)
        return {"data": {"total_alerts": 0, "top_rules": [], "by_level": [], "top_agents": []}}


@pytest.mark.asyncio
async def test_time_range_becomes_date_math(monkeypatch):
    client = _Client()
    monkeypatch.setattr(server.state, "cluster_registry", ClusterRegistry({"default": client}, "default", False))
    result = await handle_tools_call(
        {"name": "get_alerts_aggregated", "arguments": {"time_range": "7d"}}, _session()
    )
    assert result["isError"] is False
    assert client.calls == [
        {"timestamp_start": "now-7d", "timestamp_end": "now", "top_rules": 50, "top_agents": 50}
    ]


@pytest.mark.asyncio
async def test_time_range_and_timestamp_start_conflict(monkeypatch):
    client = _Client()
    monkeypatch.setattr(server.state, "cluster_registry", ClusterRegistry({"default": client}, "default", False))
    result = await handle_tools_call(
        {
            "name": "get_alerts_aggregated",
            "arguments": {"time_range": "24h", "timestamp_start": "now-1h"},
        },
        _session(),
    )
    assert result["isError"] is True
    assert "timestamp_start" in result["content"][0]["text"]
    assert client.calls == []


@pytest.mark.asyncio
async def test_omitted_window_stays_the_default(monkeypatch):
    client = _Client()
    monkeypatch.setattr(server.state, "cluster_registry", ClusterRegistry({"default": client}, "default", False))
    result = await handle_tools_call({"name": "get_alerts_aggregated", "arguments": {}}, _session())
    assert result["isError"] is False
    assert client.calls[0]["timestamp_start"] == "now-24h"
