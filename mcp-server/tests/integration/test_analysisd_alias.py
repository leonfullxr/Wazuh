"""The analysisd stats tool keeps its old name as a deprecated alias."""

import json
from datetime import datetime, timezone

import pytest

from wazuh_mcp import server
from wazuh_mcp.auth import AuthToken
from wazuh_mcp.clusters import ClusterRegistry
from wazuh_mcp.server.sessions import MCPSession
from wazuh_mcp.server.tool_calls import handle_tools_call
from wazuh_mcp.server.tool_catalog import handle_tools_list
from wazuh_mcp.toolsets import TOOLSETS


def _session() -> MCPSession:
    session = MCPSession("analysisd", None)
    session._auth_token = AuthToken(
        token="t", api_key_id="tester", created_at=datetime.now(timezone.utc), scopes=["wazuh:read"]
    )
    return session


@pytest.mark.asyncio
async def test_both_names_call_analysisd_and_the_old_name_is_marked_deprecated(monkeypatch):
    calls = []

    class Client:
        async def get_log_collector_stats(self):
            calls.append("analysisd")
            return {"data": {"affected_items": [{"events_processed": 12, "alerts_written": 3}], "total_affected_items": 1, "total_failed_items": 0, "failed_items": []}, "error": 0}

    monkeypatch.setattr(server.state, "cluster_registry", ClusterRegistry({"default": Client()}, "default", False))
    names = ("get_wazuh_analysisd_stats", "get_wazuh_log_collector_stats")
    texts = []
    for name in names:
        result = await handle_tools_call({"name": name, "arguments": {}}, _session())
        texts.append(result["content"][0]["text"])
    assert calls == ["analysisd", "analysisd"]
    assert texts[0] == texts[1]
    assert texts[0].startswith("Analysisd Statistics:")
    body = json.loads(texts[0].split("\n", 1)[1])
    assert body == {"events_processed": 12, "alerts_written": 3}

    listed = {tool["name"]: tool["description"] for tool in (await handle_tools_list({}, _session()))["tools"]}
    assert "GET /manager/stats/analysisd" in listed["get_wazuh_analysisd_stats"]
    assert "logcollector" in listed["get_wazuh_analysisd_stats"]
    assert listed["get_wazuh_log_collector_stats"].startswith("Deprecated alias of get_wazuh_analysisd_stats.")
    assert "get_wazuh_analysisd_stats" in TOOLSETS["system"]
    assert "get_wazuh_log_collector_stats" in TOOLSETS["system"]
