"""Tool descriptions have to match what the handler actually returns."""

from datetime import datetime, timezone

import pytest

from wazuh_mcp.auth import AuthToken
from wazuh_mcp.server.product_tools import catalog
from wazuh_mcp.server.sessions import MCPSession
from wazuh_mcp.server.tool_catalog import handle_tools_list


def _session() -> MCPSession:
    session = MCPSession("descriptions", None)
    session._auth_token = AuthToken(
        token="t", api_key_id="tester", created_at=datetime.now(timezone.utc), scopes=["wazuh:read", "wazuh:write"]
    )
    return session


@pytest.mark.asyncio
async def test_builtin_descriptions_do_not_overclaim():
    listed = {tool["name"]: tool["description"] for tool in (await handle_tools_list({}, _session()))["tools"]}
    assert "not a compliance certification" in listed["run_compliance_check"]
    assert "not_assessable" in listed["run_compliance_check"]
    assert "not anomaly detection" in listed["analyze_alert_patterns"]
    assert "effectiveness" not in listed["get_wazuh_rules_summary"].lower()
    assert "Not a fleet" in listed["get_wazuh_statistics"]
    assert "Not an agent inventory" in listed["get_wazuh_weekly_stats"]


def test_investigation_descriptions_state_the_window_and_the_expiry():
    tools = {tool["name"]: tool for tool in catalog({})}
    timeline = tools["investigate_agent_timeline"]
    assert "24 hours" in timeline["description"]
    assert "ISO 8601" in timeline["inputSchema"]["properties"]["from"]["description"]
    evidence = tools["get_investigation_evidence"]["description"]
    assert "15 minutes" in evidence
    assert "unavailable" in evidence
