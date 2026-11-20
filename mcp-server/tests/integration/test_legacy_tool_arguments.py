from datetime import datetime, timezone

import pytest

from wazuh_mcp.auth import AuthToken
from wazuh_mcp.clusters import ClusterRegistry
from wazuh_mcp.server import state, tool_policy
from wazuh_mcp.server.sessions import MCPSession
from wazuh_mcp.server.tool_calls import handle_tools_call


class Client:
    def __init__(self):
        self.calls = []

    async def get_alerts(self, **kwargs):
        self.calls.append(("alerts", kwargs))
        return {"data": {"affected_items": []}}

    async def get_vulnerabilities(self, **kwargs):
        self.calls.append(("vulnerabilities", kwargs))
        return {"data": {"affected_items": []}}

    async def block_ip(self, *args, **kwargs):
        self.calls.append(("block", {"args": args, **kwargs}))
        return {"data": {"affected_items": []}}


@pytest.fixture
def setup(monkeypatch):
    client = Client()
    monkeypatch.setattr(state, "cluster_registry", ClusterRegistry({"default": client}, "default", False))
    monkeypatch.setattr(state, "cluster_policy", None)
    monkeypatch.setattr(state.config, "TOOL_PROFILE", None)
    session = MCPSession("test")
    session._auth_token = AuthToken("token", "key", datetime.now(timezone.utc), scopes=["wazuh:read", "wazuh:write"])
    return client, session


@pytest.mark.asyncio
async def test_decimal_limit_and_string_boolean_are_normalized(setup):
    client, session = setup
    result = await handle_tools_call({"name": "get_wazuh_alerts", "arguments": {"limit": "12", "compact": "false"}}, session)
    assert not result.get("isError")
    assert client.calls[0][1]["limit"] == 12
    assert "Wazuh Alerts" in result["content"][0]["text"]


@pytest.mark.asyncio
async def test_severity_case_and_optional_null_are_normalized(setup):
    client, session = setup
    result = await handle_tools_call({"name": "get_wazuh_vulnerabilities", "arguments": {"severity": "HIGH", "agent_id": None, "limit": None}}, session)
    assert not result.get("isError")
    assert client.calls[0][1]["severity"] == "high"
    assert client.calls[0][1]["agent_id"] is None
    assert client.calls[0][1]["limit"] == 100


@pytest.mark.asyncio
async def test_single_rule_group_is_forwarded_as_list(setup):
    client, session = setup
    result = await handle_tools_call({"name": "get_wazuh_alerts", "arguments": {"rule_groups": "firewall"}}, session)
    assert not result.get("isError")
    assert client.calls[0][1]["rule_groups"] == ["firewall"]


@pytest.mark.asyncio
async def test_malformed_inputs_and_unknown_fields_are_refused(setup):
    client, session = setup
    for arguments in ({"limit": "1.5"}, {"compact": "perhaps"}, {"severity": "extreme"}, {"invented": "secret"}):
        result = await handle_tools_call({"name": "get_wazuh_alerts", "arguments": arguments}, session)
        assert result["isError"]
        assert "secret" not in str(result)
    assert not client.calls


@pytest.mark.asyncio
async def test_confirmation_and_scope_cannot_be_bypassed_by_normalization(setup, monkeypatch):
    client, session = setup
    monkeypatch.setattr(tool_policy, "_require_action_confirmation", lambda: True)
    args = {"ip_address": "192.0.2.1", "confirm": "false"}
    result = await handle_tools_call({"name": "wazuh_block_ip", "arguments": args}, session)
    assert result["isError"] and not client.calls
    session._auth_token.scopes = ["wazuh:read"]
    result = await handle_tools_call({"name": "wazuh_block_ip", "arguments": {"ip_address": "192.0.2.1", "confirm": "yes"}}, session)
    assert result["isError"] and not client.calls
    session._auth_token.scopes.append("wazuh:write")
    result = await handle_tools_call({"name": "wazuh_block_ip", "arguments": {"ip_address": "192.0.2.1", "confirm": "yes"}}, session)
    assert not result.get("isError") and len(client.calls) == 1
