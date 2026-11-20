import json
import time
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from wazuh_mcp.auth import AuthToken
from wazuh_mcp.clusters import ClusterRegistry
from wazuh_mcp.server import state
from wazuh_mcp.server.cluster_policy import authorize_cluster, load_policy


def token(owner, metadata=None, scopes=None):
    return AuthToken(
        "token",
        "principal",
        datetime.now(timezone.utc),
        scopes=scopes or ["wazuh:read", "wazuh:write"],
        owner=owner,
        metadata=metadata,
    )


@pytest.fixture
def policy(monkeypatch, tmp_path):
    registry = ClusterRegistry({"prod": object(), "stage": object()}, "prod", True)
    rules = [
        {"identity": {"type": "api_key", "id": "key-1"}, "cluster": "stage", "allow": ["wazuh:read", "wazuh:write"]},
        {
            "identity": {"type": "idp_group", "id": "analysts", "issuer": "https://issuer"},
            "cluster": "prod",
            "allow": ["wazuh:read"],
        },
        {
            "identity": {"type": "idp_group", "id": "blocked", "issuer": "https://issuer"},
            "cluster": "prod",
            "deny": ["wazuh:read"],
        },
    ]
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"rules": rules}))
    monkeypatch.setenv("WAZUH_CLUSTER_POLICY_FILE", str(path))
    monkeypatch.setattr(state, "cluster_registry", registry)
    monkeypatch.setattr(state, "cluster_policy", load_policy(registry))
    return path, registry


def test_key_policy_restricts_default_and_scope(policy):
    principal = token({"version": 1, "family": "api_key", "subject": "key-1"})
    assert not authorize_cluster(principal, None, "wazuh:read")
    assert authorize_cluster(principal, "stage", "wazuh:write")
    assert not authorize_cluster(principal, "unknown", "wazuh:read")
    principal.scopes = ["wazuh:read"]
    assert not authorize_cluster(principal, "stage", "wazuh:write")


def test_group_issuer_freshness_and_explicit_deny(policy):
    owner = {"family": "oauth", "subject_kind": "idp_user", "identity_issuer": "https://issuer"}
    principal = token(owner, {"groups": ["analysts"], "groups_at": time.time()})
    assert authorize_cluster(principal, "prod", "wazuh:read")
    principal.metadata["groups_at"] -= 901
    assert not authorize_cluster(principal, "prod", "wazuh:read")
    principal.metadata.update(groups=["analysts", "blocked"], groups_at=time.time())
    assert not authorize_cluster(principal, "prod", "wazuh:read")
    principal.metadata["groups"] = ["analysts"]
    owner["identity_issuer"] = "https://other"
    assert not authorize_cluster(principal, "prod", "wazuh:read")


def test_invalid_and_cross_cluster_configuration_fails_closed(policy):
    path, registry = policy
    path.write_text('{"rules": []}')
    with pytest.raises(ValueError):
        load_policy(registry)
    path.write_text(
        json.dumps(
            {"rules": [{"identity": {"type": "api_key", "id": "k"}, "cluster": "stage", "allow": ["wazuh:read"]}]}
        )
    )
    registry._clients["stage"] = SimpleNamespace(_indexer_client=SimpleNamespace(ccs_prefix="remote"))
    with pytest.raises(ValueError):
        load_policy(registry)


@pytest.mark.asyncio
async def test_denied_default_and_unknown_never_reach_backend_and_discovery_hides_topology(policy):
    from wazuh_mcp.server.handlers import ResourceNotFound, handle_resources_read
    from wazuh_mcp.server.sessions import MCPSession
    from wazuh_mcp.server.tool_calls import handle_tools_call
    from wazuh_mcp.server.tool_catalog import handle_tools_list

    session = MCPSession("session")
    session._auth_token = token({"version": 1, "family": "api_key", "subject": "key-1"})
    tools = await handle_tools_list({}, session)
    assert tools["tools"]
    assert all(
        "prod" not in t["inputSchema"].get("properties", {}).get("cluster_id", {}).get("description", "")
        for t in tools["tools"]
    )
    denied = await handle_tools_call({"name": "get_wazuh_agents", "arguments": {}}, session)
    unknown = await handle_tools_call({"name": "get_wazuh_agents", "arguments": {"cluster_id": "missing"}}, session)
    assert denied == unknown and denied["isError"]
    with pytest.raises(ResourceNotFound):
        await handle_resources_read({"uri": "wazuh://agents/summary"}, session)
    visible = await handle_tools_call({"name": "list_wazuh_clusters", "arguments": {}}, session)
    text = visible["content"][0]["text"]
    assert '"stage"' in text and '"prod"' not in text


@pytest.mark.asyncio
async def test_live_grant_revocation_changes_discovery_and_dispatch(policy, monkeypatch):
    from wazuh_mcp.server.cluster_policy import ClusterPolicy
    from wazuh_mcp.server.sessions import MCPSession
    from wazuh_mcp.server.tool_calls import handle_tools_call
    from wazuh_mcp.server.tool_catalog import handle_tools_list

    class Client:
        def __init__(self):
            self.calls = 0

        async def get_agents(self, **kwargs):
            self.calls += 1
            return {"data": {"affected_items": []}}

    client = Client()
    state.cluster_registry._clients["stage"] = client
    session = MCPSession("session")
    session._auth_token = token({"version": 1, "family": "api_key", "subject": "key-1"})
    response = await handle_tools_call({"name": "get_wazuh_agents", "arguments": {"cluster_id": "stage"}}, session)
    assert not response.get("isError") and client.calls == 1
    monkeypatch.setattr(state, "cluster_policy", ClusterPolicy(()))
    assert (await handle_tools_list({}, session))["tools"] == []
    response = await handle_tools_call({"name": "get_wazuh_agents", "arguments": {"cluster_id": "stage"}}, session)
    assert response["isError"] and client.calls == 1


def test_profile_indexer_capability_for_timeline_and_saved(policy, monkeypatch):
    from wazuh_mcp.server.cluster_policy import supports_tool

    monkeypatch.setattr(state.config, "TOOL_PROFILE", "analysis")
    registry = state.cluster_registry
    registry._clients["stage"] = SimpleNamespace(_indexer_client=object())
    assert supports_tool("stage", "investigate_agent_timeline")
    assert supports_tool("stage", "saved_investigation_example")
    assert not supports_tool("prod", "investigate_agent_timeline")
    assert not supports_tool("prod", "saved_investigation_example")
    assert not supports_tool("prod", "analyze_security_threat")
    assert supports_tool("stage", "analyze_security_threat")


@pytest.mark.asyncio
async def test_schema_is_not_derived_from_first_caller(policy, monkeypatch):
    from wazuh_mcp.server.sessions import MCPSession
    from wazuh_mcp.server.tool_calls import handle_tools_call
    from wazuh_mcp.server.tool_catalog import handle_tools_list

    class Client:
        calls = 0

        async def get_agents(self, **kwargs):
            self.calls += 1
            return {}

    client = Client()
    state.cluster_registry._clients["stage"] = client
    empty = MCPSession("empty")
    empty._auth_token = token({"version": 1, "family": "api_key", "subject": "wrong"})
    assert (await handle_tools_list({}, empty))["tools"] == []
    authorized = MCPSession("authorized")
    authorized._auth_token = token({"version": 1, "family": "api_key", "subject": "key-1"})
    result = await handle_tools_call(
        {"name": "get_wazuh_agents", "arguments": {"cluster_id": "stage", "bogus": 1}}, authorized
    )
    assert result["isError"] and client.calls == 0


@pytest.mark.asyncio
async def test_static_schema_rejects_invalid_types_limits_and_unknown_without_echo(policy):
    from wazuh_mcp.server.sessions import MCPSession
    from wazuh_mcp.server.tool_calls import handle_tools_call

    class Client:
        async def get_agents(self, **kwargs):
            pytest.fail("invalid request reached backend")

        async def get_alerts(self, **kwargs):
            pytest.fail("invalid request reached backend")

    state.cluster_registry._clients["stage"] = Client()
    session = MCPSession("test")
    session._auth_token = token({"version": 1, "family": "api_key", "subject": "key-1"})
    for args in (
        {"cluster_id": "stage", "limit": "not-an-integer"},
        {"cluster_id": "stage", "limit": -1},
        {"cluster_id": "stage", "secret-value-as-key": "secret-value"},
    ):
        result = await handle_tools_call({"name": "get_wazuh_alerts", "arguments": args}, session)
        assert result["isError"]
        assert "secret-value" not in str(result) and "not-an-integer" not in str(result)
