from types import SimpleNamespace

import pytest

from wazuh_mcp.server import handlers, state, timeline_viewer


@pytest.mark.asyncio
async def test_viewer_resource_with_forbidden_default(monkeypatch):
    from wazuh_mcp.server import cluster_policy

    monkeypatch.setattr(state, "investigation_config", object())
    monkeypatch.setattr(state.config, "ENABLED_TOOLS", {"investigate_agent_timeline", "get_investigation_evidence"})
    monkeypatch.setattr(state, "cluster_registry", SimpleNamespace(cluster_ids=["default", "allowed"]))
    monkeypatch.setattr(cluster_policy, "authorize_cluster", lambda token, cluster, scope: cluster == "allowed")
    session = SimpleNamespace(_auth_token=SimpleNamespace(has_scope=lambda scope: scope == "wazuh:read"))
    listed = await handlers.handle_resources_list({}, session)
    assert [resource["uri"] for resource in listed["resources"]] == [timeline_viewer.URI]
    result = await handlers.handle_resources_read({"uri": timeline_viewer.URI}, session)
    content = result["contents"][0]
    assert content["mimeType"] == "text/html;profile=mcp-app"
    assert "connect-src 'none'" in content["text"]
    assert "'unsafe-inline'" not in content["text"]
    assert 'role="listbox"' in content["text"]
    assert "ArrowDown" in content["text"]
    assert "dateTime" in content["text"]
    assert "Source Code Pro" in content["text"]
    monkeypatch.setattr(cluster_policy, "authorize_cluster", lambda token, cluster, scope: False)
    assert (await handlers.handle_resources_list({}, session))["resources"] == []
    with pytest.raises(handlers.ResourceNotFound):
        await handlers.handle_resources_read({"uri": timeline_viewer.URI}, session)


@pytest.mark.asyncio
async def test_viewer_denied_without_read_scope(monkeypatch):
    monkeypatch.setattr(state, "investigation_config", object())
    session = SimpleNamespace(_auth_token=SimpleNamespace(has_scope=lambda scope: False))
    with pytest.raises(handlers.ResourceNotFound):
        await handlers.handle_resources_read({"uri": timeline_viewer.URI}, session)
    with pytest.raises(handlers.ResourceNotFound):
        await handlers.handle_resources_read({}, session)
