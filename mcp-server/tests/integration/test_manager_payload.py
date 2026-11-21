"""Statistics, cluster and log tools drop the Manager envelope. Redaction stays."""

import json
from datetime import datetime, timezone

import pytest

from wazuh_mcp import server
from wazuh_mcp.api.wazuh_client import WazuhClient
from wazuh_mcp.auth import AuthToken
from wazuh_mcp.clusters import ClusterRegistry
from wazuh_mcp.server.sessions import MCPSession
from wazuh_mcp.server.tool_calls import handle_tools_call


def _session() -> MCPSession:
    session = MCPSession("payload", None)
    session._auth_token = AuthToken(
        token="t", api_key_id="tester", created_at=datetime.now(timezone.utc), scopes=["wazuh:read"]
    )
    return session


def _envelope(items, failed=0):
    return {
        "data": {
            "affected_items": items,
            "total_affected_items": len(items),
            "total_failed_items": failed,
            "failed_items": [{"id": "003"}] if failed else [],
        },
        "message": "All selected items were returned",
        "error": 0,
    }


@pytest.mark.asyncio
async def test_statistics_return_the_snapshot_and_logs_keep_redaction(monkeypatch):
    class Client:
        async def get_wazuh_statistics(self):
            return _envelope([{"totalAlerts": 12, "events": {"received": 2400}}])

        async def search_manager_logs(self, query, limit):
            return _envelope([
                {"timestamp": "2026-11-21T13:13:33Z", "level": "error", "description": "token=secretvalue"}
            ])

        async def get_cluster_nodes(self):
            return _envelope([{"name": "master"}, {"name": "worker-1"}], failed=1)

    monkeypatch.setattr(server.state, "cluster_registry", ClusterRegistry({"default": Client()}, "default", False))
    stats = await handle_tools_call({"name": "get_wazuh_statistics", "arguments": {}}, _session())
    body = json.loads(stats["content"][0]["text"].split("\n", 1)[1])
    assert body == {"totalAlerts": 12, "events": {"received": 2400}}
    assert "total_failed_items" not in stats["content"][0]["text"]

    logs = await handle_tools_call(
        {"name": "search_wazuh_manager_logs", "arguments": {"query": "token", "limit": 5}}, _session()
    )
    text = logs["content"][0]["text"]
    assert "secretvalue" not in text
    assert "token=[REDACTED]" in text
    assert "total_failed_items" not in text
    assert "All selected items" not in text

    nodes = await handle_tools_call({"name": "get_wazuh_cluster_nodes", "arguments": {}}, _session())
    parsed = json.loads(nodes["content"][0]["text"].split("\n", 1)[1])
    assert parsed["count"] == 2
    assert parsed["failed_count"] == 1
    assert parsed["items"][0]["name"] == "master"
    assert "message" not in parsed


def test_compliance_omits_agents_with_no_matching_policy():
    agent_data = [
        {
            "agent_id": "000",
            "agent_name": "manager",
            "sca_items": [],
        },
        {
            "agent_id": "001",
            "agent_name": "web-01",
            "sca_items": [
                {"policy_id": "pci_dss_v4", "name": "PCI DSS v4.0", "pass": 32, "fail": 18, "total_checks": 50, "score": 64}
            ],
        },
        {
            "agent_id": "002",
            "agent_name": "db-01",
            "sca_items": [
                {"policy_id": "cis_debian12", "name": "CIS Debian", "pass": 70, "fail": 16, "total_checks": 86, "score": 81}
            ],
        },
    ]
    out = WazuhClient._format_compliance_result("PCI-DSS", ["pci", "payment", "card"], agent_data)["data"]
    assert out["hardening_coverage_pct"] == 64
    assert out["agents_checked"] == 1
    assert out["agents_without_matching_policy"] == 2
    assert [row["agent_id"] for row in out["results"]] == ["001"]
    assert out["total_checks"] == 50
