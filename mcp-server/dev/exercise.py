#!/usr/bin/env python3
"""Call a running wazuh-mcp server the way an MCP client would.

Uses the official Python MCP SDK (Streamable HTTP). Auth is optional:

    python dev/exercise.py --url http://127.0.0.1:3000/mcp
    python dev/exercise.py --url http://127.0.0.1:3000/mcp --token "$TOKEN"

Prints one line per call: name, elapsed milliseconds, error flag, and a
shortened text preview. The full text of every result is written as JSON
to --transcript (default /tmp/wazuh-mcp-transcript.json).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

CALLS = [
    ("get_wazuh_alerts", {"limit": 5, "timestamp_start": "now-24h"}),
    ("get_wazuh_alert_summary", {"time_range": "24h", "group_by": "rule.id"}),
    ("analyze_alert_patterns", {"time_range": "24h", "min_frequency": 3}),
    ("get_alerts_aggregated", {"time_range": "24h"}),
    ("search_security_events", {"query": "sshd AND failed", "time_range": "24h", "limit": 5}),
    ("get_wazuh_agents", {"limit": 10}),
    ("get_wazuh_running_agents", {}),
    ("check_agent_health", {"agent_id": "001"}),
    ("check_agent_health", {"agent_id": "999"}),
    ("get_agent_processes", {"agent_id": "001", "limit": 10}),
    ("get_agent_ports", {"agent_id": "001", "limit": 10}),
    ("get_agent_configuration", {"agent_id": "001"}),
    ("get_wazuh_vulnerabilities", {"limit": 5}),
    ("get_wazuh_critical_vulnerabilities", {"limit": 5}),
    ("get_wazuh_vulnerability_summary", {}),
    ("analyze_security_threat", {"indicator": "203.0.113.50", "indicator_type": "ip"}),
    ("check_ioc_reputation", {"indicator": "203.0.113.50", "indicator_type": "ip"}),
    ("search_external_context", {"query": "CVE-2021-44228"}),
    ("perform_risk_assessment", {"agent_id": "001"}),
    ("get_top_security_threats", {"limit": 5, "time_range": "24h"}),
    ("generate_security_report", {"report_type": "daily"}),
    ("run_compliance_check", {"framework": "PCI-DSS"}),
    ("run_compliance_check", {"framework": "HIPAA"}),
    ("get_iso27001_dashboard", {}),
    ("get_iso27001_control_detail", {"control_id": "A.8.8"}),
    ("get_iso27001_gap_analysis", {}),
    ("get_iso27001_alerts", {"time_range": "24h"}),
    ("get_sca_policy_checks", {"agent_id": "001", "policy_id": "cis_ubuntu22-04"}),
    ("get_wazuh_statistics", {}),
    ("get_wazuh_weekly_stats", {}),
    ("get_wazuh_cluster_health", {}),
    ("get_wazuh_cluster_nodes", {}),
    ("get_wazuh_rules_summary", {}),
    ("get_wazuh_remoted_stats", {}),
    ("get_wazuh_analysisd_stats", {}),
    ("get_wazuh_log_collector_stats", {}),
    ("search_wazuh_manager_logs", {"query": "token", "limit": 5}),
    ("get_wazuh_manager_error_logs", {"limit": 5}),
    ("validate_wazuh_connection", {}),
    ("wazuh_block_ip", {"ip_address": "203.0.113.50", "agent_id": "001", "confirm": True}),
    ("wazuh_check_blocked_ip", {"ip_address": "198.51.100.23", "agent_id": "001"}),
    ("wazuh_isolate_host", {"agent_id": "002", "confirm": True}),
    ("wazuh_check_agent_isolation", {"agent_id": "002"}),
    ("wazuh_kill_process", {"agent_id": "001", "process_id": 4242, "confirm": True}),
    ("wazuh_check_process", {"agent_id": "001", "process_id": 4242}),
]


def _preview(text: str, limit: int = 180) -> str:
    flat = " ".join(text.split())
    return flat[:limit] + ("…" if len(flat) > limit else "")


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:3000/mcp")
    parser.add_argument("--token")
    parser.add_argument("--transcript", default="/tmp/wazuh-mcp-transcript.json")
    args = parser.parse_args()
    headers = {"Authorization": f"Bearer {args.token}"} if args.token else None
    http_client = create_mcp_http_client(headers=headers)
    transcript = []
    async with http_client:
        async with streamable_http_client(args.url, http_client=http_client) as (read, write):
            async with ClientSession(read, write) as session:
                started = time.perf_counter()
                init = await session.initialize()
                print(f"initialize {int((time.perf_counter()-started)*1000)}ms protocol={init.protocol_version} server={init.server_info.name}")
                tools = await session.list_tools()
                prompts = await session.list_prompts()
                resources = await session.list_resources()
                templates = await session.list_resource_templates()
                names = [tool.name for tool in tools.tools]
                print(f"tools={len(names)} prompts={len(prompts.prompts)} resources={len(resources.resources)} templates={len(templates.resource_templates)}")
                print("prompts:", ", ".join(item.name for item in prompts.prompts))
                print("resources:", ", ".join(str(item.uri) for item in resources.resources))
                missing_desc = [tool.name for tool in tools.tools if not (tool.description or "").strip()]
                if missing_desc:
                    print("tools missing descriptions:", ", ".join(missing_desc))
                for name, arguments in CALLS:
                    if name not in names and name != "check_agent_health":
                        # still try; the server should say why
                        pass
                    started = time.perf_counter()
                    try:
                        result = await session.call_tool(name, arguments)
                        elapsed = int((time.perf_counter() - started) * 1000)
                        text = "\n".join(block.text for block in result.content if getattr(block, "text", None))
                        is_error = bool(getattr(result, "is_error", None))
                    except Exception as exc:  # protocol or transport failure
                        elapsed = int((time.perf_counter() - started) * 1000)
                        text = f"{type(exc).__name__}: {exc}"
                        is_error = True
                        result = None
                    print(f"{'ERR' if is_error else 'ok '} {elapsed:5d}ms {name} { _preview(text)}")
                    transcript.append({
                        "tool": name,
                        "arguments": arguments,
                        "ms": elapsed,
                        "isError": is_error,
                        "text": text,
                        "structured": getattr(result, "structuredContent", None) if result else None,
                    })
    with open(args.transcript, "w", encoding="utf-8") as handle:
        json.dump(transcript, handle, indent=2, default=str)
    print(f"transcript {args.transcript}")


if __name__ == "__main__":
    asyncio.run(main())
