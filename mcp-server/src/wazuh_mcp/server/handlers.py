"""Handlers for the non-tool MCP methods: initialize, ping, logging, prompts, resources, completion."""

import json
import logging
import re as _re
from typing import Any, Dict

from wazuh_mcp import __version__
from wazuh_mcp.security import validate_agent_id

from . import state
from .constants import (
    CACHEABLE_METHOD_TTLS,
    LEGACY_PROTOCOL_VERSIONS,
    MCP_PROTOCOL_VERSION,
    META_SERVER_INFO,
    SERVER_INSTRUCTIONS,
    SUPPORTED_PROTOCOL_VERSIONS,
)
from .output import _sanitize_output_text
from .sessions import MCPSession, _bounded_capabilities, _bounded_client_info

logger = logging.getLogger(__name__)


# MCP Protocol Handlers


async def handle_initialize(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """Handle MCP initialize method per MCP specification."""
    client_protocol_version = params.get("protocolVersion", "2025-03-26")
    capabilities = params.get("capabilities", {})
    client_info = params.get("clientInfo", {})

    # Store a bounded copy of the client information (see _bounded_client_info)
    session.capabilities = _bounded_capabilities(capabilities)
    session.client_info = _bounded_client_info(client_info)

    # Protocol version negotiation per MCP spec.
    # Only legacy revisions can be negotiated here - modern revisions (2026-07-28+)
    # have no initialize handshake, so counter-offer the latest legacy revision instead.
    if client_protocol_version in LEGACY_PROTOCOL_VERSIONS:
        negotiated_version = client_protocol_version
    else:
        # Default to latest legacy version
        negotiated_version = MCP_PROTOCOL_VERSION

    # Server capabilities - only declare what we actually implement. listChanged is
    # False for all: the tool/prompt/resource lists are static and we never emit a
    # notifications/*/list_changed, so claiming true would make a spec-compliant client
    # wait for updates that never come. completions/complete IS implemented, so advertise it.
    server_capabilities = {
        "logging": {},
        "prompts": {"listChanged": False},
        "resources": {"subscribe": False, "listChanged": False},
        "tools": {"listChanged": False},
        "completions": {},
    }

    # Server information
    server_info = {
        "name": "Wazuh MCP",
        "version": __version__,
        "vendor": "Leon Elliott Fuller",
        "description": "MCP-compliant remote server for Wazuh SIEM integration",
    }

    # Mark session as awaiting initialized notification (cap to prevent unbounded growth)
    if len(state._initialized_sessions) > 10000:
        # Evict oldest entries in O(1) per removal
        for _ in range(len(state._initialized_sessions) - 5000):
            state._initialized_sessions.popitem(last=False)
    state._initialized_sessions[session.session_id] = False

    return {
        "protocolVersion": negotiated_version,
        "capabilities": server_capabilities,
        "serverInfo": server_info,
        "instructions": SERVER_INSTRUCTIONS,
    }


async def handle_initialized_notification(params: Dict[str, Any], session: MCPSession) -> None:
    """Handle notifications/initialized - marks session as fully initialized."""
    state._initialized_sessions[session.session_id] = True
    logger.info(f"Session {session.session_id} fully initialized")


async def handle_ping(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle ping method per MCP specification.
    MUST respond immediately with empty result.
    """
    return {}


async def handle_server_discover(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle server/discover per the 2026-07-28 revision: advertise supported protocol
    versions, capabilities, and identity. Servers MUST implement this RPC; clients MAY
    call it before any other request (or use it as a backward-compatibility probe).
    """
    return {
        "resultType": "complete",
        "supportedVersions": SUPPORTED_PROTOCOL_VERSIONS,
        "capabilities": {
            "tools": {},
            "prompts": {},
            "resources": {},
            "completions": {},
        },
        "instructions": SERVER_INSTRUCTIONS,
        "ttlMs": CACHEABLE_METHOD_TTLS["server/discover"],
        "cacheScope": "private",
        "_meta": {META_SERVER_INFO: {"name": "Wazuh MCP", "version": __version__}},
    }


async def handle_logging_set_level(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle logging/setLevel method per MCP specification.
    Sets the minimum log level for server log notifications.
    """
    level = params.get("level", "info")
    if not isinstance(level, str):
        raise ValueError("level must be a string")

    valid_levels = ["debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"]
    if level.lower() not in valid_levels:
        raise ValueError(f"Invalid log level: {level}. Must be one of: {', '.join(valid_levels)}")

    state._current_log_level = level.lower()
    logger.info(f"Log level set to: {state._current_log_level}")

    return {}


async def handle_prompts_list(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle prompts/list method per MCP specification.
    Returns list of available prompts with pagination support.
    """
    _cursor = params.get("cursor")  # Reserved for future pagination

    # Wazuh security prompts
    prompts = [
        {
            "name": "security_investigation",
            "description": "Investigate a security incident using Wazuh data",
            "arguments": [
                {
                    "name": "incident_type",
                    "description": "Type of incident to investigate (e.g., malware, intrusion, data_breach)",
                    "required": True,
                },
                {
                    "name": "time_range",
                    "description": "Time range for investigation (e.g., 1h, 24h, 7d)",
                    "required": False,
                },
            ],
        },
        {
            "name": "threat_hunt",
            "description": "Perform proactive threat hunting across Wazuh agents",
            "arguments": [
                {"name": "hunt_hypothesis", "description": "The threat hypothesis to investigate", "required": True},
                {
                    "name": "agent_scope",
                    "description": "Scope of agents to hunt (all, critical, specific)",
                    "required": False,
                },
            ],
        },
        {
            "name": "compliance_audit",
            "description": "Generate compliance audit report for a specific framework",
            "arguments": [
                {
                    "name": "framework",
                    "description": "Compliance framework (PCI-DSS, HIPAA, SOX, GDPR, NIST)",
                    "required": True,
                },
                {
                    "name": "include_remediation",
                    "description": "Include remediation recommendations",
                    "required": False,
                },
            ],
        },
        {
            "name": "vulnerability_assessment",
            "description": "Assess vulnerabilities across the environment",
            "arguments": [
                {
                    "name": "severity_threshold",
                    "description": "Minimum severity to include (low, medium, high, critical)",
                    "required": False,
                },
                {"name": "agent_id", "description": "Specific agent to assess (optional)", "required": False},
            ],
        },
        {
            "name": "iso27001_assessment",
            "description": (
                "Guided ISO 27001:2022 compliance assessment. Walks through dashboard overview, "
                "domain drill-down, gap analysis, and recommendations using live Wazuh data."
            ),
            "arguments": [
                {
                    "name": "scope",
                    "description": "Assessment scope: 'full' (all domains), 'technological' (A.8 only), or 'specific_control' (single control)",
                    "required": False,
                },
                {
                    "name": "control_id",
                    "description": "Specific control to assess when scope='specific_control' (e.g. 'A.8.8')",
                    "required": False,
                },
                {
                    "name": "agent_id",
                    "description": "Scope assessment to a specific Wazuh agent (optional)",
                    "required": False,
                },
            ],
        },
    ]

    # Simple pagination (no cursor means start from beginning)
    # In production, implement proper cursor-based pagination
    return {"prompts": prompts}  # No more results


async def handle_prompts_get(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle prompts/get method per MCP specification.
    Returns prompt content with substituted arguments.
    """
    name = params.get("name")
    arguments = params.get("arguments") or {}

    if not name or not isinstance(name, str):
        raise ValueError("Prompt name is required")
    if not isinstance(arguments, dict):
        raise ValueError("arguments must be an object")

    # Prompt templates
    prompt_templates = {
        "security_investigation": {
            "description": "Security incident investigation workflow",
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": f"Investigate a {arguments.get('incident_type', 'security')} incident. "
                        f"Time range: {arguments.get('time_range', '24h')}. "
                        f"Steps:\n"
                        f"1. Use get_wazuh_alerts to retrieve relevant alerts\n"
                        f"2. Use analyze_alert_patterns to identify patterns\n"
                        f"3. Use search_security_events to find related events\n"
                        f"4. Use check_agent_health for affected agents\n"
                        f"5. Use perform_risk_assessment to evaluate impact",
                    },
                }
            ],
        },
        "threat_hunt": {
            "description": "Proactive threat hunting workflow",
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": f"Hunt for threats based on hypothesis: {arguments.get('hunt_hypothesis', 'suspicious activity')}. "
                        f"Agent scope: {arguments.get('agent_scope', 'all')}. "
                        f"Workflow:\n"
                        f"1. Use get_wazuh_agents to identify target agents\n"
                        f"2. Use search_security_events with relevant patterns\n"
                        f"3. Use analyze_security_threat for any indicators found\n"
                        f"4. Use check_ioc_reputation for suspicious IPs/domains\n"
                        f"5. Use generate_security_report to document findings",
                    },
                }
            ],
        },
        "compliance_audit": {
            "description": "Compliance audit workflow",
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": f"Perform {arguments.get('framework', 'PCI-DSS')} compliance audit. "
                        f"Include remediation: {arguments.get('include_remediation', 'true')}. "
                        f"Steps:\n"
                        f"1. Use run_compliance_check with the specified framework\n"
                        f"2. Use get_wazuh_agents to assess agent coverage\n"
                        f"3. Use get_wazuh_vulnerabilities to identify security gaps\n"
                        f"4. Use generate_security_report for compliance documentation",
                    },
                }
            ],
        },
        "vulnerability_assessment": {
            "description": "Vulnerability assessment workflow",
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": f"Assess vulnerabilities with severity >= {arguments.get('severity_threshold', 'medium')}. "
                        f"Agent: {arguments.get('agent_id', 'all')}. "
                        f"Workflow:\n"
                        f"1. Use get_wazuh_vulnerabilities to retrieve vulnerability data\n"
                        f"2. Use get_wazuh_critical_vulnerabilities for highest priority items\n"
                        f"3. Use get_wazuh_vulnerability_summary for statistics\n"
                        f"4. Use perform_risk_assessment to evaluate overall risk",
                    },
                }
            ],
        },
    }

    scope = arguments.get("scope", "full")
    control_id = arguments.get("control_id", "A.8")
    agent_id_arg = arguments.get("agent_id", "all agents")

    prompt_templates["iso27001_assessment"] = {
        "description": "ISO 27001:2022 guided compliance assessment",
        "messages": [
            {
                "role": "user",
                "content": {
                    "type": "text",
                    "text": (
                        f"Perform an ISO 27001:2022 compliance assessment. "
                        f"Scope: {scope}. "
                        f"{'Control: ' + control_id + '. ' if scope == 'specific_control' else ''}"
                        f"Agent scope: {agent_id_arg}.\n\n"
                        f"Follow this workflow:\n"
                        + (
                            "1. Use get_iso27001_dashboard to get the overall compliance posture across all Annex A domains.\n"
                            "2. For each domain with a score below 70 or marked 'no_data', use get_iso27001_control_detail to investigate.\n"
                            "3. For any failing SCA policies found, use get_sca_policy_checks to get check-level detail and remediation steps.\n"
                            "4. Use get_iso27001_alerts with time_range='24h' to see which controls have active security events.\n"
                            "5. Use get_iso27001_gap_analysis to get a prioritised list of gaps with remediation hints.\n"
                            "6. Summarise findings by domain (A.5/A.6/A.7/A.8), highlight critical gaps, and provide actionable recommendations.\n"
                            if scope == "full"
                            else (
                                "1. Use get_iso27001_control_detail with control_id='A.8' to assess all Technological controls.\n"
                                "2. For failing SCA policies, use get_sca_policy_checks to drill into individual checks.\n"
                                "3. Use get_iso27001_alerts with time_range='24h' to see alert activity for A.8 controls.\n"
                                "4. Use get_iso27001_gap_analysis to identify the highest-priority gaps in A.8.\n"
                                "5. Provide remediation recommendations prioritised by risk.\n"
                                if scope == "technological"
                                else (
                                    f"1. Use get_iso27001_control_detail with control_id='{control_id}' to get all Wazuh evidence.\n"
                                    "2. If the control uses SCA data, use get_sca_policy_checks to get check-level detail.\n"
                                    "3. Use get_iso27001_alerts to see recent alert activity relevant to this control.\n"
                                    "4. Provide a focused assessment of compliance status and specific remediation steps.\n"
                                )
                            )
                        )
                    ),
                },
            }
        ],
    }

    if name not in prompt_templates:
        raise ValueError(f"Unknown prompt: {name}")

    return prompt_templates[name]


async def handle_resources_list(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle resources/list method per MCP specification.
    Returns list of available resources with pagination support.
    """
    _cursor = params.get("cursor")  # Reserved for future pagination

    # Wazuh resources
    resources = [
        {
            "uri": "wazuh://manager/info",
            "name": "Wazuh Manager Information",
            "description": "Current Wazuh manager status and configuration",
            "mimeType": "application/json",
        },
        {
            "uri": "wazuh://agents/summary",
            "name": "Agents Summary",
            "description": "Summary of all Wazuh agents and their status",
            "mimeType": "application/json",
        },
        {
            "uri": "wazuh://alerts/recent",
            "name": "Recent Alerts",
            "description": "Most recent security alerts from Wazuh",
            "mimeType": "application/json",
        },
        {
            "uri": "wazuh://cluster/status",
            "name": "Cluster Status",
            "description": "Wazuh cluster health and node information",
            "mimeType": "application/json",
        },
        {
            "uri": "wazuh://rules/summary",
            "name": "Rules Summary",
            "description": "Summary of active Wazuh detection rules",
            "mimeType": "application/json",
        },
        {
            "uri": "wazuh://vulnerabilities/critical",
            "name": "Critical Vulnerabilities",
            "description": "Critical vulnerabilities from Wazuh Indexer (requires 4.8.0+)",
            "mimeType": "application/json",
        },
    ]

    return {"resources": resources}


class ResourceNotFound(ValueError):
    """resources/read for a URI this server doesn't serve (-32002 per the MCP spec)."""


_AGENT_RESOURCE = _re.compile(r"^agents/([0-9]{1,5})/(info|alerts|vulnerabilities)$")


async def handle_resources_read(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle resources/read method per MCP specification.
    Returns resource content.
    """
    uri = params.get("uri")

    if not uri or not isinstance(uri, str):
        raise ValueError("Resource URI is required")

    # Parse Wazuh resource URI
    if not uri.startswith("wazuh://"):
        raise ResourceNotFound(f"Resource not found: {uri} (expected a wazuh:// URI)")

    resource_path = uri[8:]  # Remove "wazuh://"
    agent_match = _AGENT_RESOURCE.match(resource_path)

    try:
        if agent_match:
            # The three templates advertised by resources/templates/list
            agent_id = validate_agent_id(agent_match.group(1), required=True)
            kind = agent_match.group(2)
            if kind == "info":
                data = await state.wazuh_client.get_agents(agent_id=agent_id)
            elif kind == "alerts":
                data = await state.wazuh_client.get_alerts(limit=50, agent_id=agent_id)
            else:
                data = await state.wazuh_client.get_vulnerabilities(agent_id=agent_id, limit=100)
        elif resource_path == "manager/info":
            data = await state.wazuh_client.get_manager_info()
        elif resource_path == "agents/summary":
            data = await state.wazuh_client.get_running_agents()
        elif resource_path == "alerts/recent":
            data = await state.wazuh_client.get_alerts(limit=50)
        elif resource_path == "cluster/status":
            data = await state.wazuh_client.get_cluster_health()
        elif resource_path == "rules/summary":
            data = await state.wazuh_client.get_rules_summary()
        elif resource_path == "vulnerabilities/critical":
            data = await state.wazuh_client.get_critical_vulnerabilities(limit=50)
        else:
            raise ResourceNotFound(f"Resource not found: {uri}")
    except ResourceNotFound:
        raise
    except Exception as e:
        # A backend failure is an internal error, not bad params - and its text can carry
        # internal hosts/usernames, so it goes to the log, not the client.
        logger.error(f"Error reading resource {uri}: {e}")
        raise RuntimeError("Failed to read resource") from e

    text = _sanitize_output_text(json.dumps(data, indent=2, default=str))
    return {"contents": [{"uri": uri, "mimeType": "application/json", "text": text}]}


async def handle_resources_templates_list(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle resources/templates/list method per MCP specification.
    Returns list of resource URI templates.
    """
    templates = [
        {
            "uriTemplate": "wazuh://agents/{agent_id}/info",
            "name": "Agent Information",
            "description": "Detailed information for a specific agent",
            "mimeType": "application/json",
        },
        {
            "uriTemplate": "wazuh://agents/{agent_id}/alerts",
            "name": "Agent Alerts",
            "description": "Recent alerts for a specific agent",
            "mimeType": "application/json",
        },
        {
            "uriTemplate": "wazuh://agents/{agent_id}/vulnerabilities",
            "name": "Agent Vulnerabilities",
            "description": "Vulnerabilities for a specific agent",
            "mimeType": "application/json",
        },
    ]

    return {"resourceTemplates": templates}


async def handle_completion_complete(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle completion/complete method per MCP specification.
    Returns argument completion suggestions.
    """
    ref = params.get("ref") or {}
    argument = params.get("argument") or {}
    if not isinstance(ref, dict) or not isinstance(argument, dict):
        raise ValueError("ref and argument must be objects")
    if not isinstance(argument.get("value", ""), str) or not isinstance(argument.get("name", ""), str):
        raise ValueError("argument name and value must be strings")

    ref_type = ref.get("type")
    # Prompt refs identify by `name`; resource refs identify by `uri` (per MCP spec).
    # Reading only `name` left ref_name None for a ref/resource, so ref_name.lower()
    # below raised AttributeError -> -32603. Coerce to a safe string.
    ref_name = ref.get("name") or ref.get("uri") or ""
    if not isinstance(ref_name, str):
        raise ValueError("ref.name / ref.uri must be a string")
    arg_name = argument.get("name", "")
    arg_value = argument.get("value", "")

    completions = []

    # Provide completions based on context
    if ref_type == "ref/prompt":
        if arg_name == "incident_type":
            completions = ["malware", "intrusion", "data_breach", "ransomware", "phishing", "insider_threat"]
        elif arg_name == "time_range":
            completions = ["1h", "6h", "24h", "7d", "30d"]
        elif arg_name == "framework":
            completions = ["PCI-DSS", "HIPAA", "SOX", "GDPR", "NIST"]
        elif arg_name == "severity_threshold":
            completions = ["low", "medium", "high", "critical"]
        elif arg_name == "agent_scope":
            completions = ["all", "critical", "specific"]

    elif ref_type == "ref/resource":
        if "agent" in ref_name.lower():
            # Could fetch actual agent IDs here
            completions = ["001", "002", "003", "004", "005"]

    # Filter by current value
    if arg_value:
        completions = [c for c in completions if c.lower().startswith(arg_value.lower())]

    return {
        "completion": {
            "values": completions[:100],  # Max 100 per spec
            "total": len(completions),
            "hasMore": len(completions) > 100,
        }
    }


# Notification handlers (don't return responses)
async def handle_cancelled_notification(params: Dict[str, Any], session: MCPSession) -> None:
    """Handle notifications/cancelled - acknowledge cancellation request."""
    request_id = params.get("requestId")
    reason = params.get("reason", "Unknown")
    logger.debug(f"Request {request_id} cancelled: {reason}")
