"""The tools/list handler and the tool argument-name lookup."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from wazuh_mcp.toolsets import tool_annotations

from . import state, tool_policy
from .sessions import MCPSession
from .tool_policy import WRITE_SCOPE_TOOLS


async def handle_tools_list(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """Handle tools/list method - All 55 Wazuh Security Tools with pagination.
    Filters tools based on session token scopes."""
    _cursor = params.get("cursor")  # Reserved for future pagination
    tools = [
        # Alert Management Tools (5 tools)
        {
            "name": "get_wazuh_alerts",
            "description": "Retrieve Wazuh security alerts with optional filtering",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": state.config.MAX_ALERTS_PER_QUERY,
                        "default": min(100, state.config.MAX_ALERTS_PER_QUERY),
                    },
                    "rule_id": {"type": "string", "description": "Filter by specific rule ID"},
                    "level": {
                        "type": "string",
                        "description": "Minimum alert level: '10' (or '10+') returns level 10 and above",
                    },
                    "agent_id": {"type": "string", "description": "Filter by agent ID"},
                    "rule_groups": {
                        "type": "array",
                        "items": {"type": "string"},
                        "maxItems": 20,
                        "description": "Filter by rule group(s), e.g. ['authentication_failed', 'firewall'] - matches alerts belonging to ANY listed group",
                    },
                    "timestamp_start": {
                        "type": "string",
                        "description": "Start timestamp - ISO 8601 (YYYY-MM-DDTHH:MM:SSZ) or relative date math (e.g. now-24h, now-7d)",
                    },
                    "timestamp_end": {
                        "type": "string",
                        "description": "End timestamp - ISO 8601 (YYYY-MM-DDTHH:MM:SSZ) or relative date math (e.g. now, now-1h)",
                    },
                    "compact": {
                        "type": "boolean",
                        "default": True,
                        "description": "Return compact alerts with essential fields only (recommended to avoid token limits)",
                    },
                },
                "required": [],
            },
        },
        {
            "name": "get_wazuh_alert_summary",
            "description": "Get a summary of Wazuh alerts grouped by specified field",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "time_range": {
                        "type": "string",
                        "enum": ["1h", "6h", "12h", "1d", "24h", "7d", "30d"],
                        "default": "24h",
                    },
                    "group_by": {
                        "type": "string",
                        "enum": ["rule.level", "rule.id", "rule.groups", "agent.id", "agent.name"],
                        "default": "rule.level",
                    },
                },
                "required": [],
            },
        },
        {
            "name": "analyze_alert_patterns",
            "description": "Analyze alert patterns to identify trends and anomalies",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "time_range": {
                        "type": "string",
                        "enum": ["1h", "6h", "12h", "1d", "24h", "7d", "30d"],
                        "default": "24h",
                    },
                    "min_frequency": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 5},
                },
                "required": [],
            },
        },
        {
            "name": "get_alerts_aggregated",
            "description": "Summarize ALL alerts in a time window using indexer aggregations (no document limit). Returns the true total match count plus top rules, severity levels, and agents. Prefer this over get_wazuh_alerts/get_wazuh_alert_summary when the goal is a complete overview of a period rather than individual alert documents.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "timestamp_start": {
                        "type": "string",
                        "description": "Start of window - ISO 8601 or date math (e.g. now-24h, now-7d). Default now-24h.",
                        "default": "now-24h",
                    },
                    "timestamp_end": {
                        "type": "string",
                        "description": "End of window - ISO 8601 or date math (e.g. now). Default now.",
                        "default": "now",
                    },
                    "top_rules": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 500,
                        "default": 50,
                        "description": "How many top rules to return",
                    },
                    "top_agents": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 500,
                        "default": 50,
                        "description": "How many top agents to return",
                    },
                },
                "required": [],
            },
        },
        {
            "name": "search_security_events",
            "description": "Search for specific security events across all Wazuh data. Supports free-text search (simple query syntax: AND, OR, NOT, quoted phrases, trailing-* prefix; no leading wildcards, regex, or field:value) and structured field filters. All filters are combined with AND logic.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Free-text search query (AND, OR, NOT, quoted phrases, trailing-* prefix; leading wildcards, regex, and field:value are not supported - use the structured filter parameters instead). Searched across all alert fields via Elasticsearch simple_query_string.",
                    },
                    "time_range": {
                        "type": "string",
                        "enum": ["1h", "6h", "12h", "1d", "24h", "7d", "30d"],
                        "default": "24h",
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": state.config.MAX_ALERTS_PER_QUERY,
                        "default": min(100, state.config.MAX_ALERTS_PER_QUERY),
                    },
                    "rule_id": {"type": "string", "description": "Filter by Wazuh rule ID (e.g., '5710', '100002')"},
                    "agent_id": {"type": "string", "description": "Filter by Wazuh agent ID (e.g., '001', '1234')"},
                    "level": {
                        "type": "string",
                        "description": "Minimum rule severity level (e.g., '10' for level >= 10, '12+' for level >= 12)",
                    },
                    "srcip": {"type": "string", "description": "Filter by source IP address (data.srcip)"},
                    "dstip": {"type": "string", "description": "Filter by destination IP address (data.dstip)"},
                    "compact": {
                        "type": "boolean",
                        "default": True,
                        "description": "Return compact events with essential fields only (recommended to avoid token limits)",
                    },
                },
                "required": ["query"],
            },
        },
        # Agent Management Tools (6 tools)
        {
            "name": "get_wazuh_agents",
            "description": "Retrieve information about Wazuh agents",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "Specific agent ID to query"},
                    "status": {
                        "type": "string",
                        "enum": ["active", "disconnected", "never_connected", "pending"],
                        "description": "Filter by agent status",
                    },
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
                },
                "required": [],
            },
        },
        {
            "name": "get_wazuh_running_agents",
            "description": "Get list of currently running/active Wazuh agents",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "check_agent_health",
            "description": "Check the health status of a specific Wazuh agent",
            "inputSchema": {
                "type": "object",
                "properties": {"agent_id": {"type": "string", "description": "ID of the agent to check"}},
                "required": ["agent_id"],
            },
        },
        {
            "name": "get_agent_processes",
            "description": "Get running processes from a specific Wazuh agent",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
                },
                "required": ["agent_id"],
            },
        },
        {
            "name": "get_agent_ports",
            "description": "Get open ports from a specific Wazuh agent",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
                },
                "required": ["agent_id"],
            },
        },
        {
            "name": "get_agent_configuration",
            "description": "Get configuration details for a specific Wazuh agent",
            "inputSchema": {
                "type": "object",
                "properties": {"agent_id": {"type": "string", "description": "ID of the agent"}},
                "required": ["agent_id"],
            },
        },
        # Vulnerability Management Tools (3 tools) - Requires Wazuh Indexer (4.8.0+)
        {
            "name": "get_wazuh_vulnerabilities",
            "description": "Retrieve vulnerability information from Wazuh Indexer (requires WAZUH_INDEXER_HOST configuration)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "Filter by specific agent ID"},
                    "severity": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "critical"],
                        "description": "Filter by severity level",
                    },
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100},
                    "compact": {
                        "type": "boolean",
                        "default": True,
                        "description": "Return compact vulnerabilities with essential fields only (recommended to avoid token limits)",
                    },
                },
                "required": [],
            },
        },
        {
            "name": "get_wazuh_critical_vulnerabilities",
            "description": "Get critical vulnerabilities from Wazuh Indexer (requires WAZUH_INDEXER_HOST configuration)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
                    "compact": {
                        "type": "boolean",
                        "default": True,
                        "description": "Return compact vulnerabilities with essential fields only (recommended to avoid token limits)",
                    },
                },
                "required": [],
            },
        },
        {
            "name": "get_wazuh_vulnerability_summary",
            "description": "Get vulnerability counts by severity from Wazuh Indexer (requires WAZUH_INDEXER_HOST configuration). Covers all currently open vulnerabilities unless time_range is given",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "time_range": {
                        "type": "string",
                        "enum": ["1d", "7d", "30d"],
                        "description": "Only count vulnerabilities first detected within this window",
                    },
                    "agent_id": {"type": "string", "description": "Only count vulnerabilities on this agent"},
                },
                "required": [],
            },
        },
        # Security Analysis Tools (7 tools)
        {
            "name": "analyze_security_threat",
            "description": "Analyze a security threat indicator by correlating it against recent Wazuh alert history",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "indicator": {
                        "type": "string",
                        "description": "The threat indicator to analyze (IP, hash, domain)",
                    },
                    "indicator_type": {"type": "string", "enum": ["ip", "hash", "domain", "url"], "default": "ip"},
                },
                "required": ["indicator"],
            },
        },
        {
            "name": "check_ioc_reputation",
            "description": "Count local Wazuh alert sightings of an indicator (IP/domain/hash). This reflects local activity, not an external threat-intel reputation feed; zero sightings means 'not seen locally', not 'known clean'.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "indicator": {"type": "string", "description": "The IoC to check (IP, domain, hash, etc.)"},
                    "indicator_type": {"type": "string", "enum": ["ip", "domain", "hash", "url"], "default": "ip"},
                },
                "required": ["indicator"],
            },
        },
        {
            "name": "search_external_context",
            "description": "Search the web for additional context around an indicator or security topic (opt-in via YDC_API_KEY)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Security topic or indicator to search for"},
                    "count": {"type": "integer", "minimum": 1, "maximum": 10, "default": 5},
                },
                "required": ["query"],
            },
        },
        {
            "name": "perform_risk_assessment",
            "description": "Perform comprehensive risk assessment for agents or the entire environment",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {
                        "type": "string",
                        "description": "Specific agent ID to assess (if None, assess entire environment)",
                    }
                },
                "required": [],
            },
        },
        {
            "name": "get_top_security_threats",
            "description": "Get top security threats based on alert frequency and severity",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
                    "time_range": {
                        "type": "string",
                        "enum": ["1h", "6h", "12h", "1d", "24h", "7d", "30d"],
                        "default": "24h",
                    },
                },
                "required": [],
            },
        },
        {
            "name": "generate_security_report",
            "description": "Generate comprehensive security report",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "report_type": {
                        "type": "string",
                        "enum": ["daily", "weekly", "monthly", "incident"],
                        "default": "daily",
                    },
                    "include_recommendations": {"type": "boolean", "default": True},
                },
                "required": [],
            },
        },
        {
            "name": "run_compliance_check",
            "description": "Run compliance check against security frameworks",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "framework": {
                        "type": "string",
                        "enum": ["PCI-DSS", "HIPAA", "SOX", "GDPR", "NIST", "ISO27001"],
                        "default": "PCI-DSS",
                    },
                    "agent_id": {
                        "type": "string",
                        "description": "Specific agent ID to check (if None, check entire environment)",
                    },
                },
                "required": [],
            },
        },
        # ISO 27001:2022 Tools
        {
            "name": "get_iso27001_dashboard",
            "description": (
                "ISO 27001:2022 compliance dashboard. Returns scores per Annex A domain "
                "(A.5 Organizational, A.6 People, A.7 Physical, A.8 Technological), "
                "overall posture, failing controls, and data drawn from SCA, alerts, "
                "vulnerabilities, and agent status."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {
                        "type": "string",
                        "description": "Scope dashboard to a specific agent (optional - defaults to environment-wide)",
                    },
                },
                "required": [],
            },
        },
        {
            "name": "get_iso27001_control_detail",
            "description": (
                "Drill into a specific ISO 27001:2022 Annex A control or domain. "
                "Returns Wazuh evidence (SCA policy scores, alert counts, vulnerability data, "
                "or agent coverage) for the requested control. "
                "Examples: 'A.8.8' (technical vulnerabilities), 'A.8.5' (authentication), "
                "'A.8' (all Technological controls), 'A.5' (all Organizational controls)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "control_id": {
                        "type": "string",
                        "description": (
                            "ISO 27001 control ID or domain. "
                            "Domains: A.5, A.6, A.7, A.8. "
                            "Controls: A.5.26, A.6.3, A.8.1, A.8.2, A.8.4, A.8.5, "
                            "A.8.7, A.8.8, A.8.9, A.8.12, A.8.15, A.8.16, A.8.20, A.8.22"
                        ),
                    },
                    "agent_id": {
                        "type": "string",
                        "description": "Scope to a specific agent (optional)",
                    },
                },
                "required": ["control_id"],
            },
        },
        {
            "name": "get_sca_policy_checks",
            "description": (
                "Get individual check-level detail for a specific SCA policy on a Wazuh agent. "
                "Returns each check with pass/fail status, description, rationale, and remediation steps. "
                "Use after get_iso27001_dashboard or get_iso27001_control_detail to drill into SCA findings."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {
                        "type": "string",
                        "description": "Wazuh agent ID (e.g. '001')",
                    },
                    "policy_id": {
                        "type": "string",
                        "description": "SCA policy ID (e.g. 'cis_debian10', 'cis_win2019'). "
                        "Obtain from get_iso27001_control_detail or run_compliance_check.",
                    },
                },
                "required": ["agent_id", "policy_id"],
            },
        },
        {
            "name": "get_iso27001_gap_analysis",
            "description": (
                "Identify ISO 27001:2022 Annex A controls with gaps - failing SCA scores, "
                "critical vulnerabilities, or controls with no Wazuh evidence. "
                "Returns a prioritised gap list (critical/high/medium) with remediation hints."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {
                        "type": "string",
                        "description": "Scope gap analysis to a specific agent (optional)",
                    },
                },
                "required": [],
            },
        },
        {
            "name": "get_iso27001_alerts",
            "description": (
                "Get recent Wazuh alerts mapped to ISO 27001:2022 Annex A control domains. "
                "Shows which controls are generating security events, with sample alerts per control. "
                "Useful for understanding which ISO 27001 areas have active security activity."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "time_range": {
                        "type": "string",
                        "enum": ["1h", "6h", "12h", "24h", "7d", "30d"],
                        "default": "24h",
                        "description": "Time window for alert retrieval",
                    },
                    "agent_id": {
                        "type": "string",
                        "description": "Scope to a specific agent (optional)",
                    },
                },
                "required": [],
            },
        },
        # System Monitoring Tools (10 tools)
        {
            "name": "get_wazuh_statistics",
            "description": "Get comprehensive Wazuh statistics and metrics",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "get_wazuh_weekly_stats",
            "description": "Get weekly statistics from Wazuh including alerts, agents, and trends",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "get_wazuh_cluster_health",
            "description": "Get Wazuh cluster health information",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "get_wazuh_cluster_nodes",
            "description": "Get information about Wazuh cluster nodes",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "get_wazuh_rules_summary",
            "description": "Get summary of Wazuh rules and their effectiveness",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "get_wazuh_remoted_stats",
            "description": "Get Wazuh remoted (agent communication) statistics",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "get_wazuh_log_collector_stats",
            "description": "Get Wazuh manager analysisd statistics (event decoding/rule matching throughput)",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "search_wazuh_manager_logs",
            "description": "Search Wazuh manager logs for specific patterns",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query/pattern"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100},
                },
                "required": ["query"],
            },
        },
        {
            "name": "get_wazuh_manager_error_logs",
            "description": "Get recent error logs from Wazuh manager",
            "inputSchema": {
                "type": "object",
                "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100}},
                "required": [],
            },
        },
        {
            "name": "validate_wazuh_connection",
            "description": "Validate connection to Wazuh server and return status",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        # Active Response / Action Tools (9 tools)
        {
            "name": "wazuh_block_ip",
            "description": "[ACTION] Block an IP address via Wazuh active response firewall-drop. The block is permanent until removed; wazuh_firewall_allow needs an operator-deployed undo script (WAZUH_AR_FIREWALL_UNDO_COMMAND).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ip_address": {"type": "string", "description": "IP address to block"},
                    "agent_id": {
                        "type": "string",
                        "description": "Target agent ID. Required unless all_agents=true is set.",
                    },
                    "all_agents": {
                        "type": "boolean",
                        "default": False,
                        "description": "Set true to deliberately block the IP fleet-wide. Without agent_id "
                        "or all_agents the call is refused - it never silently defaults to all agents.",
                    },
                },
                "required": ["ip_address"],
            },
        },
        {
            "name": "wazuh_isolate_host",
            "description": "[ACTION] Isolate a host from the network via active response. Risk: MEDIUM, Reversible.",
            "inputSchema": {
                "type": "object",
                "properties": {"agent_id": {"type": "string", "description": "ID of the agent to isolate"}},
                "required": ["agent_id"],
            },
        },
        {
            "name": "wazuh_kill_process",
            "description": "[ACTION] Terminate a process on an agent via active response. Risk: MEDIUM, Not reversible.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "process_id": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 999999,
                        "description": "PID of the process to kill",
                    },
                },
                "required": ["agent_id", "process_id"],
            },
        },
        {
            "name": "wazuh_disable_user",
            "description": "[ACTION] Disable a user account on an agent via active response. Risk: HIGH, Reversible.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "username": {"type": "string", "description": "Username to disable"},
                },
                "required": ["agent_id", "username"],
            },
        },
        {
            "name": "wazuh_quarantine_file",
            "description": "[ACTION] Quarantine a file on an agent via active response. Risk: LOW, Reversible.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "file_path": {"type": "string", "description": "Path of the file to quarantine"},
                },
                "required": ["agent_id", "file_path"],
            },
        },
        {
            "name": "wazuh_active_response",
            "description": "[ACTION] Execute a generic Wazuh active response command. Risk: HIGH, Not reversible.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "command": {"type": "string", "description": "Active response command name"},
                    "parameters": {"type": "object", "description": "Optional command parameters"},
                },
                "required": ["agent_id", "command"],
            },
        },
        {
            "name": "wazuh_firewall_drop",
            "description": "[ACTION] Add a firewall drop rule on an agent via active response. Risk: MEDIUM, Reversible.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "src_ip": {"type": "string", "description": "Source IP address to drop"},
                },
                "required": ["agent_id", "src_ip"],
            },
        },
        {
            "name": "wazuh_host_deny",
            "description": "[ACTION] Add an entry to hosts.deny on an agent via active response. Risk: MEDIUM, Reversible.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "src_ip": {"type": "string", "description": "Source IP address to deny"},
                },
                "required": ["agent_id", "src_ip"],
            },
        },
        {
            "name": "wazuh_restart",
            "description": "[ACTION] Restart Wazuh agent or manager service. Risk: CRITICAL, Not reversible.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Agent ID or 'manager' to restart",
                    }
                },
                "required": ["target"],
            },
        },
        # Verification Tools (5 tools)
        {
            "name": "wazuh_check_blocked_ip",
            "description": "Check if an IP was blocked by searching active response alert history (not live firewall state)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ip_address": {"type": "string", "description": "IP address to check"},
                    "agent_id": {"type": "string", "description": "Filter by agent ID (optional)"},
                },
                "required": ["ip_address"],
            },
        },
        {
            "name": "wazuh_check_agent_isolation",
            "description": "Check agent isolation status via connectivity and active response alert history (not live network state)",
            "inputSchema": {
                "type": "object",
                "properties": {"agent_id": {"type": "string", "description": "ID of the agent to check"}},
                "required": ["agent_id"],
            },
        },
        {
            "name": "wazuh_check_process",
            "description": "Check if a specific process is running on an agent",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "process_id": {"type": "integer", "minimum": 1, "maximum": 999999, "description": "PID to check"},
                },
                "required": ["agent_id", "process_id"],
            },
        },
        {
            "name": "wazuh_check_user_status",
            "description": "Check if a user account was disabled by searching active response alert history (not live OS state)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "username": {"type": "string", "description": "Username to check"},
                },
                "required": ["agent_id", "username"],
            },
        },
        {
            "name": "wazuh_check_file_quarantine",
            "description": "Check if a file has been quarantined on an agent",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "file_path": {"type": "string", "description": "Path of the file to check"},
                },
                "required": ["agent_id", "file_path"],
            },
        },
        # Rollback Tools (5 tools)
        {
            "name": "wazuh_unisolate_host",
            "description": "[ACTION] Remove host network isolation. Risk: MEDIUM, Reversal of isolate_host.",
            "inputSchema": {
                "type": "object",
                "properties": {"agent_id": {"type": "string", "description": "ID of the agent to unisolate"}},
                "required": ["agent_id"],
            },
        },
        {
            "name": "wazuh_enable_user",
            "description": "[ACTION] Re-enable a disabled user account. Risk: HIGH, Reversal of disable_user.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "username": {"type": "string", "description": "Username to re-enable"},
                },
                "required": ["agent_id", "username"],
            },
        },
        {
            "name": "wazuh_restore_file",
            "description": "[ACTION] Restore a quarantined file. Risk: LOW, Reversal of quarantine_file.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "file_path": {"type": "string", "description": "Path of the file to restore"},
                },
                "required": ["agent_id", "file_path"],
            },
        },
        {
            "name": "wazuh_firewall_allow",
            "description": "[ACTION] Remove a firewall-drop block. Risk: MEDIUM, reversal of firewall_drop. Requires an operator-deployed undo script (set WAZUH_AR_FIREWALL_UNDO_COMMAND); stock Wazuh cannot unblock via the API and this tool will refuse rather than re-block.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "src_ip": {"type": "string", "description": "Source IP to unblock"},
                },
                "required": ["agent_id", "src_ip"],
            },
        },
        {
            "name": "wazuh_host_allow",
            "description": "[ACTION] Remove a hosts.deny entry. Risk: MEDIUM, reversal of host_deny. Requires an operator-deployed undo script (set WAZUH_AR_HOSTDENY_UNDO_COMMAND); stock Wazuh cannot unblock via the API and this tool will refuse rather than re-block.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "src_ip": {"type": "string", "description": "Source IP to allow"},
                },
                "required": ["agent_id", "src_ip"],
            },
        },
    ]

    # Multi-cluster mode: advertise the cluster_id parameter on every tool and the
    # list_wazuh_clusters tool. Single-cluster deployments see no schema change.
    if state.cluster_registry.multi_cluster:
        cluster_property = {
            "type": "string",
            "description": (
                f"Target Wazuh cluster (default: {state.cluster_registry.default_id}). "
                "Use list_wazuh_clusters to see configured clusters."
            ),
        }
        for t in tools:
            t["inputSchema"].setdefault("properties", {})["cluster_id"] = cluster_property
        tools.append(
            {
                "name": "list_wazuh_clusters",
                "description": "List the configured Wazuh clusters and the default cluster for tool routing",
                "inputSchema": {"type": "object", "properties": {}, "required": []},
            }
        )

    # Operator-selected exposure (WAZUH_TOOLSETS / WAZUH_DISABLED_TOOLS)
    tools = [t for t in tools if t["name"] in state.config.ENABLED_TOOLS]

    # Filter tools by session scopes: hide write tools from read-only or unknown tokens
    auth_token = getattr(session, "_auth_token", None)
    if not auth_token or not auth_token.has_scope("wazuh:write"):
        tools = [t for t in tools if t["name"] not in WRITE_SCOPE_TOOLS]
    else:
        # Advertise the confirmation flag so schema-validating clients can send it.
        for tool in tools:
            if tool["name"] in WRITE_SCOPE_TOOLS:
                props = tool.setdefault("inputSchema", {}).setdefault("properties", {})
                props.setdefault(
                    "confirm",
                    {
                        "type": "boolean",
                        "description": (
                            "Set to true only after a human operator approved this exact target. "
                            "Required when WAZUH_REQUIRE_ACTION_CONFIRMATION is on (default in production)."
                        ),
                    },
                )

    require_confirm = tool_policy._require_action_confirmation()
    for t in tools:
        schema = t["inputSchema"]
        if require_confirm and t["name"] in WRITE_SCOPE_TOOLS:
            # The gate in handle_tools_call reads `confirm`; with a closed schema it must be declared
            schema.setdefault("properties", {}).setdefault(
                "confirm",
                {"type": "boolean", "description": "Set true only after a human operator approved this exact action"},
            )
        # Closed argument schemas: lets strict function calling (vLLM --tool-strict-level,
        # OpenAI strict mode) constrain decoding and makes clients reject invented params.
        schema["additionalProperties"] = False
        t["annotations"] = tool_annotations(t["name"], WRITE_SCOPE_TOOLS)

    # Pagination support per MCP spec
    return {"tools": tools}  # No more tools


# Accepted for backward compatibility but no longer advertised: `duration` is refused when
# positive (see _reject_block_duration) and harmless at 0, which older clients still send.
_UNADVERTISED_ARGUMENTS = {"wazuh_block_ip": {"duration"}, "wazuh_firewall_drop": {"duration"}}


async def _tool_argument_names(tool_name: str) -> Optional[frozenset]:
    """Declared inputSchema properties for a tool, taken from the tools/list definitions."""
    if state._TOOL_ARGUMENT_NAMES is None:
        from wazuh_mcp.auth import AuthToken

        schema_session = MCPSession("schema-introspection", None)
        schema_session._auth_token = AuthToken(
            token="", api_key_id="schema", created_at=datetime.now(timezone.utc), scopes=["wazuh:read", "wazuh:write"]
        )
        listed = (await handle_tools_list({}, schema_session))["tools"]
        # cluster_id and confirm are consumed before this check, so they never count as unknown
        state._TOOL_ARGUMENT_NAMES = {
            t["name"]: (frozenset(t["inputSchema"].get("properties", {})) - {"cluster_id", "confirm"})
            | frozenset(_UNADVERTISED_ARGUMENTS.get(t["name"], ()))
            for t in listed
        }
    return state._TOOL_ARGUMENT_NAMES.get(tool_name)
