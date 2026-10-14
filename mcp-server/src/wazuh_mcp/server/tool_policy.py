"""Scope classification and guardrails for tool calls: write scope, confirmations, manager targets."""

import logging
import os
from typing import Any, Dict

from wazuh_mcp.security import ToolValidationError, validate_limit

from . import state

# Tool scope mapping: tools requiring write access (active response, rollback, restart)
# All other tools only require wazuh:read
WRITE_SCOPE_TOOLS = frozenset(
    {
        "wazuh_block_ip",
        "wazuh_isolate_host",
        "wazuh_kill_process",
        "wazuh_disable_user",
        "wazuh_quarantine_file",
        "wazuh_active_response",
        "wazuh_firewall_drop",
        "wazuh_host_deny",
        "wazuh_restart",
        "wazuh_unisolate_host",
        "wazuh_enable_user",
        "wazuh_restore_file",
        "wazuh_firewall_allow",
        "wazuh_host_allow",
    }
)

# Audit logger for destructive operations
audit_logger = logging.getLogger("wazuh_mcp.audit")


# Read-scoped tools - the complete set of non-destructive tools. Kept explicit so that a
# newly-added tool defaults to requiring write (deny) unless it is deliberately listed here.
READ_SCOPE_TOOLS = frozenset(
    {
        "get_wazuh_alerts",
        "get_wazuh_alert_summary",
        "get_alerts_aggregated",
        "analyze_alert_patterns",
        "search_security_events",
        "get_wazuh_agents",
        "get_wazuh_running_agents",
        "check_agent_health",
        "get_agent_processes",
        "get_agent_ports",
        "get_agent_configuration",
        "get_wazuh_vulnerabilities",
        "get_wazuh_critical_vulnerabilities",
        "get_wazuh_vulnerability_summary",
        "analyze_security_threat",
        "check_ioc_reputation",
        "search_external_context",
        "perform_risk_assessment",
        "get_top_security_threats",
        "generate_security_report",
        "run_compliance_check",
        "get_iso27001_dashboard",
        "get_iso27001_control_detail",
        "get_iso27001_gap_analysis",
        "get_iso27001_alerts",
        "get_sca_policy_checks",
        "get_wazuh_statistics",
        "get_wazuh_cluster_health",
        "get_wazuh_cluster_nodes",
        "get_wazuh_rules_summary",
        "search_wazuh_manager_logs",
        "get_wazuh_manager_error_logs",
        "get_wazuh_log_collector_stats",
        "get_wazuh_remoted_stats",
        "get_wazuh_weekly_stats",
        "validate_wazuh_connection",
        "wazuh_check_blocked_ip",
        "wazuh_check_agent_isolation",
        "wazuh_check_process",
        "wazuh_check_user_status",
        "wazuh_check_file_quarantine",
        "list_wazuh_clusters",
    }
)

# Destructive verbs - a naming-convention safety net so a forgotten write tool cannot
# fall through to read scope even if it is missing from WRITE_SCOPE_TOOLS.
_DESTRUCTIVE_TOKENS = (
    "block",
    "isolate",
    "unisolate",
    "kill",
    "disable",
    "enable",
    "quarantine",
    "restore",
    "firewall",
    "deny",
    "allow",
    "restart",
    "active_response",
    "drop",
)


def _get_tool_scope(tool_name: str) -> str:
    """Get the required scope for a tool.

    Fails closed: a tool that is not in the explicit read set, or whose name matches a
    destructive verb, requires write. Only tools deliberately listed in READ_SCOPE_TOOLS
    are treated as read - a new write tool that someone forgot to add to WRITE_SCOPE_TOOLS
    is therefore denied to read-only tokens rather than silently allowed.
    """
    if tool_name in WRITE_SCOPE_TOOLS:
        return "wazuh:write"
    if tool_name in READ_SCOPE_TOOLS:
        return "wazuh:read"
    lowered = tool_name.lower()
    if any(tok in lowered for tok in _DESTRUCTIVE_TOKENS):
        return "wazuh:write"
    # Unknown tool: fail closed.
    return "wazuh:write"


def _arg_is_true(value: Any) -> bool:
    """Interpret a confirmation flag that may arrive as a bool or a string."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "y")
    return False


def _reject_block_duration(arguments: Dict[str, Any]) -> None:
    """Per-call block durations can't work: the Wazuh agent sets the timeout to 0 for every
    API-dispatched '!script' command (os_execd GetCommandbyName), so a "1 hour" block was
    silently permanent. Refuse a positive duration instead of implying it will expire."""
    duration = arguments.get("duration")
    if duration is None:
        return
    if validate_limit(duration, min_val=0, max_val=86400, param_name="duration") > 0:
        raise ToolValidationError(
            "duration",
            "per-call block durations are not supported: Wazuh ignores the timeout for API-triggered "
            "active response, so the block would be permanent",
            "Omit duration; remove the block later with wazuh_firewall_allow",
        )


def _require_action_confirmation() -> bool:
    """Whether state-changing tools require an explicit confirm=true.

    Defaults to ON in production and OFF otherwise; an explicit
    WAZUH_REQUIRE_ACTION_CONFIRMATION always wins. The gate is a defence-in-depth control
    against a prompt-injected model firing a destructive action off attacker-controlled
    alert text: the model has to come back with confirm=true, which is its cue to ask a
    human operator first.
    """
    from wazuh_mcp.config import env_bool, normalize_environment

    if os.getenv("WAZUH_REQUIRE_ACTION_CONFIRMATION", "").strip():
        # Same spellings as every other boolean (on/off, yes/no, 1/0); garbage is rejected at startup
        return env_bool("WAZUH_REQUIRE_ACTION_CONFIRMATION", False)
    environment = os.getenv("ENVIRONMENT")
    return (normalize_environment(environment) if environment else state.config.ENVIRONMENT) == "production"


def _fleet_wide_ar_allowed() -> bool:
    """Fleet-wide active response (all_agents=true) is opt-in via WAZUH_ALLOW_FLEET_AR=true."""
    from wazuh_mcp.config import env_bool

    return env_bool("WAZUH_ALLOW_FLEET_AR", False)


def _manager_ar_allowed() -> bool:
    """True when the operator opted in to active response against the Manager (WAZUH_ALLOW_MANAGER_AR)."""
    from wazuh_mcp.config import env_bool

    return env_bool("WAZUH_ALLOW_MANAGER_AR", False)


def _guard_manager_agent(agent_id: str, tool_name: str) -> None:
    """Refuse host-level destructive active response aimed at the manager's own agent (000).

    Agent 000 is the Wazuh manager itself. Isolating/killing/quarantining on it is a
    self-inflicted DoS of the SOC control plane - a prime target for a prompt-injected model
    steering an action off attacker-controlled alert text. Deny unless an operator explicitly
    opts in via WAZUH_ALLOW_MANAGER_AR=true.
    """
    if str(agent_id).lstrip("0") == "" and str(agent_id) != "":  # "0", "00", "000" all normalize to the manager
        if not _manager_ar_allowed():
            raise ValueError(
                f"Refusing to run '{tool_name}' against agent 000 (the Wazuh manager itself) - "
                "this would disrupt the SOC control plane. Set WAZUH_ALLOW_MANAGER_AR=true to override."
            )
