"""Action catalog: schemas, previews, tiers (D50)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from pydantic import BaseModel

from ..config import CFG
from .dashboard_templates import template_panel_summary
from .schemas import (
    ActiveResponseParams,
    AddAgentToGroupParams,
    CreateDashboardParams,
    CreateIndexerMonitorParams,
    CreateVisualizationParams,
    RestartAgentParams,
    SuppressNoisyRuleParams,
)
from .types import ActionRisk, ActionTier


@dataclass(frozen=True)
class ActionDef:
    name: str
    propose_tool_name: str
    direct_description: str
    propose_description: str
    schema: type[BaseModel]
    tier: ActionTier
    risk: ActionRisk
    preview: Callable[[BaseModel], str]

    @property
    def tool_name(self) -> str:
        return public_tool_name(self.name)

    @property
    def description(self) -> str:
        return self.direct_description if CFG.actions_direct else self.propose_description


def public_tool_name(action_name: str) -> str:
    action = get_action(action_name)
    if action and CFG.actions_direct and action.tier == ActionTier.DASHBOARD:
        return action_name
    return f"propose_{action_name}"


def _preview_create_dashboard(p: BaseModel) -> str:
    params = CreateDashboardParams.model_validate(p.model_dump())
    head = (
        f"Create dashboard **{params.title}** in folder '{params.folder}' "
        f"using template `{params.template}`."
        + (f" {params.description}" if params.description else "")
    )
    if params.template == "custom" and params.panels:
        panel_lines = [
            f"- {panel.viz_type}: {panel.title}" for panel in params.panels
        ]
        return head + f"\nPanels ({len(params.panels)}):\n" + "\n".join(panel_lines)
    panels = template_panel_summary(params.template)
    if panels:
        return head + f"\nPanels ({len(panels)}): " + "; ".join(panels)
    return head


def _preview_create_visualization(p: BaseModel) -> str:
    params = CreateVisualizationParams.model_validate(p.model_dump())
    return (
        f"Create {params.viz_type} visualization **{params.title}** "
        f"on `{params.index_pattern}` (template: {params.template})."
    )


def _preview_restart_agent(p: BaseModel) -> str:
    params = RestartAgentParams.model_validate(p.model_dump())
    return (
        f"Restart Wazuh agent **{params.agent_id}**.\n"
        f"Reason: {params.reason}"
    )


def _preview_active_response(p: BaseModel) -> str:
    params = ActiveResponseParams.model_validate(p.model_dump())
    extra = f" (trigger alert: {params.alert_id})" if params.alert_id else ""
    return (
        f"Run active response **{params.command}** on agent **{params.agent_id}**"
        f"{extra}.\nReason: {params.reason}"
    )


def _preview_add_agent_to_group(p: BaseModel) -> str:
    params = AddAgentToGroupParams.model_validate(p.model_dump())
    return (
        f"Add agent **{params.agent_id}** to group **{params.group}**.\n"
        f"Reason: {params.reason}"
    )


def _preview_create_indexer_monitor(p: BaseModel) -> str:
    params = CreateIndexerMonitorParams.model_validate(p.model_dump())
    return (
        f"Create indexer monitor **{params.title}** "
        f"(template `{params.template}`, every {params.schedule_minutes}m).\n"
        f"Reason: {params.reason}"
    )


def _preview_suppress_noisy_rule(p: BaseModel) -> str:
    params = SuppressNoisyRuleParams.model_validate(p.model_dump())
    return (
        f"Suppress noisy rule **{params.rule_id}** via custom rules file "
        f"(level 0), then reload analysisd.\n"
        f"Note: executor needs rules:update/delete plus manager:read+restart "
        f"(restart is also a full manager restart capability).\n"
        f"Reason: {params.reason}"
    )


_ACTION_DEFS = [
    ActionDef(
        name="create_dashboard",
        propose_tool_name="propose_create_dashboard",
        direct_description=(
            "Create a Wazuh dashboard immediately. Named templates (auto-sized 48-col "
            "grid): brute_force_geoip, malware_detections, agent_health, "
            "auth_failures_top_users. For custom layouts use template=custom with a "
            "panels array (1–6 items) — call dashboard_design_guide first; never "
            "pass gridData. Fields validated at write time. ok=true required to claim success."
        ),
        propose_description=(
            "Propose creating a Wazuh dashboard (NOT executed until the analyst "
            "confirms). Templates: brute_force_geoip, malware_detections, "
            "agent_health, auth_failures_top_users, custom (with panels array)."
        ),
        schema=CreateDashboardParams,
        tier=ActionTier.DASHBOARD,
        risk=ActionRisk.LOW,
        preview=_preview_create_dashboard,
    ),
    ActionDef(
        name="create_visualization",
        propose_tool_name="propose_create_visualization",
        direct_description=(
            "Create a single visualization panel immediately. Report the tool "
            "result — only claim success when ok=true."
        ),
        propose_description=(
            "Propose a single visualization panel. Requires analyst confirmation."
        ),
        schema=CreateVisualizationParams,
        tier=ActionTier.DASHBOARD,
        risk=ActionRisk.LOW,
        preview=_preview_create_visualization,
    ),
    ActionDef(
        name="create_indexer_monitor",
        propose_tool_name="propose_create_indexer_monitor",
        direct_description=(
            "Create a curated OpenSearch Alerting monitor immediately "
            "(templates: auth_failures, high_severity). Not free-form."
        ),
        propose_description=(
            "Propose a curated OpenSearch Alerting monitor (auth_failures or "
            "high_severity). Requires analyst confirmation."
        ),
        schema=CreateIndexerMonitorParams,
        tier=ActionTier.DASHBOARD,
        risk=ActionRisk.LOW,
        preview=_preview_create_indexer_monitor,
    ),
    ActionDef(
        name="restart_agent",
        propose_tool_name="propose_restart_agent",
        direct_description=(
            "Restart a Wazuh agent via the manager API. Requires a mandatory "
            "reason. Medium risk — executes immediately."
        ),
        propose_description=(
            "Propose restarting a Wazuh agent. Requires reason and confirmation."
        ),
        schema=RestartAgentParams,
        tier=ActionTier.MANAGER,
        risk=ActionRisk.MEDIUM,
        preview=_preview_restart_agent,
    ),
    ActionDef(
        name="add_agent_to_group",
        propose_tool_name="propose_add_agent_to_group",
        direct_description=(
            "Assign a Wazuh agent to a manager group. Requires reason. "
            "Confirm with target echo (agent id + group)."
        ),
        propose_description=(
            "Propose assigning an agent to a manager group. Requires confirmation "
            "with target echo (agent id + group)."
        ),
        schema=AddAgentToGroupParams,
        tier=ActionTier.MANAGER,
        risk=ActionRisk.MEDIUM,
        preview=_preview_add_agent_to_group,
    ),
    ActionDef(
        name="active_response",
        propose_tool_name="propose_active_response",
        direct_description=(
            "Run an allowlisted active-response command on an agent: restart-ossec, "
            "firewall-drop, or disable-account. High risk — executes immediately."
        ),
        propose_description=(
            "Propose an allowlisted active-response command. Requires confirmation."
        ),
        schema=ActiveResponseParams,
        tier=ActionTier.ACTIVE_RESPONSE,
        risk=ActionRisk.HIGH,
        preview=_preview_active_response,
    ),
    ActionDef(
        name="suppress_noisy_rule",
        propose_tool_name="propose_suppress_noisy_rule",
        direct_description=(
            "Suppress a noisy Wazuh rule via curated local_rules override (level 0). "
            "High risk — requires reason and target echo of the rule id."
        ),
        propose_description=(
            "Propose suppressing a noisy rule (local_rules level-0 override). "
            "High risk — requires confirmation with rule-id target echo."
        ),
        schema=SuppressNoisyRuleParams,
        tier=ActionTier.MANAGER,
        risk=ActionRisk.HIGH,
        preview=_preview_suppress_noisy_rule,
    ),
]

ACTION_REGISTRY: dict[str, ActionDef] = {d.name: d for d in _ACTION_DEFS}


def get_action(name: str) -> ActionDef | None:
    return ACTION_REGISTRY.get(name)


def get_action_by_tool(tool_name: str) -> ActionDef | None:
    for action in ACTION_REGISTRY.values():
        if action.tool_name == tool_name or action.propose_tool_name == tool_name:
            return action
    return None


def action_tool_specs() -> list[dict]:
    if not CFG.actions_enabled:
        return []
    specs = []
    for action in ACTION_REGISTRY.values():
        specs.append(
            {
                "toolSpec": {
                    "name": action.tool_name,
                    "description": action.description,
                    "inputSchema": {"json": action.schema.model_json_schema()},
                }
            }
        )
    return specs
