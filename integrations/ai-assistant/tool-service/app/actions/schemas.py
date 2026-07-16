"""Pydantic schemas for each action in the catalog (D50)."""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field, model_validator


class DashboardPanelSpec(BaseModel):
    """One panel in a custom dashboard (server applies 48-col auto-layout)."""

    title: str = Field(min_length=1, max_length=120)
    viz_type: Literal["metric", "histogram", "pie", "table", "region_map"]
    terms_field: Optional[str] = Field(
        None,
        max_length=120,
        description="Required for pie, table, region_map — use list_alert_fields names",
    )
    query: str = Field(
        default="",
        max_length=300,
        description="Kuery filter for this panel (e.g. rule.level >= 10)",
    )
    description: str = Field(default="", max_length=300)


class CreateDashboardParams(BaseModel):
    """Proposal: create a Wazuh/OpenSearch Dashboards dashboard."""

    title: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=500)
    template: Literal[
        "brute_force_geoip",
        "auth_failures_top_users",
        "malware_detections",
        "agent_health",
        "custom",
    ] = "custom"
    panels: Optional[list[DashboardPanelSpec]] = Field(
        default=None,
        min_length=1,
        max_length=6,
        description="Required when template=custom — 1 to 6 panels; layout is automatic",
    )
    folder: str = Field(
        default="Wazuh AI",
        max_length=80,
        description="Dashboards folder / tag grouping shown in the UI",
    )

    @model_validator(mode="after")
    def _custom_requires_panels(self) -> CreateDashboardParams:
        if self.template == "custom" and not self.panels:
            raise ValueError(
                "template=custom requires a panels array (1–6 items). "
                "Call dashboard_design_guide for the schema, or pick a named template."
            )
        if self.template != "custom" and self.panels:
            raise ValueError("panels may only be set when template=custom")
        return self


class CreateVisualizationParams(BaseModel):
    """Proposal: create a single visualization (panel)."""

    title: str = Field(min_length=1, max_length=120)
    viz_type: Literal["table", "pie", "metric", "map", "histogram"] = "table"
    template: Literal["brute_force_geoip", "auth_failures_by_user", "custom"] = (
        "custom"
    )
    index_pattern: str = Field(default="wazuh-alerts-*", max_length=120)


class RestartAgentParams(BaseModel):
    """Proposal: restart a Wazuh agent via the manager API."""

    agent_id: str = Field(min_length=1, max_length=32)
    reason: str = Field(
        min_length=10,
        max_length=500,
        description="Operator-visible justification for the restart",
    )


class ActiveResponseParams(BaseModel):
    """Proposal: run an allowlisted active-response command on an agent."""

    agent_id: str = Field(min_length=1, max_length=32)
    command: Literal["restart-ossec", "firewall-drop", "disable-account"]
    reason: str = Field(min_length=10, max_length=500)
    alert_id: Optional[str] = Field(
        None, description="Optional triggering alert document id"
    )
