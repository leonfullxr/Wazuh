"""The typed tool catalog - lane 1 (D23/D32).

Each tool is a pydantic schema plus a function turning validated params into a
Query IR. The model only ever emits a tool name and params; it never writes a
query (D4). Lane 2 is one special tool, run_query_ir, whose params ARE the IR
document, schema-validated and allowlist-bound like everything else.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Literal, Optional

from pydantic import BaseModel, Field

from .config import CFG
from .models import IRAggregation, IRFilter, QueryIR, TimeRange


# ---------------------------------------------------------------------------
# Lane 1 parameter schemas
# ---------------------------------------------------------------------------
class SearchAlertsParams(BaseModel):
    """Find alerts matching structured filters. Use for lookups and drill-downs."""

    time_range: TimeRange = Field(default_factory=TimeRange)
    rule_ids: Optional[list[str]] = Field(None, description="Wazuh rule ids, e.g. ['5710']")
    agent_names: Optional[list[str]] = Field(None, description="Agent names, e.g. ['web-01']")
    severity_gte: Optional[int] = Field(None, ge=0, le=15, description="Minimum rule.level")
    source_ip: Optional[str] = Field(None, description="Exact data.srcip")
    user: Optional[str] = Field(None, description="Exact data.dstuser (target user)")
    match_description: Optional[str] = Field(None, description="Free text against rule.description")
    size: int = Field(20, ge=1, le=50)


def _search_alerts_ir(p: SearchAlertsParams) -> QueryIR:
    filters: list[IRFilter] = []
    if p.rule_ids:
        filters.append(IRFilter(field="rule.id", op="in", value=p.rule_ids))
    if p.agent_names:
        filters.append(IRFilter(field="agent.name", op="in", value=p.agent_names))
    if p.severity_gte is not None:
        filters.append(IRFilter(field="rule.level", op="gte", value=p.severity_gte))
    if p.source_ip:
        filters.append(IRFilter(field="data.srcip", op="eq", value=p.source_ip))
    if p.user:
        filters.append(IRFilter(field="data.dstuser", op="eq", value=p.user))
    if p.match_description:
        filters.append(IRFilter(field="rule.description", op="match", value=p.match_description))
    return QueryIR(time_range=p.time_range, filters=filters, limit=p.size)


class GetAlertParams(BaseModel):
    """Fetch one alert by its exact id (for explain-this-alert and drill-down)."""

    alert_id: str


def _get_alert_ir(p: GetAlertParams) -> QueryIR:
    # Wide window: an id lookup should not miss because of the default 24h.
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    return QueryIR(
        time_range=TimeRange(gte=now - timedelta(days=90), lte=now),
        filters=[IRFilter(field="_id", op="eq", value=p.alert_id)],
        limit=1,
    )


class CountAlertsParams(BaseModel):
    """Exact count of matching alerts, computed by the datastore. ALWAYS use
    this (or another aggregation tool) for any 'how many' question."""

    time_range: TimeRange = Field(default_factory=TimeRange)
    rule_ids: Optional[list[str]] = None
    agent_names: Optional[list[str]] = None
    severity_gte: Optional[int] = Field(None, ge=0, le=15)


def _count_alerts_ir(p: CountAlertsParams) -> QueryIR:
    base = _search_alerts_ir(
        SearchAlertsParams(
            time_range=p.time_range,
            rule_ids=p.rule_ids,
            agent_names=p.agent_names,
            severity_gte=p.severity_gte,
        )
    )
    base.aggregation = IRAggregation(kind="count")
    base.limit = 0
    return base


class TopRulesParams(BaseModel):
    """Most frequent rules in a window, with exact per-rule counts."""

    time_range: TimeRange = Field(default_factory=TimeRange)
    size: int = Field(10, ge=1, le=50)


def _top_rules_ir(p: TopRulesParams) -> QueryIR:
    return QueryIR(
        time_range=p.time_range,
        aggregation=IRAggregation(kind="terms", field="rule.id", size=p.size),
        limit=0,
    )


class AlertHistogramParams(BaseModel):
    """Alert volume over time (trend), computed by the datastore."""

    time_range: TimeRange = Field(default_factory=TimeRange)
    interval: Literal["1h", "3h", "12h", "1d"] = "1d"
    severity_gte: Optional[int] = Field(None, ge=0, le=15)


def _alert_histogram_ir(p: AlertHistogramParams) -> QueryIR:
    filters = []
    if p.severity_gte is not None:
        filters.append(IRFilter(field="rule.level", op="gte", value=p.severity_gte))
    return QueryIR(
        time_range=p.time_range,
        filters=filters,
        aggregation=IRAggregation(kind="date_histogram", interval=p.interval),
        limit=0,
    )


class AuthFailuresParams(BaseModel):
    """Authentication failures grouped by user, source ip or agent, with exact counts."""

    time_range: TimeRange = Field(default_factory=TimeRange)
    group_by: Literal["data.dstuser", "data.srcip", "agent.name"] = "data.dstuser"
    size: int = Field(10, ge=1, le=50)


def _auth_failures_ir(p: AuthFailuresParams) -> QueryIR:
    return QueryIR(
        time_range=p.time_range,
        filters=[IRFilter(field="rule.groups", op="eq", value="authentication_failed")],
        aggregation=IRAggregation(kind="terms", field=p.group_by, size=p.size),
        limit=0,
    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
@dataclass
class ToolDef:
    name: str
    description: str
    schema: type[BaseModel]
    to_ir: Callable[[BaseModel], QueryIR]
    lane: int


REGISTRY: dict[str, ToolDef] = {
    t.name: t
    for t in [
        ToolDef(
            "search_alerts",
            "Search this tenant's Wazuh alerts with structured filters "
            "(rules, agents, severity, ips, users, free text). Returns sample "
            "alerts plus the exact datastore-computed total.",
            SearchAlertsParams,
            _search_alerts_ir,
            lane=1,
        ),
        ToolDef(
            "get_alert",
            "Fetch a single alert by its exact document id.",
            GetAlertParams,
            _get_alert_ir,
            lane=1,
        ),
        ToolDef(
            "count_alerts",
            "Exact count of matching alerts. Use for every 'how many' question. "
            "Never count listed alerts yourself.",
            CountAlertsParams,
            _count_alerts_ir,
            lane=1,
        ),
        ToolDef(
            "top_rules",
            "Most frequent rule ids in a time window with exact counts per rule.",
            TopRulesParams,
            _top_rules_ir,
            lane=1,
        ),
        ToolDef(
            "alert_histogram",
            "Alert volume over time as a histogram (trend detection).",
            AlertHistogramParams,
            _alert_histogram_ir,
            lane=1,
        ),
        ToolDef(
            "auth_failures",
            "Authentication failures grouped by user, source ip or agent, "
            "with exact counts (brute-force triage).",
            AuthFailuresParams,
            _auth_failures_ir,
            lane=1,
        ),
    ]
}

if CFG.lane2_enabled:
    REGISTRY["run_query_ir"] = ToolDef(
        "run_query_ir",
        "Long-tail escape hatch: run a typed query plan you compose yourself. "
        "Only allowlisted fields and operators are accepted, the plan is "
        "schema-validated, mapping-checked and dry-run before execution. "
        "Prefer the specific tools above when they can express the question.",
        QueryIR,
        lambda ir: ir,  # the params ARE the IR
        lane=2,
    )


def converse_tool_specs() -> list[dict]:
    """pydantic schemas -> Bedrock Converse toolSpec list."""
    specs = []
    for t in REGISTRY.values():
        specs.append(
            {
                "toolSpec": {
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": {"json": t.schema.model_json_schema()},
                }
            }
        )
    return specs
