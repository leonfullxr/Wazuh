"""The typed tool catalog - lane 1 (D23/D32).

Each tool is a pydantic schema plus a function turning validated params into a
Query IR. The model only ever emits a tool name and params; it never writes a
query (D4). Lane 2 is one special tool, run_query_ir, whose params ARE the IR
document, schema-validated and allowlist-bound like everything else.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Literal, Optional

from pydantic import BaseModel, Field, model_validator

from .auth_groups import AUTH_FAILURE_GROUPS
from .brute_force import BruteForceSummaryParams
from .config import CFG
from .correlation import (
    AgentPostureParams,
    CompareWindowsParams,
    RelatedAlertsParams,
    _agent_posture_ir,
    _compare_windows_ir,
    _related_alerts_ir,
)
from .environment import (
    DashboardDesignGuideParams,
    IndexHealthParams,
    ListAgentsParams,
    ListAlertFieldsParams,
    ListDashboardsParams,
    dashboard_design_guide,
    index_health,
    list_agents_ir,
    list_alert_fields,
    list_dashboards,
)
from .capabilities import DescribeCapabilitiesParams
from .knowledge import (
    FieldDictionaryParams,
    KnowledgeSearchParams,
    MitreLookupParams,
    RuleReferenceParams,
)
from .models import IRAggregation, IRFilter, QueryIR, TimeRange
from .states_models import StatesQueryIR
from .states_tools import (
    CountVulnerabilitiesParams,
    VulnerabilitiesBySeverityParams,
    count_vulnerabilities_ir,
    vulnerabilities_by_severity_ir,
)


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

    from .compiler import SOURCE_FIELDS_DETAIL

    now = datetime.now(timezone.utc)
    return QueryIR(
        time_range=TimeRange(gte=now - timedelta(days=90), lte=now),
        filters=[IRFilter(field="_id", op="eq", value=p.alert_id)],
        limit=1,
        source_fields=SOURCE_FIELDS_DETAIL,
    )


class CountAlertsParams(BaseModel):
    """Exact count of matching alerts, computed by the datastore. Use for
    'how many' questions. Do NOT use when the user asks which agents are
    reporting or active — use list_agents instead."""

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
        filters=[
            IRFilter(
                field="rule.groups",
                op="in",
                value=list(AUTH_FAILURE_GROUPS),
            )
        ],
        aggregation=IRAggregation(kind="terms", field=p.group_by, size=p.size),
        limit=0,
    )


class AlertTimelineParams(BaseModel):
    """Ordered alerts for an agent, source IP, or user over a window."""

    time_range: TimeRange = Field(default_factory=TimeRange)
    agent_name: Optional[str] = Field(None, description="Exact agent.name")
    source_ip: Optional[str] = Field(None, description="Exact data.srcip")
    user: Optional[str] = Field(None, description="Exact data.dstuser")
    size: int = Field(30, ge=1, le=50)
    include_histogram: bool = Field(
        False, description="Also return a date_histogram under aggregations"
    )
    interval: Literal["1h", "3h", "12h", "1d"] = "1h"

    @model_validator(mode="after")
    def _need_entity(self) -> "AlertTimelineParams":
        if not self.agent_name and not self.source_ip and not self.user:
            raise ValueError(
                "alert_timeline requires at least one of agent_name, source_ip, user"
            )
        return self


def _alert_timeline_ir(p: AlertTimelineParams) -> QueryIR:
    from .compiler import SOURCE_FIELDS_LIST

    filters: list[IRFilter] = []
    if p.agent_name:
        filters.append(IRFilter(field="agent.name", op="eq", value=p.agent_name))
    if p.source_ip:
        filters.append(IRFilter(field="data.srcip", op="eq", value=p.source_ip))
    if p.user:
        filters.append(IRFilter(field="data.dstuser", op="eq", value=p.user))
    agg = None
    if p.include_histogram:
        agg = IRAggregation(kind="date_histogram", interval=p.interval)
    return QueryIR(
        time_range=p.time_range,
        filters=filters,
        aggregation=agg,
        limit=p.size,
        sort="timestamp:asc",
        source_fields=SOURCE_FIELDS_LIST,
    )


class MitreCoverageParams(BaseModel):
    """Which MITRE techniques are firing (terms on rule.mitre.id)."""

    time_range: TimeRange = Field(default_factory=TimeRange)
    size: int = Field(15, ge=1, le=50)
    severity_gte: Optional[int] = Field(None, ge=0, le=15)


def _mitre_coverage_ir(p: MitreCoverageParams) -> QueryIR:
    filters: list[IRFilter] = []
    if p.severity_gte is not None:
        filters.append(IRFilter(field="rule.level", op="gte", value=p.severity_gte))
    return QueryIR(
        time_range=p.time_range,
        filters=filters,
        aggregation=IRAggregation(kind="terms", field="rule.mitre.id", size=p.size),
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
    to_ir: Callable[[BaseModel], QueryIR | StatesQueryIR] | None
    lane: int
    knowledge: bool = False
    environment: bool = False
    composite: bool = False
    states: bool = False


def _mitre_lookup_ir(_p: MitreLookupParams) -> QueryIR:
    raise RuntimeError("knowledge tool - not an indexer query")


def _knowledge_search_ir(_p: KnowledgeSearchParams) -> QueryIR:
    raise RuntimeError("knowledge tool - not an indexer query")


def _rule_reference_ir(_p: RuleReferenceParams) -> QueryIR:
    raise RuntimeError("knowledge tool - not an indexer query")


def _field_dictionary_ir(_p: FieldDictionaryParams) -> QueryIR:
    raise RuntimeError("knowledge tool - not an indexer query")


def _describe_capabilities_ir(_p: DescribeCapabilitiesParams) -> QueryIR:
    raise RuntimeError("knowledge tool - not an indexer query")


def _list_dashboards_ir(_p: ListDashboardsParams) -> QueryIR:
    raise RuntimeError("environment tool - not an alerts-index IR query")


def _index_health_ir(_p: IndexHealthParams) -> QueryIR:
    raise RuntimeError("environment tool - not an alerts-index IR query")


def _list_alert_fields_ir(_p: ListAlertFieldsParams) -> QueryIR:
    raise RuntimeError("environment tool - not an alerts-index IR query")


def _dashboard_design_guide_ir(_p: DashboardDesignGuideParams) -> QueryIR:
    raise RuntimeError("environment tool - not an alerts-index IR query")


def _brute_force_summary_ir(_p: BruteForceSummaryParams) -> QueryIR:
    raise RuntimeError("composite tool - executed via brute_force_summary()")


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
            "Never count listed alerts yourself. time_range defaults to the "
            "last 24 hours - ALWAYS pass it explicitly to match the question.",
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
            "Authentication failures / failed logins (fallos de autenticacion, "
            "fallos de login) grouped by user, source ip or agent, with exact "
            "counts (brute-force triage). Filters rule.groups on authentication_failed, "
            "authentication_failures, and win_authentication_failed. ALWAYS use this "
            "for auth-failure questions — never free text.",
            AuthFailuresParams,
            _auth_failures_ir,
            lane=1,
        ),
        ToolDef(
            "brute_force_summary",
            "Brute-force triage in one call: MITRE T1110 OR auth-failure rule groups, "
            "with exact total_matching, timeline histogram, top source IPs and targeted "
            "users. Prefer this over composing multiple tools for brute-force summaries.",
            BruteForceSummaryParams,
            _brute_force_summary_ir,
            lane=1,
            composite=True,
        ),
        ToolDef(
            "mitre_lookup",
            "Look up a MITRE ATT&CK technique by exact id (e.g. T1110). "
            "Returns tactic, name and description from the local catalog. "
            "Does not query tenant alerts - use search_alerts with rule.mitre.id "
            "to find alerts tagged with a technique.",
            MitreLookupParams,
            _mitre_lookup_ir,
            lane=1,
            knowledge=True,
        ),
        ToolDef(
            "knowledge_search",
            "Semantic search over curated PUBLIC remediation notes and "
            "version-pinned Wazuh documentation (never tenant telemetry). "
            "Use for how-to / configure / remediate questions. "
            "Cite hits as [kb:<doc_id>] and include the hit url when present.",
            KnowledgeSearchParams,
            _knowledge_search_ir,
            lane=1,
            knowledge=True,
        ),
        ToolDef(
            "rule_reference",
            "Exact lookup of a Wazuh rule id, rule group, or decoder name "
            "from the local curated catalog (no embeddings). Cite as "
            "[kb:rule-<id>], [kb:group-<name>], or [kb:decoder-<name>].",
            RuleReferenceParams,
            _rule_reference_ir,
            lane=1,
            knowledge=True,
        ),
        ToolDef(
            "field_dictionary",
            "Look up what an alert field means (e.g. rule.level, data.srcip) "
            "from the local field dictionary. Cite as [kb:field-<name>].",
            FieldDictionaryParams,
            _field_dictionary_ir,
            lane=1,
            knowledge=True,
        ),
        ToolDef(
            "describe_capabilities",
            "List what this assistant can do in the current environment: "
            "tools, lanes, data families, and enabled action tiers. "
            "Use for 'what can you do' / discoverability questions.",
            DescribeCapabilitiesParams,
            _describe_capabilities_ir,
            lane=1,
            knowledge=True,
        ),
        ToolDef(
            "list_agents",
            "List Wazuh agents that produced alerts in the time window, with "
            "exact alert counts and last-seen timestamps per agent. Use when "
            "the question asks which agents are reporting, active, or sending "
            "alerts — not count_alerts.",
            ListAgentsParams,
            list_agents_ir,
            lane=1,
        ),
        ToolDef(
            "index_health",
            "Read-only health, document count and store size for each "
            "wazuh-alerts-* index in this cluster.",
            IndexHealthParams,
            _index_health_ir,
            lane=1,
            environment=True,
        ),
        ToolDef(
            "list_dashboards",
            "Inventory of shared dashboards, visualizations and index patterns "
            "(titles and types only — not saved object bodies).",
            ListDashboardsParams,
            _list_dashboards_ir,
            lane=1,
            environment=True,
        ),
        ToolDef(
            "list_alert_fields",
            "List dashboard-safe field names on wazuh-alerts-* (from the live "
            "index pattern). Call before custom visualizations; curated "
            "create_dashboard templates already use validated fields.",
            ListAlertFieldsParams,
            _list_alert_fields_ir,
            lane=1,
            environment=True,
        ),
        ToolDef(
            "dashboard_design_guide",
            "How to build custom dashboards: 48-column grid rules, panel schema, "
            "viz types, and an example create_dashboard custom payload. Call before "
            "template=custom — never invent gridData coordinates.",
            DashboardDesignGuideParams,
            _dashboard_design_guide_ir,
            lane=1,
            environment=True,
        ),
        ToolDef(
            "count_vulnerabilities",
            "Exact count of vulnerability state records on wazuh-states-vulnerabilities-* "
            "(detected-at window). Use for 'how many vulnerabilities' questions — not "
            "count_alerts.",
            CountVulnerabilitiesParams,
            count_vulnerabilities_ir,
            lane=1,
            states=True,
        ),
        ToolDef(
            "vulnerabilities_by_severity",
            "Vulnerability counts grouped by severity (low/medium/high/critical) with "
            "exact per-bucket counts from the states index.",
            VulnerabilitiesBySeverityParams,
            vulnerabilities_by_severity_ir,
            lane=1,
            states=True,
        ),
        ToolDef(
            "alert_timeline",
            "Ordered (oldest-first) alerts for one agent, source IP, or target user "
            "over a window. Use for investigation timelines and pivot follow-ups.",
            AlertTimelineParams,
            _alert_timeline_ir,
            lane=1,
        ),
        ToolDef(
            "related_alerts",
            "Pivot from one alert (or an explicit srcip/user/rule.id) to related "
            "alerts sharing that key. Prefer alert_id when explaining an alert.",
            RelatedAlertsParams,
            _related_alerts_ir,
            lane=1,
            composite=True,
        ),
        ToolDef(
            "compare_windows",
            "Datastore-computed alert count delta between two time windows "
            "(e.g. this week vs last). Never subtract totals yourself — call this.",
            CompareWindowsParams,
            _compare_windows_ir,
            lane=1,
            composite=True,
        ),
        ToolDef(
            "mitre_coverage",
            "Which MITRE ATT&CK technique ids are firing in the window, with exact "
            "per-technique counts (terms on rule.mitre.id).",
            MitreCoverageParams,
            _mitre_coverage_ir,
            lane=1,
        ),
        ToolDef(
            "agent_posture",
            "One agent: last-seen from alerts, recent high-severity alerts, and open "
            "vulnerability count. Use for agent triage / health questions.",
            AgentPostureParams,
            _agent_posture_ir,
            lane=1,
            composite=True,
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


def converse_tool_specs(subset: set[str] | None = None) -> list[dict]:
    """pydantic schemas -> Bedrock Converse toolSpec list.

    When ``subset`` is set (D62), only those REGISTRY tools are offered.
    Action propose_* tools are always included (writes stay reachable).
    Callers should fail open to subset=None when intent is unclear.
    """
    from .actions.registry import action_tool_specs

    specs = []
    for t in REGISTRY.values():
        if subset is not None and t.name not in subset:
            continue
        specs.append(
            {
                "toolSpec": {
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": {"json": t.schema.model_json_schema()},
                }
            }
        )
    # Fail open if subset stripped the catalog too aggressively.
    if subset is not None and len(specs) < 4:
        return converse_tool_specs(None)
    specs.extend(action_tool_specs())
    return specs
