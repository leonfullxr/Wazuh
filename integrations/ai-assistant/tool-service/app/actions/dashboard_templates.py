"""Curated dashboard bundles (D50) — validated saved-object shapes for Wazuh OSD 2.19."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from .dashboard_layout import GRID_COLUMNS, layout_for_panel_count, layout_five_panel_triage
from .fields import (
    FIELD_AGENT,
    FIELD_COUNTRY,
    FIELD_DST_USER,
    FIELD_RULE_ID,
    FIELD_RULE_LEVEL,
    FIELD_RULE_MITRE,
    FIELD_SRC_IP,
    FIELD_TIMESTAMP,
)
from .schemas import CreateDashboardParams, DashboardPanelSpec

INDEX_PATTERN_ID = "wazuh-alerts-*"
AUTH_FILTER = "rule.groups: authentication_failed"
HIGH_SEVERITY_FILTER = "rule.level >= 10"
ALL_ALERTS_FILTER = ""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _index_ref() -> list[dict[str, str]]:
    return [
        {
            "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
            "type": "index-pattern",
            "id": INDEX_PATTERN_ID,
        }
    ]


def _search_source(query: str = "") -> str:
    return json.dumps(
        {
            "index": INDEX_PATTERN_ID,
            "query": {"language": "kuery", "query": query},
            "filter": [],
        }
    )


def _terms_agg(
    agg_id: str,
    field: str,
    schema: str,
    *,
    size: int = 10,
    order_by: str = "2",
) -> dict[str, Any]:
    return {
        "id": agg_id,
        "enabled": True,
        "type": "terms",
        "schema": schema,
        "params": {
            "field": field,
            "size": size,
            "order": "desc",
            "orderBy": order_by,
        },
    }


def _count_agg(agg_id: str, schema: str = "metric") -> dict[str, Any]:
    return {
        "id": agg_id,
        "enabled": True,
        "type": "count",
        "schema": schema,
        "params": {},
    }


def _date_histogram_agg(agg_id: str, schema: str = "segment") -> dict[str, Any]:
    return {
        "id": agg_id,
        "enabled": True,
        "type": "date_histogram",
        "schema": schema,
        "params": {
            "field": FIELD_TIMESTAMP,
            "interval": "auto",
            "min_doc_count": 1,
        },
    }


def _vis_doc(
    vid: str,
    title: str,
    vis_type: str,
    vis_state: dict[str, Any],
    *,
    query: str = "",
    description: str = "",
) -> dict[str, Any]:
    return {
        "id": f"visualization:{vid}",
        "document": {
            "type": "visualization",
            "visualization": {
                "title": title,
                "visState": json.dumps(vis_state),
                "uiStateJSON": "{}",
                "description": description,
                "version": 1,
                "kibanaSavedObjectMeta": {"searchSourceJSON": _search_source(query)},
            },
            "references": _index_ref(),
            "migrationVersion": {"visualization": "7.10.0"},
            "updated_at": _now_iso(),
        },
    }


def _metric_vis(
    vid: str,
    title: str,
    *,
    query: str = "",
    subtitle: str = "",
    description: str = "",
) -> dict[str, Any]:
    return _vis_doc(
        vid,
        title,
        "metric",
        {
            "title": title,
            "type": "metric",
            "params": {
                "addTooltip": True,
                "addLegend": False,
                "type": "metric",
                "metric": {
                    "percentageMode": False,
                    "useRanges": False,
                    "colorSchema": "Green to Red",
                    "metricColorMode": "None",
                    "colorsRange": [{"from": 0, "to": 100000}],
                    "labels": {"show": True},
                    "invertColors": False,
                    "style": {
                        "bgFill": "#000",
                        "bgColor": False,
                        "labelColor": False,
                        "subText": subtitle,
                        "fontSize": 48,
                    },
                },
            },
            "aggs": [_count_agg("1")],
        },
        query=query,
        description=description,
    )


def _trend_vis(
    vid: str,
    title: str,
    *,
    query: str = "",
    description: str = "",
) -> dict[str, Any]:
    return _vis_doc(
        vid,
        title,
        "histogram",
        {
            "title": title,
            "type": "histogram",
            "params": {
                "type": "histogram",
                "grid": {"categoryLines": False},
                "categoryAxes": [
                    {
                        "id": "CategoryAxis-1",
                        "type": "category",
                        "position": "bottom",
                        "show": True,
                        "labels": {"show": True, "truncate": 100},
                    }
                ],
                "valueAxes": [
                    {
                        "id": "ValueAxis-1",
                        "name": "LeftAxis-1",
                        "type": "value",
                        "position": "left",
                        "show": True,
                        "labels": {"show": True, "truncate": 100},
                    }
                ],
                "seriesParams": [
                    {
                        "show": True,
                        "type": "histogram",
                        "mode": "stacked",
                        "data": {"label": "Count", "id": "1"},
                        "valueAxis": "ValueAxis-1",
                        "drawLinesBetweenPoints": True,
                        "showCircles": True,
                    }
                ],
                "addTooltip": True,
                "legendPosition": "right",
                "times": [],
                "addLegend": True,
            },
            "aggs": [_date_histogram_agg("2"), _count_agg("1", schema="metric")],
        },
        query=query,
        description=description,
    )


def _pie_vis(
    vid: str,
    title: str,
    field: str,
    *,
    query: str = "",
    description: str = "",
    size: int = 10,
) -> dict[str, Any]:
    return _vis_doc(
        vid,
        title,
        "pie",
        {
            "title": title,
            "type": "pie",
            "params": {
                "type": "pie",
                "addTooltip": True,
                "addLegend": True,
                "legendPosition": "right",
                "isDonut": False,
                "labels": {
                    "show": False,
                    "values": True,
                    "last_level": True,
                    "truncate": 100,
                },
            },
            "aggs": [
                _terms_agg("1", field, "segment", order_by="2", size=size),
                _count_agg("2"),
            ],
        },
        query=query,
        description=description,
    )


def _table_vis(
    vid: str,
    title: str,
    field: str,
    *,
    query: str = "",
    description: str = "",
    size: int = 10,
) -> dict[str, Any]:
    return _vis_doc(
        vid,
        title,
        "table",
        {
            "title": title,
            "type": "table",
            "params": {
                "perPage": 10,
                "showPartialRows": False,
                "showMetricsAtAllLevels": False,
                "sort": {"columnIndex": None, "direction": None},
                "showTotal": False,
                "totalFunc": "sum",
            },
            "aggs": [
                _terms_agg("1", field, "bucket", order_by="2", size=size),
                _count_agg("2"),
            ],
        },
        query=query,
        description=description,
    )


def _panel(
    index: str,
    x: int,
    y: int,
    w: int,
    h: int,
    vid: str,
) -> dict[str, Any]:
    return {
        "version": "7.3.0",
        "gridData": {"x": x, "y": y, "w": w, "h": h, "i": index},
        "panelIndex": index,
        "embeddableConfig": {},
        "panelRefName": f"panel_{index}",
        "type": "visualization",
        "id": vid,
    }


def _dashboard_doc(
    dash_id: str,
    params: CreateDashboardParams,
    panels: list[dict[str, Any]],
    vis_ids: list[str],
    *,
    query: str = "",
    description: str = "",
    time_restore: bool = True,
    time_from: str = "now-24h",
    time_to: str = "now",
) -> dict[str, Any]:
    dash_body: dict[str, Any] = {
        "title": params.title,
        "description": description or params.description,
        "hits": 0,
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps(
            {"hidePanelTitles": False, "useMargins": True, "syncColors": False}
        ),
        "version": 1,
        "timeRestore": time_restore,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": _search_source(query),
        },
    }
    if time_restore:
        dash_body["timeTo"] = time_to
        dash_body["timeFrom"] = time_from
    return {
        "id": f"dashboard:{dash_id}",
        "document": {
            "type": "dashboard",
            "dashboard": dash_body,
            "references": [
                {"name": f"panel_{i + 1}", "type": "visualization", "id": vid}
                for i, vid in enumerate(vis_ids)
            ],
            "migrationVersion": {"dashboard": "7.9.3"},
            "updated_at": _now_iso(),
        },
    }


def build_brute_force_geoip_bundle(params: CreateDashboardParams) -> list[dict[str, Any]]:
    """Auth-failure triage: volume, trend, GeoIP countries, source IPs, target users."""
    suffix = uuid.uuid4().hex[:10]
    metric_id = f"wazuh-ai-bf-metric-{suffix}"
    trend_id = f"wazuh-ai-bf-trend-{suffix}"
    geo_id = f"wazuh-ai-bf-geo-{suffix}"
    src_id = f"wazuh-ai-bf-srcip-{suffix}"
    users_id = f"wazuh-ai-bf-users-{suffix}"
    dash_id = f"wazuh-ai-bf-dash-{suffix}"

    metric = _metric_vis(
        metric_id,
        f"{params.title} — failed logins",
        query=AUTH_FILTER,
        subtitle="authentication_failed",
        description="Total authentication failures in the selected time range",
    )
    trend = _trend_vis(
        trend_id,
        f"{params.title} — failures over time",
        query=AUTH_FILTER,
        description="Brute-force activity trend (use dashboard time picker)",
    )
    geo = _vis_doc(
        geo_id,
        f"{params.title} — source countries",
        "region_map",
        {
            "title": f"{params.title} — source countries",
            "type": "region_map",
            "params": {
                "legendPosition": "bottomright",
                "showAllShapes": True,
                "colorSchema": "Yellow to Red",
                "outlineWeight": 0.5,
                "isDisplayWarning": True,
            },
            "aggs": [
                _terms_agg("2", FIELD_COUNTRY, "segment", order_by="1"),
                _count_agg("1"),
            ],
        },
        query=AUTH_FILTER,
        description="GeoIP country distribution (requires GeoLocation enrichment on data.srcip)",
    )
    src_ips = _pie_vis(
        src_id,
        f"{params.title} — top source IPs",
        FIELD_SRC_IP,
        query=AUTH_FILTER,
        description="Attacker source addresses for failed logins",
    )
    users = _table_vis(
        users_id,
        f"{params.title} — targeted users",
        FIELD_DST_USER,
        query=AUTH_FILTER,
        description="Accounts seeing the most failed login attempts",
    )

    vis_ids = [metric_id, trend_id, geo_id, src_id, users_id]
    layout = layout_five_panel_triage()
    dashboard = _dashboard_doc(
        dash_id,
        params,
        [
            _panel(str(i + 1), *layout[i], vid)
            for i, vid in enumerate(vis_ids)
        ],
        vis_ids,
        query=AUTH_FILTER,
        description=(
            "Brute-force / authentication failure triage: trend, GeoIP countries, "
            "source IPs, and targeted users (wazuh-ai)"
        ),
    )
    return [metric, trend, geo, src_ips, users, dashboard]


def build_malware_detections_bundle(params: CreateDashboardParams) -> list[dict[str, Any]]:
    """High-severity / attack alerts: volume, trend, rules, agents, MITRE techniques."""
    suffix = uuid.uuid4().hex[:10]
    metric_id = f"wazuh-ai-mal-metric-{suffix}"
    trend_id = f"wazuh-ai-mal-trend-{suffix}"
    rules_id = f"wazuh-ai-mal-rules-{suffix}"
    agents_id = f"wazuh-ai-mal-agents-{suffix}"
    mitre_id = f"wazuh-ai-mal-mitre-{suffix}"
    dash_id = f"wazuh-ai-mal-dash-{suffix}"

    metric = _metric_vis(
        metric_id,
        f"{params.title} — high severity",
        query=HIGH_SEVERITY_FILTER,
        subtitle="rule.level >= 10",
        description="Alerts at severity 10 or higher",
    )
    trend = _trend_vis(
        trend_id,
        f"{params.title} — detections over time",
        query=HIGH_SEVERITY_FILTER,
        description="High-severity alert trend",
    )
    rules = _pie_vis(
        rules_id,
        f"{params.title} — top rules",
        FIELD_RULE_ID,
        query=HIGH_SEVERITY_FILTER,
        description="Most frequent high-severity rule IDs",
    )
    agents = _table_vis(
        agents_id,
        f"{params.title} — affected agents",
        FIELD_AGENT,
        query=HIGH_SEVERITY_FILTER,
        description="Agents generating high-severity alerts",
    )
    mitre = _pie_vis(
        mitre_id,
        f"{params.title} — MITRE techniques",
        FIELD_RULE_MITRE,
        query=HIGH_SEVERITY_FILTER,
        description="MITRE ATT&CK techniques in high-severity alerts",
        size=8,
    )

    vis_ids = [metric_id, trend_id, rules_id, agents_id, mitre_id]
    layout = layout_five_panel_triage()
    dashboard = _dashboard_doc(
        dash_id,
        params,
        [
            _panel(str(i + 1), *layout[i], vid)
            for i, vid in enumerate(vis_ids)
        ],
        vis_ids,
        query=HIGH_SEVERITY_FILTER,
        description=(
            "High-severity detection triage: trend, top rules, affected agents, "
            "and MITRE mapping (wazuh-ai)"
        ),
        time_from="now-7d",
    )
    return [metric, trend, rules, agents, mitre, dashboard]


def build_agent_health_bundle(params: CreateDashboardParams) -> list[dict[str, Any]]:
    """Fleet overview: total volume, trend, alerts per agent, top rules, severity mix."""
    suffix = uuid.uuid4().hex[:10]
    metric_id = f"wazuh-ai-agt-metric-{suffix}"
    trend_id = f"wazuh-ai-agt-trend-{suffix}"
    agents_id = f"wazuh-ai-agt-agents-{suffix}"
    rules_id = f"wazuh-ai-agt-rules-{suffix}"
    levels_id = f"wazuh-ai-agt-levels-{suffix}"
    dash_id = f"wazuh-ai-agt-dash-{suffix}"

    metric = _metric_vis(
        metric_id,
        f"{params.title} — total alerts",
        query=ALL_ALERTS_FILTER,
        subtitle="all agents",
        description="Total alert volume in the selected time range",
    )
    trend = _trend_vis(
        trend_id,
        f"{params.title} — alert volume over time",
        query=ALL_ALERTS_FILTER,
        description="Alert throughput trend across the fleet",
    )
    agents = _pie_vis(
        agents_id,
        f"{params.title} — alerts by agent",
        FIELD_AGENT,
        query=ALL_ALERTS_FILTER,
        description="Which agents are generating the most alerts",
    )
    rules = _table_vis(
        rules_id,
        f"{params.title} — top rules",
        FIELD_RULE_ID,
        query=ALL_ALERTS_FILTER,
        description="Most frequent rule IDs fleet-wide",
    )
    levels = _pie_vis(
        levels_id,
        f"{params.title} — severity distribution",
        FIELD_RULE_LEVEL,
        query=ALL_ALERTS_FILTER,
        description="Alert counts grouped by rule.level",
        size=15,
    )

    vis_ids = [metric_id, trend_id, agents_id, rules_id, levels_id]
    layout = layout_five_panel_triage()
    dashboard = _dashboard_doc(
        dash_id,
        params,
        [
            _panel(str(i + 1), *layout[i], vid)
            for i, vid in enumerate(vis_ids)
        ],
        vis_ids,
        query=ALL_ALERTS_FILTER,
        description=(
            "Agent fleet health: alert volume, per-agent breakdown, top rules, "
            "and severity mix (wazuh-ai)"
        ),
        time_from="now-7d",
    )
    return [metric, trend, agents, rules, levels, dashboard]


def build_auth_failures_top_users_bundle(
    params: CreateDashboardParams,
) -> list[dict[str, Any]]:
    suffix = uuid.uuid4().hex[:10]
    users_id = f"wazuh-ai-auth-users-{suffix}"
    dash_id = f"wazuh-ai-auth-dash-{suffix}"
    users = _table_vis(
        users_id,
        params.title,
        FIELD_DST_USER,
        query=AUTH_FILTER,
        description="Top users with failed login attempts",
    )
    dashboard = _dashboard_doc(
        dash_id,
        params,
        [_panel("1", 0, 0, GRID_COLUMNS, 30, users_id)],
        [users_id],
        query=AUTH_FILTER,
        time_restore=False,
    )
    return [users, dashboard]


def _panel_from_spec(
    spec: DashboardPanelSpec,
    vid: str,
) -> dict[str, Any]:
    if spec.viz_type == "metric":
        return _metric_vis(
            vid,
            spec.title,
            query=spec.query,
            subtitle=spec.query or "alerts",
            description=spec.description,
        )
    if spec.viz_type == "histogram":
        return _trend_vis(
            vid,
            spec.title,
            query=spec.query,
            description=spec.description,
        )
    if not spec.terms_field:
        raise ValueError(
            f"panel {spec.title!r} ({spec.viz_type}) requires terms_field"
        )
    if spec.viz_type == "pie":
        return _pie_vis(
            vid,
            spec.title,
            spec.terms_field,
            query=spec.query,
            description=spec.description,
        )
    if spec.viz_type == "table":
        return _table_vis(
            vid,
            spec.title,
            spec.terms_field,
            query=spec.query,
            description=spec.description,
        )
    if spec.viz_type == "region_map":
        return _vis_doc(
            vid,
            spec.title,
            "region_map",
            {
                "title": spec.title,
                "type": "region_map",
                "params": {
                    "legendPosition": "bottomright",
                    "showAllShapes": True,
                    "colorSchema": "Yellow to Red",
                    "outlineWeight": 0.5,
                    "isDisplayWarning": True,
                },
                "aggs": [
                    _terms_agg("2", spec.terms_field, "segment", order_by="1"),
                    _count_agg("1"),
                ],
            },
            query=spec.query,
            description=spec.description,
        )
    raise ValueError(f"unsupported viz_type {spec.viz_type!r}")


def build_custom_dashboard_bundle(params: CreateDashboardParams) -> list[dict[str, Any]]:
    """Bounded custom dashboard — panels list only; layout is automatic (48-col grid)."""
    assert params.panels is not None
    suffix = uuid.uuid4().hex[:10]
    dash_id = f"wazuh-ai-custom-dash-{suffix}"

    vis_objs: list[dict[str, Any]] = []
    vis_ids: list[str] = []
    for i, spec in enumerate(params.panels):
        vid = f"wazuh-ai-custom-p{i}-{suffix}"
        vis_ids.append(vid)
        vis_objs.append(_panel_from_spec(spec, vid))

    layout = layout_for_panel_count(len(vis_ids))
    dashboard = _dashboard_doc(
        dash_id,
        params,
        [_panel(str(i + 1), *layout[i], vid) for i, vid in enumerate(vis_ids)],
        vis_ids,
        query=params.panels[0].query if params.panels else "",
        description=params.description or "Custom dashboard (wazuh-ai)",
    )
    return [*vis_objs, dashboard]


def build_dashboard_bundle(params: CreateDashboardParams) -> list[dict[str, Any]]:
    builders = {
        "brute_force_geoip": build_brute_force_geoip_bundle,
        "auth_failures_top_users": build_auth_failures_top_users_bundle,
        "malware_detections": build_malware_detections_bundle,
        "agent_health": build_agent_health_bundle,
        "custom": build_custom_dashboard_bundle,
    }
    builder = builders.get(params.template)
    if builder is None:
        raise ValueError(f"unsupported dashboard template {params.template!r}")
    return builder(params)