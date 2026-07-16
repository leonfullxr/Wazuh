"""OpenSearch Dashboards grid layout (OSD 2.19 uses 48 columns, not 24)."""
from __future__ import annotations

GRID_COLUMNS = 48
"""Full dashboard width in grid units. Pre-6.3 Kibana used 12; 6.3+ uses 48."""

ROW_HEIGHT_PX = 20
"""Approximate pixels per grid row when margins are enabled (~8px between rows)."""


def layout_for_panel_count(n: int) -> list[tuple[int, int, int, int]]:
    """Return (x, y, w, h) placements for 1–6 panels on the 48-column grid."""
    if n < 1 or n > 6:
        raise ValueError(f"auto-layout supports 1–6 panels, got {n}")
    if n == 1:
        return [(0, 0, 48, 30)]
    if n == 2:
        return [(0, 0, 24, 24), (24, 0, 24, 24)]
    if n == 3:
        return [(0, 0, 16, 24), (16, 0, 16, 24), (32, 0, 16, 24)]
    if n == 4:
        return [
            (0, 0, 24, 20),
            (24, 0, 24, 20),
            (0, 20, 24, 20),
            (24, 20, 24, 20),
        ]
    if n == 5:
        return layout_five_panel_triage()
    # n == 6
    return [
        (0, 0, 16, 18),
        (16, 0, 16, 18),
        (32, 0, 16, 18),
        (0, 18, 16, 18),
        (16, 18, 16, 18),
        (32, 18, 16, 18),
    ]


def layout_five_panel_triage() -> list[tuple[int, int, int, int]]:
    """Metric + wide trend on top; three equal panels below (brute-force / triage)."""
    return [
        (0, 0, 16, 16),
        (16, 0, 32, 16),
        (0, 16, 16, 24),
        (16, 16, 16, 24),
        (32, 16, 16, 24),
    ]


DESIGN_GUIDE: dict = {
    "grid_columns": GRID_COLUMNS,
    "row_height_px": ROW_HEIGHT_PX,
    "rules": [
        "OpenSearch Dashboards 2.x uses a 48-column grid (full width = w:48).",
        "Do NOT specify gridData/x/y/w/h — the server auto-layouts panels.",
        "Prefer a named template (brute_force_geoip, malware_detections, agent_health) "
        "when it matches the request.",
        "For custom dashboards use create_dashboard with template=custom and a panels "
        "array (1–6 items). Call list_alert_fields for valid field names first.",
        "Metric panels are compact; charts need w>=16; maps and tables need h>=20.",
        "Wazuh keyword fields have no .keyword suffix (data.dstuser, not data.dstuser.keyword).",
    ],
    "panel_sizes": {
        "metric": {"recommended_w": 16, "recommended_h": 16},
        "histogram": {"recommended_w": 32, "recommended_h": 16},
        "pie": {"recommended_w": 16, "recommended_h": 24},
        "table": {"recommended_w": 24, "recommended_h": 24},
        "region_map": {"recommended_w": 16, "recommended_h": 24},
    },
    "viz_types": {
        "metric": "Single count — no terms_field",
        "histogram": "Alerts over time — no terms_field",
        "pie": "Top values — requires terms_field",
        "table": "Ranked buckets — requires terms_field",
        "region_map": "GeoIP countries — terms_field=GeoLocation.country_name",
    },
    "example_custom": {
        "title": "SSH auth overview",
        "template": "custom",
        "panels": [
            {
                "title": "Failed logins",
                "viz_type": "metric",
                "query": "rule.groups: authentication_failed",
            },
            {
                "title": "Failures over time",
                "viz_type": "histogram",
                "query": "rule.groups: authentication_failed",
            },
            {
                "title": "Top source IPs",
                "viz_type": "pie",
                "terms_field": "data.srcip",
                "query": "rule.groups: authentication_failed",
            },
        ],
    },
}
