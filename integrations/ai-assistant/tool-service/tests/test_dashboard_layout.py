"""Dashboard layout and custom template tests."""
import json

from app.actions.dashboard_layout import GRID_COLUMNS, layout_five_panel_triage
from app.actions.dashboard_templates import build_dashboard_bundle
from app.actions.schemas import CreateDashboardParams, DashboardPanelSpec


def test_five_panel_layout_uses_48_column_grid():
    layout = layout_five_panel_triage()
    top_row = [slot for slot in layout if slot[1] == 0]
    assert sum(w for _, _, w, _ in top_row) == GRID_COLUMNS
    assert layout[0][2] == 16


def test_brute_force_panels_span_full_width():
    objs = build_dashboard_bundle(
        CreateDashboardParams(title="BF", template="brute_force_geoip")
    )
    dash = objs[-1]["document"]["dashboard"]
    panels = json.loads(dash["panelsJSON"])
    top_row_width = sum(p["gridData"]["w"] for p in panels if p["gridData"]["y"] == 0)
    assert top_row_width == GRID_COLUMNS


def test_custom_dashboard_three_panels():
    objs = build_dashboard_bundle(
        CreateDashboardParams(
            title="Custom SSH",
            template="custom",
            panels=[
                DashboardPanelSpec(
                    title="Failed logins",
                    viz_type="metric",
                    query="rule.groups: authentication_failed",
                ),
                DashboardPanelSpec(
                    title="Over time",
                    viz_type="histogram",
                    query="rule.groups: authentication_failed",
                ),
                DashboardPanelSpec(
                    title="Top IPs",
                    viz_type="pie",
                    terms_field="data.srcip",
                    query="rule.groups: authentication_failed",
                ),
            ],
        )
    )
    assert len(objs) == 4
    panels = json.loads(objs[-1]["document"]["dashboard"]["panelsJSON"])
    assert len(panels) == 3
    assert sum(p["gridData"]["w"] for p in panels) == GRID_COLUMNS
