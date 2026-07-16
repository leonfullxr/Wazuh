"""Dashboard template bundle tests."""
import json

import pytest

from app.actions.dashboard_templates import build_dashboard_bundle
from app.actions.fields import (
    FIELD_AGENT,
    FIELD_COUNTRY,
    FIELD_DST_USER,
    FIELD_RULE_ID,
    FIELD_RULE_LEVEL,
    FIELD_RULE_MITRE,
    FIELD_SRC_IP,
)
from app.actions.schemas import CreateDashboardParams

TEMPLATES_5_PANEL = ("brute_force_geoip", "malware_detections", "agent_health")


@pytest.mark.parametrize("template", TEMPLATES_5_PANEL)
def test_five_panel_template_shape(template: str):
    objs = build_dashboard_bundle(
        CreateDashboardParams(title="Test", template=template)  # type: ignore[arg-type]
    )
    assert len(objs) == 6
    types = [o["document"]["type"] for o in objs]
    assert types.count("visualization") == 5
    assert types[-1] == "dashboard"
    bundle = json.dumps(
        [
            o["document"]["visualization"]["visState"]
            for o in objs
            if o["document"]["type"] == "visualization"
        ]
    )
    assert ".keyword" not in bundle


def test_brute_force_geoip_fields():
    objs = build_dashboard_bundle(
        CreateDashboardParams(title="BF", template="brute_force_geoip")
    )
    joined = _vis_states(objs)
    assert FIELD_COUNTRY in joined
    assert '"name": "iso2"' in joined
    assert "World Countries" in joined
    assert FIELD_DST_USER in joined
    assert FIELD_SRC_IP in joined


def test_malware_detections_fields():
    objs = build_dashboard_bundle(
        CreateDashboardParams(title="Mal", template="malware_detections")
    )
    joined = _vis_states(objs)
    assert FIELD_RULE_ID in joined
    assert FIELD_AGENT in joined
    assert FIELD_RULE_MITRE in joined
    dash = objs[-1]["document"]["dashboard"]
    assert "rule.level >= 10" in dash["kibanaSavedObjectMeta"]["searchSourceJSON"]


def test_agent_health_fields():
    objs = build_dashboard_bundle(
        CreateDashboardParams(title="Agents", template="agent_health")
    )
    joined = _vis_states(objs)
    assert FIELD_AGENT in joined
    assert FIELD_RULE_ID in joined
    assert FIELD_RULE_LEVEL in joined


def test_auth_failures_top_users_single_panel():
    objs = build_dashboard_bundle(
        CreateDashboardParams(title="Users", template="auth_failures_top_users")
    )
    assert len(objs) == 2
    assert FIELD_DST_USER in _vis_states(objs)


def _vis_states(objs: list) -> str:
    return " ".join(
        o["document"]["visualization"]["visState"]
        for o in objs
        if o["document"]["type"] == "visualization"
    )
