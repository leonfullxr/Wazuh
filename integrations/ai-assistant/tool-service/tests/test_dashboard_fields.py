"""Dashboard template field names match wazuh-alerts-* index pattern."""
from app.actions.dashboard_templates import build_dashboard_bundle
from app.actions.fields import FIELD_COUNTRY, FIELD_DST_USER, FIELD_SRC_IP
from app.actions.schemas import CreateDashboardParams


def test_brute_force_template_uses_index_pattern_fields():
    objs = build_dashboard_bundle(
        CreateDashboardParams(title="BF", template="brute_force_geoip")
    )
    vis_states = [
        o["document"]["visualization"]["visState"]
        for o in objs
        if o["document"]["type"] == "visualization"
    ]
    joined = " ".join(vis_states)
    assert FIELD_COUNTRY in joined
    assert FIELD_DST_USER in joined
    assert FIELD_SRC_IP in joined
    assert "country_name.keyword" not in joined
    assert "dstuser.keyword" not in joined
