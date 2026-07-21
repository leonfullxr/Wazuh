"""V3.7 unit tests — auth filter triad, IR should_any, dashboard previews."""
import json

from app.actions.dashboard_templates import build_dashboard_bundle, template_panel_summary
from app.actions.registry import _preview_create_dashboard
from app.actions.schemas import CreateDashboardParams
from app.auth_groups import AUTH_FAILURE_GROUPS
from app.compiler import compile_opensearch
from app.models import IRAggregation, IRFilter, QueryIR, TimeRange
from app.tools import _auth_failures_ir, AuthFailuresParams
from app.veracity import term_buckets


from app.loop import _record_composite_agg


def test_record_composite_agg_registers_nested_citations():
    agg_names: set[str] = set()
    agg_values: dict[str, set[int]] = {}
    payload = {
        "total_matching": 42,
        "top_source_ips": [{"key": "10.0.0.1", "count": 5}],
        "top_target_users": [{"key": "admin", "count": 3}],
    }
    _record_composite_agg(agg_names, agg_values, "brute_force_summary", payload)
    assert "top_source_ips.key" in agg_names
    assert "top_target_users.key" in agg_names
    assert 42 in agg_values["total_matching"]
    assert 5 in agg_values["top_source_ips"]


def test_term_buckets_accepts_veracity_lists():
    aggs = {"by": [{"key": "web-01", "count": 12}]}
    assert term_buckets(aggs, "by") == aggs["by"]
    assert term_buckets({}, "by") == []


def test_auth_failures_uses_group_triad():
    ir = _auth_failures_ir(AuthFailuresParams())
    assert len(ir.filters) == 1
    f = ir.filters[0]
    assert f.field == "rule.groups"
    assert f.op == "in"
    assert set(f.value) == set(AUTH_FAILURE_GROUPS)


def test_compiler_should_any_minimum_match():
    ir = QueryIR(
        should_any=[
            IRFilter(field="rule.groups", op="in", value=list(AUTH_FAILURE_GROUPS)),
            IRFilter(field="rule.mitre.id", op="eq", value="T1110"),
        ],
        aggregation=IRAggregation(kind="count"),
        limit=0,
    )
    body = compile_opensearch(ir)
    bool_q = body["query"]["bool"]
    assert bool_q["minimum_should_match"] == 1
    assert len(bool_q["should"]) == 2


def test_brute_force_geoip_preview_lists_five_panels():
    preview = _preview_create_dashboard(
        CreateDashboardParams(title="BF", template="brute_force_geoip")
    )
    assert "Panels (5)" in preview
    assert "region_map" in preview
    assert "timeline" in preview


def test_template_panel_summary_count():
    assert len(template_panel_summary("brute_force_geoip")) == 5


def test_brute_force_bundle_has_region_map_vis():
    objs = build_dashboard_bundle(
        CreateDashboardParams(title="BF", template="brute_force_geoip")
    )
    joined = json.dumps(
        [
            o["document"]["visualization"]["visState"]
            for o in objs
            if o["document"]["type"] == "visualization"
        ]
    )
    assert "region_map" in joined or "choropleth" in joined.lower()
