"""Unit tests for E4 IR builders, answer shapes, and playbook binding."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.answer_shapes import select_shape, shape_text
from app.playbooks import _dig, _question_slots, _resolve_bind
from app.tools import (
    AlertTimelineParams,
    MitreCoverageParams,
    REGISTRY,
    _alert_timeline_ir,
    _mitre_coverage_ir,
)
from app.correlation import CompareWindowsParams, RelatedAlertsParams


def test_e4_tools_registered():
    for name in (
        "alert_timeline",
        "related_alerts",
        "compare_windows",
        "mitre_coverage",
        "agent_posture",
    ):
        assert name in REGISTRY


def test_alert_timeline_ir_ascending():
    ir = _alert_timeline_ir(AlertTimelineParams(agent_name="web-01", size=10))
    assert ir.sort == "timestamp:asc"
    assert ir.limit == 10
    assert any(f.field == "agent.name" for f in ir.filters)


def test_alert_timeline_requires_entity():
    with pytest.raises(Exception):
        AlertTimelineParams()


def test_mitre_coverage_ir():
    ir = _mitre_coverage_ir(MitreCoverageParams(size=5))
    assert ir.aggregation is not None
    assert ir.aggregation.field == "rule.mitre.id"
    assert ir.limit == 0


def test_related_alerts_requires_pivot():
    with pytest.raises(Exception):
        RelatedAlertsParams()


def test_compare_windows_params():
    now = datetime.now(timezone.utc)
    p = CompareWindowsParams(
        window_a={"gte": now - timedelta(days=7), "lte": now},
        window_b={"gte": now - timedelta(days=14), "lte": now - timedelta(days=7)},
    )
    assert p.window_a.gte < p.window_a.lte


def test_dig_flat_dotted_keys():
    hit = {"data.srcip": "1.2.3.4", "rule.mitre.id": "T1110"}
    assert _dig(hit, "data.srcip") == "1.2.3.4"
    assert _dig({"hits": [hit]}, "hits.0.rule.mitre.id") == "T1110"


def test_question_slots_alert_and_agent():
    ctx = _question_slots("Investigate alert nAP8a58B0Y_4M-XCNW9z")
    assert ctx["question"]["alert_id"] == "nAP8a58B0Y_4M-XCNW9z"
    ctx2 = _question_slots("triage agent web-01 posture")
    assert ctx2["question"]["agent"] == "web-01"
    assert ctx2["question"]["agent_list"] == ["web-01"]


def test_resolve_bind_prior():
    prior = [{"hits": [{"data.srcip": "10.0.0.1"}], "top_source_ips": [{"key": "9.9.9.9"}]}]
    assert _resolve_bind("prior.0.hits.0.data.srcip", {}, prior) == "10.0.0.1"
    assert _resolve_bind("prior.0.top_source_ips.0.key", {}, prior) == "9.9.9.9"


def test_select_shape_playbook_triage():
    got = select_shape("anything", playbook=True, lang="en")
    assert got is not None
    assert got[0] == "triage_card"
    assert "Triage" in got[1]


def test_select_shape_exec():
    got = select_shape("Give me an executive summary of this week", lang="en")
    assert got is not None
    assert got[0] == "exec_rollup"


def test_shape_text_bilingual():
    assert "Resumen" in shape_text("triage_card", "es")
    assert "Summary" in shape_text("triage_card", "en")
