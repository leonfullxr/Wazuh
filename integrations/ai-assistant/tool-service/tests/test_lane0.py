"""Lane 0 slot extraction and template plumbing (D40). Deterministic and
bilingual by design, so it is exactly the kind of code unit tests own."""
from datetime import datetime, timezone

from app.lane0 import EXEMPLARS, Lane0Match, _cosine, _set_path, extract_slots, render_local
from app.models import IRAggregation, QueryIR, TimeRange
from app.veracity import Evidence


def _window_hours(slots) -> float:
    gte = datetime.fromisoformat(slots["time_range"]["gte"])
    lte = datetime.fromisoformat(slots["time_range"]["lte"])
    return (lte - gte).total_seconds() / 3600


def test_time_window_english():
    assert round(_window_hours(extract_slots("alerts in the last 12 hours"))) == 12
    assert round(_window_hours(extract_slots("failures in the past 3 days"))) == 72
    assert round(_window_hours(extract_slots("top rules this week"))) == 168
    assert round(_window_hours(extract_slots("no time given"))) == 24  # default


def test_time_window_spanish():
    assert round(_window_hours(extract_slots("las ultimas 48 horas"))) == 48
    assert round(_window_hours(extract_slots("los ultimos 7 dias"))) == 168
    assert round(_window_hours(extract_slots("esta semana"))) == 168


def test_entity_slots():
    slots = extract_slots("top 7 alerts for agent web-01 rule 5710 level 10")
    assert slots["size"] == 7
    assert slots["agent"] == ["web-01"]
    assert slots["rule"] == ["5710"]
    assert slots["severity"] == 10


def test_spanish_entity_slots():
    slots = extract_slots("alertas del agente db-01 con la regla 31103")
    assert slots["agent"] == ["db-01"]
    assert slots["rule"] == ["31103"]


def test_set_path_nested():
    params = {"aggregation": {"kind": "terms", "field": "agent.name", "size": 10}}
    _set_path(params, "aggregation.size", 5)
    _set_path(params, "time_range", {"gte": "a", "lte": "b"})
    assert params["aggregation"]["size"] == 5
    assert params["time_range"] == {"gte": "a", "lte": "b"}


def test_cosine():
    assert _cosine([1.0, 0.0], [1.0, 0.0]) == 1.0
    assert _cosine([1.0, 0.0], [0.0, 1.0]) == 0.0


def test_exemplar_templates_validate_against_their_tools():
    """Every curated template must produce a valid IR out of the box - a
    template that cannot validate would silently escalate every time."""
    from app import tools as toolsmod
    from app.states_models import StatesQueryIR

    for ex in EXEMPLARS:
        tool = toolsmod.REGISTRY.get(ex.tool)
        assert tool is not None, f"exemplar {ex.id} names unknown tool {ex.tool}"
        params = tool.schema.model_validate(ex.params)
        if tool.knowledge or tool.environment or tool.composite:
            # These do not produce an alerts QueryIR; lane 0 escalates them.
            continue
        ir = tool.to_ir(params)
        assert isinstance(ir, (QueryIR, StatesQueryIR)), (
            f"exemplar {ex.id} produced {type(ir).__name__}"
        )
        if tool.states:
            assert isinstance(ir, StatesQueryIR)
        else:
            assert isinstance(ir, QueryIR)


def test_render_local_terms():
    ex = next(e for e in EXEMPLARS if e.id == "noisy-agents" and e.lang == "en")
    match = Lane0Match(exemplar=ex, score=0.91, params={})
    ir = QueryIR(time_range=TimeRange(),
                 aggregation=IRAggregation(kind="terms", field="agent.name", size=5),
                 limit=0)
    ev = Evidence(total=120, total_computed_by="datastore", hits=[],
                  aggregations={"by": [{"key": "web-01", "count": 80},
                                       {"key": "db-01", "count": 40}]},
                  checks_passed=["dry_run"], checks_skipped=[])
    out = render_local(match, ir, ev)
    assert "1. web-01 (80)" in out
    assert "2. db-01 (40)" in out


def test_render_local_zero():
    ex = next(e for e in EXEMPLARS if e.id == "count-alerts" and e.lang == "es")
    match = Lane0Match(exemplar=ex, score=0.9, params={})
    ir = QueryIR(time_range=TimeRange(), limit=0)
    ev = Evidence(total=0, total_computed_by="datastore", hits=[], aggregations={},
                  checks_passed=["zero_hit_diagnosis"], checks_skipped=[])
    assert "Sin alertas" in render_local(match, ir, ev)
