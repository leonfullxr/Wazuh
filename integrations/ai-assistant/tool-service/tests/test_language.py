"""Language detection (V3.8a)."""
from app.language import detect, language_name
from app.lane0 import EXEMPLARS, Lane0Match, render_local
from app.models import QueryIR, TimeRange
from app.veracity import Evidence


def test_detect_english_question():
    assert detect("How many alerts did we get in the last 24 hours?") == "en"


def test_detect_spanish_question():
    assert detect("Cuantas alertas hemos tenido en las ultimas 24 horas?") == "es"


def test_detect_spanish_diacritics():
    assert detect("¿Qué usuarios tienen más fallos?") == "es"


def test_language_name():
    assert language_name("es") == "Spanish"
    assert language_name("en") == "English"


def test_render_local_uses_question_language_not_exemplar():
    ex = next(e for e in EXEMPLARS if e.id == "count-alerts" and e.lang == "es")
    match = Lane0Match(exemplar=ex, score=0.9, params={})
    ir = QueryIR(time_range=TimeRange(), limit=0)
    ev = Evidence(
        total=5,
        total_computed_by="datastore",
        hits=[],
        aggregations={},
        checks_passed=["dry_run"],
        checks_skipped=[],
    )
    out = render_local(match, ir, ev, "how many alerts did we get in the last 24 hours")
    assert "matching alerts" in out
    assert "alertas coincidentes" not in out
