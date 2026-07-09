"""Evidence cache keying (D41) and evidence compaction honesty."""
from datetime import datetime, timezone

from app import veracity
from app.config import CFG
from app.models import IRFilter, QueryIR, TimeRange
from app.veracity import Evidence, _cache_key


def _tr(gte_s: int, lte_s: int) -> TimeRange:
    return TimeRange(
        gte=datetime.fromtimestamp(gte_s, tz=timezone.utc),
        lte=datetime.fromtimestamp(lte_s, tz=timezone.utc),
    )


def test_cache_key_buckets_now_jitter(monkeypatch):
    monkeypatch.setattr(CFG, "evidence_cache_ttl", 60)
    a = QueryIR(time_range=_tr(600, 3600))
    b = QueryIR(time_range=_tr(610, 3650))  # same 60s buckets
    c = QueryIR(time_range=_tr(600, 3720))  # lte in the next bucket
    assert _cache_key(a) == _cache_key(b)
    assert _cache_key(a) != _cache_key(c)


def test_cache_key_distinguishes_filters(monkeypatch):
    monkeypatch.setattr(CFG, "evidence_cache_ttl", 60)
    base = QueryIR(time_range=_tr(600, 3600))
    other = QueryIR(time_range=_tr(600, 3600),
                    filters=[IRFilter(field="rule.level", op="gte", value=10)])
    assert _cache_key(base) != _cache_key(other)


def test_tool_result_discloses_cache_hit():
    ev = Evidence(total=3, total_computed_by="datastore", hits=[], aggregations={},
                  checks_passed=["dry_run"], checks_skipped=[], from_cache=True)
    assert ev.to_tool_result()["served_from_cache"] is True


def test_tool_result_compacts_to_budget(monkeypatch):
    monkeypatch.setattr(CFG, "evidence_budget_chars", 600)
    hits = [{"_id": f"id{i}", "timestamp": "t", "rule.id": "1", "rule.level": 3,
             "rule.description": "x" * 80, "agent.name": "a", "data.srcip": "s",
             "data.dstuser": "u"} for i in range(20)]
    ev = Evidence(total=20, total_computed_by="datastore", hits=hits,
                  aggregations={}, checks_passed=[], checks_skipped=[])
    payload = ev.to_tool_result()
    assert payload["alerts_truncated"] is True
    assert payload["total_matching"] == 20  # the exact total survives compaction
    assert len(payload["alerts"]) < 20
