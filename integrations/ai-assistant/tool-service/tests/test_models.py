"""IR validation - the first structural veracity guarantee (D4/D29)."""
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.models import IRAggregation, IRFilter, QueryIR, TimeRange


def test_field_allowlist_rejects_unknown_field():
    with pytest.raises(ValidationError, match="not allowlisted"):
        IRFilter(field="data.password", op="eq", value="x")


def test_op_type_compatibility():
    with pytest.raises(ValidationError, match="not allowed"):
        IRFilter(field="rule.level", op="match", value="ten")  # long has no match
    with pytest.raises(ValidationError, match="not allowed"):
        IRFilter(field="rule.description", op="eq", value="x")  # text only match


def test_in_requires_nonempty_list():
    with pytest.raises(ValidationError):
        IRFilter(field="rule.id", op="in", value="5710")
    with pytest.raises(ValidationError):
        IRFilter(field="rule.id", op="in", value=[])
    ok = IRFilter(field="rule.id", op="in", value=["5710", "5716"])
    assert ok.value == ["5710", "5716"]


def test_exists_drops_value():
    f = IRFilter(field="data.srcip", op="exists", value="ignored")
    assert f.value is None


def test_time_window_capped_at_90_days():
    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError, match="capped"):
        TimeRange(gte=now - timedelta(days=120), lte=now)


def test_time_window_order():
    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError, match="before"):
        TimeRange(gte=now, lte=now - timedelta(hours=1))


def test_terms_aggregation_requires_keyword_field():
    with pytest.raises(ValidationError, match="keyword"):
        IRAggregation(kind="terms", field="rule.description")  # text field
    ok = IRAggregation(kind="terms", field="agent.name", size=5)
    assert ok.size == 5


def test_query_ir_limits():
    ir = QueryIR()
    assert ir.limit == 20
    with pytest.raises(ValidationError):
        QueryIR(limit=500)
