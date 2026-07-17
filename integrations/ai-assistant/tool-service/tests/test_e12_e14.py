"""Unit tests for E12/E14: env card helpers and field projection."""
from __future__ import annotations

from datetime import datetime, timezone

from app.compiler import (
    SOURCE_FIELDS,
    SOURCE_FIELDS_DETAIL,
    SOURCE_FIELDS_LIST,
    compile_opensearch,
)
from app.environment_card import _retention_from_names
from app.models import IRFilter, QueryIR, TimeRange
from app.tools import GetAlertParams, _get_alert_ir


def test_retention_from_index_names():
    assert _retention_from_names([]) is None
    assert "2024.01.01" in (
        _retention_from_names(["wazuh-alerts-4.x-2024.01.01"]) or ""
    )
    text = _retention_from_names(
        [
            "wazuh-alerts-4.x-2024.01.01",
            "wazuh-alerts-4.x-2024.01.15",
            "other",
        ]
    )
    assert text is not None
    assert "2024.01.01" in text and "2024.01.15" in text


def test_default_source_projection_aligned():
    ir = QueryIR(
        time_range=TimeRange(
            gte=datetime(2026, 7, 1, tzinfo=timezone.utc),
            lte=datetime(2026, 7, 2, tzinfo=timezone.utc),
        ),
        limit=5,
    )
    dsl = compile_opensearch(ir)
    assert dsl["_source"] == SOURCE_FIELDS
    assert "location" not in dsl["_source"]
    assert "full_log" not in dsl["_source"]


def test_get_alert_uses_detail_projection():
    ir = _get_alert_ir(GetAlertParams(alert_id="abc"))
    assert ir.source_fields == SOURCE_FIELDS_DETAIL
    dsl = compile_opensearch(ir)
    assert "full_log" in dsl["_source"]


def test_custom_list_projection():
    ir = QueryIR(
        time_range=TimeRange(
            gte=datetime(2026, 7, 1, tzinfo=timezone.utc),
            lte=datetime(2026, 7, 2, tzinfo=timezone.utc),
        ),
        filters=[IRFilter(field="agent.name", op="eq", value="web-01")],
        limit=10,
        source_fields=SOURCE_FIELDS_LIST,
    )
    assert compile_opensearch(ir)["_source"] == SOURCE_FIELDS_LIST
