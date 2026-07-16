"""V3.4 states-index unit tests."""
from app.index_families import VULNERABILITIES_TIME_FIELD, VULN_ALLOWED_FIELDS
from app.states_compiler import compile_vulnerabilities
from app.states_models import (
    StatesIRAggregation,
    StatesIRFilter,
    StatesQueryIR,
)


def test_vuln_allowlist_is_separate_from_alerts():
    from app.models import ALLOWED_FIELDS

    assert "rule.groups" in ALLOWED_FIELDS
    assert "rule.groups" not in VULN_ALLOWED_FIELDS
    assert "vulnerability.severity" in VULN_ALLOWED_FIELDS


def test_compile_vulnerabilities_uses_detected_at_window():
    ir = StatesQueryIR(
        filters=[
            StatesIRFilter(
                field="vulnerability.severity",
                op="eq",
                value="high",
            )
        ],
        aggregation=StatesIRAggregation(kind="count"),
        limit=0,
    )
    body = compile_vulnerabilities(ir)
    assert VULNERABILITIES_TIME_FIELD in body["query"]["bool"]["filter"][0]["range"]
    assert body["query"]["bool"]["filter"][1] == {
        "term": {"vulnerability.severity": {"value": "high"}}
    }
    assert body["size"] == 0


def test_count_vulnerabilities_ir_filters_severity():
    from app.states_tools import CountVulnerabilitiesParams, count_vulnerabilities_ir

    ir = count_vulnerabilities_ir(CountVulnerabilitiesParams(severity="high"))
    assert len(ir.filters) == 1
    assert ir.filters[0].field == "vulnerability.severity"
    assert ir.aggregation is not None
    assert ir.aggregation.kind == "count"
