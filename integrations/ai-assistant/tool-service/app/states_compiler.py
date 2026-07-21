"""States Query IR -> OpenSearch DSL (V3.4 vulnerabilities)."""
from __future__ import annotations

from .index_families import VULNERABILITIES_TIME_FIELD, VULN_SOURCE_FIELDS
from .states_models import StatesQueryIR


def compile_vulnerabilities(ir: StatesQueryIR) -> dict:
    gte, lte = ir.time_range.iso()
    filter_clauses: list[dict] = [
        {"range": {VULNERABILITIES_TIME_FIELD: {"gte": gte, "lte": lte}}}
    ]
    must_clauses: list[dict] = []

    def _clause(f) -> dict:
        if f.field == "_id":
            values = f.value if isinstance(f.value, list) else [f.value]
            return {"ids": {"values": values}}
        if f.op == "eq":
            return {"term": {f.field: {"value": f.value}}}
        if f.op == "in":
            return {"terms": {f.field: f.value}}
        if f.op in ("gte", "lte"):
            return {"range": {f.field: {f.op: f.value}}}
        if f.op == "exists":
            return {"exists": {"field": f.field}}
        if f.op == "match":
            must_clauses.append({"match": {f.field: {"query": f.value}}})
            return {}
        raise ValueError(f"unsupported filter op {f.op!r}")

    for f in ir.filters:
        clause = _clause(f)
        if clause:
            filter_clauses.append(clause)

    bool_query: dict = {"filter": filter_clauses}
    if must_clauses:
        bool_query["must"] = must_clauses

    body: dict = {
        "query": {"bool": bool_query},
        "track_total_hits": True,
        "_source": VULN_SOURCE_FIELDS,
    }

    if ir.aggregation is None:
        body["size"] = ir.limit
        field, direction = ir.sort.split(":")
        body["sort"] = [{field: {"order": direction}}]
        return body

    agg = ir.aggregation
    body["size"] = 0
    if agg.kind == "count":
        pass
    elif agg.kind == "terms":
        body["aggs"] = {"by": {"terms": {"field": agg.field, "size": agg.size}}}
    elif agg.kind == "cardinality":
        body["aggs"] = {"distinct": {"cardinality": {"field": agg.field}}}
    elif agg.kind == "date_histogram":
        body["aggs"] = {
            "over_time": {
                "date_histogram": {
                    "field": VULNERABILITIES_TIME_FIELD,
                    "fixed_interval": agg.interval,
                    "min_doc_count": 0,
                }
            }
        }
    return body
