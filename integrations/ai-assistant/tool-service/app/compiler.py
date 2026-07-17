"""Query IR -> OpenSearch DSL (the first storage adapter, D29/D22).

Values only ever land in filter clauses. No scripts, no regexp, no wildcards,
no string concatenation - the whole injection story is this module plus the
pydantic validation above it (D4). The ClickHouse adapter will be a sibling
module compiling the same IR to parameterized SQL.
"""
from __future__ import annotations

from .models import QueryIR

# Fields projected into evidence. _id rides along implicitly.
# Keep aligned with veracity._flatten_hit — unused fields waste evidence budget (E14).
SOURCE_FIELDS = [
    "timestamp",
    "rule.id",
    "rule.level",
    "rule.description",
    "rule.mitre.id",
    "agent.name",
    "data.srcip",
    "data.dstuser",
]

# Narrower projection for timeline / related-list tools.
SOURCE_FIELDS_LIST = [
    "timestamp",
    "rule.id",
    "rule.level",
    "rule.description",
    "agent.name",
    "data.srcip",
    "data.dstuser",
]

# Detail projection for single-alert explain (includes attacker-controlled full_log).
SOURCE_FIELDS_DETAIL = SOURCE_FIELDS + [
    "full_log",
    "rule.groups",
    "agent.id",
]


def compile_opensearch(ir: QueryIR) -> dict:
    gte, lte = ir.time_range.iso()
    filter_clauses: list[dict] = [
        {"range": {"timestamp": {"gte": gte, "lte": lte}}}
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
    if ir.should_any:
        should_clauses = []
        for f in ir.should_any:
            clause = _clause(f)
            if clause:
                should_clauses.append(clause)
        if should_clauses:
            bool_query["should"] = should_clauses
            bool_query["minimum_should_match"] = 1
    if must_clauses:
        bool_query["must"] = must_clauses

    source = list(ir.source_fields) if ir.source_fields else list(SOURCE_FIELDS)
    body: dict = {
        "query": {"bool": bool_query},
        "track_total_hits": True,  # exact totals, the datastore-computed count
        "_source": source,
    }

    if ir.aggregation is None:
        body["size"] = ir.limit
        field, direction = ir.sort.split(":")
        body["sort"] = [{field: {"order": direction}}]
        return body

    agg = ir.aggregation
    body["size"] = 0  # aggregation queries return numbers, not documents
    if agg.kind == "count":
        pass  # track_total_hits already computes it
    elif agg.kind == "terms":
        terms = {"terms": {"field": agg.field, "size": agg.size}}
        if agg.last_seen:
            body["aggs"] = {
                "by": {
                    "terms": terms["terms"],
                    "aggs": {"last_seen": {"max": {"field": "timestamp"}}},
                }
            }
        else:
            body["aggs"] = {"by": terms}
    elif agg.kind == "cardinality":
        body["aggs"] = {"distinct": {"cardinality": {"field": agg.field}}}
    elif agg.kind == "date_histogram":
        body["aggs"] = {
            "over_time": {
                "date_histogram": {
                    "field": "timestamp",
                    "fixed_interval": agg.interval,
                    "min_doc_count": 0,
                }
            }
        }
    return body
