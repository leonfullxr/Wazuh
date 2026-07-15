"""Query IR -> OpenSearch DSL (the first storage adapter, D29/D22).

Values only ever land in filter clauses. No scripts, no regexp, no wildcards,
no string concatenation - the whole injection story is this module plus the
pydantic validation above it (D4). The ClickHouse adapter will be a sibling
module compiling the same IR to parameterized SQL.
"""
from __future__ import annotations

from .models import QueryIR

# Fields projected into evidence. _id rides along implicitly.
SOURCE_FIELDS = [
    "timestamp",
    "rule.id",
    "rule.level",
    "rule.description",
    "rule.groups",
    "rule.mitre.id",
    "agent.id",
    "agent.name",
    "data.srcip",
    "data.srcuser",
    "data.dstuser",
    "location",
]


def compile_opensearch(ir: QueryIR) -> dict:
    gte, lte = ir.time_range.iso()
    filter_clauses: list[dict] = [
        {"range": {"timestamp": {"gte": gte, "lte": lte}}}
    ]
    must_clauses: list[dict] = []

    for f in ir.filters:
        if f.field == "_id":
            values = f.value if isinstance(f.value, list) else [f.value]
            filter_clauses.append({"ids": {"values": values}})
        elif f.op == "eq":
            filter_clauses.append({"term": {f.field: {"value": f.value}}})
        elif f.op == "in":
            filter_clauses.append({"terms": {f.field: f.value}})
        elif f.op in ("gte", "lte"):
            filter_clauses.append({"range": {f.field: {f.op: f.value}}})
        elif f.op == "exists":
            filter_clauses.append({"exists": {"field": f.field}})
        elif f.op == "match":
            must_clauses.append({"match": {f.field: {"query": f.value}}})

    bool_query: dict = {"filter": filter_clauses}
    if must_clauses:
        bool_query["must"] = must_clauses

    body: dict = {
        "query": {"bool": bool_query},
        "track_total_hits": True,  # exact totals, the datastore-computed count
        "_source": SOURCE_FIELDS,
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
