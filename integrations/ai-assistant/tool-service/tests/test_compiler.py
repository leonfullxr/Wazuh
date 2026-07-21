"""IR -> OpenSearch DSL compilation (D29). Values only ever land in filter
clauses, totals are always exact, aggregation queries return no documents."""
from datetime import datetime, timezone

from app.compiler import compile_opensearch
from app.models import IRAggregation, IRFilter, QueryIR, TimeRange

T0 = datetime(2026, 7, 1, tzinfo=timezone.utc)
T1 = datetime(2026, 7, 2, tzinfo=timezone.utc)
TR = TimeRange(gte=T0, lte=T1)


def test_search_query_shape():
    ir = QueryIR(
        time_range=TR,
        filters=[
            IRFilter(field="rule.id", op="in", value=["5710"]),
            IRFilter(field="rule.level", op="gte", value=10),
            IRFilter(field="agent.name", op="eq", value="web-01"),
            IRFilter(field="rule.description", op="match", value="sql injection"),
        ],
        limit=25,
    )
    dsl = compile_opensearch(ir)
    assert dsl["track_total_hits"] is True
    assert dsl["size"] == 25
    assert dsl["sort"] == [{"timestamp": {"order": "desc"}}]
    filt = dsl["query"]["bool"]["filter"]
    assert {"range": {"timestamp": {"gte": T0.isoformat(), "lte": T1.isoformat()}}} in filt
    assert {"terms": {"rule.id": ["5710"]}} in filt
    assert {"range": {"rule.level": {"gte": 10}}} in filt
    assert {"term": {"agent.name": {"value": "web-01"}}} in filt
    assert dsl["query"]["bool"]["must"] == [
        {"match": {"rule.description": {"query": "sql injection"}}}
    ]


def test_id_lookup_uses_ids_query():
    ir = QueryIR(time_range=TR,
                 filters=[IRFilter(field="_id", op="eq", value="abc123")], limit=1)
    filt = compile_opensearch(ir)["query"]["bool"]["filter"]
    assert {"ids": {"values": ["abc123"]}} in filt


def test_aggregation_queries_return_no_documents():
    ir = QueryIR(time_range=TR,
                 aggregation=IRAggregation(kind="terms", field="agent.name", size=5))
    dsl = compile_opensearch(ir)
    assert dsl["size"] == 0
    assert dsl["aggs"] == {"by": {"terms": {"field": "agent.name", "size": 5}}}
    assert "sort" not in dsl


def test_terms_last_seen_subaggregation():
    ir = QueryIR(
        time_range=TR,
        aggregation=IRAggregation(
            kind="terms", field="agent.name", size=5, last_seen=True
        ),
    )
    dsl = compile_opensearch(ir)
    assert dsl["aggs"]["by"]["terms"] == {"field": "agent.name", "size": 5}
    assert dsl["aggs"]["by"]["aggs"] == {"last_seen": {"max": {"field": "timestamp"}}}


def test_histogram_and_cardinality():
    hist = compile_opensearch(
        QueryIR(time_range=TR, aggregation=IRAggregation(kind="date_histogram", interval="1h"))
    )
    assert hist["aggs"]["over_time"]["date_histogram"]["fixed_interval"] == "1h"
    card = compile_opensearch(
        QueryIR(time_range=TR, aggregation=IRAggregation(kind="cardinality", field="data.srcip"))
    )
    assert card["aggs"]["distinct"]["cardinality"]["field"] == "data.srcip"


def _keys(node):
    if isinstance(node, dict):
        for k, v in node.items():
            yield k
            yield from _keys(v)
    elif isinstance(node, list):
        for item in node:
            yield from _keys(item)


def test_no_script_clauses_anywhere():
    ir = QueryIR(time_range=TR,
                 filters=[IRFilter(field="data.srcip", op="eq", value="1.2.3.4")])
    keys = set(_keys(compile_opensearch(ir)))
    assert not {"script", "script_score", "regexp", "wildcard"} & keys
