"""Veracity pipeline for vulnerability states indices (V3.4)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .indexer import Indexer, get_indexer
from .principal import Principal, env_id_for, indexer_headers
from .states_compiler import compile_vulnerabilities
from .states_models import StatesQueryIR
from .veracity import VeracityError


def _flatten_vuln_hit(hit: dict) -> dict:
    src = hit.get("_source", {})

    def get(path: str):
        node = src
        for part in path.split("."):
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
        return node

    return {
        "_id": hit["_id"],
        "vulnerability.detected_at": get("vulnerability.detected_at"),
        "vulnerability.id": get("vulnerability.id"),
        "vulnerability.severity": get("vulnerability.severity"),
        "vulnerability.status": get("vulnerability.status"),
        "vulnerability.score.base": get("vulnerability.score.base"),
        "agent.name": get("agent.name"),
        "package.name": get("package.name"),
        "package.version": get("package.version"),
    }


@dataclass
class StatesEvidence:
    total: int
    total_computed_by: str
    hits: list[dict]
    aggregations: dict
    checks_passed: list[str]
    checks_skipped: list[str]
    zero_hit_diagnosis: Optional[dict] = None
    window: dict = field(default_factory=dict)
    from_cache: bool = False

    def to_tool_result(self) -> dict:
        return {
            "total_matching": self.total,
            "total_computed_by": self.total_computed_by,
            "executed_window": self.window,
            "aggregations": self.aggregations,
            "veracity_checks_passed": self.checks_passed,
            "veracity_checks_skipped": self.checks_skipped,
            "records": self.hits,
            "index_family": "vulnerabilities",
        }


async def _check_vuln_mapping(
    ir: StatesQueryIR, indexer: Indexer, headers: dict[str, str]
) -> Optional[str]:
    mapping = await indexer.get_mapping_index(indexer.vulnerabilities_index, headers)
    if mapping is None:
        return None
    fields_used = [f.field for f in ir.filters if f.field != "_id"]
    if ir.aggregation and ir.aggregation.field:
        fields_used.append(ir.aggregation.field)
    for f in fields_used:
        if f in mapping:
            continue
        if f"{f}.keyword" in mapping or any(
            k == f or k.startswith(f + ".") for k in mapping
        ):
            continue
        raise VeracityError(
            f"field '{f}' does not exist in the vulnerability states mapping"
        )
    return "mapping_validation"


async def execute_vulnerabilities_ir(
    ir: StatesQueryIR, principal: Principal
) -> StatesEvidence:
    env_id = env_id_for(principal)
    indexer = get_indexer(env_id)
    headers = indexer_headers(principal)
    checks_passed: list[str] = []
    checks_skipped: list[str] = []

    ran = await _check_vuln_mapping(ir, indexer, headers)
    if ran:
        checks_passed.append(ran)
    else:
        checks_skipped.append("mapping_validation")

    dsl = compile_vulnerabilities(ir)
    validation = await indexer.dry_run_index(
        indexer.vulnerabilities_index, headers, dsl
    )
    if not validation.get("valid", False):
        raise VeracityError(f"compiled query failed validation: {validation}")
    checks_passed.append("dry_run")

    res = await indexer.search_index(indexer.vulnerabilities_index, headers, dsl)
    total = res["hits"]["total"]["value"]
    checks_passed.append("datastore_computed_counts")

    aggregations: dict = {}
    for name, agg in res.get("aggregations", {}).items():
        if "buckets" in agg:
            buckets = []
            for b in agg["buckets"]:
                buckets.append(
                    {
                        "key": b.get("key_as_string", b["key"]),
                        "count": b["doc_count"],
                    }
                )
            aggregations[name] = buckets
        elif "value" in agg:
            aggregations[name] = agg["value"]

    hits = [_flatten_vuln_hit(h) for h in res["hits"]["hits"]]
    gte, lte = ir.time_range.iso()
    return StatesEvidence(
        total=total,
        total_computed_by="datastore",
        hits=hits,
        aggregations=aggregations,
        checks_passed=checks_passed,
        checks_skipped=checks_skipped,
        window={"gte": gte, "lte": lte},
    )
