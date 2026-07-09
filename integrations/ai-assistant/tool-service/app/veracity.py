"""The veracity subsystem (D24, D32) - the product thesis, not an afterthought.

Every query, from any lane, passes through this pipeline:

  1. mapping-aware validation  - reject fields the live index does not have
  2. pre-execution dry-run     - the datastore validates the compiled query
  3. execution as the analyst  - via the turn JWT (D11)
  4. zero-hit differential diagnosis - "no such events" vs "wrong query"

Counts are enforced structurally: totals and aggregation values come from the
datastore response, and the synthesis prompt receives them as explicit fields
the model must cite, never as a list to count.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, Optional

from .compiler import compile_opensearch
from .config import CFG
from .indexer import INDEXER
from .models import ALLOWED_FIELDS, QueryIR


class VeracityError(Exception):
    """Raised when a query fails validation. The message is returned to the
    model as a tool error so it can self-correct - never retried raw."""


@dataclass
class Evidence:
    """What the synthesis step is allowed to see: compacted, verified, and
    carrying its own provenance."""

    total: int
    total_computed_by: str
    hits: list[dict]
    aggregations: dict
    checks_passed: list[str]
    checks_skipped: list[str]
    zero_hit_diagnosis: Optional[dict] = None
    compiled_query: dict = field(default_factory=dict)
    from_cache: bool = False

    def to_tool_result(self) -> dict:
        """The JSON handed back to the model, kept inside the evidence budget."""
        payload = {
            "total_matching": self.total,
            "total_computed_by": self.total_computed_by,
            "aggregations": self.aggregations,
            "veracity_checks_passed": self.checks_passed,
            "veracity_checks_skipped": self.checks_skipped,
            "alerts": self.hits,
        }
        if self.from_cache:
            payload["served_from_cache"] = True  # honesty over freshness (D41)
        if self.zero_hit_diagnosis is not None:
            payload["zero_hit_diagnosis"] = self.zero_hit_diagnosis
        # Evidence compaction: drop hits until the payload fits.
        while (
            len(json.dumps(payload, default=str)) > CFG.evidence_budget_chars
            and payload["alerts"]
        ):
            payload["alerts"] = payload["alerts"][:-1]
            payload["alerts_truncated"] = True
        return payload


def _flatten_hit(hit: dict) -> dict:
    src = hit.get("_source", {})

    def get(path: str) -> Any:
        node = src
        for part in path.split("."):
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
        return node

    desc = get("rule.description")
    return {
        "_id": hit["_id"],
        "timestamp": get("timestamp"),
        "rule.id": get("rule.id"),
        "rule.level": get("rule.level"),
        "rule.description": (desc or "")[:160],
        "agent.name": get("agent.name"),
        "data.srcip": get("data.srcip"),
        "data.dstuser": get("data.dstuser"),
    }


async def _check_mapping(ir: QueryIR, user_jwt: str) -> Optional[str]:
    """Check 1. Returns the check name if it ran, None if it was skipped."""
    mapping = await INDEXER.get_mapping(user_jwt)
    if mapping is None:
        return None
    fields_used = [f.field for f in ir.filters if f.field != "_id"]
    if ir.aggregation and ir.aggregation.field:
        fields_used.append(ir.aggregation.field)
    for f in fields_used:
        if f in mapping:
            continue
        # keyword sub-fields of text fields count as present
        if f"{f}.keyword" in mapping or any(
            k == f or k.startswith(f + ".") for k in mapping
        ):
            continue
        raise VeracityError(
            f"field '{f}' does not exist in the live index mapping. "
            f"Nearby fields: "
            f"{[k for k in sorted(mapping) if k.split('.')[0] == f.split('.')[0]][:8]}"
        )
    return "mapping_validation"


async def _diagnose_zero_hits(ir: QueryIR, user_jwt: str) -> dict:
    """Check 4. A zero-result query is ambiguous between 'no such events' and
    'wrong query'. Probe the window and each filter individually so the answer
    can be precise instead of hopeful."""
    window_ir = QueryIR(time_range=ir.time_range, filters=[], limit=0)
    window_res = await INDEXER.search_as_user(
        user_jwt, compile_opensearch(window_ir)
    )
    diagnosis: dict = {
        "documents_in_time_window": window_res["hits"]["total"]["value"],
        "per_filter_matches": {},
    }
    for f in ir.filters:
        probe = QueryIR(time_range=ir.time_range, filters=[f], limit=0)
        res = await INDEXER.search_as_user(user_jwt, compile_opensearch(probe))
        key = f"{f.field} {f.op} {f.value}"
        diagnosis["per_filter_matches"][key] = res["hits"]["total"]["value"]
    diagnosis["interpretation"] = (
        "window empty: no data exists in this time range at all"
        if diagnosis["documents_in_time_window"] == 0
        else "data exists in the window: the zero result is real for this "
        "filter combination, or one filter (see per_filter_matches with 0) "
        "references a value that matches nothing"
    )
    return diagnosis


# IR-keyed evidence cache (D41). The IR is canonical, so identical query
# plans hash identically once the "now"-anchored window is bucketed to the
# TTL grid. Served results carry served_from_cache so honesty survives reuse.
_EVIDENCE_CACHE: dict[str, tuple[float, "Evidence"]] = {}


def _cache_key(ir: QueryIR) -> str:
    doc = ir.model_dump(mode="json")
    ttl = CFG.evidence_cache_ttl
    for bound in ("gte", "lte"):
        ts = datetime.fromisoformat(doc["time_range"][bound])
        doc["time_range"][bound] = int(ts.timestamp()) // ttl * ttl
    return hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()


async def execute_ir(ir: QueryIR, user_jwt: str) -> Evidence:
    """The full pipeline. Every lane funnels through here."""
    if CFG.evidence_cache_ttl > 0:
        key = _cache_key(ir)
        entry = _EVIDENCE_CACHE.get(key)
        if entry and entry[0] > time.monotonic():
            return replace(entry[1], from_cache=True)

    checks_passed: list[str] = []
    checks_skipped: list[str] = []

    # 1. mapping-aware validation
    ran = await _check_mapping(ir, user_jwt)
    if ran:
        checks_passed.append(ran)
    else:
        checks_skipped.append("mapping_validation")

    dsl = compile_opensearch(ir)

    # 2. pre-execution dry-run
    validation = await INDEXER.dry_run_as_user(user_jwt, dsl)
    if not validation.get("valid", False):
        raise VeracityError(f"compiled query failed validation: {validation}")
    checks_passed.append("dry_run")

    # 3. execute as the analyst
    res = await INDEXER.search_as_user(user_jwt, dsl)
    total = res["hits"]["total"]["value"]
    checks_passed.append("datastore_computed_counts")

    aggregations: dict = {}
    for name, agg in res.get("aggregations", {}).items():
        if "buckets" in agg:
            aggregations[name] = [
                {"key": b.get("key_as_string", b["key"]), "count": b["doc_count"]}
                for b in agg["buckets"]
            ]
        elif "value" in agg:
            aggregations[name] = agg["value"]

    hits = [_flatten_hit(h) for h in res["hits"]["hits"]]

    # 4. zero-hit differential diagnosis
    zero_diag = None
    if total == 0:
        zero_diag = await _diagnose_zero_hits(ir, user_jwt)
        checks_passed.append("zero_hit_diagnosis")

    evidence = Evidence(
        total=total,
        total_computed_by="datastore",
        hits=hits,
        aggregations=aggregations,
        checks_passed=checks_passed,
        checks_skipped=checks_skipped,
        zero_hit_diagnosis=zero_diag,
        compiled_query=dsl,
    )
    if CFG.evidence_cache_ttl > 0:
        if len(_EVIDENCE_CACHE) > 512:  # cheap bound: drop expired entries
            now = time.monotonic()
            for stale in [k for k, v in _EVIDENCE_CACHE.items() if v[0] <= now]:
                del _EVIDENCE_CACHE[stale]
        _EVIDENCE_CACHE[key] = (time.monotonic() + CFG.evidence_cache_ttl, evidence)
    return evidence
