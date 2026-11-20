"""Read-only evidence for configuring investigation ordering.

The scroll snapshot is traversed in internal document order, so the field being
verified is never itself relied on as a pagination key.
"""

import asyncio
import json
import re
from dataclasses import dataclass
from decimal import Decimal
from typing import Any
from urllib.parse import quote

import httpx

from wazuh_mcp.investigation_queries import INDEX_RE, evidence_path, timeline_sort


@dataclass(frozen=True)
class PreflightLimits:
    seconds: float = 30
    pages: int = 100
    documents: int = 10000
    bytes: int = 10_000_000
    page_size: int = 200


class _Inconclusive(Exception):
    pass


class _Violation(Exception):
    pass


_FIELD = re.compile(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\Z")
# Restrict verification to field types with unambiguous doc-value representations.
_TYPES = {"keyword", "byte", "short", "integer", "long", "unsigned_long"}


def valid_tie_breaker(field: str) -> bool:
    return isinstance(field, str) and len(field) <= 256 and _FIELD.fullmatch(field) is not None


def _complete_search(raw: dict) -> dict:
    clusters = raw.get("_clusters", {})
    if (
        not isinstance(clusters, dict)
        or any(clusters.get(key) for key in ("partial", "failed", "skipped", "running"))
        or raw.get("terminated_early") is True
    ):
        raise _Inconclusive("Search was partial")
    if raw.get("timed_out") is not False:
        raise _Inconclusive("Search timed out or lacks timeout status")
    shards = raw.get("_shards")
    if (
        not isinstance(shards, dict)
        or type(shards.get("failed")) is not int
        or shards["failed"] != 0
        or type(shards.get("total")) is not int
        or shards.get("successful", -1) != shards["total"]
    ):
        raise _Inconclusive("Search had incomplete shards")
    hits = raw.get("hits")
    if not isinstance(hits, dict) or not isinstance(hits.get("hits"), list):
        raise _Inconclusive("Invalid search response")
    return hits


def _mapping_projection(field: str) -> str:
    """Request the leaf definition, ancestor types (including nested), and source visibility."""
    parts = field.split(".")
    paths = ["*.mappings._source"]
    parent = "*.mappings"
    for part in parts[:-1]:
        parent += ".properties." + part
        paths.append(parent + ".type")
    paths.append(parent + ".properties." + parts[-1])
    return ",".join(paths)


def _mapping(mappings: dict, before: dict, field: str) -> None:
    if mappings.keys() < before.keys():
        raise _Inconclusive("Tie-breaker mapping unavailable for one or more visible indices")
    if set(mappings) != set(before):
        raise _Inconclusive("Index topology changed during verification")
    field_mapping = None
    for name in before:
        mapping = mappings[name].get("mappings", {})
        source_config = mapping.get("_source", {})
        if source_config.get("enabled") is False or source_config.get("includes") or source_config.get("excludes"):
            raise _Inconclusive("Source values are unavailable or projected")
        properties = mapping.get("properties", {})
        for part in field.split("."):
            node = properties.get(part) if isinstance(properties, dict) else None
            if not isinstance(node, dict):
                raise _Inconclusive("Tie-breaker mapping or source path is unsupported")
            if node.get("type") == "nested":
                raise _Inconclusive("Nested tie-breaker mappings are unsupported")
            properties = node.get("properties", {})
        if node.get("type") not in _TYPES:
            raise _Inconclusive("Tie-breaker mapping type is unsupported")
        if node.get("doc_values", True) is not True:
            raise _Violation("Tie-breaker is not sortable with doc values")
        if field_mapping is None:
            field_mapping = node
        elif node != field_mapping:
            raise _Inconclusive("Tie-breaker mappings differ across indices")


def _value(hit: dict, field: str) -> tuple:
    fields = hit.get("fields")
    values = fields.get(field) if isinstance(fields, dict) else None
    source = hit.get("_source")
    parts = field.split(".")
    for position, part in enumerate(parts):
        if isinstance(source, dict) and any(
            "." in key and (".".join(parts[position:]) + ".").startswith(key + ".") for key in source
        ):
            raise _Inconclusive("Literal dotted source keys are ambiguous")
        if isinstance(source, dict) and part not in source and not values:
            raise _Violation("Tie-breaker is missing from the visible alert")
        if not isinstance(source, dict) or part not in source:
            raise _Inconclusive("Tie-breaker source path is unavailable or ambiguous")
        source = source[part]
        if isinstance(source, list):
            raise _Violation("Tie-breaker is multi-valued")
    if source is None or isinstance(source, dict):
        raise _Violation("Tie-breaker is missing or null")
    if not isinstance(values, list) or len(values) != 1 or values[0] is None or isinstance(values[0], (dict, list)):
        raise _Violation("Tie-breaker is missing or multi-valued in doc values")
    value = values[0]
    if isinstance(value, str) and not value.strip():
        raise _Violation("Tie-breaker is empty")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return ("number", Decimal(str(value)))
    return (type(value).__name__, value)


async def investigation_preflight(
    indexer: Any, tie_breaker: str, *, limits: PreflightLimits = PreflightLimits()
) -> dict:
    """Examine every visible alert in a bounded snapshot, without disclosing values."""
    report = {
        "status": "inconclusive",
        "reason": "Verification could not be completed",
        "indices_checked": 0,
        "documents_checked": 0,
    }
    scroll_id = None
    used = 0

    async def request(method: str, path: str, body: dict | None = None, *, cleanup: bool = False) -> dict:
        nonlocal used
        await indexer._ensure_initialized()
        async with indexer.client.stream(
            method, indexer.base_url + path, json=body, headers={"Accept-Encoding": "identity"}
        ) as response:
            response.raise_for_status()
            if response.headers.get("content-encoding", "identity").lower() not in ("", "identity"):
                raise _Inconclusive("Compressed response cannot be verified")
            chunks = bytearray()
            async for chunk in response.aiter_raw():
                if not cleanup:
                    used += len(chunk)
                    if used > limits.bytes:
                        raise _Inconclusive("Response byte budget exceeded")
                elif len(chunks) + len(chunk) > 65536:
                    raise _Inconclusive("Invalid cleanup response")
                chunks.extend(chunk)
        value = json.loads(chunks)
        if not isinstance(value, dict):
            raise _Inconclusive("Invalid backend response")
        return value

    async def topology() -> dict[str, str]:
        result = await request(
            "GET",
            "/wazuh-alerts-*/_settings?expand_wildcards=open&allow_no_indices=false&filter_path=*.settings.index.uuid",
        )
        if not result:
            raise _Inconclusive("No visible alert indices")
        identities = {}
        for name, settings in result.items():
            if not isinstance(name, str) or not INDEX_RE.fullmatch(name) or not isinstance(settings, dict):
                raise _Inconclusive("Invalid index identity response")
            uuid = settings.get("settings", {}).get("index", {}).get("uuid")
            if not isinstance(uuid, str) or not uuid or uuid == "_na_":
                raise _Inconclusive("Index identity unavailable")
            identities[name] = uuid
        return identities

    async def run() -> None:
        nonlocal scroll_id
        if not valid_tie_breaker(tie_breaker):
            raise _Violation("Invalid tie-breaker field")
        if getattr(indexer, "ccs_prefix", ""):
            raise _Inconclusive("A direct Indexer connection is required")
        if limits.seconds <= 0 or min(limits.pages, limits.documents, limits.bytes, limits.page_size) <= 0:
            raise _Inconclusive("Invalid verification budget")
        if limits.page_size > 10_000:
            raise _Inconclusive("Page size exceeds the supported maximum of 10000")
        before = await topology()
        mappings = await request(
            "GET",
            "/wazuh-alerts-*/_mapping?expand_wildcards=open&allow_no_indices=false&filter_path="
            + _mapping_projection(tie_breaker),
        )
        _mapping(mappings, before, tie_breaker)
        for name, uuid in before.items():
            concrete = await request("GET", f"/{quote(name, safe='')}/_settings?filter_path=*.settings.index.uuid")
            if concrete.get(name, {}).get("settings", {}).get("index", {}).get("uuid") != uuid:
                raise _Inconclusive("Concrete index identity unavailable or changed")
        report["indices_checked"] = len(before)
        seen = set()
        sample_ids = {}
        total = None
        for page in range(limits.pages):
            if page == 0:
                raw = await request(
                    "POST",
                    "/wazuh-alerts-*/_search?scroll=1m&expand_wildcards=open&allow_no_indices=false&allow_partial_search_results=false",
                    {
                        "size": min(limits.page_size, limits.documents),
                        "sort": ["_doc"],
                        "track_total_hits": True,
                        "_source": [tie_breaker],
                        "docvalue_fields": [tie_breaker],
                        "query": {"match_all": {}},
                    },
                )
            else:
                raw = await request("POST", "/_search/scroll", {"scroll": "1m", "scroll_id": scroll_id})
            next_scroll = raw.get("_scroll_id")
            if isinstance(next_scroll, str) and next_scroll:
                scroll_id = next_scroll
            if not scroll_id:
                raise _Inconclusive("Search snapshot unavailable")
            hits = _complete_search(raw)
            if total is None:
                count = hits.get("total")
                if isinstance(count, dict):
                    count = count.get("value") if count.get("relation") == "eq" else None
                if type(count) is not int or count < 0:
                    raise _Inconclusive("Exact document count unavailable")
                if count > limits.documents:
                    raise _Inconclusive("Document budget exceeded")
                total = count
            rows = hits["hits"]
            if not rows:
                if report["documents_checked"] != total:
                    raise _Inconclusive("Snapshot document count was incomplete")
                break
            for hit in rows:
                if report["documents_checked"] >= limits.documents:
                    raise _Inconclusive("Document budget exceeded")
                if not isinstance(hit, dict) or hit.get("_index") not in before:
                    raise _Inconclusive("Unexpected snapshot index")
                doc_id = hit.get("_id")
                if not isinstance(doc_id, str) or not doc_id or len(doc_id) > 512:
                    raise _Inconclusive("Document identity unavailable")
                sample_ids.setdefault(hit["_index"], doc_id)
                key = _value(hit, tie_breaker)
                if key in seen:
                    raise _Violation("Tie-breaker values are not unique across visible documents")
                seen.add(key)
                report["documents_checked"] += 1
        else:
            raise _Inconclusive("Page budget exceeded")
        if sample_ids.keys() != before.keys():
            raise _Inconclusive("At least one index has no visible document for an evidence read")
        pilot = await request(
            "POST",
            "/wazuh-alerts-*/_search?allow_partial_search_results=false",
            {
                "size": 1,
                "_source": False,
                "query": {"match_all": {}},
                "sort": timeline_sort(tie_breaker),
            },
        )
        pilot_hits = _complete_search(pilot)["hits"]
        if len(pilot_hits) != 1 or not isinstance(pilot_hits[0], dict):
            raise _Inconclusive("Investigation sort could not be verified")
        sort = pilot_hits[0].get("sort")
        if not isinstance(sort, list) or len(sort) != 2 or any(value is None for value in sort):
            raise _Inconclusive("Investigation sort values unavailable")
        for name, doc_id in sample_ids.items():
            result = await request("GET", evidence_path(name, doc_id))
            if result.get("_index") != name or result.get("_id") != doc_id or result.get("found") is not True:
                raise _Inconclusive("Document read permission or identity unavailable")
            if not isinstance(result.get("_source"), dict):
                raise _Inconclusive("Document source unavailable")
        if await topology() != before:
            raise _Inconclusive("Index topology changed during verification")
        report.update(status="pass", reason="Every visible document has a unique sortable tie-breaker")

    try:
        async with asyncio.timeout(limits.seconds):
            await run()
    except httpx.HTTPStatusError as exc:
        report.update(
            status="inconclusive",
            reason="Indexer permission denied" if exc.response.status_code in (401, 403) else "Indexer request failed",
        )
    except _Violation as exc:
        report.update(status="fail", reason=str(exc))
    except _Inconclusive as exc:
        report.update(status="inconclusive", reason=str(exc))
    except Exception:
        report.update(status="inconclusive", reason="Backend request or verification failed")
    finally:
        if scroll_id:
            try:
                async with asyncio.timeout(2):
                    cleanup_result = await request(
                        "DELETE", "/_search/scroll", {"scroll_id": [scroll_id]}, cleanup=True
                    )
                    if cleanup_result.get("succeeded") is not True:
                        raise _Inconclusive("Snapshot cleanup failed")
            except Exception:
                if report["status"] != "fail":
                    report.update(status="inconclusive", reason="Snapshot cleanup failed")
    return report
