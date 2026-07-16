"""Resolve and validate dashboard field names against live index-pattern + mapping."""
from __future__ import annotations

import json
import re
from typing import Any

from ..indexer import Indexer, IndexerError

FIELD_IN_VISSTATE_RE = re.compile(r'"field"\s*:\s*"([^"]+)"')

# Dashboard-relevant fields the assistant should know about (wazuh-alerts-*).
DASHBOARD_FIELD_CATALOG: dict[str, str] = {
    "timestamp": "Alert time (date_histogram, time picker)",
    "GeoLocation.country_name": "GeoIP country (terms, region map) — no .keyword suffix",
    "GeoLocation.city_name": "GeoIP city",
    "GeoLocation.location": "GeoIP geo_point for maps",
    "data.srcip": "Source IP (terms) — keyword field, no .keyword suffix",
    "data.dstuser": "Target username for auth failures — keyword, no .keyword suffix",
    "agent.name": "Wazuh agent hostname",
    "rule.id": "Rule ID",
    "rule.groups": "Rule groups (e.g. authentication_failed)",
    "rule.level": "Rule severity level",
    "rule.description": "Rule description (text)",
    "rule.mitre.id": "MITRE ATT&CK technique id (terms)",
}


# Upstream-style aliases the model may emit (V3.7).
FIELD_ALIASES: dict[str, str] = {
    "geo.country": "GeoLocation.country_name",
    "country": "GeoLocation.country_name",
    "geoip.country": "GeoLocation.country_name",
    "src_ip": "data.srcip",
    "source_ip": "data.srcip",
    "dst_user": "data.dstuser",
    "username": "data.dstuser",
    "user": "data.dstuser",
    "agent": "agent.name",
    "severity": "rule.level",
    "mitre": "rule.mitre.id",
}


def resolve_field(field: str, known: set[str]) -> str:
    """Pick the aggregatable field name present in the index pattern or mapping."""
    field = FIELD_ALIASES.get(field, field)
    if field in known:
        return field
    kw = f"{field}.keyword"
    if kw in known:
        return kw
    if field.endswith(".keyword"):
        base = field[: -len(".keyword")]
        if base in known:
            return base
    prefix = field + "."
    children = sorted(k for k in known if k.startswith(prefix))
    if children:
        if kw in known:
            return kw
        return children[0]
    raise ValueError(
        f"field {field!r} not found in index pattern. "
        f"Nearby: {[k for k in sorted(known) if field.split('.')[0] in k][:6]}"
    )


def extract_vis_fields(objects: list[dict[str, Any]]) -> set[str]:
    fields: set[str] = set()
    for obj in objects:
        doc = obj.get("document", {})
        if doc.get("type") != "visualization":
            continue
        vis_state = doc.get("visualization", {}).get("visState", "")
        fields.update(FIELD_IN_VISSTATE_RE.findall(vis_state))
    return fields


def rewrite_vis_fields(objects: list[dict[str, Any]], resolved: dict[str, str]) -> None:
    """In-place replace field names inside visState JSON strings."""
    for obj in objects:
        doc = obj.get("document", {})
        if doc.get("type") != "visualization":
            continue
        vis = doc.get("visualization", {})
        state = vis.get("visState", "")
        for old, new in resolved.items():
            if old != new:
                state = state.replace(f'"field":"{old}"', f'"field":"{new}"')
                state = state.replace(f'"field": "{old}"', f'"field": "{new}"')
        vis["visState"] = state


def validate_and_resolve_bundle_fields(
    objects: list[dict[str, Any]], known: set[str]
) -> dict[str, str]:
    """Validate all visualization fields; return old→resolved map (may be empty)."""
    used = extract_vis_fields(objects)
    resolved: dict[str, str] = {}
    for field in used:
        target = resolve_field(field, known)
        if target != field:
            resolved[field] = target
    rewrite_vis_fields(objects, resolved)
    return resolved


async def load_index_pattern_fields(
    indexer: Indexer, headers: dict[str, str], pattern_id: str = "wazuh-alerts-*"
) -> set[str]:
    """Fields registered on the OSD index pattern (what visualizations require)."""
    body = {
        "size": 1,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"type": "index-pattern"}},
                    {"ids": {"values": [f"index-pattern:{pattern_id}"]}},
                ]
            }
        },
        "_source": ["index-pattern.fields", "index-pattern.title"],
    }
    try:
        res = await indexer.saved_objects_search(headers, body)
    except IndexerError:
        return set()

    hits = res.get("hits", {}).get("hits", [])
    if not hits:
        return set()

    raw = (hits[0].get("_source", {}).get("index-pattern") or {}).get("fields", "[]")
    try:
        field_rows = json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError:
        return set()
    return {row["name"] for row in field_rows if isinstance(row, dict) and row.get("name")}


async def load_known_fields(
    indexer: Indexer, headers: dict[str, str], pattern_id: str = "wazuh-alerts-*"
) -> set[str]:
    """Union of index-pattern fields and live ES mapping (best-effort)."""
    known = await load_index_pattern_fields(indexer, headers, pattern_id)
    mapping = await indexer.get_mapping(headers)
    if mapping:
        known |= set(mapping.keys())
    return known


def catalog_for_model(known: set[str]) -> list[dict[str, str]]:
    """Curated dashboard fields that exist in this tenant, for tool responses."""
    rows: list[dict[str, str]] = []
    for name, hint in DASHBOARD_FIELD_CATALOG.items():
        try:
            resolved = resolve_field(name, known) if known else name
        except ValueError:
            continue
        rows.append({"field": resolved, "hint": hint})
    return rows
