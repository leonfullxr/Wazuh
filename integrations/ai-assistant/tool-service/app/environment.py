"""Environment lookup tools (C1b) — hardcoded indexer endpoints, principal auth."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .config import CFG
from .indexer import IndexerError, get_indexer
from .models import IRAggregation, QueryIR, TimeRange
from .principal import Principal, env_id_for, indexer_headers


class ListAgentsParams(BaseModel):
    """Agents that produced alerts in the window, with last-seen timestamps."""

    time_range: TimeRange = Field(default_factory=TimeRange)
    size: int = Field(20, ge=1, le=50)


def list_agents_ir(p: ListAgentsParams) -> QueryIR:
    return QueryIR(
        time_range=p.time_range,
        aggregation=IRAggregation(
            kind="terms", field="agent.name", size=p.size, last_seen=True
        ),
        limit=0,
    )


class IndexHealthParams(BaseModel):
    """Read-only health and size of wazuh-alerts-* indices."""

    pass


async def index_health(
    principal: Principal, _params: IndexHealthParams
) -> dict[str, Any]:
    indexer = get_indexer(env_id_for(principal))
    headers = indexer_headers(principal)
    path = (
        "/_cat/indices/wazuh-alerts-*"
        "?format=json&h=index,health,docs.count,store.size"
    )
    try:
        rows = await indexer.cat_indices(headers, path)
    except IndexerError as exc:
        return {"error": str(exc), "indices": []}
    names = [row.get("index", "") for row in rows if row.get("index")]
    return {
        "indices": rows,
        "count": len(rows),
        "index_names": names,
        "summary": (
            f"{len(rows)} wazuh-alerts indices"
            + (f": {', '.join(names[:8])}" if names else "")
        ),
    }


class ListDashboardsParams(BaseModel):
    """Inventory of shared dashboards/visualizations (titles only — privacy boundary)."""

    size: int = Field(30, ge=1, le=100)


class ListAlertFieldsParams(BaseModel):
    """Dashboard-relevant fields on wazuh-alerts-* (from index pattern + mapping)."""

    index_pattern: str = Field(default="wazuh-alerts-*", max_length=120)


class DashboardDesignGuideParams(BaseModel):
    """How to build custom dashboards (grid layout, panel schema, examples)."""

    pass


async def list_dashboards(
    principal: Principal, params: ListDashboardsParams
) -> dict[str, Any]:
    indexer = get_indexer(env_id_for(principal))
    headers = indexer_headers(principal)
    body = {
        "size": params.size,
        "query": {
            "bool": {
                "filter": [
                    {
                        "terms": {
                            "type": ["dashboard", "visualization", "index-pattern"]
                        }
                    }
                ]
            }
        },
        "_source": [
            "type",
            "dashboard.title",
            "visualization.title",
            "index-pattern.title",
            "updated_at",
        ],
    }
    try:
        res = await indexer.saved_objects_search(headers, body)
    except IndexerError as exc:
        return {"error": str(exc), "objects": []}

    objects: list[dict[str, Any]] = []
    for hit in res.get("hits", {}).get("hits", []):
        src = hit.get("_source", {})
        obj_type = src.get("type", "")
        title = (
            (src.get(obj_type) or {}).get("title")
            if isinstance(src.get(obj_type), dict)
            else None
        )
        objects.append(
            {
                "type": obj_type,
                "title": title or "(untitled)",
                "updated_at": src.get("updated_at"),
            }
        )
    return {
        "objects": objects,
        "count": len(objects),
        "saved_objects_index": CFG.saved_objects_index,
    }


async def list_alert_fields(
    principal: Principal, params: ListAlertFieldsParams
) -> dict[str, Any]:
    from .actions.field_resolver import catalog_for_model, load_known_fields

    indexer = get_indexer(env_id_for(principal))
    headers = indexer_headers(principal)
    known = await load_known_fields(indexer, headers, params.index_pattern)
    catalog = catalog_for_model(known)
    return {
        "index_pattern": params.index_pattern,
        "field_count": len(known),
        "dashboard_fields": catalog,
        "guidance": (
            "Use these exact field names in dashboards. Wazuh alerts use keyword "
            "fields directly (e.g. data.dstuser, GeoLocation.country_name) — do NOT "
            "append .keyword unless list_alert_fields shows that suffix."
        ),
    }


async def dashboard_design_guide(
    _principal: Principal, _params: DashboardDesignGuideParams
) -> dict[str, Any]:
    from .actions.dashboard_layout import DESIGN_GUIDE

    return DESIGN_GUIDE
