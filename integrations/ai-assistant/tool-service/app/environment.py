"""Environment lookup tools (C1b) — hardcoded indexer endpoints, analyst JWT.

Each function maps to exactly one allowed URL. No generic passthrough.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .config import CFG
from .indexer import INDEXER, IndexerError
from .models import IRAggregation, QueryIR, TimeRange


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


async def index_health(user_jwt: str, _params: IndexHealthParams) -> dict[str, Any]:
    path = (
        "/_cat/indices/wazuh-alerts-*"
        "?format=json&h=index,health,docs.count,store.size"
    )
    try:
        rows = await INDEXER.cat_indices_as_user(user_jwt, path)
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


async def list_dashboards(user_jwt: str, params: ListDashboardsParams) -> dict[str, Any]:
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
        "_source": ["type", "dashboard.title", "visualization.title", "index-pattern.title", "updated_at"],
    }
    try:
        res = await INDEXER.saved_objects_search_as_user(user_jwt, body)
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
