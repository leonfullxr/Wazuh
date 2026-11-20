"""Bounded investigation primitives; callers must supply current policy decisions."""

import asyncio
import copy
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable
from urllib.parse import quote

import httpx
from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from wazuh_mcp.config import tls_verify
from wazuh_mcp.security import validate_agent_id
from wazuh_mcp.server.output import _sanitize_output_text

MAX_RESPONSE_BYTES = 256_000
MAX_BACKEND_BYTES = 2_000_000
DEADLINE_SECONDS = 10
INDEX_RE = re.compile(r"^wazuh-alerts-[a-zA-Z0-9._-]+$")
FIELDS = ["timestamp", "agent.id", "agent.name", "rule.id", "rule.level", "rule.description", "rule.groups"]


@dataclass(frozen=True)
class InvestigationContext:
    cluster: str
    cluster_revision: str
    owner: str
    indexer: Any
    manager: Any
    keys: tuple[bytes, ...]
    tie_breaker: str
    authorize: Callable[[str, str], Awaitable[bool]]

    def __post_init__(self):
        if not self.keys or not self.tie_breaker or not re.fullmatch(r"[A-Za-z0-9_.-]+", self.tie_breaker):
            raise ValueError("Investigation key ring and verified sortable unique tie-breaker are required")
        for key in self.keys:
            Fernet(key)
        if self.indexer and self.indexer.ccs_prefix:
            raise ValueError("Investigation requires a direct Indexer connection")


def _cipher(ctx: InvestigationContext) -> MultiFernet:
    return MultiFernet([Fernet(key) for key in ctx.keys])


def _stamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, AttributeError):
        raise ValueError("Timestamps must be absolute ISO 8601 values with a timezone") from None


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _window(args: dict, now: datetime, *, explicit: bool = False) -> tuple[str, str, int, str]:
    allowed = {"agent_id", "from", "to", "limit", "cluster_id"}
    if set(args) - allowed:
        raise ValueError("Unknown investigation parameter")
    if explicit and ("from" not in args or "to" not in args):
        raise ValueError("Both from and to timestamps are required")
    if ("from" in args) != ("to" in args):
        raise ValueError("Provide both from and to timestamps")
    end = _stamp(args["to"]) if "to" in args else now
    start = _stamp(args["from"]) if "from" in args else end - timedelta(hours=1)
    if start >= end or end - start > timedelta(hours=24):
        raise ValueError("Time window must be positive and at most 24 hours")
    limit = args.get("limit", 50)
    if type(limit) is not int or not 1 <= limit <= 50:
        raise ValueError("limit must be an integer from 1 to 50")
    if not isinstance(args.get("agent_id"), str):
        raise ValueError("agent_id is required and must be a string")
    return _iso(start), _iso(end), limit, validate_agent_id(args["agent_id"], required=True)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _clean(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    return _sanitize_output_text(value) if isinstance(value, str) else value


async def _request(
    indexer: Any, method: str, path: str, body: dict | None = None, budget: list[int] | None = None
) -> dict:
    await indexer._ensure_initialized()
    async with indexer.client.stream(
        method, indexer.base_url + path, json=body, headers={"Accept-Encoding": "identity"}
    ) as response:
        response.raise_for_status()
        if response.headers.get("content-encoding", "identity").lower() not in ("", "identity"):
            raise ValueError("Compressed backend response is unsupported")
        chunks = bytearray()
        async for chunk in response.aiter_raw():
            chunks.extend(chunk)
            if budget is not None:
                budget[0] += len(chunk)
            if len(chunks) > MAX_BACKEND_BYTES or (budget is not None and budget[0] > MAX_BACKEND_BYTES):
                raise ValueError("Backend response exceeds budget")
    result = json.loads(chunks)
    if not isinstance(result, dict):
        raise ValueError("Invalid backend response")
    return result


async def _index_uuid(indexer: Any, index: str, budget: list[int] | None = None) -> str:
    data = await _request(indexer, "GET", f"/{quote(index, safe='')}/_settings", budget=budget)
    uuid = data.get(index, {}).get("settings", {}).get("index", {}).get("uuid")
    if not isinstance(uuid, str) or not uuid:
        raise ValueError("Index identity unavailable")
    return uuid


def _locator(ctx: InvestigationContext, index: str, uuid: str, doc_id: str, source: dict) -> str:
    payload = {
        "v": 1,
        "cluster": ctx.cluster,
        "revision": ctx.cluster_revision,
        "owner": ctx.owner,
        "index": index,
        "uuid": uuid,
        "id": doc_id,
        "digest": hashlib.sha256(_canonical(source)).hexdigest(),
    }
    return "ev_" + _cipher(ctx).encrypt(_canonical(payload)).decode()


async def evidence(ctx: InvestigationContext, ref: str) -> dict:
    try:
        if not await ctx.authorize(ctx.owner, ctx.cluster) or len(ref) > 8192 or not ref.startswith("ev_"):
            raise ValueError
        payload = json.loads(_cipher(ctx).decrypt(ref[3:].encode(), ttl=900))
        if (
            payload.get("v") != 1
            or payload.get("owner") != ctx.owner
            or payload.get("cluster") != ctx.cluster
            or payload.get("revision") != ctx.cluster_revision
            or not INDEX_RE.fullmatch(payload.get("index", ""))
        ):
            raise ValueError
        async with asyncio.timeout(DEADLINE_SECONDS):
            budget = [0]
            index = payload["index"]
            if await _index_uuid(ctx.indexer, index, budget) != payload["uuid"]:
                raise ValueError
            response = await _request(
                ctx.indexer,
                "GET",
                f"/{quote(index, safe='')}/_doc/{quote(payload['id'], safe='')}?_source_includes={','.join(FIELDS)}",
                budget=budget,
            )
            source = response.get("_source")
            if not isinstance(source, dict) or hashlib.sha256(_canonical(source)).hexdigest() != payload["digest"]:
                raise ValueError
            return {"status": "available", "evidence_ref": ref, "event": _clean(source)}
    except (Exception, InvalidToken):
        return {"status": "unavailable"}


def _total(hits: dict) -> int | None:
    total = hits.get("total")
    if isinstance(total, dict):
        total = total.get("value") if total.get("relation") == "eq" else None
    return total if type(total) is int and total >= 0 else None


async def timeline(
    ctx: InvestigationContext,
    args: dict,
    *,
    query: dict | None = None,
    now: datetime | None = None,
    explicit: bool = False,
) -> dict:
    start, end, limit, agent_id = _window(args, now or datetime.now(timezone.utc), explicit=explicit)
    if not await ctx.authorize(ctx.owner, ctx.cluster):
        raise PermissionError("Investigation unavailable")
    collected = _iso(datetime.now(timezone.utc))
    result = {
        "cluster": ctx.cluster,
        "agent_id": agent_id,
        "window": {"from": start, "to": end},
        "collected_at": collected,
        "sources": {
            "alerts": {"status": "unavailable", "matched": None, "returned": 0, "truncated": False},
            "agent_status": {"status": "unavailable", "observed_at": None},
        },
        "selection_order": "most recent first; displayed oldest first",
        "events": [],
    }
    filters = [{"term": {"agent.id": agent_id}}, {"range": {"timestamp": {"gte": start, "lte": end}}}]
    if query:
        filters.append(query)
    body = {
        "size": limit,
        "track_total_hits": True,
        "_source": FIELDS,
        "query": {"bool": {"filter": filters}},
        "sort": [{"timestamp": "desc"}, {ctx.tie_breaker: "desc"}],
    }
    budget = [0]

    async def alert_source():
        raw = await _request(ctx.indexer, "POST", "/wazuh-alerts-*/_search", body, budget)
        hits = raw.get("hits", {})
        rows = hits.get("hits", [])
        matched = _total(hits)
        if not isinstance(rows, list) or len(rows) > limit or (matched is not None and matched < len(rows)):
            raise ValueError("Invalid search results")
        truncated = matched > len(rows) if matched is not None else None
        clusters = raw.get("_clusters") or {}
        partial = (
            matched is None
            or truncated
            or raw.get("timed_out") is True
            or bool((raw.get("_shards") or {}).get("failed"))
            or any(clusters.get(key) for key in ("partial", "failed", "skipped", "running"))
        )
        uuids = {}
        events = []
        sort_keys = set()
        for hit in rows:
            index, doc_id, source = hit.get("_index"), hit.get("_id"), hit.get("_source")
            sort = hit.get("sort")
            if (
                not isinstance(index, str)
                or not INDEX_RE.fullmatch(index)
                or not isinstance(doc_id, str)
                or len(doc_id) > 512
                or not isinstance(source, dict)
                or not isinstance(sort, list)
                or len(sort) != 2
                or None in sort
            ):
                raise ValueError("Unverifiable alert origin or ordering")
            key = _canonical(sort)
            if key in sort_keys:
                raise ValueError("Alert ordering is not unique")
            sort_keys.add(key)
            if index not in uuids:
                uuids[index] = await _index_uuid(ctx.indexer, index, budget)
            ref = _locator(ctx, index, uuids[index], doc_id, source)
            event = {
                "at": source.get("timestamp"),
                "rule_id": (source.get("rule") or {}).get("id"),
                "evidence_ref": ref,
            }
            event = _clean(event)
            if len(_canonical(events + [event])) > MAX_RESPONSE_BYTES // 2:
                partial = truncated = True
                break
            events.append(event)
        result["events"] = list(reversed(events))
        result["sources"]["alerts"] = {
            "status": "partial" if partial else "complete",
            "matched": matched,
            "returned": len(events),
            "truncated": truncated,
        }

    async def status_source():
        manager = ctx.manager
        if not manager.client:
            async with manager._init_lock:
                if not manager.client:
                    manager.client = httpx.AsyncClient(
                        verify=tls_verify(manager.config.verify_ssl),
                        timeout=manager.config.request_timeout_seconds,
                        limits=httpx.Limits(
                            max_connections=manager.config.max_connections,
                            max_keepalive_connections=max(5, manager.config.max_connections // 2),
                        ),
                    )

        async def read_json(response):
            response.raise_for_status()
            if response.headers.get("content-encoding", "identity").lower() not in ("", "identity"):
                raise ValueError("Compressed backend response is unsupported")
            content = bytearray()
            async for chunk in response.aiter_raw():
                content.extend(chunk)
                budget[0] += len(chunk)
                if budget[0] > MAX_BACKEND_BYTES:
                    raise ValueError("Backend response exceeds budget")
            return json.loads(content)

        async def authenticate():
            async with manager.client.stream(
                "POST",
                f"{manager.config.base_url}/security/user/authenticate",
                auth=(manager.config.wazuh_user, manager.config.wazuh_pass),
                headers={"Accept-Encoding": "identity"},
            ) as response:
                payload = await read_json(response)
            token = payload.get("data", {}).get("token")
            if not isinstance(token, str) or not token:
                raise ValueError("Invalid authentication response")
            manager.token = token

        if not manager.token:
            async with manager._auth_lock:
                if not manager.token:
                    await authenticate()
        for attempt in range(2):
            stale_token = manager.token
            async with manager.client.stream(
                "GET",
                f"{manager.config.base_url}/agents",
                params={"agents_list": agent_id, "select": "id,status"},
                headers={"Authorization": f"Bearer {stale_token}", "Accept-Encoding": "identity"},
            ) as response:
                if response.status_code != 401 or attempt:
                    payload = await read_json(response)
                    break
            async with manager._auth_lock:
                if manager.token is None or manager.token == stale_token:
                    manager.token = None
                    await authenticate()
        data = payload.get("data", {})
        rows = data.get("affected_items", [])
        if data.get("total_failed_items") != 0 or len(rows) != 1:
            return
        item = rows[0]
        if item.get("id") != agent_id or not isinstance(item.get("status"), str) or not item["status"]:
            return
        result["sources"]["agent_status"] = {
            "status": "available",
            "observed_at": _iso(datetime.now(timezone.utc)),
            "observation": _clean({"status": item.get("status")}),
        }

    async def safe(coro):
        try:
            await coro
        except Exception:
            pass

    try:
        async with asyncio.timeout(DEADLINE_SECONDS):
            await asyncio.gather(safe(alert_source()), safe(status_source()))
    except TimeoutError:
        pass
    return result


TIMELINE_NAME = "investigate_agent_timeline"
EVIDENCE_NAME = "get_investigation_evidence"
_SCHEMA = {
    "type": "object",
    "properties": {
        "agent_id": {"type": "string"},
        "from": {"type": "string"},
        "to": {"type": "string"},
        "limit": {"type": "integer", "minimum": 1, "maximum": 50},
        "cluster_id": {"type": "string"},
    },
    "required": ["agent_id"],
    "additionalProperties": False,
}


def catalog(saved: dict[str, dict] | None = None) -> list[dict]:
    tools = [
        {
            "name": TIMELINE_NAME,
            "description": "Investigate a bounded agent alert timeline.",
            "inputSchema": copy.deepcopy(_SCHEMA),
            "_meta": {"ui": {"resourceUri": "ui://wazuh/agent-timeline.html"}},
        },
        {
            "name": EVIDENCE_NAME,
            "description": "Retrieve currently authorized timeline evidence.",
            "inputSchema": {
                "type": "object",
                "properties": {"evidence_ref": {"type": "string"}, "cluster_id": {"type": "string"}},
                "required": ["evidence_ref"],
                "additionalProperties": False,
            },
        },
    ]
    for name, definition in (saved or {}).items():
        if not re.fullmatch(r"saved_investigation_[a-z0-9_]{1,48}", name):
            raise ValueError("Invalid saved investigation name")
        if set(definition) != {"version", "rule_groups"} or not isinstance(definition["version"], str):
            raise ValueError("Invalid saved investigation definition")
        groups = definition["rule_groups"]
        if not isinstance(groups, list) or not groups or any(not isinstance(x, str) or not x for x in groups):
            raise ValueError("Invalid saved investigation rule groups")
        schema = copy.deepcopy(_SCHEMA)
        schema["required"] = ["agent_id", "from", "to"]
        tools.append({"name": name, "description": "Run an operator-approved investigation.", "inputSchema": schema})
    return tools


async def execute(ctx: InvestigationContext, name: str, args: dict, saved: dict[str, dict] | None = None) -> dict:
    if not isinstance(args, dict):
        raise ValueError("Arguments must be an object")
    if name == EVIDENCE_NAME:
        if set(args) - {"evidence_ref", "cluster_id"} or not isinstance(args.get("evidence_ref"), str):
            raise ValueError("evidence_ref is required")
        return await evidence(ctx, args["evidence_ref"])
    if name == TIMELINE_NAME:
        return await timeline(ctx, args)
    definitions = saved or {}
    catalog(definitions)
    if name not in definitions:
        raise ValueError("Unknown investigation")
    definition = definitions[name]
    result = await timeline(ctx, args, explicit=True, query={"terms": {"rule.groups": definition["rule_groups"]}})
    result["query"] = {
        "name": name,
        "version": definition["version"],
        "filters": {"agent_id": result["agent_id"], **result["window"], "limit": args.get("limit", 50)},
    }
    return result


def render(result: dict) -> dict:
    # Count both representations in the envelope. Drop whole oldest events if needed.
    result = copy.deepcopy(result)
    while True:
        text = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
        envelope = {
            "structuredContent": result,
            "content": [
                {"type": "text", "text": "Investigation evidence and coverage."},
                {"type": "text", "text": text},
            ],
        }
        if len(_canonical(envelope)) <= MAX_RESPONSE_BYTES:
            return envelope
        events = result.get("events")
        if not isinstance(events, list) or not events:
            raise ValueError("Investigation response exceeds budget")
        events.pop(0)
        coverage = result["sources"]["alerts"]
        coverage.update({"status": "partial", "returned": len(events), "truncated": True})


@dataclass(frozen=True)
class ProductConfig:
    keys: tuple[bytes, ...]
    tie_breaker: str
    saved: dict[str, dict]


def load_config(path: str | None, keys: str | None) -> ProductConfig | None:
    """Load reviewed operator settings at startup. Keys are comma-separated Fernet keys."""
    if not path:
        return None

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate investigation configuration key")
            result[key] = value
        return result

    with open(path, encoding="utf-8") as source:
        obj = json.load(source, object_pairs_hook=unique)
    if (
        not isinstance(obj, dict)
        or set(obj) != {"tie_breaker", "tie_breaker_verified", "saved"}
        or obj["tie_breaker_verified"] is not True
        or not isinstance(obj["saved"], dict)
    ):
        raise ValueError("Investigation configuration requires a verified unique tie-breaker and saved definitions")
    ring = tuple(key.strip().encode() for key in (keys or "").split(",") if key.strip())
    if not ring:
        raise ValueError("Investigation key ring is required")
    for key in ring:
        Fernet(key)
    if not isinstance(obj["tie_breaker"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", obj["tie_breaker"]):
        raise ValueError("Invalid investigation tie-breaker")
    catalog(obj["saved"])
    return ProductConfig(ring, obj["tie_breaker"], obj["saved"])


def cluster_revision(client: Any) -> str:
    indexer = client._indexer_client
    return hashlib.sha256(
        _canonical(
            [client.config.base_url, indexer.base_url if indexer else None, indexer.ccs_prefix if indexer else None]
        )
    ).hexdigest()
