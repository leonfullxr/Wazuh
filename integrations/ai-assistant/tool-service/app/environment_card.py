"""Per-environment context card (V3.7c / E12) — cached snapshot for the model loop.

Best-effort only: each field degrades independently so a single indexer/manager
error never blocks the turn. Card text stays under a hard size cap and rides as
transient context (never in the cached prelude).
"""
from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from . import audit
from .config import CFG
from .environment import (
    IndexHealthParams,
    ListAgentsParams,
    ListAlertFieldsParams,
    ListDashboardsParams,
    index_health,
    list_agents_ir,
    list_alert_fields,
    list_dashboards,
)
from .indexer import IndexerError, get_indexer
from .models import IRAggregation, QueryIR, TimeRange
from .principal import Principal, env_id_for, indexer_headers
from .tools import TopRulesParams, _top_rules_ir
from .veracity import execute_ir, term_buckets

log = logging.getLogger("wazuh-ai.env_card")

_CACHE: dict[str, tuple[float, str]] = {}
_CARD_CAP = 3200
_INDEX_DATE = re.compile(r"(\d{4}\.\d{2}\.\d{2})$")


async def get_env_card_text(principal: Principal) -> tuple[str | None, int | None]:
    """Return (card text, age_seconds) or (None, None) when disabled."""
    ttl = CFG.env_card_ttl
    if ttl <= 0:
        return None, None

    env_id = env_id_for(principal)
    now = time.time()
    entry = _CACHE.get(env_id)
    if entry and entry[0] > now:
        age_s = int(ttl - (entry[0] - now))
        return entry[1], age_s

    try:
        text = await _build_card(principal)
    except Exception as exc:  # noqa: BLE001 — never block a turn
        log.warning("env_card build failed: %s", exc)
        text = (
            "Environment context unavailable this turn "
            "(snapshot build failed — continue with tools)."
        )
        audit.emit("env_card_build_failed", env=env_id, error=str(exc)[:200])
    if len(text) > _CARD_CAP:
        text = text[: _CARD_CAP - 3] + "..."
    _CACHE[env_id] = (now + ttl, text)
    audit.emit("env_card_built", env=env_id, chars=len(text))
    return text, 0


async def _safe(label: str, coro) -> Any | None:
    try:
        return await coro
    except Exception as exc:  # noqa: BLE001
        log.info("env_card field %s degraded: %s", label, exc)
        return None


def _retention_from_names(names: list[str]) -> str | None:
    dates: list[str] = []
    for n in names:
        m = _INDEX_DATE.search(n or "")
        if m:
            dates.append(m.group(1))
    if not dates:
        return None
    dates.sort()
    if dates[0] == dates[-1]:
        return f"daily indices through {dates[-1]}"
    return f"approx retention {dates[0]} → {dates[-1]} ({len(dates)} dated indices)"


async def _cluster_and_version(principal: Principal) -> dict[str, str]:
    out: dict[str, str] = {}
    indexer = get_indexer(env_id_for(principal))
    headers = indexer_headers(principal)
    root = await _safe("indexer_root", indexer.get_json(headers, "/"))
    if isinstance(root, dict):
        ver = (root.get("version") or {}).get("number")
        if ver:
            out["indexer_version"] = str(ver)
        cluster_name = root.get("cluster_name") or root.get("name")
        if cluster_name:
            out["cluster_name"] = str(cluster_name)
    health = await _safe(
        "cluster_health", indexer.get_json(headers, "/_cluster/health")
    )
    if isinstance(health, dict):
        status = health.get("status")
        if status:
            out["cluster_health"] = (
                f"{status} (nodes={health.get('number_of_nodes', '?')}, "
                f"shards={health.get('active_shards', '?')})"
            )
    return out


async def _wazuh_manager_version(principal: Principal) -> str | None:
    """Best-effort manager version when executor creds exist; else None."""
    from .env_registry import get_env

    try:
        env = get_env(env_id_for(principal))
    except Exception:
        return None
    if not env.manager_api_url or not env.manager_executor_basic:
        return None
    try:
        import httpx

        from .actions.executors import _manager_verify, _wazuh_api_token

        token = await _wazuh_api_token(env, env.manager_executor_basic)
        verify = _manager_verify(env)
        async with httpx.AsyncClient(verify=verify, timeout=5.0) as client:
            r = await client.get(
                f"{env.manager_api_url.rstrip('/')}/",
                headers={"Authorization": f"Bearer {token}"},
            )
            if r.status_code >= 400:
                return None
            data = r.json()
            # Wazuh API root often: {"data":{"title":"Wazuh API","api_version":"..."}}
            api_ver = (data.get("data") or {}).get("api_version") or data.get(
                "api_version"
            )
            return str(api_ver) if api_ver else None
    except Exception as exc:  # noqa: BLE001
        log.info("env_card wazuh version degraded: %s", exc)
        return None


async def _build_card(principal: Principal) -> str:
    now = datetime.now(timezone.utc)
    window = TimeRange(gte=now - timedelta(days=7), lte=now)
    lines = [
        "Environment context (cached snapshot — use for orientation, not as live counts):",
    ]

    meta = await _cluster_and_version(principal)
    wazuh_ver = await _wazuh_manager_version(principal)
    if wazuh_ver:
        lines.append(f"- Wazuh API version: {wazuh_ver}")
    if meta.get("indexer_version"):
        lines.append(f"- Indexer version: {meta['indexer_version']}")
    if meta.get("cluster_health"):
        lines.append(f"- Cluster health: {meta['cluster_health']}")
    elif meta.get("cluster_name"):
        lines.append(f"- Cluster: {meta['cluster_name']}")

    health = await _safe(
        "index_health", index_health(principal, IndexHealthParams())
    )
    if isinstance(health, dict) and not health.get("error"):
        names = [str(n) for n in (health.get("index_names") or []) if n]
        index_count = health.get("count", len(names))
        lines.append(
            f"- Alert indices: {index_count}"
            + (f" — {', '.join(names[:6])}" if names else "")
            + ("…" if len(names) > 6 else "")
        )
        retention = _retention_from_names(names)
        if retention:
            lines.append(f"- Alert index window: {retention}")
        summary = health.get("summary")
        if summary and index_count == 0:
            lines.append(f"- Index health: {summary}")
    else:
        lines.append("- Alert indices: unavailable")

    agents_ev = await _safe(
        "agents",
        execute_ir(
            list_agents_ir(ListAgentsParams(time_range=window, size=20)), principal
        ),
    )
    if agents_ev is not None:
        agent_buckets = term_buckets(agents_ev.aggregations, "by")
        agent_names = [str(b.get("key")) for b in agent_buckets[:8] if b.get("key")]
        lines.append(
            f"- Agents with alerts (7d): {len(agent_buckets)}"
            + (f" — e.g. {', '.join(agent_names)}" if agent_names else "")
        )

    groups_ev = await _safe(
        "rule_groups",
        execute_ir(
            QueryIR(
                time_range=window,
                aggregation=IRAggregation(kind="terms", field="rule.groups", size=8),
                limit=0,
            ),
            principal,
        ),
    )
    if groups_ev is not None:
        group_buckets = term_buckets(groups_ev.aggregations, "by")
        top_groups = [
            f"{b.get('key')} ({b.get('count', 0)})"
            for b in group_buckets[:6]
            if b.get("key")
        ]
        if top_groups:
            lines.append(f"- Top rule groups (7d): {', '.join(top_groups)}")
            # Cheap module signal from group names (not a live manager inventory).
            hints = []
            joined = " ".join(str(b.get("key", "")).lower() for b in group_buckets)
            for label, needles in (
                ("syscheck/FIM", ("syscheck", "fim")),
                ("vulnerability", ("vulnerability", "cve")),
                ("sca", ("sca",)),
                ("authentication", ("authentication", "sshd", "pam")),
                ("web/attack", ("web", "attack", "sql_injection")),
            ):
                if any(n in joined for n in needles):
                    hints.append(label)
            if hints:
                lines.append(
                    f"- Signal families seen (7d groups): {', '.join(hints)}"
                )

    rules_ev = await _safe(
        "top_rules",
        execute_ir(_top_rules_ir(TopRulesParams(time_range=window)), principal),
    )
    if rules_ev is not None:
        rule_buckets = term_buckets(rules_ev.aggregations, "by")
        top_rules = [str(b.get("key")) for b in rule_buckets[:5] if b.get("key")]
        if top_rules:
            lines.append(f"- Frequent rules (7d): {', '.join(top_rules)}")

    fields = await _safe(
        "fields", list_alert_fields(principal, ListAlertFieldsParams())
    )
    if isinstance(fields, dict):
        field_names = {
            f.get("field") for f in fields.get("dashboard_fields", []) if f.get("field")
        }
        has_geo = "GeoLocation.country_name" in field_names
        has_vuln = any("vulnerability" in (n or "") for n in field_names)
        lines.append(f"- Geo fields present: {'yes' if has_geo else 'no'}")
        lines.append(f"- Vulnerability fields present: {'yes' if has_vuln else 'no'}")

    dashboards = await _safe(
        "dashboards", list_dashboards(principal, ListDashboardsParams(size=20))
    )
    if isinstance(dashboards, dict):
        dash_titles = [
            o.get("title", "")
            for o in dashboards.get("objects", [])
            if o.get("type") == "dashboard" and o.get("title")
        ][:10]
        if dash_titles:
            lines.append(
                "- Existing dashboards (dedupe before proposing): "
                + "; ".join(dash_titles)
            )

    return "\n".join(lines)
