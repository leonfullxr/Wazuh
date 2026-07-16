"""Per-environment context card (V3.7c) — cached snapshot for the model loop."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

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
from .models import IRAggregation, QueryIR, TimeRange
from .principal import Principal, env_id_for
from .tools import TopRulesParams, _top_rules_ir
from .veracity import execute_ir, term_buckets

_CACHE: dict[str, tuple[float, str]] = {}


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

    text = await _build_card(principal)
    if len(text) > 3200:
        text = text[:3197] + "..."
    _CACHE[env_id] = (now + ttl, text)
    audit.emit("env_card_built", env=env_id, chars=len(text))
    return text, 0


async def _build_card(principal: Principal) -> str:
    now = datetime.now(timezone.utc)
    window = TimeRange(gte=now - timedelta(days=7), lte=now)

    health = await index_health(principal, IndexHealthParams())
    index_count = health.get("count", 0)

    agents_ev = await execute_ir(
        list_agents_ir(ListAgentsParams(time_range=window, size=20)), principal
    )
    agent_buckets = term_buckets(agents_ev.aggregations, "by")
    agent_names = [str(b.get("key")) for b in agent_buckets[:8] if b.get("key")]

    groups_ir = QueryIR(
        time_range=window,
        aggregation=IRAggregation(kind="terms", field="rule.groups", size=8),
        limit=0,
    )
    groups_ev = await execute_ir(groups_ir, principal)
    group_buckets = term_buckets(groups_ev.aggregations, "by")
    top_groups = [
        f"{b.get('key')} ({b.get('count', 0)})"
        for b in group_buckets[:6]
        if b.get("key")
    ]

    rules_ev = await execute_ir(_top_rules_ir(TopRulesParams(time_range=window)), principal)
    rule_buckets = term_buckets(rules_ev.aggregations, "by")
    top_rules = [str(b.get("key")) for b in rule_buckets[:5] if b.get("key")]

    fields = await list_alert_fields(principal, ListAlertFieldsParams())
    field_names = {f.get("field") for f in fields.get("dashboard_fields", []) if f.get("field")}
    has_geo = "GeoLocation.country_name" in field_names
    has_vuln = any("vulnerability" in (n or "") for n in field_names)

    dashboards = await list_dashboards(principal, ListDashboardsParams(size=20))
    dash_titles = [
        o.get("title", "")
        for o in dashboards.get("objects", [])
        if o.get("type") == "dashboard" and o.get("title")
    ][:10]

    lines = [
        "Environment context (cached snapshot — use for orientation, not as live counts):",
        f"- Alert indices: {index_count} ({health.get('summary', 'n/a')})",
        f"- Agents with alerts (7d): {len(agent_buckets)}"
        + (f" — e.g. {', '.join(agent_names)}" if agent_names else ""),
    ]
    if top_groups:
        lines.append(f"- Top rule groups (7d): {', '.join(top_groups)}")
    if top_rules:
        lines.append(f"- Frequent rules (7d): {', '.join(top_rules)}")
    lines.append(f"- Geo fields present: {'yes' if has_geo else 'no'}")
    lines.append(f"- Vulnerability fields present: {'yes' if has_vuln else 'no'}")
    if dash_titles:
        lines.append(
            "- Existing dashboards (dedupe before proposing): "
            + "; ".join(dash_titles)
        )
    return "\n".join(lines)
