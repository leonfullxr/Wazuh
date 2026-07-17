"""Correlation / posture composite tools (E4) - server-side joins and deltas.

compare_windows differences two datastore counts; agent_posture joins alerts
and vulnerability states; related_alerts pivots from a seed alert. The model
never computes deltas or invents pivot keys (D4).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field, model_validator

from .models import IRAggregation, IRFilter, QueryIR, TimeRange
from .principal import Principal
from .states_models import StatesTimeRange
from .states_tools import CountVulnerabilitiesParams, count_vulnerabilities_ir
from .states_veracity import execute_vulnerabilities_ir
from .veracity import execute_ir, term_buckets


class RelatedAlertsParams(BaseModel):
    """Pivot from one alert on shared srcip, dstuser, or rule.id."""

    alert_id: Optional[str] = Field(
        None, description="Seed alert id; pivots are taken from its fields"
    )
    source_ip: Optional[str] = Field(None, description="Explicit data.srcip pivot")
    user: Optional[str] = Field(None, description="Explicit data.dstuser pivot")
    rule_id: Optional[str] = Field(None, description="Explicit rule.id pivot")
    time_range: TimeRange = Field(default_factory=TimeRange)
    size: int = Field(20, ge=1, le=50)

    @model_validator(mode="after")
    def _need_pivot(self) -> "RelatedAlertsParams":
        if not self.alert_id and not self.source_ip and not self.user and not self.rule_id:
            raise ValueError(
                "related_alerts requires alert_id or at least one of "
                "source_ip, user, rule_id"
            )
        return self


async def related_alerts(
    principal: Principal, params: RelatedAlertsParams
) -> dict[str, Any]:
    checks: set[str] = set()
    seed_id = params.alert_id
    source_ip, user, rule_id = params.source_ip, params.user, params.rule_id
    seed_hit: dict | None = None

    if seed_id:
        now = datetime.now(timezone.utc)
        seed_ir = QueryIR(
            time_range=TimeRange(gte=now - timedelta(days=90), lte=now),
            filters=[IRFilter(field="_id", op="eq", value=seed_id)],
            limit=1,
        )
        seed_ev = await execute_ir(seed_ir, principal)
        checks |= set(seed_ev.checks_passed)
        if not seed_ev.hits:
            return {
                "total_matching": 0,
                "alerts": [],
                "pivot": {},
                "seed_alert_id": seed_id,
                "seed_found": False,
                "veracity_checks_passed": sorted(checks),
                "zero_hit_diagnosis": seed_ev.zero_hit_diagnosis,
            }
        seed_hit = seed_ev.hits[0]
        source_ip = source_ip or seed_hit.get("data.srcip")
        user = user or seed_hit.get("data.dstuser")
        rule_id = rule_id or (
            str(seed_hit["rule.id"]) if seed_hit.get("rule.id") is not None else None
        )

    filters: list[IRFilter] = []
    pivot: dict[str, str] = {}
    # Prefer IP, then user, then rule - one primary pivot for a tight set.
    if source_ip:
        filters.append(IRFilter(field="data.srcip", op="eq", value=source_ip))
        pivot["data.srcip"] = source_ip
    elif user:
        filters.append(IRFilter(field="data.dstuser", op="eq", value=user))
        pivot["data.dstuser"] = user
    elif rule_id:
        filters.append(IRFilter(field="rule.id", op="eq", value=str(rule_id)))
        pivot["rule.id"] = str(rule_id)
    else:
        return {
            "total_matching": 0,
            "alerts": [],
            "pivot": {},
            "seed_alert_id": seed_id,
            "seed_found": True,
            "veracity_checks_passed": sorted(checks),
            "note": "seed alert had no srcip, dstuser, or rule.id to pivot on",
        }

    from .compiler import SOURCE_FIELDS_LIST

    search_ir = QueryIR(
        time_range=params.time_range,
        filters=filters,
        limit=params.size,
        source_fields=SOURCE_FIELDS_LIST,
    )
    ev = await execute_ir(search_ir, principal)
    checks |= set(ev.checks_passed)
    hits = [h for h in ev.hits if h.get("_id") != seed_id]
    # Datastore total still includes the seed when it matched; disclose both.
    return {
        "total_matching": ev.total,
        "total_computed_by": ev.total_computed_by,
        "executed_window": ev.window,
        "alerts": hits,
        "pivot": pivot,
        "seed_alert_id": seed_id,
        "seed_found": seed_hit is not None if seed_id else None,
        "excluded_seed_from_sample": bool(seed_id),
        "veracity_checks_passed": sorted(checks),
        "zero_hit_diagnosis": ev.zero_hit_diagnosis,
    }


class CompareWindowsParams(BaseModel):
    """Datastore-computed delta between two time windows (never by the model)."""

    window_a: TimeRange = Field(description="First window (e.g. this week)")
    window_b: TimeRange = Field(description="Second window (e.g. last week)")
    severity_gte: Optional[int] = Field(None, ge=0, le=15)
    agent_names: Optional[list[str]] = None
    rule_ids: Optional[list[str]] = None


def _count_ir(params: CompareWindowsParams, window: TimeRange) -> QueryIR:
    filters: list[IRFilter] = []
    if params.severity_gte is not None:
        filters.append(IRFilter(field="rule.level", op="gte", value=params.severity_gte))
    if params.agent_names:
        filters.append(IRFilter(field="agent.name", op="in", value=params.agent_names))
    if params.rule_ids:
        filters.append(IRFilter(field="rule.id", op="in", value=params.rule_ids))
    return QueryIR(
        time_range=window,
        filters=filters,
        aggregation=IRAggregation(kind="count"),
        limit=0,
    )


async def compare_windows(
    principal: Principal, params: CompareWindowsParams
) -> dict[str, Any]:
    a_ev = await execute_ir(_count_ir(params, params.window_a), principal)
    b_ev = await execute_ir(_count_ir(params, params.window_b), principal)
    checks = set(a_ev.checks_passed) | set(b_ev.checks_passed)
    delta = a_ev.total - b_ev.total
    return {
        "window_a": {"total_matching": a_ev.total, "executed_window": a_ev.window},
        "window_b": {"total_matching": b_ev.total, "executed_window": b_ev.window},
        "delta": delta,
        "delta_computed_by": "tool-service",
        "total_matching": a_ev.total,
        "veracity_checks_passed": sorted(checks),
    }


class AgentPostureParams(BaseModel):
    """One agent: last-seen, recent high-sev alerts, open vuln count."""

    agent_name: str = Field(min_length=1, max_length=128)
    time_range: TimeRange = Field(default_factory=TimeRange)
    severity_gte: int = Field(10, ge=0, le=15)
    alert_size: int = Field(10, ge=1, le=50)


async def agent_posture(
    principal: Principal, params: AgentPostureParams
) -> dict[str, Any]:
    checks: set[str] = set()

    last_seen_ir = QueryIR(
        time_range=params.time_range,
        filters=[IRFilter(field="agent.name", op="eq", value=params.agent_name)],
        aggregation=IRAggregation(
            kind="terms", field="agent.name", size=1, last_seen=True
        ),
        limit=0,
    )
    last_ev = await execute_ir(last_seen_ir, principal)
    checks |= set(last_ev.checks_passed)
    buckets = term_buckets(last_ev.aggregations, "by")
    last_seen = buckets[0].get("last_seen") if buckets else None
    alert_total = last_ev.total

    high_ir = QueryIR(
        time_range=params.time_range,
        filters=[
            IRFilter(field="agent.name", op="eq", value=params.agent_name),
            IRFilter(field="rule.level", op="gte", value=params.severity_gte),
        ],
        limit=params.alert_size,
    )
    high_ev = await execute_ir(high_ir, principal)
    checks |= set(high_ev.checks_passed)

    vuln_params = CountVulnerabilitiesParams(
        time_range=StatesTimeRange(
            gte=params.time_range.gte, lte=params.time_range.lte
        ),
        agent_names=[params.agent_name],
    )
    vuln_ir = count_vulnerabilities_ir(vuln_params)
    vuln_ev = await execute_vulnerabilities_ir(vuln_ir, principal)
    checks |= set(vuln_ev.checks_passed)

    return {
        "agent_name": params.agent_name,
        "last_seen": last_seen,
        "alert_total": alert_total,
        "high_severity_total": high_ev.total,
        "high_severity_alerts": high_ev.hits,
        "open_vuln_count": vuln_ev.total,
        "total_matching": alert_total,
        "executed_window": high_ev.window,
        "veracity_checks_passed": sorted(checks),
    }


def _related_alerts_ir(_p: RelatedAlertsParams) -> QueryIR:
    raise RuntimeError("composite tool - executed via related_alerts()")


def _compare_windows_ir(_p: CompareWindowsParams) -> QueryIR:
    raise RuntimeError("composite tool - executed via compare_windows()")


def _agent_posture_ir(_p: AgentPostureParams) -> QueryIR:
    raise RuntimeError("composite tool - executed via agent_posture()")
