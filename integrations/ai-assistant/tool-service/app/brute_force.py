"""Brute-force summary composite tool (V3.7a)."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from .auth_groups import AUTH_FAILURE_GROUPS, BRUTE_FORCE_MITRE
from .models import IRAggregation, IRFilter, QueryIR, TimeRange
from .principal import Principal
from .veracity import execute_ir, term_buckets


class BruteForceSummaryParams(BaseModel):
    """MITRE T1110 OR auth-failure groups: totals, timeline, top IPs and users."""

    time_range: TimeRange = Field(default_factory=TimeRange)
    size: int = Field(10, ge=1, le=50)
    interval: Literal["1h", "3h", "12h", "1d"] = "1h"


def _base_ir(params: BruteForceSummaryParams) -> QueryIR:
    return QueryIR(
        time_range=params.time_range,
        should_any=[
            IRFilter(
                field="rule.groups",
                op="in",
                value=list(AUTH_FAILURE_GROUPS),
            ),
            IRFilter(field="rule.mitre.id", op="eq", value=BRUTE_FORCE_MITRE),
        ],
    )


def _bucket_list(aggregations: dict, key: str) -> list[dict[str, Any]]:
    return term_buckets(aggregations, key)


async def brute_force_summary(
    principal: Principal, params: BruteForceSummaryParams
) -> dict[str, Any]:
    base = _base_ir(params)
    checks: set[str] = set()

    count_ir = base.model_copy(
        update={"aggregation": IRAggregation(kind="count"), "limit": 0}
    )
    count_ev = await execute_ir(count_ir, principal)
    checks |= set(count_ev.checks_passed)

    timeline_ir = base.model_copy(
        update={
            "aggregation": IRAggregation(
                kind="date_histogram",
                interval=params.interval,
            ),
            "limit": 0,
        }
    )
    timeline_ev = await execute_ir(timeline_ir, principal)
    checks |= set(timeline_ev.checks_passed)

    src_ir = base.model_copy(
        update={
            "aggregation": IRAggregation(
                kind="terms", field="data.srcip", size=params.size
            ),
            "limit": 0,
        }
    )
    src_ev = await execute_ir(src_ir, principal)
    checks |= set(src_ev.checks_passed)

    user_ir = base.model_copy(
        update={
            "aggregation": IRAggregation(
                kind="terms", field="data.dstuser", size=params.size
            ),
            "limit": 0,
        }
    )
    user_ev = await execute_ir(user_ir, principal)
    checks |= set(user_ev.checks_passed)

    return {
        "total_matching": count_ev.total,
        "total_computed_by": count_ev.total_computed_by,
        "executed_window": count_ev.window,
        "recipe": (
            f"rule.mitre.id={BRUTE_FORCE_MITRE} OR rule.groups in "
            f"{list(AUTH_FAILURE_GROUPS)}"
        ),
        "timeline": _bucket_list(timeline_ev.aggregations, "over_time"),
        "top_source_ips": _bucket_list(src_ev.aggregations, "by"),
        "top_target_users": _bucket_list(user_ev.aggregations, "by"),
        "veracity_checks_passed": sorted(checks),
    }
