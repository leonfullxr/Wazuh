"""Lane-1 tools for Wazuh states indices (V3.4 vulnerabilities)."""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

from .states_models import (
    StatesIRAggregation,
    StatesIRFilter,
    StatesQueryIR,
    StatesTimeRange,
)


class CountVulnerabilitiesParams(BaseModel):
    """Exact count of vulnerability state records in the detected-at window."""

    time_range: StatesTimeRange = Field(default_factory=StatesTimeRange)
    severity: Optional[Literal["low", "medium", "high", "critical", "none"]] = Field(
        None, description="Filter vulnerability.severity"
    )
    agent_names: Optional[list[str]] = Field(None, description="Filter agent.name values")
    package_name: Optional[str] = Field(None, description="Exact package.name")


def count_vulnerabilities_ir(p: CountVulnerabilitiesParams) -> StatesQueryIR:
    filters: list[StatesIRFilter] = []
    if p.severity:
        filters.append(
            StatesIRFilter(field="vulnerability.severity", op="eq", value=p.severity)
        )
    if p.agent_names:
        filters.append(StatesIRFilter(field="agent.name", op="in", value=p.agent_names))
    if p.package_name:
        filters.append(
            StatesIRFilter(field="package.name", op="eq", value=p.package_name)
        )
    return StatesQueryIR(
        time_range=p.time_range,
        filters=filters,
        aggregation=StatesIRAggregation(kind="count"),
        limit=0,
    )


class VulnerabilitiesBySeverityParams(BaseModel):
    """Vulnerability counts grouped by severity (exact datastore terms agg)."""

    time_range: StatesTimeRange = Field(default_factory=StatesTimeRange)
    size: int = Field(10, ge=1, le=20)


def vulnerabilities_by_severity_ir(
    p: VulnerabilitiesBySeverityParams,
) -> StatesQueryIR:
    return StatesQueryIR(
        time_range=p.time_range,
        aggregation=StatesIRAggregation(
            kind="terms", field="vulnerability.severity", size=p.size
        ),
        limit=0,
    )
