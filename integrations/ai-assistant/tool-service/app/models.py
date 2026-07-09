"""The typed Query IR (D29, 11 s2) - the storage-agnostic query plan.

Lane 1 tools compile validated params into this IR. Lane 2 lets the model emit
an IR document directly, and this schema is the gate it passes through. The IR
is the contract everything pins to: the audit log stores it, the golden set
asserts against it, and each datastore gets a compiler (OpenSearch DSL today,
ClickHouse SQL when the migration lands) behind an unchanged interface.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal, Optional, Union

from pydantic import BaseModel, Field, model_validator

# ---------------------------------------------------------------------------
# Field allowlist. The model can never reference a field outside this table,
# which is the first structural veracity guarantee (D4): no free-form fields,
# no scripts, no wildcards, by construction.
# ---------------------------------------------------------------------------
ALLOWED_FIELDS: dict[str, str] = {
    "_id": "keyword",
    "timestamp": "date",
    "rule.id": "keyword",
    "rule.level": "long",
    "rule.description": "text",
    "rule.groups": "keyword",
    "rule.mitre.id": "keyword",
    "rule.mitre.technique": "keyword",
    "agent.id": "keyword",
    "agent.name": "keyword",
    "agent.ip": "keyword",
    "data.srcip": "keyword",
    "data.srcuser": "keyword",
    "data.dstuser": "keyword",
    "decoder.name": "keyword",
    "location": "keyword",
    "full_log": "text",
}

OPS_BY_TYPE: dict[str, set[str]] = {
    "keyword": {"eq", "in", "exists"},
    "long": {"eq", "gte", "lte"},
    "date": set(),  # dates travel through time_range, never through raw filters
    "text": {"match"},
}

MAX_WINDOW_DAYS = 90  # hard cap
MAX_FILTERS = 10
MAX_SIZE = 50


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TimeRange(BaseModel):
    """ISO-8601 window, capped at 90 days."""

    gte: datetime = Field(default_factory=lambda: _utcnow() - timedelta(hours=24))
    lte: datetime = Field(default_factory=_utcnow)

    @model_validator(mode="after")
    def _check(self) -> "TimeRange":
        if self.gte >= self.lte:
            raise ValueError("time_range.gte must be before time_range.lte")
        if self.lte - self.gte > timedelta(days=MAX_WINDOW_DAYS):
            raise ValueError(f"time window capped at {MAX_WINDOW_DAYS} days")
        return self

    def iso(self) -> tuple[str, str]:
        return self.gte.isoformat(), self.lte.isoformat()


class IRFilter(BaseModel):
    field: str = Field(description="One of the allowlisted alert fields")
    op: Literal["eq", "in", "gte", "lte", "exists", "match"]
    value: Union[str, int, float, list[str], None] = None

    @model_validator(mode="after")
    def _check(self) -> "IRFilter":
        ftype = ALLOWED_FIELDS.get(self.field)
        if ftype is None:
            raise ValueError(
                f"field '{self.field}' is not allowlisted "
                f"(allowed: {', '.join(sorted(ALLOWED_FIELDS))})"
            )
        if self.op not in OPS_BY_TYPE[ftype]:
            raise ValueError(
                f"op '{self.op}' not allowed on {ftype} field '{self.field}'"
            )
        if self.op == "in":
            if not isinstance(self.value, list) or not self.value:
                raise ValueError("op 'in' requires a non-empty list value")
            if len(self.value) > 20:
                raise ValueError("op 'in' capped at 20 values")
        elif self.op == "exists":
            self.value = None
        else:
            if isinstance(self.value, list) or self.value is None:
                raise ValueError(f"op '{self.op}' requires a scalar value")
        return self


class IRAggregation(BaseModel):
    """Counts and trends are computed HERE, by the datastore - never by the
    model reading a list (D24 check 4)."""

    kind: Literal["count", "terms", "date_histogram", "cardinality"]
    field: Optional[str] = None
    interval: Literal["1h", "3h", "12h", "1d"] = "1d"
    size: int = Field(10, ge=1, le=MAX_SIZE)

    @model_validator(mode="after")
    def _check(self) -> "IRAggregation":
        if self.kind in ("terms", "cardinality"):
            if self.field is None:
                raise ValueError(f"aggregation '{self.kind}' requires a field")
            if ALLOWED_FIELDS.get(self.field) != "keyword":
                raise ValueError(
                    f"aggregation '{self.kind}' requires a keyword field, "
                    f"got '{self.field}'"
                )
        return self


class QueryIR(BaseModel):
    """The full typed query plan. This is what gets audited and compiled."""

    time_range: TimeRange = Field(default_factory=TimeRange)
    filters: list[IRFilter] = Field(default_factory=list, max_length=MAX_FILTERS)
    aggregation: Optional[IRAggregation] = None
    limit: int = Field(20, ge=0, le=MAX_SIZE)
    sort: Literal["timestamp:desc", "timestamp:asc"] = "timestamp:desc"
