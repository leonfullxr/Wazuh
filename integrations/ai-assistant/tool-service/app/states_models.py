"""States-index Query IR (V3.4) — parallel to alerts IR, separate allowlist."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal, Optional, Union

from pydantic import BaseModel, Field, model_validator

from .index_families import VULN_ALLOWED_FIELDS
from .models import MAX_FILTERS, MAX_SIZE, MAX_WINDOW_DAYS, OPS_BY_TYPE


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class StatesTimeRange(BaseModel):
    """Rolling window on vulnerability.detected_at."""

    gte: datetime = Field(default_factory=lambda: _utcnow() - timedelta(days=30))
    lte: datetime = Field(default_factory=_utcnow)

    @model_validator(mode="after")
    def _check(self) -> "StatesTimeRange":
        if self.gte >= self.lte:
            raise ValueError("time_range.gte must be before time_range.lte")
        if self.lte - self.gte > timedelta(days=MAX_WINDOW_DAYS):
            raise ValueError(f"time window capped at {MAX_WINDOW_DAYS} days")
        return self

    def iso(self) -> tuple[str, str]:
        return self.gte.isoformat(), self.lte.isoformat()


class StatesIRFilter(BaseModel):
    field: str
    op: Literal["eq", "in", "gte", "lte", "exists", "match"]
    value: Union[str, int, float, list[str], None] = None

    @model_validator(mode="after")
    def _check(self) -> "StatesIRFilter":
        ftype = VULN_ALLOWED_FIELDS.get(self.field)
        if ftype is None:
            raise ValueError(
                f"field '{self.field}' is not allowlisted for vulnerability states "
                f"(allowed: {', '.join(sorted(VULN_ALLOWED_FIELDS))})"
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


class StatesIRAggregation(BaseModel):
    kind: Literal["count", "terms", "date_histogram", "cardinality"]
    field: Optional[str] = None
    interval: Literal["1h", "3h", "12h", "1d"] = "1d"
    size: int = Field(10, ge=1, le=MAX_SIZE)

    @model_validator(mode="after")
    def _check(self) -> "StatesIRAggregation":
        if self.kind in ("terms", "cardinality"):
            if self.field is None:
                raise ValueError(f"aggregation '{self.kind}' requires a field")
            if VULN_ALLOWED_FIELDS.get(self.field) != "keyword":
                raise ValueError(
                    f"aggregation '{self.kind}' requires a keyword field, "
                    f"got '{self.field}'"
                )
        return self


class StatesQueryIR(BaseModel):
    time_range: StatesTimeRange = Field(default_factory=StatesTimeRange)
    filters: list[StatesIRFilter] = Field(default_factory=list, max_length=MAX_FILTERS)
    aggregation: Optional[StatesIRAggregation] = None
    limit: int = Field(20, ge=0, le=MAX_SIZE)
    sort: Literal[
        "vulnerability.detected_at:desc", "vulnerability.detected_at:asc"
    ] = "vulnerability.detected_at:desc"
