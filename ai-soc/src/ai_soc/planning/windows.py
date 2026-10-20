"""Finite bilingual window grammar with explicit timezone and DST handling."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo

from ai_soc.contracts.models import ResolvedWindow

_ROLLING = re.compile(
    r"\b(?:last|últimos?|ultimos?|últimas?|ultimas?)\s+(\d{1,3})\s+"
    r"(minutes?|mins?|minutos?|hours?|hrs?|horas?|days?|días?|dias?)\b",
    re.IGNORECASE,
)
_ABSOLUTE = re.compile(
    r"\b(?:from|desde)\s+(\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}"
    r"(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:?\d{2})?)?)\s+"
    r"(?:to|hasta)\s+(\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}"
    r"(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:?\d{2})?)?)\b",
    re.IGNORECASE,
)


class WindowParseError(ValueError):
    """The requested window is missing, ambiguous, or outside contract bounds."""


@dataclass(frozen=True, slots=True)
class WindowMatch:
    window: ResolvedWindow
    start: int
    end: int


def _local_boundary(day: date, zone: ZoneInfo) -> datetime:
    naive = datetime.combine(day, time.min)
    candidate = naive.replace(tzinfo=zone, fold=0)
    round_trip = candidate.astimezone(UTC).astimezone(zone).replace(tzinfo=None)
    if round_trip != naive:
        raise WindowParseError("local calendar boundary falls in a DST gap")
    return candidate


def _parse_endpoint(value: str, zone: ZoneInfo) -> datetime:
    canonical = value.replace(" ", "T", 1).replace("Z", "+00:00")
    canonical = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", canonical)
    try:
        parsed = datetime.fromisoformat(canonical)
    except ValueError as exc:
        raise WindowParseError("invalid absolute timestamp") from exc
    if parsed.tzinfo is not None:
        return parsed.astimezone(UTC)
    first = parsed.replace(tzinfo=zone, fold=0)
    second = parsed.replace(tzinfo=zone, fold=1)
    first_valid = first.astimezone(UTC).astimezone(zone).replace(tzinfo=None) == parsed
    second_valid = second.astimezone(UTC).astimezone(zone).replace(tzinfo=None) == parsed
    if not first_valid and not second_valid:
        raise WindowParseError("absolute local time falls in a DST gap")
    if first_valid and second_valid and first.utcoffset() != second.utcoffset():
        raise WindowParseError("absolute local time is ambiguous at a DST fold")
    return first.astimezone(UTC)


def parse_window(text: str, *, anchor_at: datetime, timezone: str) -> WindowMatch:
    """Parse exactly one supported window and resolve it against the injected anchor."""
    if anchor_at.tzinfo is None or anchor_at.utcoffset() is None:
        raise ValueError("anchor_at must be timezone-aware")
    anchor = anchor_at.astimezone(UTC)
    try:
        zone = ZoneInfo(timezone)
    except Exception as exc:
        raise WindowParseError("unknown IANA timezone") from exc
    rolling = list(_ROLLING.finditer(text))
    absolute = list(_ABSOLUTE.finditer(text))
    calendar = list(re.finditer(r"\b(today|yesterday|hoy|ayer)\b", text, re.IGNORECASE))
    matches = [(m.start(), m.end(), "rolling", m) for m in rolling]
    matches += [(m.start(), m.end(), "absolute", m) for m in absolute]
    matches += [(m.start(), m.end(), "calendar", m) for m in calendar]
    if len(matches) != 1:
        raise WindowParseError("exactly one explicit window is required")
    start_idx, end_idx, kind, match = matches[0]
    source = match.group(0).casefold()
    if kind == "rolling":
        amount = int(match.group(1))
        unit = match.group(2).casefold()
        if amount <= 0:
            raise WindowParseError("window amount must be positive")
        if unit.startswith(("min",)):
            delta = timedelta(minutes=amount)
        elif unit.startswith(("hour", "hr", "hora")):
            delta = timedelta(hours=amount)
        else:
            delta = timedelta(days=amount)
        start, end = anchor - delta, anchor
        unit_name = (
            "minutes"
            if unit.startswith("min")
            else "hours"
            if unit.startswith(("hour", "hr", "hora"))
            else "days"
        )
        canonical = f"rolling:{amount}:{unit_name}"
        semantics = "rolling"
    elif kind == "absolute":
        start = _parse_endpoint(match.group(1), zone)
        end = _parse_endpoint(match.group(2), zone)
        canonical = f"absolute:{start.isoformat()}:{end.isoformat()}"
        semantics = "absolute"
    else:
        current_local = anchor.astimezone(zone).date()
        if source in {"today", "hoy"}:
            day = current_local
            start = _local_boundary(day, zone).astimezone(UTC)
            end = anchor
        else:
            day = current_local - timedelta(days=1)
            start = _local_boundary(day, zone).astimezone(UTC)
            end = _local_boundary(day + timedelta(days=1), zone).astimezone(UTC)
        canonical = (
            f"calendar:{day.isoformat()}:{'today' if source in {'today', 'hoy'} else 'yesterday'}"
        )
        semantics = "calendar"
    if start >= end:
        raise WindowParseError("window must have positive duration")
    if end > anchor:
        raise WindowParseError("window end cannot be in the future")
    if end - start > timedelta(days=90):
        raise WindowParseError("window cannot exceed 90 days")
    return WindowMatch(
        ResolvedWindow(
            start=start,
            end=end,
            semantics=semantics,
            source_text=canonical,
            timezone=timezone,
            anchor_at=anchor,
        ),
        start_idx,
        end_idx,
    )
