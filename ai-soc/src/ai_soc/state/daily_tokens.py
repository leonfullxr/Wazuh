"""UTC daily token ledger keys for owner and service spend caps."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


def utc_day_start_epoch(now: datetime) -> int:
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    day = now.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    return int(day.timestamp())


def daily_ledger_ttl_epoch(day_start_epoch: int) -> int:
    """Retain ledger rows until two days after the UTC day boundary for TTL cleanup."""
    return day_start_epoch + int(timedelta(days=2).total_seconds())


def owner_daily_key(owner_key: str, day_start_epoch: int) -> tuple[str, str]:
    return f"TOKENDAY#owner#{owner_key}", str(day_start_epoch)


def service_daily_key(day_start_epoch: int) -> tuple[str, str]:
    return "TOKENDAY#service", str(day_start_epoch)
