from datetime import UTC, datetime

import pytest

from ai_soc.planning.windows import WindowParseError, parse_window


def test_rolling_window_is_half_open_from_one_utc_anchor() -> None:
    anchor = datetime(2026, 9, 30, 12, tzinfo=UTC)
    parsed = parse_window("last 24 hours", anchor_at=anchor, timezone="UTC").window
    assert parsed.start == datetime(2026, 9, 29, 12, tzinfo=UTC)
    assert parsed.end == anchor
    assert parsed.semantics == "rolling"


def test_spanish_feminine_rolling_window_matches_reviewed_generic_fetch_example() -> None:
    anchor = datetime(2026, 9, 30, 12, tzinfo=UTC)
    parsed = parse_window(
        "Muestra alertas de las últimas 24 horas",
        anchor_at=anchor,
        timezone="UTC",
    ).window
    assert parsed.start == datetime(2026, 9, 29, 12, tzinfo=UTC)
    assert parsed.end == anchor
    assert parsed.source_text == "rolling:24:hours"


@pytest.mark.parametrize(
    ("anchor", "expected_hours"),
    [
        (datetime(2026, 3, 30, 10, tzinfo=UTC), 23),
        (datetime(2026, 10, 26, 10, tzinfo=UTC), 25),
    ],
)
def test_yesterday_preserves_dst_calendar_duration(anchor: datetime, expected_hours: int) -> None:
    parsed = parse_window("yesterday", anchor_at=anchor, timezone="Europe/Madrid").window
    assert (parsed.end - parsed.start).total_seconds() == expected_hours * 3600


def test_ambiguous_or_nonexistent_absolute_local_times_clarify() -> None:
    with pytest.raises(WindowParseError, match="ambiguous"):
        parse_window(
            "from 2026-10-25T02:30 to 2026-10-25T03:30",
            anchor_at=datetime(2026, 10, 26, tzinfo=UTC),
            timezone="Europe/Madrid",
        )
    with pytest.raises(WindowParseError, match="gap"):
        parse_window(
            "from 2026-03-29T02:30 to 2026-03-29T03:30",
            anchor_at=datetime(2026, 3, 30, tzinfo=UTC),
            timezone="Europe/Madrid",
        )


def test_zero_duration_today_and_oversized_windows_are_rejected() -> None:
    with pytest.raises(WindowParseError, match="positive"):
        parse_window(
            "today",
            anchor_at=datetime(2026, 9, 30, 0, tzinfo=UTC),
            timezone="UTC",
        )
    with pytest.raises(WindowParseError, match="90 days"):
        parse_window(
            "last 91 days",
            anchor_at=datetime(2026, 9, 30, 12, tzinfo=UTC),
            timezone="UTC",
        )
