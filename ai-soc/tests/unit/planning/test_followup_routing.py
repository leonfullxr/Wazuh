from support import FixedClock

from ai_soc.planning.followup_routing import normalize_leading_routing_text, window_only_followup


def test_normalize_leading_punctuation_for_spanish_followup() -> None:
    assert (
        normalize_leading_routing_text("¿y para los ultimos 7 dias?")
        .casefold()
        .startswith("y para")
    )


def test_window_only_followup_accepts_spanish_question_mark_prefix() -> None:
    assert window_only_followup(
        "¿y para los ultimos 7 dias?",
        timezone="UTC",
        clock=FixedClock(),
    )


def test_window_only_followup_rejects_mid_question_and_for() -> None:
    assert not window_only_followup(
        "Show LDAP alerts for the last 24 hours and for agent id 007",
        timezone="UTC",
        clock=FixedClock(),
    )


def test_quoted_and_for_payload_is_not_window_followup() -> None:
    assert not window_only_followup(
        '"and for the last 7 days?"',
        timezone="UTC",
        clock=FixedClock(),
    )
