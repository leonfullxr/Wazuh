"""Recognize window-only follow-up questions after leading punctuation normalization."""

from __future__ import annotations

import re

from ai_soc.contracts.ports import Clock
from ai_soc.planning.windows import WindowParseError, parse_window

# Quotes start quoted payloads; only strip whitespace and Spanish sentence openers.
_LEADING_PUNCT = re.compile(r"^[\s¿?¡!]+")


def normalize_leading_routing_text(question: str) -> str:
    text = question.strip()
    text = _LEADING_PUNCT.sub("", text)
    return text.strip()


def window_only_followup(question: str, *, timezone: str, clock: Clock) -> bool:
    """True when the whole question is a spec window_only follow-up."""
    routed = normalize_leading_routing_text(question)
    if not re.match(r"(?i)^(?:and for|y para)\b", routed):
        return False
    try:
        parse_window(question, anchor_at=clock.now(), timezone=timezone)
    except WindowParseError:
        return False
    return True
