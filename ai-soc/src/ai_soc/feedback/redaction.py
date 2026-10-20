"""Reject likely credentials and replace common direct identifiers in feedback notes."""

from __future__ import annotations

import re

_SECRET = re.compile(
    r"(?i)\b(password|passwd|secret|api[_ -]?key|access[_ -]?token|authorization)\s*[:=]"
)
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}\b")
_IDENTIFIER = re.compile(r"\b(?=[A-Za-z0-9_-]{24,}\b)(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]+\b")


def redact_note(note: str | None) -> str | None:
    if note is None:
        return None
    if len(note) > 1000 or len(note.encode("utf-8")) > 4096:
        raise ValueError("feedback note exceeds its limit")
    if _SECRET.search(note):
        raise ValueError("feedback note appears to contain a secret")
    text = _EMAIL.sub("[redacted email]", note)
    text = _IPV4.sub("[redacted address]", text)
    text = _IPV6.sub("[redacted address]", text)
    return _IDENTIFIER.sub("[redacted identifier]", text)
