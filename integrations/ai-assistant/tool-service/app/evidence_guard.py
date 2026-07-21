"""Evidence-side injection guard (E8) - deterministic, no model.

Alert fields (full_log, descriptions) are attacker-influenced. Before synthesis,
scan compacted evidence for prompt-injection shapes, audit, and neutralize by
delimiting rather than dropping legitimate content.
"""
from __future__ import annotations

import json
import re
from typing import Any

from . import audit

_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.I),
    re.compile(r"disregard\s+(your|the)\s+(system|safety)\s+prompt", re.I),
    re.compile(r"you\s+are\s+now\s+(dan|unrestricted|jailbroken)", re.I),
    re.compile(r"print\s+(your|the)\s+system\s+prompt", re.I),
    re.compile(r"reveal\s+(your|the)\s+(hidden|system)\s+instructions?", re.I),
    re.compile(r"<\s*/?\s*system\s*>", re.I),
    re.compile(r"\[\s*INST\s*\]", re.I),
    re.compile(r"nuevo\s+sistema\s*:\s*ignora", re.I),
    re.compile(r"ignora\s+(todas\s+)?(las\s+)?instrucciones", re.I),
]


def _scan_text(text: str) -> list[str]:
    hits = []
    for pat in _PATTERNS:
        if pat.search(text):
            hits.append(pat.pattern)
    return hits


def _walk(obj: Any, path: str, findings: list[tuple[str, str]]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            _walk(v, f"{path}.{k}" if path else str(k), findings)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _walk(v, f"{path}[{i}]", findings)
    elif isinstance(obj, str) and len(obj) >= 12:
        for pat in _scan_text(obj):
            findings.append((path, pat))


def neutralize_string(text: str) -> str:
    """Wrap suspicious text so the model treats it as untrusted data."""
    return (
        "<<UNTRUSTED_EVIDENCE>>\n"
        f"{text}\n"
        "<<END_UNTRUSTED_EVIDENCE>>"
    )


def guard_evidence(
    payload: Any,
    *,
    env_id: str | None = None,
    source: str = "tool",
) -> Any:
    """Return a copy of payload with injection-shaped strings delimited.

    Audits when anything is flagged. Legitimate evidence without matches is
    returned unchanged (same object identity when clean).
    """
    findings: list[tuple[str, str]] = []
    _walk(payload, "", findings)
    if not findings:
        return payload

    audit.emit(
        "evidence_injection_flagged",
        env=env_id,
        source=source,
        paths=[p for p, _ in findings[:20]],
        patterns=[pat[:80] for _, pat in findings[:10]],
        count=len(findings),
    )

    def _scrub(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: _scrub(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_scrub(v) for v in obj]
        if isinstance(obj, str) and _scan_text(obj):
            return neutralize_string(obj)
        return obj

    return _scrub(payload)


def guard_evidence_text(text: str, *, env_id: str | None = None) -> str:
    """Guard a JSON/text blob used for playbook synthesis."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        if _scan_text(text):
            audit.emit(
                "evidence_injection_flagged",
                env=env_id,
                source="playbook_text",
                count=1,
            )
            return neutralize_string(text)
        return text
    cleaned = guard_evidence(data, env_id=env_id, source="playbook")
    return json.dumps(cleaned, default=str)
