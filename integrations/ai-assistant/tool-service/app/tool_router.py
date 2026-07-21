"""Per-intent tool subsetting (D62 / E13).

Routing optimization only: never changes tool behavior or veracity. Fail open
to the full catalog when intent is unclear.
"""
from __future__ import annotations

import logging

from .config import CFG
from .tools import REGISTRY, converse_tool_specs

log = logging.getLogger("wazuh-ai.tool_router")

# Always offered so nothing becomes unanswerable.
_CORE = frozenset(
    {
        "count_alerts",
        "search_alerts",
        "get_alert",
        "knowledge_search",
        "describe_capabilities",
        "run_query_ir",
        "rule_reference",
        "field_dictionary",
        "mitre_lookup",
    }
)

_INTENT_TOOLS: dict[str, frozenset[str]] = {
    "vuln": frozenset(
        {
            "count_vulnerabilities",
            "vulnerabilities_by_severity",
            "agent_posture",
            "list_agents",
            "knowledge_search",
        }
    ),
    "auth": frozenset(
        {
            "auth_failures",
            "brute_force_summary",
            "top_rules",
            "alert_histogram",
            "related_alerts",
            "alert_timeline",
        }
    ),
    "investigate": frozenset(
        {
            "related_alerts",
            "compare_windows",
            "agent_posture",
            "alert_timeline",
            "mitre_coverage",
            "get_alert",
        }
    ),
    "dashboard": frozenset(
        {
            "list_dashboards",
            "list_alert_fields",
            "dashboard_design_guide",
            "index_health",
        }
    ),
    "docs": frozenset(
        {
            "knowledge_search",
            "rule_reference",
            "field_dictionary",
            "mitre_lookup",
            "describe_capabilities",
        }
    ),
    "ops": frozenset(
        {
            "index_health",
            "list_agents",
            "list_dashboards",
            "describe_capabilities",
        }
    ),
}

_INTENT_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    (
        "vuln",
        ("vulnerabilit", "cve", "cve-", "patch", "cvss", "vulnerable package"),
    ),
    (
        "auth",
        (
            "brute",
            "auth",
            "login",
            "ssh",
            "password",
            "failed log",
            "fallo",
            "autentic",
        ),
    ),
    (
        "investigate",
        (
            "explain",
            "investigate",
            "related",
            "timeline",
            "posture",
            "triage",
            "correlate",
            "compare",
        ),
    ),
    (
        "dashboard",
        ("dashboard", "visualization", "panel", "geoip", "create a dashboard"),
    ),
    (
        "docs",
        (
            "how do i",
            "how to",
            "configure",
            "documentation",
            "what does rule",
            "what does the field",
            "remediat",
            "active response",
            "que significa",
            "como configuro",
        ),
    ),
    (
        "ops",
        (
            "index health",
            "cluster",
            "what can you",
            "que puedes",
            "capabilities",
            "list agents",
        ),
    ),
]


def classify_intent(text: str) -> str | None:
    """Cheap keyword intent — fail open (None) when unclear or ambiguous."""
    q = (text or "").casefold()
    if len(q) < 8:
        return None
    hits: list[str] = []
    for intent, kws in _INTENT_KEYWORDS:
        if any(k in q for k in kws):
            hits.append(intent)
    if len(hits) == 1:
        return hits[0]
    return None


def subset_tool_names(intent: str | None) -> set[str] | None:
    """Return allowed REGISTRY tool names, or None for the full catalog."""
    if not CFG.tool_subset_enabled:
        return None
    if intent is None or intent not in _INTENT_TOOLS:
        return None
    allowed = set(_CORE) | set(_INTENT_TOOLS[intent])
    return {n for n in allowed if n in REGISTRY}


def tool_specs_for_turn(question: str) -> tuple[list[dict], dict]:
    """Return (specs, audit_meta) for this model turn."""
    intent = classify_intent(question) if CFG.tool_subset_enabled else None
    allowed = subset_tool_names(intent)
    specs = converse_tool_specs(allowed)
    meta = {
        "intent": intent,
        "subset": allowed is not None,
        "offered_tool_count": len(specs),
        "full_tool_count": len(converse_tool_specs(None)),
    }
    if allowed is not None:
        log.info(
            "tool_subset intent=%s offered=%s/%s",
            intent,
            meta["offered_tool_count"],
            meta["full_tool_count"],
        )
    return specs, meta
