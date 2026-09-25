"""Intent routing: analysis (MCP) vs destructive actions."""
from __future__ import annotations

import re
from typing import Callable

ANALYSIS = "analysis"
ACTION_RESTART = "action_restart"
ACTION_DASHBOARD = "action_dashboard"
ACTION_REPORT = "action_report"
CONFIRM = "confirm"
NO = "no"

ACTION_INTENTS = {ACTION_RESTART, ACTION_DASHBOARD, ACTION_REPORT}

_ANALYSIS_HINTS = (
    "alert",
    "dql",
    "vulnerability",
    "vulnerabilities",
    "sca",
    "hygiene",
    "compliance",
    "mitre",
    "how many",
    "show me",
    "list ",
    "what ",
    "which ",
)


def keyword_classify(message: str) -> str:
    """Rule-based classifier used when no LLM is configured."""
    text = message.strip()
    upper = text.upper()
    lower = text.lower()

    if text == "CONFIRM":
        return CONFIRM
    if upper == "NO":
        return NO

    if re.search(r"\brestart\b.*\bagent\b|\bagent\b.*\brestart\b", lower):
        return ACTION_RESTART
    if re.search(r"\b(create|new)\b.*\bdashboard\b|\bdashboard\b.*\b(create|new)\b", lower):
        return ACTION_DASHBOARD
    if re.search(r"\b(email|send)\b.*\b(report|pdf)\b|\b(report|pdf)\b.*\b(email|send)\b", lower):
        return ACTION_REPORT

    if any(hint in lower for hint in _ANALYSIS_HINTS):
        return ANALYSIS

    if text.endswith("?") or lower.startswith(("how", "what", "which", "show", "list")):
        return ANALYSIS

    return ANALYSIS


def classify_intent(
    message: str,
    classifier: Callable[[str], str] | None = None,
) -> str:
    """Return an intent label. Uses injected classifier or keyword rules."""
    fn = classifier or keyword_classify
    return fn(message)


def extract_action_params(intent: str, message: str) -> dict:
    """Best-effort parameter extraction from natural language."""
    lower = message.lower()
    params: dict = {"raw_message": message}

    if intent == ACTION_RESTART:
        match = re.search(r"\bagent[_\s-]?id[:\s]+([a-zA-Z0-9._-]+)", lower)
        if not match:
            match = re.search(r"\b(?:agent|host)\s+([a-zA-Z0-9._-]+)", lower)
        if match:
            params["agent_id"] = match.group(1)
    elif intent == ACTION_DASHBOARD:
        match = re.search(r"dashboard\s+['\"]?([^'\"]+)['\"]?", message, re.I)
        if match:
            params["dashboard_name"] = match.group(1).strip()
    elif intent == ACTION_REPORT:
        match = re.search(r"[\w.+-]+@[\w.-]+\.\w+", message)
        if match:
            params["email"] = match.group(0)

    return params
