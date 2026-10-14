"""Redaction and compaction of tool output before it reaches the client."""

import re as _re

# Patterns to redact from output text (credentials, tokens, keys in log lines). Results are
# usually serialized JSON on one line, so a value ends at whitespace, a quote or an escape
# (an escaped backslash `\\` is part of the value): unbounded `.+` / `\S+` would swallow the
# rest of the result or the closing quote and corrupt the JSON.
_REDACT_VALUE = r"(?:[^\s\"\\]|\\\\)+"
_OUTPUT_REDACT_PATTERNS = [
    _re.compile(r"(?i)((?:password|passwd|pwd)\s*[=:]\s*)" + _REDACT_VALUE),
    _re.compile(r"(?i)((?:api[_-]?key|secret|token)\s*[=:]\s*)" + _REDACT_VALUE),
    # The whole header value ("Bearer <token>"), up to the end of the line or JSON string
    _re.compile(r"(?i)(Authorization:\s*)(?:[^\"\\\n]|\\\\)+"),
]


def _sanitize_output_text(text: str) -> str:
    """Redact credentials/tokens from log text before returning to MCP clients."""
    for pattern in _OUTPUT_REDACT_PATTERNS:
        text = pattern.sub(r"\1[REDACTED]", text)
    return text


def _compact_alert(alert: dict) -> dict:
    """Strip a raw Wazuh alert to essential fields for MCP output."""
    compact = {}
    if "timestamp" in alert:
        compact["timestamp"] = alert["timestamp"]
    # `key or {}` (not `.get(key, {})`): a Wazuh alert can carry an explicit JSON null for
    # agent/rule/data, and `.get("data", {})` returns None for a present-but-null key, so a
    # single malformed alert would AttributeError and fail the whole get_wazuh_alerts call.
    agent = alert.get("agent") or {}
    if agent:
        compact["agent"] = {"id": agent.get("id", ""), "name": agent.get("name", "")}
    rule = alert.get("rule") or {}
    if rule:
        compact["rule"] = {
            "id": rule.get("id", ""),
            "level": rule.get("level", 0),
            "description": rule.get("description", ""),
            "groups": rule.get("groups", []),
        }
        if rule.get("mitre"):
            compact["rule"]["mitre"] = rule["mitre"]
    src = alert.get("data") or {}
    if src.get("srcip"):
        compact["srcip"] = src["srcip"]
    if src.get("dstip"):
        compact["dstip"] = src["dstip"]
    if alert.get("syscheck"):
        sc = alert["syscheck"]
        compact["syscheck"] = {"path": sc.get("path", ""), "event": sc.get("event", "")}
    if alert.get("full_log"):
        log = str(alert["full_log"])
        log = (log[:300] + "...") if len(log) > 300 else log
        compact["full_log"] = _sanitize_output_text(log)
    return compact


def _compact_alerts_result(result: dict) -> dict:
    """Apply compaction to a standard alerts result dict."""
    data = result.get("data", {})
    items = data.get("affected_items", [])
    data["affected_items"] = [_compact_alert(a) for a in items]
    return result


def _add_truncation_warning(result: dict, requested_limit: int) -> dict:
    """Add a warning if results hit the requested limit (likely truncated)."""
    data = result.get("data", {})
    items = data.get("affected_items", [])
    total = data.get("total_affected_items", len(items))
    if total >= requested_limit:
        result["_warning"] = (
            f"Results may be truncated ({total} items returned, limit was {requested_limit}). "
            f"Use more specific filters (time_range, agent_id, rule_id, level) or increase limit for complete results."
        )
    return result


def _compact_vulnerability(vuln: dict) -> dict:
    """Strip a raw Wazuh vulnerability to essential fields for MCP output."""
    compact = {}
    for key in ("id", "severity"):
        if key in vuln:
            compact[key] = vuln[key]
    if "id" in vuln:
        compact["cve"] = vuln["id"]
    if vuln.get("description"):
        desc = str(vuln["description"])
        compact["description"] = (desc[:120] + "...") if len(desc) > 120 else desc
    if "reference" in vuln:
        compact["reference"] = vuln["reference"]
    if "published_at" in vuln:
        compact["published_at"] = vuln["published_at"]
    pkg = vuln.get("package", {})
    if pkg:
        compact["package"] = {"name": pkg.get("name", ""), "version": pkg.get("version", "")}
    agent = vuln.get("agent", {})
    if agent:
        compact["agent"] = {"id": agent.get("id", ""), "name": agent.get("name", "")}
    return compact


def _compact_vulns_result(result: dict) -> dict:
    """Apply compaction to a standard vulnerabilities result dict."""
    data = result.get("data", {})
    items = data.get("affected_items", [])
    if items:
        data["affected_items"] = [_compact_vulnerability(v) for v in items]
    return result
