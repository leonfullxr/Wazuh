"""Redaction and compaction of tool output before it reaches the client."""

import json
import math
import re as _re
from datetime import date, datetime, time
from uuid import UUID

_SENSITIVE = frozenset({
    "password", "passwd", "apikey", "xapikey", "apisecret", "clientsecret", "privatekey",
    "authorization", "proxyauthorization", "accesstoken", "refreshtoken", "idtoken",
    "sessiontoken", "token", "secret", "cookie", "setcookie", "secretkey", "dbpassword", "apitoken",
})
_MARKER = "[REDACTED]"
_TRUNCATED = "[Truncated: output could not be safely inspected]"
# Handle literal and escaped JSON keys as well as conventional log assignments.
_ASSIGNMENT = _re.compile(
    r"(?i)((?:\\?[\"']?)(?<![A-Za-z0-9])(?:db[_-]?password|secret[_-]?key|api[_-]?token|password|passwd|pwd|api[_-]?key|x[_-]?api[_-]?key|api[_-]?secret|client[_-]?secret|private[_-]?key|authorization|proxy[_-]?authorization|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|token|secret|cookie|set[_-]?cookie)(?:\\?[\"']?)\s*[=:]\s*)(?:\\\".*?(?:\\\"|$)|\"[^\"]*(?:\"|$)|'[^']*(?:'|$)|(?:bearer\s+|basic\s+)?[^\s,;\"'\\}]+)"
)
_FLAG = _re.compile(
    r"(?i)(?<!\S)(--(?:password|passwd|pwd|token|api[_-]?key|api[_-]?token|secret[_-]?key))\s+(?:\"[^\"]*(?:\"|$)|'[^']*(?:'|$)|(?!-{1,2}[A-Za-z])[^\s]+)"
)
_HEADER = _re.compile(r"(?i)\b(bearer|basic)\s+([A-Za-z0-9._~+/=-]+)")
_URL_USERINFO = _re.compile(r"(?i)(https?://)[^\s/@]+@")


def _sanitize_output_text(text: str) -> str:
    if len(text) > 1_000_000:
        return _TRUNCATED
    text = _ASSIGNMENT.sub(lambda m: m.group(1) + _MARKER, text)
    text = _FLAG.sub(lambda m: m.group(1) + " " + _MARKER, text)

    def redact_token(match):
        candidate = match.group(2)
        if (match.group(1).lower(), candidate.lower()) in {("basic", "authentication"), ("bearer", "of")}:
            return match.group(0)
        return match.group(1) + " " + _MARKER

    text = _HEADER.sub(redact_token, text)
    return _URL_USERINFO.sub(r"\1[REDACTED]@", text)


def sanitize_output(value, *, max_chars=1_000_000, max_depth=32):
    """Return an independently owned, bounded JSON-compatible redacted value."""
    remaining = max_chars

    def visit(item, depth):
        nonlocal remaining
        remaining -= 1  # Charge every visited node, including empty containers and strings.
        if depth > max_depth or remaining <= 0:
            return _TRUNCATED
        if item is None or isinstance(item, (bool, int, float)):
            if isinstance(item, float) and not math.isfinite(item):
                return _TRUNCATED
            try:
                remaining -= len(str(item))
            except ValueError:
                return _TRUNCATED
            return item if remaining >= 0 else _TRUNCATED
        if isinstance(item, (datetime, date, time, UUID)):
            return visit(str(item), depth)
        if isinstance(item, str):
            remaining -= len(item)
            return _sanitize_output_text(item) if remaining >= 0 else _TRUNCATED
        if isinstance(item, (list, tuple)):
            result = []
            for child in item:
                if remaining <= 0:
                    result.append(_TRUNCATED)
                    break
                result.append(visit(child, depth + 1))
            return result
        if isinstance(item, dict):
            result = {}
            next_suffix = {}
            for key, child in item.items():
                if remaining <= 0:
                    result["[truncated]"] = _TRUNCATED
                    break
                if not isinstance(key, str):
                    if key is None:
                        key = "null"
                    elif isinstance(key, bool):
                        key = "true" if key else "false"
                    elif isinstance(key, int) or (isinstance(key, float) and math.isfinite(key)):
                        try:
                            key = str(key)
                        except ValueError:
                            return _TRUNCATED
                    else:
                        return _TRUNCATED
                remaining -= len(key)
                if remaining < 0:
                    result["[truncated]"] = _TRUNCATED
                    break
                safe_key = _sanitize_output_text(key)
                base = safe_key
                suffix = next_suffix.get(base, 2)
                while safe_key in result:
                    safe_key = f"{base} [{suffix}]"
                    suffix += 1
                if safe_key != base:
                    next_suffix[base] = suffix
                sensitive = False
                if key.isascii():
                    # Every accepted credential suffix is short. Inspect only a bounded
                    # tail, retaining one preceding character for the boundary check.
                    tail = key[-65:]
                    for index, char in enumerate(tail):
                        previous = key[len(key) - len(tail) + index - 1] if len(key) - len(tail) + index else ""
                        boundary = not previous or previous in "_.-" or (previous.islower() and char.isupper())
                        if not boundary:
                            continue
                        normalized = tail[index:].lower().replace("-", "").replace("_", "").replace(".", "")
                        if normalized in _SENSITIVE or (normalized == "pwd" and previous):
                            sensitive = True
                            break
                result[safe_key] = _MARKER if sensitive else visit(child, depth + 1)
            return result
        return _TRUNCATED

    return visit(value, 0)


def render_json(value, *, max_chars=1_000_000):
    """Emit complete JSON, including when encoding overhead exceeds the configured budget."""
    value = sanitize_output(value, max_chars=max_chars)
    parts = []
    size = 0
    for part in json.JSONEncoder(indent=2).iterencode(value):
        size += len(part)
        if size > max_chars:
            return json.dumps({"warning": _TRUNCATED})
        parts.append(part)
    return "".join(parts)


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


def present_manager_payload(result, *, single: bool = False):
    """Drop the Manager transport envelope before a tool result is shown.

    Statistics endpoints return one object inside ``affected_items``. Logs and
    node lists return ``count`` plus ``items``. ``message``, ``error``, and an
    empty ``failed_items`` are not part of the answer. A non-zero failure count
    stays, so a partial Manager response is still visible. Anything that is not
    that envelope is returned unchanged, and redaction still runs on the result.
    """
    if not isinstance(result, dict):
        return result
    data = result.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("affected_items"), list):
        return result
    items = data["affected_items"]
    failed = data.get("total_failed_items") or 0
    if single and len(items) == 1 and isinstance(items[0], dict):
        body = dict(items[0])
    else:
        body = {"count": data.get("total_affected_items", len(items)), "items": items}
    if failed:
        body["failed_count"] = failed
        failed_items = data.get("failed_items") or []
        if failed_items:
            body["failed"] = failed_items
    return body


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
