#!/usr/bin/env python3
"""Local stand-in for a Wazuh 4.x Manager API and Indexer.

The MCP server always dials the Manager over HTTPS. This process generates a
one-day self-signed certificate and serves:

* Manager API on https://127.0.0.1:55000 (basic auth ``wazuh`` / ``wazuh``)
* Indexer on http://127.0.0.1:9200 (basic auth ``admin`` / ``admin``)

Seeded data is Wazuh-shaped: agents, alerts, vulnerabilities, SCA policies,
manager logs (including one credential-shaped line), cluster health, and an
active-response endpoint. The Indexer implements the query subset the MCP
server sends (term, terms, range, bool, simple_query_string, date math,
aggregations, scroll, settings, mappings, and document get).

Stdlib only, plus ``openssl`` to mint the certificate. Nothing here is a
Wazuh installation; it exists so the MCP server can be exercised without one.

    python3 dev/standin.py
"""

from __future__ import annotations

import base64
import json
import re
import ssl
import subprocess
import tempfile
import threading
from collections import Counter
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

MANAGER_USER = "wazuh"
MANAGER_PASS = "wazuh"
INDEXER_USER = "admin"
INDEXER_PASS = "admin"
MANAGER_TOKEN = "mock-manager-token"
ALERT_INDEX = "wazuh-alerts-4.x-2026.11.21"
ALERT_UUID = "alerts-index-uuid-0001"
VULN_INDEX = "wazuh-states-vulnerabilities-manager"
VULN_UUID = "vuln-index-uuid-0001"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(value) -> datetime:
    """ISO 8601 or OpenSearch date math (now-24h, now-7d/d)."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = value / 1000 if value > 10_000_000_000 else value
        return datetime.fromtimestamp(seconds, timezone.utc)
    text = str(value).strip()
    if text[:3].lower() == "now":
        moment = _now()
        rest = text[3:]
        for sign, count, unit in re.findall(r"([+-])(\d+)([yMwdhHms])", rest):
            amount = int(count)
            delta = {
                "s": timedelta(seconds=amount),
                "m": timedelta(minutes=amount),
                "h": timedelta(hours=amount),
                "H": timedelta(hours=amount),
                "d": timedelta(days=amount),
                "w": timedelta(weeks=amount),
                "M": timedelta(days=30 * amount),
                "y": timedelta(days=365 * amount),
            }[unit]
            moment = moment + delta if sign == "+" else moment - delta
        if rest.endswith("/d"):
            moment = moment.replace(hour=0, minute=0, second=0, microsecond=0)
        return moment
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


def _get(doc: dict, path: str):
    current = doc
    for part in path.split("."):
        if isinstance(current, list):
            return current
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _project(doc: dict, fields: list) -> dict:
    projected: dict = {}
    for field in fields:
        value = _get(doc, field)
        cursor = projected
        parts = field.split(".")
        for part in parts[:-1]:
            nxt = cursor.get(part)
            if not isinstance(nxt, dict):
                nxt = {}
                cursor[part] = nxt
            cursor = nxt
        cursor[parts[-1]] = value
    return projected


def _in_range(got, spec: dict) -> bool:
    if got is None:
        return False
    textual = isinstance(got, str) and ("T" in got or str(spec.get("gte", "")).startswith("now") or str(spec.get("lte", "")).startswith("now"))
    if textual or any(isinstance(spec.get(k), str) and (str(spec[k]).startswith("now") or "T" in str(spec[k])) for k in ("gte", "lte", "gt", "lt")):
        current = parse_time(got)

        def bound(raw):
            return parse_time(raw)

    else:
        current = float(got)

        def bound(raw):
            return float(raw)

    checks = (("gte", lambda a, b: a >= b), ("gt", lambda a, b: a > b), ("lte", lambda a, b: a <= b), ("lt", lambda a, b: a < b))
    for key, op in checks:
        if key in spec and not op(current, bound(spec[key])):
            return False
    return True


def _simple_query(doc: dict, query: str) -> bool:
    """AND/OR/NOT already translated to +, |, - by the MCP indexer client."""
    haystack = json.dumps(doc, default=str).lower()
    groups = [part.strip() for part in query.split("|")]
    for group in groups:
        required = []
        excluded = []
        for token in re.split(r"[\s+]+", group):
            token = token.strip().strip('"').lower()
            if not token:
                continue
            if token.startswith("-") and len(token) > 1:
                excluded.append(token[1:])
            else:
                required.append(token.rstrip("*"))
        if all(token in haystack for token in required) and all(token not in haystack for token in excluded):
            return True
    return False


def matches(doc: dict, clause: dict) -> bool:
    if not clause or "match_all" in clause:
        return True
    if "term" in clause:
        field, expected = next(iter(clause["term"].items()))
        if isinstance(expected, dict):
            expected = expected.get("value")
        got = _get(doc, field)
        if isinstance(got, list):
            return expected in got or str(expected) in [str(item) for item in got]
        return got == expected or str(got) == str(expected)
    if "terms" in clause:
        field, values = next(iter(clause["terms"].items()))
        got = _get(doc, field)
        wanted = {str(item) for item in values}
        if isinstance(got, list):
            return bool(wanted & {str(item) for item in got})
        return str(got) in wanted
    if "range" in clause:
        field, spec = next(iter(clause["range"].items()))
        return _in_range(_get(doc, field), spec)
    if "simple_query_string" in clause:
        return _simple_query(doc, clause["simple_query_string"].get("query", ""))
    if "bool" in clause:
        body = clause["bool"]
        for key in ("must", "filter"):
            nested = body.get(key) or []
            nested = [nested] if isinstance(nested, dict) else nested
            if not all(matches(doc, item) for item in nested):
                return False
        negated = body.get("must_not") or []
        negated = [negated] if isinstance(negated, dict) else negated
        if any(matches(doc, item) for item in negated):
            return False
        should = body.get("should") or []
        should = [should] if isinstance(should, dict) else should
        if should and not (body.get("must") or body.get("filter")) and not any(matches(doc, item) for item in should):
            return False
        return True
    return False


def _aggregate(docs: list[dict], spec: dict) -> dict:
    result = {}
    for name, body in spec.items():
        if "terms" in body:
            field = body["terms"]["field"]
            size = int(body["terms"].get("size", 10))
            grouped: dict = {}
            for doc in docs:
                value = _get(doc, field)
                values = value if isinstance(value, list) else [value]
                for item in values:
                    if item is None:
                        continue
                    grouped.setdefault(item, []).append(doc)
            buckets = []
            for key, rows in Counter({k: len(v) for k, v in grouped.items()}).most_common(size):
                bucket = {"key": key, "doc_count": len(grouped[key])}
                if body.get("aggs"):
                    bucket.update(_aggregate(grouped[key], body["aggs"]))
                buckets.append(bucket)
            result[name] = {"buckets": buckets}
        elif "cardinality" in body:
            values = {_get(doc, body["cardinality"]["field"]) for doc in docs}
            values.discard(None)
            result[name] = {"value": len(values)}
        elif "value_count" in body:
            field = body["value_count"]["field"]
            result[name] = {"value": sum(1 for doc in docs if _get(doc, field) is not None)}
        elif "top_hits" in body:
            size = int(body["top_hits"].get("size", 1))
            fields = body["top_hits"].get("_source")
            hits = []
            for doc in docs[:size]:
                source = _project(doc, fields) if isinstance(fields, list) else doc
                hits.append({"_source": source})
            result[name] = {"hits": {"hits": hits}}
    return result


def _sort_value(doc: dict, field: str):
    value = _get(doc, field)
    if field == "timestamp" and isinstance(value, str):
        return parse_time(value)
    return "" if value is None else value


def _sort_docs(docs: list[dict], spec) -> list[dict]:
    if not spec:
        return docs
    ordered = list(docs)
    # Apply the last key first so the first key wins.
    for item in reversed(spec):
        if isinstance(item, str):
            field, descending = item, False
        elif isinstance(item, dict):
            field, direction = next(iter(item.items()))
            if isinstance(direction, dict):
                direction = direction.get("order", "asc")
            descending = str(direction).lower() == "desc"
        else:
            continue
        ordered.sort(key=lambda doc, field=field: _sort_value(doc, field), reverse=descending)
    return ordered


class Catalog:
    def __init__(self) -> None:
        now = _now()
        self.agents = [
            {
                "id": "000",
                "name": "wazuh-manager",
                "ip": "127.0.0.1",
                "status": "active",
                "os": {"name": "Ubuntu", "version": "24.04"},
                "version": "Wazuh v4.14.1",
                "lastKeepAlive": _iso(now),
                "dateAdd": "2026-01-15T00:00:00Z",
                "group": ["default"],
                "node_name": "master",
                "configSum": "ab12",
                "mergedSum": "cd34",
            },
            {
                "id": "001",
                "name": "web-01",
                "ip": "10.0.1.21",
                "status": "active",
                "os": {"name": "Ubuntu", "version": "22.04"},
                "version": "Wazuh v4.14.1",
                "lastKeepAlive": _iso(now - timedelta(minutes=1)),
                "dateAdd": "2026-02-02T08:00:00Z",
                "group": ["web", "linux"],
                "node_name": "master",
                "configSum": "aa01",
                "mergedSum": "bb01",
            },
            {
                "id": "002",
                "name": "db-01",
                "ip": "10.0.1.22",
                "status": "active",
                "os": {"name": "Debian", "version": "12"},
                "version": "Wazuh v4.14.1",
                "lastKeepAlive": _iso(now - timedelta(minutes=4)),
                "dateAdd": "2026-03-01T08:00:00Z",
                "group": ["database"],
                "node_name": "worker-1",
                "configSum": "aa02",
                "mergedSum": "bb02",
            },
            {
                "id": "003",
                "name": "vpn-01",
                "ip": "10.0.1.23",
                "status": "disconnected",
                "os": {"name": "Ubuntu", "version": "22.04"},
                "version": "Wazuh v4.9.0",
                "lastKeepAlive": _iso(now - timedelta(hours=30)),
                "dateAdd": "2025-11-01T08:00:00Z",
                "group": ["vpn"],
                "node_name": "worker-1",
                "configSum": "aa03",
                "mergedSum": "bb03",
            },
        ]
        self.alerts = self._alerts(now)
        self.vulnerabilities = [
            self._vuln("CVE-2021-44228", "Critical", 10.0, "001", "web-01", "log4j", "2.14.1", now - timedelta(days=2)),
            self._vuln("CVE-2024-3094", "High", 9.8, "002", "db-01", "xz-utils", "5.6.0", now - timedelta(days=1)),
            self._vuln("CVE-2023-44487", "Medium", 7.5, "001", "web-01", "nginx", "1.18.0", now - timedelta(days=6)),
            self._vuln("CVE-2022-0847", "High", 7.8, "003", "vpn-01", "linux-kernel", "5.15.0", now - timedelta(days=20)),
            self._vuln("CVE-2020-14145", "Low", 3.1, "002", "db-01", "openssh", "8.2", now - timedelta(days=40)),
        ]
        self.processes = {
            "001": [
                {"pid": 1, "name": "systemd", "cmd": "/sbin/init", "euser": "root"},
                {"pid": 842, "name": "sshd", "cmd": "/usr/sbin/sshd -D", "euser": "root"},
                {"pid": 4242, "name": "nginx", "cmd": "nginx: master process", "euser": "www-data"},
            ],
            "002": [
                {"pid": 1, "name": "systemd", "cmd": "/sbin/init", "euser": "root"},
                {"pid": 2201, "name": "postgres", "cmd": "postgres: checkpointer", "euser": "postgres"},
            ],
        }
        self.ports = {
            "001": [
                {"local": {"ip": "0.0.0.0", "port": 22}, "process": "sshd", "protocol": "tcp", "state": "listening"},
                {"local": {"ip": "0.0.0.0", "port": 443}, "process": "nginx", "protocol": "tcp", "state": "listening"},
            ],
            "002": [
                {"local": {"ip": "10.0.1.22", "port": 5432}, "process": "postgres", "protocol": "tcp", "state": "listening"},
            ],
        }
        self.sca = {
            "001": [
                {"policy_id": "cis_ubuntu22-04", "name": "CIS Ubuntu 22.04 LTS Benchmark", "score": 78, "pass": 86, "fail": 24, "total_checks": 110},
                {"policy_id": "pci_dss_v4", "name": "PCI DSS v4.0", "score": 64, "pass": 32, "fail": 18, "total_checks": 50},
            ],
            "002": [
                {"policy_id": "cis_debian12", "name": "CIS Debian 12 Benchmark", "score": 81, "pass": 70, "fail": 16, "total_checks": 86},
            ],
        }
        self.sca_checks = {
            ("001", "cis_ubuntu22-04"): [
                {"id": 11001, "title": "Ensure SSH root login is disabled", "description": "PermitRootLogin must be no", "rationale": "Direct root SSH is a common brute-force target.", "remediation": "Set PermitRootLogin no in /etc/ssh/sshd_config", "result": "failed"},
                {"id": 11002, "title": "Ensure password authentication is hardened", "description": "PasswordAuthentication review", "rationale": "Weak password logins remain in the auth logs.", "remediation": "Prefer public keys", "result": "passed"},
                {"id": 11003, "title": "Ensure a firewall default deny policy", "description": "Inbound default policy", "rationale": "Open ports expand the attack surface.", "remediation": "Set the default incoming policy to deny", "result": "failed"},
            ]
        }
        self.logs = [
            {"timestamp": _iso(now - timedelta(minutes=5)), "level": "info", "tag": "wazuh-modulesd", "description": "Vulnerability detector cycle finished"},
            {"timestamp": _iso(now - timedelta(minutes=12)), "level": "error", "tag": "wazuh-remoted", "description": "Agent 003 disconnected during keepalive"},
            {"timestamp": _iso(now - timedelta(minutes=20)), "level": "error", "tag": "wazuh-authd", "description": "Rejected enrollment token=example-enrollment from 203.0.113.50"},
            {"timestamp": _iso(now - timedelta(hours=2)), "level": "warning", "tag": "wazuh-analysisd", "description": "Rule 5710 fired repeatedly for web-01"},
        ]
        self.rules = [
            {"id": 5710, "level": 10, "groups": ["sshd", "authentication_failed"]},
            {"id": 550, "level": 7, "groups": ["syscheck", "fim"]},
            {"id": 100100, "level": 12, "groups": ["active_response"]},
            {"id": 31106, "level": 13, "groups": ["web", "attack"]},
            {"id": 5902, "level": 8, "groups": ["malware"]},
            {"id": 40112, "level": 5, "groups": ["syslog"]},
        ]
        self.syscheck = {
            "001": [{"file": "/etc/ssh/sshd_config", "event": "modified", "perm": "rw-r--r--"}],
        }
        self.actions: list[dict] = []
        self.scrolls: dict[str, dict] = {}
        self._scroll_seq = 0
        self.lock = threading.Lock()

    def _alerts(self, now: datetime) -> list[dict]:
        rows = []

        def add(minutes, agent, rule, level, description, groups, srcip=None, extra=None):
            index = len(rows) + 1
            source = {
                "timestamp": _iso(now - timedelta(minutes=minutes)),
                "event": {"id": f"evt-{index:04d}"},
                "agent": {"id": agent["id"], "name": agent["name"], "ip": agent["ip"]},
                "rule": {"id": str(rule), "level": level, "description": description, "groups": groups},
                "full_log": extra.get("full_log") if extra else description,
                "location": extra.get("location", "/var/log/auth.log") if extra else "/var/log/auth.log",
            }
            if srcip:
                source["data"] = {"srcip": srcip}
            if extra and extra.get("syscheck"):
                source["syscheck"] = extra["syscheck"]
            if extra and extra.get("mitre"):
                source["rule"]["mitre"] = extra["mitre"]
            rows.append(source)

        web = self.agents[1]
        db = self.agents[2]
        for offset in (4, 8, 12, 18, 25, 40):
            add(
                offset,
                web,
                5710,
                10,
                "sshd: authentication failed.",
                ["sshd", "authentication_failed", "authentication"],
                "203.0.113.50",
                {"full_log": "sshd[842]: Failed password for root from 203.0.113.50 port 51422 ssh2", "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]}},
            )
        add(15, web, 550, 7, "Integrity checksum changed.", ["syscheck", "fim"], extra={"syscheck": {"path": "/etc/ssh/sshd_config", "event": "modified"}})
        add(
            30,
            web,
            100100,
            12,
            "Active response: firewall-drop executed.",
            ["active_response"],
            "198.51.100.23",
            {"full_log": "active-response: firewall-drop srcip 198.51.100.23"},
        )
        add(50, db, 100100, 12, "Active response: host-isolation executed.", ["active_response"], extra={"full_log": "active-response: isolation applied on db-01"})
        add(
            90,
            web,
            31106,
            13,
            "<script>alert(1)</script>",
            ["web", "attack"],
            "203.0.113.50",
            {"full_log": "<img src=x onerror=alert(1)> sql injection from 203.0.113.50"},
        )
        add(180, db, 5902, 8, "Malware signature matched.", ["malware", "rootcheck"])
        add(60 * 24 * 10, web, 40112, 5, "User login succeeded.", ["syslog", "authentication_success"], "10.0.1.40")
        return rows

    def _vuln(self, cve, severity, score, agent_id, agent_name, package, version, detected):
        return {
            "vulnerability": {
                "id": cve,
                "severity": severity,
                "description": f"{package} {version} is affected by {cve}",
                "reference": f"https://nvd.nist.gov/vuln/detail/{cve}",
                "score": {"base": score},
                "under_evaluation": False,
                "detected_at": _iso(detected),
                "published_at": "2024-01-01T00:00:00Z",
            },
            "agent": {"id": agent_id, "name": agent_name},
            "package": {"name": package, "version": version, "architecture": "amd64"},
        }

    def documents(self, pattern: str) -> list[dict]:
        regex = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
        found = []
        if regex.match(ALERT_INDEX):
            for source in self.alerts:
                found.append({"_index": ALERT_INDEX, "_id": source["event"]["id"], "_source": source})
        if regex.match(VULN_INDEX):
            for source in self.vulnerabilities:
                cve = source["vulnerability"]["id"]
                agent = source["agent"]["id"]
                found.append({"_index": VULN_INDEX, "_id": f"{agent}-{cve}", "_source": source})
        return found


CATALOG = Catalog()


def envelope(items, total=None, failed=None):
    return {
        "data": {
            "affected_items": items,
            "total_affected_items": len(items) if total is None else total,
            "total_failed_items": 0 if failed is None else len(failed),
            "failed_items": failed or [],
        },
        "message": "All selected items were returned",
        "error": 0,
    }


def _page(items: list, query: dict) -> dict:
    offset = int(query.get("offset", ["0"])[0] or 0)
    limit = int(query.get("limit", ["500"])[0] or 500)
    return envelope(items[offset : offset + limit], total=len(items))


def _authorized(header: str | None, user: str, password: str) -> bool:
    if not header or not header.startswith("Basic "):
        return False
    try:
        raw = base64.b64decode(header.split(" ", 1)[1]).decode()
    except (ValueError, UnicodeDecodeError):
        return False
    got_user, _, got_pass = raw.partition(":")
    return got_user == user and got_pass == password


class ManagerHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        print(f"[manager] {self.address_string()} {fmt % args}")

    def _json(self, code: int, payload) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        return json.loads(raw)

    def _query(self) -> dict:
        return parse_qs(urlsplit(self.path).query)

    def _path(self) -> str:
        return unquote(urlsplit(self.path).path)

    def do_POST(self) -> None:  # noqa: N802
        if self._path() != "/security/user/authenticate":
            self._json(404, {"error": 404, "message": f"unknown {self._path()}"})
            return
        if not _authorized(self.headers.get("Authorization"), MANAGER_USER, MANAGER_PASS):
            self._json(401, {"error": 401, "message": "invalid credentials"})
            return
        self._json(200, {"data": {"token": MANAGER_TOKEN}, "error": 0})

    def do_PUT(self) -> None:  # noqa: N802
        self._authed(self._put)

    def do_GET(self) -> None:  # noqa: N802
        self._authed(self._get)

    def _authed(self, handler) -> None:
        if self.headers.get("Authorization") != f"Bearer {MANAGER_TOKEN}":
            self._json(401, {"error": 401, "message": "unauthorized"})
            return
        handler()

    def _put(self) -> None:
        path = self._path()
        query = self._query()
        body = self._body()
        if path == "/active-response":
            agents = (query.get("agents_list") or ["001"])[0].split(",")
            with CATALOG.lock:
                CATALOG.actions.append({"command": body.get("command"), "agents": agents, "arguments": body.get("arguments")})
            self._json(200, envelope(agents))
            return
        if path == "/manager/restart" or re.fullmatch(r"/agents/\d+/restart", path):
            self._json(200, envelope(["restart queued"]))
            return
        self._json(404, {"error": 404, "message": f"unknown {path}"})

    def _get(self) -> None:
        path = self._path()
        query = self._query()
        if path == "/":
            self._json(200, {"data": {"title": "Wazuh API REST", "api_version": "4.14.1", "hostname": "wazuh-manager", "type": "server", "revision": 41401}, "error": 0})
            return
        if path == "/agents":
            items = list(CATALOG.agents)
            if "status" in query:
                items = [item for item in items if item["status"] == query["status"][0]]
            if "agents_list" in query:
                wanted = set(query["agents_list"][0].split(","))
                items = [item for item in items if item["id"] in wanted]
            self._json(200, _page(items, query))
            return
        process = re.fullmatch(r"/syscollector/(\d+)/processes", path)
        if process:
            items = list(CATALOG.processes.get(process.group(1), []))
            # The MCP server asks for one PID with q=pid=<n> rather than paging the inventory.
            if query.get("q") and query["q"][0].startswith("pid="):
                wanted = query["q"][0].split("=", 1)[1]
                items = [item for item in items if str(item.get("pid")) == wanted]
            self._json(200, _page(items, query))
            return
        ports = re.fullmatch(r"/syscollector/(\d+)/ports", path)
        if ports:
            self._json(200, _page(CATALOG.ports.get(ports.group(1), []), query))
            return
        group = re.fullmatch(r"/groups/([^/]+)/configuration", path)
        if group:
            self._json(200, envelope([{"group": group.group(1), "config": {"syscheck": {"disabled": "no"}, "rootcheck": {"disabled": "no"}}}]))
            return
        sca = re.fullmatch(r"/sca/(\d+)", path)
        if sca:
            self._json(200, envelope(CATALOG.sca.get(sca.group(1), [])))
            return
        checks = re.fullmatch(r"/sca/(\d+)/checks/([^/]+)", path)
        if checks:
            self._json(200, envelope(CATALOG.sca_checks.get((checks.group(1), checks.group(2)), [])))
            return
        if path == "/cluster/status":
            self._json(200, {"data": {"enabled": "yes", "running": "yes"}, "error": 0})
            return
        if path == "/cluster/healthcheck":
            self._json(200, envelope([
                {"info": {"name": "master", "type": "master", "version": "4.14.1", "ip": "10.0.0.10"}, "status": "connected", "n_active_agents": 2},
                {"info": {"name": "worker-1", "type": "worker", "version": "4.14.1", "ip": "10.0.0.11"}, "status": "connected", "n_active_agents": 1},
            ]))
            return
        if path == "/cluster/nodes":
            self._json(200, envelope([
                {"name": "master", "type": "master", "version": "4.14.1", "ip": "10.0.0.10", "status": "connected"},
                {"name": "worker-1", "type": "worker", "version": "4.14.1", "ip": "10.0.0.11", "status": "connected"},
            ]))
            return
        if path == "/manager/logs":
            items = list(CATALOG.logs)
            if "level" in query:
                items = [item for item in items if item["level"] == query["level"][0]]
            if "search" in query:
                needle = query["search"][0].lower()
                items = [item for item in items if needle in json.dumps(item).lower()]
            self._json(200, _page(items, query))
            return
        if path == "/manager/configuration":
            self._json(200, envelope([{"active-response": {"command": [{"name": "firewall-drop", "executable": "firewall-drop"}, {"name": "host-deny", "executable": "host-deny"}]}}]))
            return
        if path == "/lists":
            self._json(200, envelope([{"filename": "audit-keys", "relative_dirname": "etc/lists"}]))
            return
        if path == "/manager/stats":
            self._json(200, envelope([{"totalAlerts": len(CATALOG.alerts), "totalEvents": 2400, "events": {"received": 2400}, "alerts": {"written": len(CATALOG.alerts)}}]))
            return
        if path == "/manager/stats/weekly":
            self._json(200, envelope([{"Sun": {"alerts": 4}, "Mon": {"alerts": 6}, "Tue": {"alerts": len(CATALOG.alerts)}}]))
            return
        if path == "/manager/stats/remoted":
            self._json(200, envelope([{"queue_size": 0, "total_queue_size": 131072, "tcp_sessions": 3, "events_processed": 1800}]))
            return
        if path == "/manager/stats/analysisd":
            self._json(200, envelope([{"events_received": 2400, "events_processed": 2390, "alerts_written": len(CATALOG.alerts), "events_dropped": 0}]))
            return
        if path == "/rules":
            self._json(200, _page(CATALOG.rules, query))
            return
        stats = re.fullmatch(r"/agents/(\d+)/stats/([A-Za-z0-9_-]+)", path)
        if stats:
            self._json(200, envelope([{"agent": stats.group(1), "component": stats.group(2), "events": 120, "bytes": 4096}]))
            return
        fim = re.fullmatch(r"/syscheck/(\d+)", path)
        if fim:
            items = CATALOG.syscheck.get(fim.group(1), [])
            if "q" in query and query["q"][0].startswith("file="):
                wanted = query["q"][0].split("=", 1)[1]
                items = [item for item in items if item.get("file") == wanted]
            self._json(200, envelope(items))
            return
        self._json(404, {"error": 404, "message": f"unknown {path}"})


class IndexerHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        print(f"[indexer] {self.address_string()} {fmt % args}")

    def _json(self, code: int, payload) -> None:
        body = json.dumps(payload, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _guard(self) -> bool:
        if _authorized(self.headers.get("Authorization"), INDEXER_USER, INDEXER_PASS):
            return True
        self._json(401, {"error": "security_exception", "status": 401})
        return False

    def _body(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b""
        return json.loads(raw) if raw else {}

    def _path(self) -> str:
        return unquote(urlsplit(self.path).path)

    def do_GET(self) -> None:  # noqa: N802
        if not self._guard():
            return
        path = self._path()
        if path == "/_cluster/health":
            self._json(200, {"cluster_name": "wazuh-standin", "status": "green", "number_of_nodes": 1, "active_shards": 2, "timed_out": False})
            return
        settings = re.fullmatch(r"/([^/]+)/_settings", path)
        if settings:
            self._json(200, self._settings(settings.group(1)))
            return
        mapping = re.fullmatch(r"/([^/]+)/_mapping", path)
        if mapping:
            self._json(200, self._mapping(mapping.group(1)))
            return
        document = re.fullmatch(r"/([^/]+)/_doc/([^/]+)", path)
        if document:
            index, doc_id = document.group(1), document.group(2)
            includes = parse_qs(urlsplit(self.path).query).get("_source_includes", [""])[0]
            fields = [field for field in includes.split(",") if field] if includes else None
            for hit in CATALOG.documents(index):
                if hit["_id"] == doc_id:
                    source = _project(hit["_source"], fields) if fields else hit["_source"]
                    self._json(200, {"_index": hit["_index"], "_id": hit["_id"], "found": True, "_source": source})
                    return
            self._json(404, {"found": False, "_index": index, "_id": doc_id})
            return
        self._json(404, {"error": f"unknown {path}"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._guard():
            return
        path = self._path()
        if path == "/_search/scroll":
            body = self._body()
            with CATALOG.lock:
                state = CATALOG.scrolls.get(body.get("scroll_id"))
            if not state:
                self._json(404, {"error": "unknown scroll"})
                return
            self._json(200, self._hits([], state["total"], scroll_id=body.get("scroll_id")))
            return
        search = re.fullmatch(r"/([^/]+)/_search", path)
        if not search:
            self._json(404, {"error": f"unknown {path}"})
            return
        self._json(200, self._search(search.group(1), self._body(), "scroll" in parse_qs(urlsplit(self.path).query)))

    def do_DELETE(self) -> None:  # noqa: N802
        if not self._guard():
            return
        if self._path() == "/_search/scroll":
            body = self._body()
            ids = body.get("scroll_id") or []
            ids = ids if isinstance(ids, list) else [ids]
            with CATALOG.lock:
                for scroll_id in ids:
                    CATALOG.scrolls.pop(scroll_id, None)
            self._json(200, {"succeeded": True, "num_freed": len(ids)})
            return
        self._json(404, {"error": f"unknown {self._path()}"})

    def _indices(self, pattern: str) -> list[tuple[str, str]]:
        regex = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
        found = []
        if regex.match(ALERT_INDEX):
            found.append((ALERT_INDEX, ALERT_UUID))
        if regex.match(VULN_INDEX):
            found.append((VULN_INDEX, VULN_UUID))
        return found

    def _settings(self, pattern: str) -> dict:
        return {name: {"settings": {"index": {"uuid": uuid}}} for name, uuid in self._indices(pattern)}

    def _mapping(self, pattern: str) -> dict:
        properties = {
            "timestamp": {"type": "date"},
            "event": {"properties": {"id": {"type": "keyword"}}},
            "agent": {"properties": {"id": {"type": "keyword"}, "name": {"type": "keyword"}}},
            "rule": {"properties": {"id": {"type": "keyword"}, "level": {"type": "long"}, "description": {"type": "text"}, "groups": {"type": "keyword"}}},
            "data": {"properties": {"srcip": {"type": "ip"}, "dstip": {"type": "ip"}}},
            "vulnerability": {"properties": {"id": {"type": "keyword"}, "severity": {"type": "keyword"}, "detected_at": {"type": "date"}}},
        }
        return {name: {"mappings": {"properties": properties}} for name, _uuid in self._indices(pattern)}

    def _search(self, pattern: str, body: dict, scroll: bool) -> dict:
        query = body.get("query") or {"match_all": {}}
        docs = [hit for hit in CATALOG.documents(pattern) if matches(hit["_source"], query)]
        docs = _sort_docs(docs, body.get("sort"))
        size = int(body.get("size", 10))
        page = docs[:size]
        scroll_id = None
        if scroll:
            with CATALOG.lock:
                CATALOG._scroll_seq += 1
                scroll_id = f"standin-scroll-{CATALOG._scroll_seq}"
                CATALOG.scrolls[scroll_id] = {"total": len(docs)}
        hits = []
        source_filter = body.get("_source", True)
        docvalues = body.get("docvalue_fields") or []
        for hit in page:
            rendered = {"_index": hit["_index"], "_id": hit["_id"]}
            if source_filter is False:
                pass
            elif isinstance(source_filter, list):
                rendered["_source"] = _project(hit["_source"], source_filter)
            else:
                rendered["_source"] = hit["_source"]
            if docvalues:
                rendered["fields"] = {field: [_get(hit["_source"], field)] for field in docvalues}
            if body.get("sort"):
                rendered["sort"] = []
                for item in body["sort"]:
                    field = item if isinstance(item, str) else next(iter(item))
                    value = _get(hit["_source"], field)
                    rendered["sort"].append(_iso(parse_time(value)) if field == "timestamp" and isinstance(value, str) else value)
            hits.append(rendered)
        response = self._hits(hits, len(docs), scroll_id=scroll_id)
        aggs = body.get("aggs") or body.get("aggregations")
        if aggs:
            response["aggregations"] = _aggregate([hit["_source"] for hit in docs], aggs)
        return response

    def _hits(self, hits: list, total: int, scroll_id: str | None = None) -> dict:
        payload = {
            "took": 2,
            "timed_out": False,
            "terminated_early": False,
            "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
            "_clusters": {"total": 1, "successful": 1, "skipped": 0, "failed": 0, "partial": 0, "running": 0},
            "hits": {"total": {"value": total, "relation": "eq"}, "hits": hits},
        }
        if scroll_id:
            payload["_scroll_id"] = scroll_id
        return payload


def _serve(httpd: ThreadingHTTPServer) -> None:
    httpd.serve_forever()


def _certificate(directory: str) -> tuple[str, str]:
    cert = f"{directory}/standin.crt"
    key = f"{directory}/standin.key"
    subprocess.check_call(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key, "-out", cert, "-days", "1",
            "-subj", "/CN=127.0.0.1",
            "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return cert, key


def main() -> None:
    cert_dir = tempfile.mkdtemp(prefix="wazuh-standin-")
    cert, key = _certificate(cert_dir)
    manager = ThreadingHTTPServer(("127.0.0.1", 55000), ManagerHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    manager.socket = context.wrap_socket(manager.socket, server_side=True)
    indexer = ThreadingHTTPServer(("127.0.0.1", 9200), IndexerHandler)
    threading.Thread(target=_serve, args=(manager,), daemon=True).start()
    threading.Thread(target=_serve, args=(indexer,), daemon=True).start()
    print("Wazuh stand-in ready")
    print("  Manager  https://127.0.0.1:55000")
    print("  Indexer  http://127.0.0.1:9200")
    print("  Local basic-auth defaults are listed in dev/README.md")
    print(f"  certificate {cert}")
    print(f"  alerts={len(CATALOG.alerts)} vulnerabilities={len(CATALOG.vulnerabilities)} agents={len(CATALOG.agents)}")
    print("Use WAZUH_ALLOW_SELF_SIGNED=true and WAZUH_INDEXER_HOST=http://127.0.0.1")
    print("Tie-breaker field for preflight: event.id")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nstopping")


if __name__ == "__main__":
    main()
