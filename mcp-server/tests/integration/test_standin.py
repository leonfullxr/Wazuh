"""The local stand-in has to answer the queries the MCP server actually sends."""

import importlib.util
from pathlib import Path

STANDIN = Path(__file__).resolve().parents[2] / "dev" / "standin.py"


def _load():
    spec = importlib.util.spec_from_file_location("wazuh_standin", STANDIN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_alert_filters_and_unique_tie_breaker():
    standin = _load()
    catalog = standin.CATALOG
    ids = [alert["event"]["id"] for alert in catalog.alerts]
    assert len(ids) == len(set(ids))
    recent_failures = [
        alert
        for alert in catalog.alerts
        if standin.matches(
            alert,
            {
                "bool": {
                    "must": [
                        {"term": {"rule.groups": "authentication_failed"}},
                        {"range": {"timestamp": {"gte": "now-24h"}}},
                    ]
                }
            },
        )
    ]
    assert len(recent_failures) == 6
    critical = [
        doc["_source"]
        for doc in catalog.documents("wazuh-states-vulnerabilities-*")
        if standin.matches(doc["_source"], {"term": {"vulnerability.severity": "Critical"}})
    ]
    assert [item["vulnerability"]["id"] for item in critical] == ["CVE-2021-44228"]


def test_process_inventory_includes_a_pid_past_the_first_row():
    standin = _load()
    # wazuh_check_process asks for one PID (q=pid=4242). That row must not be the only way
    # a client learns the inventory: it sits after systemd, so an unfiltered first page misses it.
    rows = standin.CATALOG.processes["001"]
    assert rows[0]["pid"] != 4242
    assert any(row["pid"] == 4242 for row in rows)
