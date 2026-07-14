#!/usr/bin/env python3
"""Seed the lab indexer with deterministic synthetic alerts.

Generates ~2000 alerts across 7 days, 5 agents and a small rule set, bulk
indexes them into wazuh-alerts-4.x-<date> (so the stock Wazuh template
applies), and writes the exact ground truths to golden/ground_truth.json.
The golden runner asserts the assistant's counts against those truths, which
is the whole point: veracity is only a claim if it is measured (D33).

Re-running is idempotent: previous synthetic documents (manager.name marker)
are deleted before the new batch is indexed.

Run from the host: python3 seed/seed_alerts.py
"""
from __future__ import annotations

import json
import random
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

INDEXER = "https://localhost:9200"
AUTH = ("admin", "SecretPassword")  # wazuh-docker single-node default - verify
SEED = 20260708
N_ALERTS = 2000
SEED_MARKER = "wazuh-ai-seed"

AGENTS = [
    ("001", "web-01"), ("002", "web-02"), ("003", "db-01"),
    ("004", "dc-01"), ("005", "vpn-01"),
]
# (rule_id, level, description, groups, mitre)
RULES = [
    ("5710", 5, "sshd: Attempt to login using a non-existent user",
     ["syslog", "sshd", "authentication_failed"], "T1110"),
    ("5716", 5, "sshd: authentication failed",
     ["syslog", "sshd", "authentication_failed"], "T1110"),
    ("5715", 3, "sshd: authentication success",
     ["syslog", "sshd", "authentication_success"], None),
    ("31103", 10, "SQL injection attempt detected in web request",
     ["web", "attack", "sql_injection"], "T1190"),
    ("533", 3, "Listened ports status (netstat) changed",
     ["ossec"], None),
    ("100100", 12, "Multiple failed logins followed by success (possible brute force)",
     ["authentication_failures"], "T1110"),
]
# Weights make auth failures dominate, like a real perimeter box.
WEIGHTS = [0.32, 0.28, 0.12, 0.08, 0.17, 0.03]
SRC_IPS = ["203.0.113.66", "198.51.100.23", "192.0.2.14", "10.0.7.5"]
USERS = ["root", "admin", "svc-backup", "leon", "postgres"]


def _delete_previous_synthetic(client: httpx.Client) -> int:
    """Remove prior synthetic batches so re-seeding is idempotent."""
    r = client.post(
        f"{INDEXER}/wazuh-alerts-*/_delete_by_query",
        json={"query": {"term": {"manager.name": SEED_MARKER}}},
        params={"refresh": "true", "conflicts": "proceed"},
    )
    r.raise_for_status()
    return r.json().get("deleted", 0)


def main() -> None:
    rng = random.Random(SEED)
    now = datetime.now(timezone.utc)
    docs: list[dict] = []
    for _ in range(N_ALERTS):
        ts = now - timedelta(seconds=rng.randint(0, 7 * 24 * 3600))
        agent_id, agent_name = rng.choice(AGENTS)
        rule_id, level, desc, groups, mitre = rng.choices(RULES, WEIGHTS)[0]
        doc = {
            "timestamp": ts.isoformat(),
            "rule": {
                "id": rule_id, "level": level, "description": desc,
                "groups": groups,
                **({"mitre": {"id": [mitre], "technique": [desc[:40]]}} if mitre else {}),
            },
            "agent": {"id": agent_id, "name": agent_name, "ip": f"10.0.0.{int(agent_id)}"},
            "manager": {"name": SEED_MARKER},
            "decoder": {"name": "sshd" if rule_id.startswith("57") else "web-accesslog"},
            "location": "/var/log/auth.log" if rule_id.startswith("57") else "/var/log/nginx/access.log",
            "data": {
                "srcip": rng.choice(SRC_IPS),
                "dstuser": rng.choice(USERS),
            },
            "full_log": f"synthetic event rule={rule_id} on {agent_name}",
        }
        docs.append(doc)

    client = httpx.Client(verify=False, auth=AUTH, timeout=60.0)
    removed = _delete_previous_synthetic(client)
    if removed:
        print(f"removed {removed} prior synthetic alerts")

    # Bulk index, one index per event date (stock template pattern).
    lines: list[str] = []
    for doc in docs:
        day = doc["timestamp"][:10].replace("-", ".")
        lines.append(json.dumps({"index": {"_index": f"wazuh-alerts-4.x-{day}"}}))
        lines.append(json.dumps(doc))
    body = "\n".join(lines) + "\n"
    r = client.post(f"{INDEXER}/_bulk", content=body,
                    headers={"Content-Type": "application/x-ndjson"})
    r.raise_for_status()
    errors = r.json().get("errors")
    client.post(f"{INDEXER}/wazuh-alerts-*/_refresh")

    # Ground truths for the golden set.
    last24 = now - timedelta(hours=24)
    in24 = [d for d in docs if datetime.fromisoformat(d["timestamp"]) >= last24]
    auth_failed_24 = [d for d in in24 if "authentication_failed" in d["rule"]["groups"]]
    rule_counts = Counter(d["rule"]["id"] for d in docs)
    top_rule, top_rule_count = rule_counts.most_common(1)[0]
    high_sev_7d = sum(1 for d in docs if d["rule"]["level"] >= 10)

    # One known alert id for the citation test: fetch a real _id back.
    sample = client.post(
        f"{INDEXER}/wazuh-alerts-*/_search",
        json={"size": 1, "query": {"term": {"manager.name": SEED_MARKER}}},
    ).json()
    sample_id = sample["hits"]["hits"][0]["_id"] if sample["hits"]["hits"] else None

    truths = {
        "generated_at": now.isoformat(),
        "seed_marker": SEED_MARKER,
        "total_7d": len(docs),
        "auth_failures_24h": len(auth_failed_24),
        "high_severity_7d": high_sev_7d,
        "top_rule_id": top_rule,
        "top_rule_count": top_rule_count,
        "sample_alert_id": sample_id,
        "bulk_errors": bool(errors),
    }
    out = Path(__file__).resolve().parent.parent / "golden" / "ground_truth.json"
    out.write_text(json.dumps(truths, indent=2))
    print(f"indexed {len(docs)} alerts (bulk errors: {errors})")
    print(f"ground truths -> {out}")
    print(json.dumps(truths, indent=2))


if __name__ == "__main__":
    main()
