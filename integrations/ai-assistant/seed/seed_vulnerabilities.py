#!/usr/bin/env python3
"""Seed vulnerability state documents for V3.4 golden cases.

Indexes synthetic CVE rows into wazuh-states-vulnerabilities-wazuh (lab PoC
index name). Idempotent via wazuh.cluster.name marker.

Run from the host: python3 seed/seed_vulnerabilities.py
"""
from __future__ import annotations

import json
import random
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

INDEXER = "https://localhost:9200"
AUTH = ("admin", "SecretPassword")
INDEX = "wazuh-states-vulnerabilities-wazuh"
SEED = 20260716
SEED_MARKER = "wazuh-ai-seed-vuln"
N_VULNS = 200

AGENTS = [
    ("001", "web-01"),
    ("002", "web-02"),
    ("003", "db-01"),
    ("004", "dc-01"),
    ("005", "vpn-01"),
]
SEVERITIES = ["low", "medium", "high", "critical"]
SEVERITY_WEIGHTS = [0.40, 0.30, 0.20, 0.10]
PACKAGES = [
    ("openssl", "1.1.1"),
    ("nginx", "1.24.0"),
    ("curl", "8.5.0"),
    ("postgresql", "15.4"),
    ("sudo", "1.9.14"),
]

INDEX_MAPPING = {
    "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
    "mappings": {
        "dynamic": "strict",
        "properties": {
            "agent": {
                "properties": {
                    "id": {"type": "keyword", "ignore_above": 1024},
                    "name": {"type": "keyword", "ignore_above": 1024},
                }
            },
            "package": {
                "properties": {
                    "name": {"type": "keyword", "ignore_above": 1024},
                    "version": {"type": "keyword", "ignore_above": 1024},
                }
            },
            "vulnerability": {
                "properties": {
                    "id": {"type": "keyword", "ignore_above": 1024},
                    "severity": {"type": "keyword", "ignore_above": 1024},
                    "status": {"type": "keyword", "ignore_above": 1024},
                    "detected_at": {"type": "date"},
                    "score": {
                        "properties": {
                            "base": {"type": "float"},
                        }
                    },
                }
            },
            "wazuh": {
                "properties": {
                    "cluster": {
                        "properties": {
                            "name": {"type": "keyword", "ignore_above": 1024},
                        }
                    }
                }
            },
        },
    },
}


def _ensure_index(client: httpx.Client) -> None:
    r = client.head(f"{INDEXER}/{INDEX}")
    if r.status_code == 200:
        return
    r = client.put(f"{INDEXER}/{INDEX}", json=INDEX_MAPPING)
    r.raise_for_status()


def _delete_previous(client: httpx.Client) -> int:
    r = client.post(
        f"{INDEXER}/{INDEX}/_delete_by_query",
        json={"query": {"term": {"wazuh.cluster.name": SEED_MARKER}}},
        params={"refresh": "true", "conflicts": "proceed"},
    )
    r.raise_for_status()
    return r.json().get("deleted", 0)


def main() -> None:
    rng = random.Random(SEED)
    now = datetime.now(timezone.utc)
    docs: list[dict] = []
    for i in range(N_VULNS):
        detected = now - timedelta(seconds=rng.randint(0, 30 * 24 * 3600))
        agent_id, agent_name = rng.choice(AGENTS)
        pkg_name, pkg_ver = rng.choice(PACKAGES)
        severity = rng.choices(SEVERITIES, SEVERITY_WEIGHTS)[0]
        score = {"low": 3.1, "medium": 5.5, "high": 7.8, "critical": 9.4}[severity]
        docs.append(
            {
                "agent": {"id": agent_id, "name": agent_name},
                "package": {"name": pkg_name, "version": pkg_ver},
                "vulnerability": {
                    "id": f"CVE-2026-{10000 + i:05d}",
                    "severity": severity,
                    "status": "active",
                    "detected_at": detected.isoformat(),
                    "score": {"base": score},
                },
                "wazuh": {"cluster": {"name": SEED_MARKER}},
            }
        )

    client = httpx.Client(verify=False, auth=AUTH, timeout=60.0)
    _ensure_index(client)
    removed = _delete_previous(client)
    if removed:
        print(f"removed {removed} prior synthetic vulnerability rows")

    lines: list[str] = []
    for doc in docs:
        lines.append(json.dumps({"index": {"_index": INDEX}}))
        lines.append(json.dumps(doc))
    body = "\n".join(lines) + "\n"
    r = client.post(
        f"{INDEXER}/_bulk", content=body, headers={"Content-Type": "application/x-ndjson"}
    )
    r.raise_for_status()
    errors = r.json().get("errors")
    client.post(f"{INDEXER}/{INDEX}/_refresh")

    window_start = now - timedelta(days=30)
    in_window = [
        d
        for d in docs
        if datetime.fromisoformat(d["vulnerability"]["detected_at"]) >= window_start
    ]
    sev_counts = Counter(d["vulnerability"]["severity"] for d in in_window)

    gt_path = Path(__file__).resolve().parent.parent / "golden" / "ground_truth.json"
    truths = {}
    if gt_path.exists():
        truths = json.loads(gt_path.read_text())
    truths.update(
        {
            "vulnerabilities_30d": len(in_window),
            "vulnerabilities_high_30d": sev_counts.get("high", 0),
            "vulnerability_seed_marker": SEED_MARKER,
            "vulnerability_bulk_errors": bool(errors),
        }
    )
    gt_path.write_text(json.dumps(truths, indent=2))
    print(f"indexed {len(docs)} vulnerability rows (bulk errors: {errors})")
    print(f"ground truths updated -> {gt_path}")
    print(
        json.dumps(
            {
                "vulnerabilities_30d": len(in_window),
                "vulnerabilities_high_30d": sev_counts.get("high", 0),
                "bulk_errors": bool(errors),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
