"""Live ground-truth refresh for identifiers that drift (R2.0).

Count assertions use per-case /v1/tools bracketing in run_evals.py (REF_TOOLS).
This module only re-resolves top_rule_id and sample_alert_id before the suite.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

INDEXER = os.environ.get("WAI_INDEXER_URL", "https://localhost:9200")
AUTH = (
    os.environ.get("INDEXER_ADMIN_USER", "admin"),
    os.environ.get("INDEXER_ADMIN_PASSWORD", "SecretPassword"),
)


def _top_rule(client: httpx.Client, gte: str, lte: str) -> tuple[str, int]:
    r = client.post(
        f"{INDEXER}/wazuh-alerts-*/_search",
        json={
            "size": 0,
            "query": {"range": {"timestamp": {"gte": gte, "lte": lte}}},
            "aggs": {"top_rules": {"terms": {"field": "rule.id", "size": 1}}},
        },
    )
    r.raise_for_status()
    buckets = r.json()["aggregations"]["top_rules"]["buckets"]
    if not buckets:
        return "", 0
    return str(buckets[0]["key"]), int(buckets[0]["doc_count"])


def refresh(gt: dict) -> dict:
    """Return a copy of gt with live top_rule and sample_alert_id."""
    now = datetime.now(timezone.utc)
    gte_7d = (now - timedelta(days=7)).isoformat()
    lte = now.isoformat()

    client = httpx.Client(verify=False, auth=AUTH, timeout=60.0)
    live = dict(gt)
    live["refreshed_at"] = now.isoformat()

    top_id, top_count = _top_rule(client, gte_7d, lte)
    live["top_rule_id"] = top_id
    live["top_rule_count"] = top_count

    marker = gt.get("seed_marker", "wazuh-ai-seed")
    sample_id = gt.get("sample_alert_id")
    if sample_id:
        check = client.post(
            f"{INDEXER}/wazuh-alerts-*/_search",
            json={"size": 1, "query": {"ids": {"values": [sample_id]}}},
        ).json()
        if not check["hits"]["hits"]:
            sample_id = None
    if not sample_id:
        sample = client.post(
            f"{INDEXER}/wazuh-alerts-*/_search",
            json={"size": 1, "query": {"term": {"manager.name": marker}}},
        ).json()
        sample_id = sample["hits"]["hits"][0]["_id"] if sample["hits"]["hits"] else None
    live["sample_alert_id"] = sample_id
    return live


def load_and_refresh(path: str) -> dict[str, Any]:
    gt = json.loads(open(path).read())
    return refresh(gt)
