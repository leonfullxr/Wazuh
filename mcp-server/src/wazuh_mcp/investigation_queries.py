"""Indexer query shapes shared by the investigation tools and operator preflight."""

import re
from urllib.parse import quote

INDEX_RE = re.compile(r"^wazuh-alerts-[a-zA-Z0-9._-]+$")
FIELDS = ["timestamp", "agent.id", "agent.name", "rule.id", "rule.level", "rule.description", "rule.groups"]


def timeline_sort(tie_breaker: str) -> list[dict[str, str]]:
    return [{"timestamp": "desc"}, {tie_breaker: "desc"}]


def evidence_path(index: str, doc_id: str) -> str:
    return f"/{quote(index, safe='')}/_doc/{quote(doc_id, safe='')}?_source_includes={','.join(FIELDS)}"
