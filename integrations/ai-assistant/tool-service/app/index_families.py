"""Index-family registry (V3.4) — separate allowlists per Wazuh states family."""
from __future__ import annotations

from enum import Enum


class IndexFamily(str, Enum):
    ALERTS = "alerts"
    VULNERABILITIES = "vulnerabilities"


VULNERABILITIES_INDEX = "wazuh-states-vulnerabilities-*"
VULNERABILITIES_TIME_FIELD = "vulnerability.detected_at"

# Keyword/long fields the model may filter or aggregate on. Alerts allowlist
# stays in models.py — do not merge these tables.
VULN_ALLOWED_FIELDS: dict[str, str] = {
    "_id": "keyword",
    "agent.id": "keyword",
    "agent.name": "keyword",
    "package.name": "keyword",
    "package.version": "keyword",
    "vulnerability.id": "keyword",
    "vulnerability.severity": "keyword",
    "vulnerability.status": "keyword",
    "vulnerability.score.base": "long",
}

VULN_SOURCE_FIELDS = [
    "vulnerability.detected_at",
    "agent.id",
    "agent.name",
    "package.name",
    "package.version",
    "vulnerability.id",
    "vulnerability.severity",
    "vulnerability.status",
    "vulnerability.score.base",
]
