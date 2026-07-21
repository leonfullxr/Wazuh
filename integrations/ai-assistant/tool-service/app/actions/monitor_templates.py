"""Curated OpenSearch Alerting monitor templates (E5) - never free-form."""
from __future__ import annotations

from typing import Any

from .schemas import CreateIndexerMonitorParams

_AUTH_FAILURE_QUERY = (
    "rule.groups:authentication_failed OR "
    "rule.groups:authentication_failures OR "
    "rule.groups:win_authentication_failed"
)
_HIGH_SEV_QUERY = "rule.level:>=10"


def build_monitor_body(params: CreateIndexerMonitorParams) -> dict[str, Any]:
    if params.template == "auth_failures":
        query = _AUTH_FAILURE_QUERY
        name = params.title or "Wazuh AI auth failures"
    else:
        query = _HIGH_SEV_QUERY
        name = params.title or "Wazuh AI high severity"
    minutes = params.schedule_minutes
    return {
        "type": "monitor",
        "name": name,
        "enabled": True,
        "schedule": {"period": {"interval": minutes, "unit": "MINUTES"}},
        "inputs": [
            {
                "search": {
                    "indices": ["wazuh-alerts-*"],
                    "query": {
                        "size": 0,
                        "query": {
                            "bool": {
                                "filter": [
                                    {"query_string": {"query": query}},
                                    {
                                        "range": {
                                            "timestamp": {
                                                "gte": f"now-{minutes}m",
                                                "lte": "now",
                                            }
                                        }
                                    },
                                ]
                            }
                        },
                    },
                }
            }
        ],
        "triggers": [
            {
                "name": f"{params.template}-trigger",
                "severity": "1",
                "condition": {
                    "script": {
                        "source": "ctx.results[0].hits.total.value > 0",
                        "lang": "painless",
                    }
                },
                "actions": [],
            }
        ],
        "wazuh_ai_template": params.template,
        "wazuh_ai_reason": params.reason,
    }
