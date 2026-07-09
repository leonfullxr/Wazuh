"""Prometheus metrics. Scrape /metrics."""
from __future__ import annotations

from prometheus_client import Counter, Histogram

TURNS = Counter("wazuh_ai_turns_total", "Completed turns", ["lane"])
TOOL_CALLS = Counter("wazuh_ai_tool_calls_total", "Tool executions", ["tool", "outcome"])
LANE0 = Counter("wazuh_ai_lane0_total", "Lane 0 outcomes", ["result"])
TOKENS = Counter("wazuh_ai_tokens_total", "Model tokens", ["direction"])
ERRORS = Counter("wazuh_ai_errors_total", "Errors by kind", ["kind"])
TURN_SECONDS = Histogram(
    "wazuh_ai_turn_seconds",
    "End-to-end turn latency",
    buckets=(0.1, 0.5, 1, 2, 5, 10, 20, 40, 80, 160, 320),
)
