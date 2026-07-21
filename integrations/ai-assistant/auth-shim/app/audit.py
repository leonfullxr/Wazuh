"""Structured audit events (D8) — same JSON-line shape as the tool-service."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone


def emit(event: str, *, env: str | None = None, **fields) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "service": "auth-shim",
        "event": event,
        **fields,
    }
    if env is not None:
        record["env"] = env
    sys.stdout.write(json.dumps(record, default=str) + "\n")
    sys.stdout.flush()
