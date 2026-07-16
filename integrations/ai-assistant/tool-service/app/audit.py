"""App-level audit (D8). In the lab, events go to stdout as JSON lines, which
`docker logs` and any collector can pick up. In production the same events are
written to the tenant's own indexer via the wazuh_ai_state principal and
mirrored into the SIEM, so the SIEM watches the AI."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone

from .config import CFG


def emit(event: str, *, env: str | None = None, **fields) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "tenant": CFG.tenant,
        "event": event,
        **fields,
    }
    if env is not None:
        record["env"] = env
    sys.stdout.write(json.dumps(record, default=str) + "\n")
    sys.stdout.flush()
