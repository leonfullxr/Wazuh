from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scripts.staging.certification import normalize_live_result
from scripts.staging.models import GateStatus, LiveGateResult, redact_secrets, utc_now_iso


def write_evidence(
    path: Path,
    *,
    status: GateStatus,
    reason: str,
    result: LiveGateResult | None,
) -> None:
    if result is not None:
        result = normalize_live_result(result)
        status = result.status
    document: dict[str, Any] = {
        "schema_version": "1",
        "status": status,
        "recorded_at": utc_now_iso(),
        "reason": reason,
        "result": result.to_dict() if result is not None else None,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    safe_document = redact_secrets(document)
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(safe_document, indent=2, sort_keys=True) + "\n")
