"""Static knowledge tools (P1.3) - exact lookup, no embeddings.

The typed-tool pipeline against the indexer is the retrieval layer for
tenant telemetry. Knowledge tools answer questions about reference data
(MITRE ATT&CK techniques, etc.) without duplicating alert data.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

_TECHNIQUES: dict[str, dict[str, str]] = json.loads(
    (Path(__file__).parent / "knowledge" / "mitre_techniques.json").read_text()
)
_MITRE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)


class MitreLookupParams(BaseModel):
    """Look up a MITRE ATT&CK technique by exact id (e.g. T1110)."""

    technique_id: str = Field(
        description="MITRE ATT&CK technique id, e.g. T1110 or T1190"
    )


def mitre_lookup(params: MitreLookupParams) -> dict[str, Any]:
    tid = params.technique_id.strip().upper()
    if not _MITRE_ID.fullmatch(tid):
        return {
            "found": False,
            "technique_id": tid,
            "error": "invalid MITRE technique id format (expected T####)",
        }
    base = tid.split(".")[0]
    entry = _TECHNIQUES.get(base)
    if entry is None:
        return {"found": False, "technique_id": tid, "error": "technique not in local catalog"}
    return {"found": True, "technique_id": base, **entry}
