"""Strict audit event serialization."""

from __future__ import annotations

import json
from typing import Final

from ai_soc.contracts.models import AuditEvent

_ALLOWED_FIELDS: Final[frozenset[str]] = frozenset(AuditEvent.model_fields)


def audit_json(event: AuditEvent) -> str:
    """Serialize only the frozen AuditEvent fields in canonical key order."""
    payload = event.model_dump(mode="json", exclude_none=False)
    if frozenset(payload) != _ALLOWED_FIELDS:
        raise ValueError("audit schema differs from the frozen contract")
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
