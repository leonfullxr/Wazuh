"""LV-NETWORK obligation IDs aligned with docs/operations/continuity.md."""

from __future__ import annotations

LV_NETWORK_OBLIGATION_IDS: tuple[str, ...] = (
    "site_private_pinned_ca_hostname",
    "indexer_transport_without_public_fallback",
    "bedrock_invoke_via_vpce_allowed",
    "bedrock_invoke_public_denied",
    "gp4_missing_pin_denied",
    "gp4_wrong_pin_denied",
    "gp4_rotation_invalidates_hash",
)
