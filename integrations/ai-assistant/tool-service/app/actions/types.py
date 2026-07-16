"""Shared types for the Actions framework (D20/D35)."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal


class ActionTier(str, Enum):
    DASHBOARD = "dashboard"
    MANAGER = "manager"
    ACTIVE_RESPONSE = "active_response"
    REPORTS = "reports"


class ActionRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


ProposalStatus = Literal["pending", "confirmed", "rejected", "expired"]


@dataclass
class ActionProposal:
    proposal_id: str
    action_name: str
    tool_name: str
    env_id: str
    proposer_sub: str | None  # None when env-scoped connector proposed
    params: dict[str, Any]
    preview: str
    tier: ActionTier
    risk: ActionRisk
    created_at: float
    expires_at: float
    status: ProposalStatus = "pending"
    idempotency_key: str | None = None
    result: dict[str, Any] | None = None
    confirmed_by: str | None = None

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "action_name": self.action_name,
            "env_id": self.env_id,
            "preview": self.preview,
            "tier": self.tier.value,
            "risk": self.risk.value,
            "status": self.status,
            "expires_at": self.expires_at,
            "proposer_sub": self.proposer_sub,
            "confirm_path": f"/v1/actions/{self.proposal_id}/confirm",
        }


@dataclass
class ActionResult:
    ok: bool
    status: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)
