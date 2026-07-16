"""Turn principals (D11 / D42). User = per-analyst JWT; EnvPrincipal = env reader."""
from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import TYPE_CHECKING, Union

if TYPE_CHECKING:
    from .env_registry import EnvConfig

from .auth import User
from .env_registry import get_env


@dataclass(frozen=True)
class EnvPrincipal:
    """Environment-scoped read-only principal for the connector edge (D42)."""

    env_id: str

    @property
    def admission_key(self) -> str:
        return f"env:{self.env_id}"

    @property
    def edge(self) -> str:
        return "connector"

    @property
    def audit_user(self) -> None:
        return None


Principal = Union[User, EnvPrincipal]


def env_id_for(principal: Principal) -> str:
    if isinstance(principal, EnvPrincipal):
        return principal.env_id
    return principal.env_id


def admission_key(principal: Principal) -> str:
    if isinstance(principal, EnvPrincipal):
        return principal.admission_key
    return principal.sub


def edge_name(principal: Principal) -> str:
    if isinstance(principal, EnvPrincipal):
        return principal.edge
    return "direct"


def is_env_scoped(principal: Principal) -> bool:
    return isinstance(principal, EnvPrincipal)


def proposer_sub(principal: Principal) -> str | None:
    if isinstance(principal, User):
        return principal.sub
    return None


def can_confirm_actions(user: User) -> bool:
    """Dashboard-tier confirm (R6.11)."""
    from .config import CFG

    return CFG.operator_role in user.roles


def can_confirm_responder(user: User) -> bool:
    """Manager + active-response tier confirm (R6.11)."""
    from .config import CFG

    return CFG.responder_role in user.roles


def can_confirm_tier(user: User, tier: "ActionTier") -> bool:
    from .actions.types import ActionTier

    if tier == ActionTier.DASHBOARD:
        return can_confirm_actions(user)
    if tier in (ActionTier.MANAGER, ActionTier.ACTIVE_RESPONSE):
        return can_confirm_responder(user)
    return False


def indexer_headers(principal: Principal, env: EnvConfig | None = None) -> dict[str, str]:
    """Auth headers for indexer calls — JWT or env reader credential."""
    if isinstance(principal, User):
        return {"Authorization": f"Bearer {principal.raw_jwt}"}
    cfg = env or get_env(principal.env_id)
    if cfg.reader_bearer:
        return {"Authorization": f"Bearer {cfg.reader_bearer}"}
    if not cfg.reader_basic or ":" not in cfg.reader_basic:
        raise RuntimeError(f"environment {cfg.env_id}: reader credential not configured")
    user, passwd = cfg.reader_basic.split(":", 1)
    token = base64.b64encode(f"{user}:{passwd}".encode()).decode("ascii")
    return {"Authorization": f"Basic {token}"}
