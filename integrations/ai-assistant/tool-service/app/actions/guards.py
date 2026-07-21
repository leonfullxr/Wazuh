"""Action permission and tier guards (R6.2, R6.6)."""
from __future__ import annotations

from ..config import CFG
from ..env_registry import EnvConfig
from ..principal import Principal, is_env_scoped
from .types import ActionTier


class ActionPermissionError(Exception):
    pass


def tier_enabled(env: EnvConfig, tier: ActionTier) -> bool:
    return tier.value in env.actions_tiers


def direct_execution_allowed(tier: ActionTier) -> bool:
    return CFG.actions_direct and tier == ActionTier.DASHBOARD


def assert_tier_enabled(env: EnvConfig, tier: ActionTier) -> None:
    if not tier_enabled(env, tier):
        raise ActionPermissionError(
            f"actions of tier {tier.value!r} are not enabled for environment {env.env_id!r}"
        )


def assert_may_execute(
    principal: Principal,
    tier: ActionTier,
    *,
    via_confirm: bool,
) -> None:
    if is_env_scoped(principal):
        raise ActionPermissionError(
            "connector edge may propose actions but cannot execute — "
            "confirm with a verified operator JWT"
        )
    if not via_confirm and not direct_execution_allowed(tier):
        raise ActionPermissionError(
            f"tier {tier.value} requires propose/confirm — direct execution is disabled"
        )
