"""Execute write actions immediately (direct mode — dashboard tier only)."""
from __future__ import annotations

from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel

from .. import audit
from ..auth import User
from ..config import CFG
from ..env_registry import get_env
from ..principal import Principal, can_confirm_tier, env_id_for, is_env_scoped
from .executors import run_executor
from .guards import (
    ActionPermissionError,
    assert_may_execute,
    assert_tier_enabled,
    direct_execution_allowed,
)
from .registry import get_action, get_action_by_tool, public_tool_name
from .types import ActionResult, ActionTier


def operator_for_writes(principal: Principal, tier: ActionTier) -> User:
    """Verified operator identity — never fabricated (R6.2)."""
    if isinstance(principal, User):
        if not can_confirm_tier(principal, tier):
            role = (
                CFG.operator_role
                if tier == ActionTier.DASHBOARD
                else CFG.responder_role
            )
            raise ActionPermissionError(
                f"missing role {role} — cannot run {tier.value} actions"
            )
        return principal
    raise ActionPermissionError(
        "connector edge may propose actions but cannot execute — "
        "confirm with a verified operator JWT"
    )


async def execute_action_tool(
    tool_name: str,
    params: BaseModel,
    principal: Principal,
) -> dict[str, Any]:
    action = get_action_by_tool(tool_name)
    if action is None:
        raise ValueError(f"unknown action tool {tool_name}")

    env_id = env_id_for(principal)
    env = get_env(env_id)
    assert_tier_enabled(env, action.tier)
    assert_may_execute(principal, action.tier, via_confirm=False)
    if not direct_execution_allowed(action.tier):
        raise ActionPermissionError(
            f"tool {tool_name!r} requires propose/confirm — direct mode is dashboard-only"
        )

    operator = operator_for_writes(principal, action.tier)
    result = await run_executor(
        action.tier,
        action.name,
        params,
        env,
        operator,
        principal,
    )
    audit.emit(
        "action_executed",
        env=env_id,
        tool=tool_name,
        action=action.name,
        ok=result.ok,
        status=result.status,
        sub=operator.sub,
        edge="connector" if is_env_scoped(principal) else "direct",
    )
    return _result_payload(action.name, result)


async def execute_action_by_name(
    action_name: str,
    params: dict[str, Any],
    principal: Principal,
) -> dict[str, Any]:
    action = get_action(action_name)
    if action is None:
        raise HTTPException(400, f"unknown action {action_name!r}")
    try:
        validated = action.schema.model_validate(params)
    except Exception as exc:
        raise HTTPException(422, f"invalid params: {exc}") from exc
    return await execute_action_tool(public_tool_name(action_name), validated, principal)


def _result_payload(action_name: str, result: ActionResult) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "action": action_name,
        "ok": result.ok,
        "status": result.status,
        "message": result.message,
        "details": result.details,
    }
    if result.ok and result.details.get("dashboard_path"):
        payload["dashboard_path"] = result.details["dashboard_path"]
    return payload
