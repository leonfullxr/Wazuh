"""Execute write actions immediately (direct mode)."""
from __future__ import annotations

from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel

from .. import audit
from ..auth import User
from ..config import CFG
from ..env_registry import get_env
from ..principal import Principal, can_confirm_actions, env_id_for, is_env_scoped
from .executors import run_executor
from .registry import get_action, get_action_by_tool, public_tool_name
from .types import ActionResult


class ActionPermissionError(Exception):
    pass


def operator_for_writes(principal: Principal) -> User:
    """Resolve the operator identity used for executor audit fields."""
    if isinstance(principal, User):
        if not can_confirm_actions(principal):
            raise ActionPermissionError(
                f"missing operator role {CFG.operator_role} — cannot run write actions"
            )
        return principal
    return User(
        sub=f"connector:{principal.env_id}",
        roles=[CFG.operator_role, CFG.access_role],
        raw_jwt="",
        env_id=principal.env_id,
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
    operator = operator_for_writes(principal)
    env = get_env(env_id)
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
