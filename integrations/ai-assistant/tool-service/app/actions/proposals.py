"""In-memory proposal store with TTL and idempotency (D20/D49)."""
from __future__ import annotations

import time
import uuid
from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel

from .. import audit
from ..auth import User
from ..config import CFG
from ..env_registry import get_env
from ..principal import Principal, can_confirm_actions, env_id_for, proposer_sub
from .executors import run_executor
from .registry import get_action, get_action_by_tool
from .types import ActionProposal, ActionResult


class ProposalStore:
    def __init__(self) -> None:
        self._proposals: dict[str, ActionProposal] = {}
        self._idempotency: dict[str, str] = {}

    def _expire_stale(self) -> None:
        now = time.time()
        for pid, prop in list(self._proposals.items()):
            if prop.status == "pending" and prop.expires_at <= now:
                prop.status = "expired"

    def create(
        self,
        tool_name: str,
        params: BaseModel,
        principal: Principal,
    ) -> ActionProposal:
        action = get_action_by_tool(tool_name)
        if action is None:
            raise ValueError(f"unknown action tool {tool_name}")

        env_id = env_id_for(principal)
        now = time.time()
        proposal_id = uuid.uuid4().hex
        preview = action.preview(params)
        prop = ActionProposal(
            proposal_id=proposal_id,
            action_name=action.name,
            tool_name=tool_name,
            env_id=env_id,
            proposer_sub=proposer_sub(principal),
            params=params.model_dump(mode="json"),
            preview=preview,
            tier=action.tier,
            risk=action.risk,
            created_at=now,
            expires_at=now + CFG.action_proposal_ttl_s,
        )
        self._proposals[proposal_id] = prop
        audit.emit(
            "action_proposed",
            env=env_id,
            proposal_id=proposal_id,
            action=action.name,
            tier=action.tier.value,
            risk=action.risk.value,
            sub=prop.proposer_sub,
        )
        return prop

    def get(self, proposal_id: str) -> ActionProposal | None:
        self._expire_stale()
        return self._proposals.get(proposal_id)

    def reject(self, proposal_id: str, user: User) -> ActionProposal:
        prop = self.get(proposal_id)
        if prop is None:
            raise HTTPException(404, "proposal not found")
        if prop.env_id != user.env_id:
            raise HTTPException(403, "proposal belongs to another environment")
        if prop.status != "pending":
            raise HTTPException(409, f"proposal already {prop.status}")
        prop.status = "rejected"
        audit.emit(
            "action_rejected",
            env=prop.env_id,
            proposal_id=proposal_id,
            action=prop.action_name,
            sub=user.sub,
        )
        return prop

    async def confirm(
        self,
        proposal_id: str,
        user: User,
        idempotency_key: str,
    ) -> tuple[ActionProposal, ActionResult]:
        if not can_confirm_actions(user):
            raise HTTPException(
                403,
                f"missing operator role {CFG.operator_role} — cannot confirm actions",
            )

        self._expire_stale()
        idem = f"{user.env_id}:{idempotency_key}"
        if idem in self._idempotency:
            existing_id = self._idempotency[idem]
            prop = self._proposals.get(existing_id)
            if prop and prop.result is not None:
                return prop, ActionResult(
                    ok=prop.result.get("ok", False),
                    status=prop.result.get("status", "replay"),
                    message=prop.result.get("message", "idempotent replay"),
                    details=prop.result.get("details", {}),
                )

        prop = self.get(proposal_id)
        if prop is None:
            raise HTTPException(404, "proposal not found")
        if prop.env_id != user.env_id:
            raise HTTPException(403, "proposal belongs to another environment")
        if prop.status == "expired":
            raise HTTPException(410, "proposal expired")
        if prop.status != "pending":
            raise HTTPException(409, f"proposal already {prop.status}")

        action = get_action(prop.action_name)
        if action is None:
            raise HTTPException(500, "action definition missing")

        env = get_env(prop.env_id)
        validated = action.schema.model_validate(prop.params)
        result = await run_executor(
            prop.tier, prop.action_name, validated, env, user, user
        )

        prop.status = "confirmed"
        prop.idempotency_key = idempotency_key
        prop.confirmed_by = user.sub
        prop.result = {
            "ok": result.ok,
            "status": result.status,
            "message": result.message,
            "details": result.details,
        }
        self._idempotency[idem] = proposal_id

        audit.emit(
            "action_confirmed",
            env=prop.env_id,
            proposal_id=proposal_id,
            action=prop.action_name,
            tier=prop.tier.value,
            ok=result.ok,
            status=result.status,
            sub=user.sub,
        )
        return prop, result


_STORE = ProposalStore()


def create_proposal(tool_name: str, params: BaseModel, principal: Principal) -> dict[str, Any]:
    prop = _STORE.create(tool_name, params, principal)
    return {
        "proposal_id": prop.proposal_id,
        "action": prop.action_name,
        "preview": prop.preview,
        "tier": prop.tier.value,
        "risk": prop.risk.value,
        "status": "pending",
        "confirm_path": f"/v1/actions/{prop.proposal_id}/confirm",
        "expires_in_s": int(prop.expires_at - prop.created_at),
        "note": "NOT executed — analyst with operator role must confirm",
    }


def create_proposal_by_action(
    action_name: str, params: dict[str, Any], principal: Principal
) -> dict[str, Any]:
    action = get_action(action_name)
    if action is None:
        raise HTTPException(400, f"unknown action {action_name!r}")
    try:
        validated = action.schema.model_validate(params)
    except Exception as exc:
        raise HTTPException(422, f"invalid params: {exc}") from exc
    return create_proposal(action.tool_name, validated, principal)


def get_proposal(proposal_id: str) -> ActionProposal | None:
    return _STORE.get(proposal_id)


def reject_proposal(proposal_id: str, user: User) -> ActionProposal:
    return _STORE.reject(proposal_id, user)


async def confirm_proposal(
    proposal_id: str, user: User, idempotency_key: str
) -> tuple[ActionProposal, ActionResult]:
    return await _STORE.confirm(proposal_id, user, idempotency_key)


def reset_store_for_tests() -> None:
    _STORE._proposals.clear()
    _STORE._idempotency.clear()
