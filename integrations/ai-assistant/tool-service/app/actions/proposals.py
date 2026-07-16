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
from ..env_registry import EnvConfig, get_env
from ..principal import Principal, can_confirm_tier, env_id_for, is_env_scoped, proposer_sub, admission_key, edge_name
from .executors import run_executor
from .guards import ActionPermissionError, assert_tier_enabled
from .limits import LIMITER
from .registry import get_action, get_action_by_tool
from .types import ActionProposal, ActionResult, ActionRisk, ActionTier

_MAX_PENDING = 512


def conversation_scope(principal: Principal, conversation_id: str | None) -> str:
    env_id = env_id_for(principal)
    if conversation_id:
        return conversation_id
    if is_env_scoped(principal):
        return f"connector:{env_id}"
    return f"direct:{admission_key(principal)}"


def _executor_user(principal: Principal, env_id: str) -> User:
    if isinstance(principal, User):
        return principal
    return User(
        sub=f"env:{env_id}",
        roles=[CFG.operator_role, CFG.responder_role],
        raw_jwt="",
        env_id=env_id,
    )


class ProposalStore:
    def __init__(self) -> None:
        self._proposals: dict[str, ActionProposal] = {}
        self._idempotency: dict[str, str] = {}

    def _expire_stale(self) -> None:
        now = time.time()
        for pid, prop in list(self._proposals.items()):
            if prop.status == "pending" and prop.expires_at <= now:
                prop.status = "expired"
        pending = [p for p in self._proposals.values() if p.status == "pending"]
        if len(pending) > _MAX_PENDING:
            pending.sort(key=lambda p: p.created_at)
            for prop in pending[: len(pending) - _MAX_PENDING]:
                prop.status = "expired"

    def create(
        self,
        tool_name: str,
        params: BaseModel,
        principal: Principal,
        conversation_id: str | None = None,
    ) -> ActionProposal:
        action = get_action_by_tool(tool_name)
        if action is None:
            raise ValueError(f"unknown action tool {tool_name}")

        env_id = env_id_for(principal)
        env = get_env(env_id)
        try:
            assert_tier_enabled(env, action.tier)
        except ActionPermissionError as exc:
            raise HTTPException(403, str(exc)) from exc

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
            conversation_scope=conversation_scope(principal, conversation_id),
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

    def list_pending(
        self,
        env_id: str,
        scope: str,
        *,
        window_s: int | None = None,
    ) -> list[ActionProposal]:
        self._expire_stale()
        now = time.time()
        out: list[ActionProposal] = []
        for prop in self._proposals.values():
            if prop.status != "pending" or prop.env_id != env_id:
                continue
            if prop.conversation_scope != scope:
                continue
            if window_s and scope.startswith("connector:"):
                if prop.created_at < now - window_s:
                    continue
            out.append(prop)
        out.sort(key=lambda p: p.created_at, reverse=True)
        return out

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

    def reject_principal(self, proposal_id: str, principal: Principal) -> ActionProposal:
        if isinstance(principal, User):
            return self.reject(proposal_id, principal)
        prop = self.get(proposal_id)
        if prop is None:
            raise HTTPException(404, "proposal not found")
        if prop.env_id != env_id_for(principal):
            raise HTTPException(403, "proposal belongs to another environment")
        if prop.status != "pending":
            raise HTTPException(409, f"proposal already {prop.status}")
        prop.status = "rejected"
        audit.emit(
            "action_rejected",
            env=prop.env_id,
            proposal_id=proposal_id,
            action=prop.action_name,
            sub=None,
            edge=edge_name(principal),
            claimed_user=None,
        )
        return prop

    def _rate_limit(self, env: EnvConfig, tier: ActionTier) -> None:
        if tier == ActionTier.MANAGER:
            cap = env.manager_actions_per_hour
        elif tier == ActionTier.ACTIVE_RESPONSE:
            cap = env.active_response_actions_per_hour
        else:
            return
        if not LIMITER.allow(env.env_id, tier.value, cap):
            audit.emit(
                "action_rate_limited",
                env=env.env_id,
                tier=tier.value,
            )
            raise HTTPException(
                429,
                f"rate limit exceeded for {tier.value} actions in this environment",
            )

    def _validate_confirm_target(
        self, prop: ActionProposal, confirm_target: dict[str, Any] | None
    ) -> None:
        needs_echo = prop.risk == ActionRisk.HIGH or prop.action_name in {
            "add_agent_to_group",
        }
        if not needs_echo:
            return
        if prop.action_name == "active_response":
            expected = {
                "agent_id": prop.params.get("agent_id"),
                "command": prop.params.get("command"),
            }
        elif prop.action_name == "restart_agent":
            expected = {"agent_id": prop.params.get("agent_id")}
        elif prop.action_name == "add_agent_to_group":
            expected = {
                "agent_id": prop.params.get("agent_id"),
                "group": prop.params.get("group"),
            }
        elif prop.action_name == "suppress_noisy_rule":
            expected = {"rule_id": str(prop.params.get("rule_id"))}
        else:
            return
        if confirm_target != expected:
            raise HTTPException(
                409,
                detail={
                    "error": "confirm_target mismatch",
                    "expected": expected,
                    "got": confirm_target,
                },
            )

    async def confirm(
        self,
        proposal_id: str,
        user: User,
        idempotency_key: str,
        confirm_target: dict[str, Any] | None = None,
    ) -> tuple[ActionProposal, ActionResult]:
        return await self._confirm(
            proposal_id, user, idempotency_key, confirm_target, principal=user
        )

    async def confirm_principal(
        self,
        proposal_id: str,
        principal: Principal,
        idempotency_key: str,
        confirm_target: dict[str, Any] | None = None,
    ) -> tuple[ActionProposal, ActionResult]:
        if isinstance(principal, User):
            return await self._confirm(
                proposal_id, principal, idempotency_key, confirm_target, principal=principal
            )
        return await self._confirm(
            proposal_id,
            _executor_user(principal, env_id_for(principal)),
            idempotency_key,
            confirm_target,
            principal=principal,
        )

    async def _confirm(
        self,
        proposal_id: str,
        user: User,
        idempotency_key: str,
        confirm_target: dict[str, Any] | None,
        *,
        principal: Principal,
    ) -> tuple[ActionProposal, ActionResult]:
        prop = self.get(proposal_id)
        if prop is None:
            raise HTTPException(404, "proposal not found")
        if isinstance(principal, User):
            if not can_confirm_tier(user, prop.tier):
                role = (
                    CFG.operator_role
                    if prop.tier == ActionTier.DASHBOARD
                    else CFG.responder_role
                )
                raise HTTPException(
                    403,
                    f"missing role {role} — cannot confirm {prop.tier.value} actions",
                )
        self._expire_stale()
        idem = f"{user.env_id}:{idempotency_key}"
        if idem in self._idempotency:
            existing_id = self._idempotency[idem]
            if existing_id != proposal_id:
                raise HTTPException(
                    409,
                    "idempotency key already used for a different proposal",
                )
            existing = self._proposals.get(existing_id)
            if existing and existing.result is not None:
                return existing, ActionResult(
                    ok=existing.result.get("ok", False),
                    status=existing.result.get("status", "replay"),
                    message=existing.result.get("message", "idempotent replay"),
                    details=existing.result.get("details", {}),
                )

        if prop.env_id != user.env_id:
            raise HTTPException(403, "proposal belongs to another environment")
        if prop.status == "expired":
            raise HTTPException(410, "proposal expired")
        if prop.status != "pending":
            raise HTTPException(409, f"proposal already {prop.status}")

        self._validate_confirm_target(prop, confirm_target)

        action = get_action(prop.action_name)
        if action is None:
            raise HTTPException(500, "action definition missing")

        env = get_env(prop.env_id)
        try:
            assert_tier_enabled(env, prop.tier)
        except ActionPermissionError as exc:
            raise HTTPException(403, str(exc)) from exc
        self._rate_limit(env, prop.tier)

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
            sub=user.sub if isinstance(principal, User) else None,
            edge=edge_name(principal),
            claimed_user=user.sub if isinstance(principal, User) else None,
        )
        return prop, result


_STORE = ProposalStore()


def create_proposal(
    tool_name: str,
    params: BaseModel,
    principal: Principal,
    conversation_id: str | None = None,
) -> dict[str, Any]:
    prop = _STORE.create(tool_name, params, principal, conversation_id)
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
    action_name: str,
    params: dict[str, Any],
    principal: Principal,
    conversation_id: str | None = None,
) -> dict[str, Any]:
    action = get_action(action_name)
    if action is None:
        raise HTTPException(400, f"unknown action {action_name!r}")
    try:
        validated = action.schema.model_validate(params)
    except Exception as exc:
        raise HTTPException(422, f"invalid params: {exc}") from exc
    return create_proposal(action.propose_tool_name, validated, principal, conversation_id)


def list_pending_proposals(
    principal: Principal,
    conversation_id: str | None,
) -> list[ActionProposal]:
    env_id = env_id_for(principal)
    scope = conversation_scope(principal, conversation_id)
    window = CFG.confirm_window_s if scope.startswith("connector:") else None
    return _STORE.list_pending(env_id, scope, window_s=window)


def reject_proposal_principal(proposal_id: str, principal: Principal) -> ActionProposal:
    return _STORE.reject_principal(proposal_id, principal)


async def confirm_proposal_principal(
    proposal_id: str,
    principal: Principal,
    idempotency_key: str,
    confirm_target: dict[str, Any] | None = None,
) -> tuple[ActionProposal, ActionResult]:
    return await _STORE.confirm_principal(
        proposal_id, principal, idempotency_key, confirm_target
    )


def get_proposal(proposal_id: str) -> ActionProposal | None:
    return _STORE.get(proposal_id)


def reject_proposal(proposal_id: str, user: User) -> ActionProposal:
    return _STORE.reject(proposal_id, user)


async def confirm_proposal(
    proposal_id: str,
    user: User,
    idempotency_key: str,
    confirm_target: dict[str, Any] | None = None,
) -> tuple[ActionProposal, ActionResult]:
    return await _STORE.confirm(proposal_id, user, idempotency_key, confirm_target)


def reset_store_for_tests() -> None:
    _STORE._proposals.clear()
    _STORE._idempotency.clear()
    LIMITER.reset_for_tests()
