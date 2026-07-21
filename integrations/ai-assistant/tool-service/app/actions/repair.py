"""Recover actions when the model prints JSON instead of calling tools."""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any, Iterator

from pydantic import ValidationError

from ..config import CFG
from ..principal import Principal, is_env_scoped
from .cards import card_from_proposal
from .proposals import create_proposal
from .registry import public_tool_name
from .run import ActionPermissionError, execute_action_tool
from .schemas import CreateDashboardParams

_DASHBOARD_TOOL = public_tool_name("create_dashboard")
_PROPOSE_DASHBOARD_TOOL = "propose_create_dashboard"
_FENCED_JSON_RE = re.compile(
    r"```(?:json)?\s*(\{.*?\})\s*```",
    re.DOTALL | re.IGNORECASE,
)


def _iter_json_object_candidates(text: str) -> Iterator[str]:
    stripped = text.strip()
    if stripped.startswith("{"):
        yield stripped

    for match in _FENCED_JSON_RE.finditer(text):
        yield match.group(1)

    idx = 0
    while idx < len(text):
        start = text.find("{", idx)
        if start < 0:
            break
        try:
            _, end = json.JSONDecoder().raw_decode(text[start:])
        except json.JSONDecodeError:
            idx = start + 1
            continue
        yield text[start : start + end]
        idx = start + end


def _looks_like_dashboard_params(data: object) -> bool:
    return isinstance(data, dict) and isinstance(data.get("title"), str)


def _dashboard_called(tools_called: list[str]) -> bool:
    return "create_dashboard" in tools_called or "propose_create_dashboard" in tools_called


def _format_direct_result(payload: dict[str, Any]) -> str:
    lines = [payload.get("message", "Dashboard action completed.")]
    if payload.get("dashboard_path"):
        lines.append(f"Open: {payload['dashboard_path']}")
    if not payload.get("ok"):
        lines.insert(0, "The dashboard action failed.")
    return "\n".join(lines)


async def _repair_dashboard_async(
    text: str,
    principal: Principal,
    *,
    tools_called: list[str],
    ui_base: str,
) -> tuple[str, dict[str, Any] | None]:
    if not CFG.actions_enabled or _dashboard_called(tools_called):
        return text, None

    seen: set[str] = set()
    for raw in _iter_json_object_candidates(text):
        if raw in seen:
            continue
        seen.add(raw)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not _looks_like_dashboard_params(data):
            continue
        try:
            params = CreateDashboardParams.model_validate(data)
        except ValidationError:
            continue

        cleaned = re.sub(r"\n{3,}", "\n\n", text.replace(raw, "").strip())
        try:
            if CFG.actions_direct and not is_env_scoped(principal):
                payload = await execute_action_tool(_DASHBOARD_TOOL, params, principal)
                answer = cleaned or _format_direct_result(payload)
                return answer, payload
            payload = create_proposal(_PROPOSE_DASHBOARD_TOOL, params, principal)
            card = card_from_proposal(payload, ui_base=ui_base)
            preview = payload["preview"]
            answer = cleaned or (
                f"{preview}\n\n"
                "This is a **proposal only** — confirm with your operator role "
                "to create it."
            )
            return answer, card
        except ActionPermissionError as exc:
            return text, {"error": str(exc)}

    return text, None


def try_repair_dashboard_action(
    text: str,
    principal: Principal,
    *,
    tools_called: list[str],
    ui_base: str,
) -> tuple[str, dict[str, Any] | None]:
    """Sync wrapper for tests."""
    return asyncio.run(
        _repair_dashboard_async(
            text, principal, tools_called=tools_called, ui_base=ui_base
        )
    )
