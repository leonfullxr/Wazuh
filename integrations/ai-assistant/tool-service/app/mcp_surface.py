"""Streamable HTTP MCP surface on the gateway (V3.3).

Auth on each request: ``Authorization: Bearer`` turn JWT (per-user, D11) or
``X-Env-Key`` (env-scoped reader, D42) — same principal resolution as the
connector edge. Stdio adapter remains in ``mcp/server.py`` for offline use.
"""
from __future__ import annotations

import json
from contextvars import ContextVar
from typing import Any

from fastapi import HTTPException
from mcp.server.fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from . import audit
from .auth import user_from_token
from .env_registry import resolve_by_key
from .loop import run_turn
from .principal import EnvPrincipal, Principal
from .tools import REGISTRY

_current_principal: ContextVar[Principal | None] = ContextVar(
    "mcp_principal", default=None
)


def _principal() -> Principal:
    principal = _current_principal.get()
    if principal is None:
        raise RuntimeError("MCP principal not set")
    return principal


def _env_enabled(env_id: str) -> None:
    from .env_registry import get_env

    env = get_env(env_id)
    if not env.enabled:
        audit.emit("env_disabled_rejected", env=env_id)
        raise HTTPException(503, f"environment {env_id!r} is disabled")


class _McpAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            principal = _resolve_principal(request)
        except HTTPException as exc:
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        token = _current_principal.set(principal)
        try:
            return await call_next(request)
        finally:
            _current_principal.reset(token)


def _resolve_principal(request: Request) -> Principal:
    env_key = request.headers.get("X-Env-Key", "").strip()
    if env_key:
        env = resolve_by_key(env_key)
        if env is None:
            audit.emit("env_key_rejected", env=None)
            raise HTTPException(401, "invalid environment key")
        _env_enabled(env.env_id)
        return EnvPrincipal(env.env_id)

    auth = request.headers.get("Authorization", "").strip()
    if auth.startswith("Bearer "):
        return user_from_token(auth.removeprefix("Bearer ").strip())

    audit.emit("mcp_auth_rejected", reason="missing_credentials")
    raise HTTPException(401, "Bearer token or X-Env-Key required")


async def _collect_sync(text: str, principal: Principal) -> dict[str, Any]:
    answer, done, corrections = "", {}, []
    async for ev in run_turn(text, principal, None):
        if ev["event"] == "token":
            answer += ev["data"]["text"]
        elif ev["event"] == "done":
            done = ev["data"]
        elif ev["event"] == "correction":
            corrections.append(ev["data"])
    return {"answer": answer, **done, "corrections": corrections}


def _create_mcp() -> tuple[FastMCP, Any]:
    mcp = FastMCP("wazuh-ai", streamable_http_path="/")

    @mcp.tool()
    async def wazuh_chat(text: str) -> str:
        """Ask the wazuh-ai analyst assistant about this environment's alerts."""
        payload = await _collect_sync(text, _principal())
        return json.dumps(payload, indent=2, default=str)

    @mcp.tool()
    async def wazuh_list_tools() -> str:
        """List the typed tool catalog exposed by the gateway."""
        tools = [
            {
                "name": t.name,
                "lane": t.lane,
                "description": t.description,
                "input_schema": t.schema.model_json_schema(),
            }
            for t in REGISTRY.values()
        ]
        return json.dumps(tools, indent=2, default=str)

    starlette_app = mcp.streamable_http_app()
    starlette_app.add_middleware(_McpAuthMiddleware)
    return mcp, starlette_app


MCP, MCP_APP = _create_mcp()
