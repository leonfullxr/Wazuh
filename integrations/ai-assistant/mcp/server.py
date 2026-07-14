#!/usr/bin/env python3
"""Stdio MCP adapter (P1.8) over the wazuh-ai tool-service HTTP surface.

Exposes the typed tool catalog and the sync chat endpoint to MCP hosts.
Authenticates with WAI_MCP_JWT (override) or mints on demand via Keycloak +
shim exchange (R2.7), refreshing before expiry.

Run: python3 mcp/server.py
"""
from __future__ import annotations

import json
import os
import sys
import time
from typing import Any

import httpx

SVC = os.environ.get("WAI_MCP_BASE_URL", "http://localhost:8080")
KC = os.environ.get("WAI_MCP_KC_URL", "http://localhost:8085")
SHIM = os.environ.get("WAI_MCP_SHIM_URL", "http://localhost:8081")
REALM = os.environ.get("WAI_MCP_REALM", "wazuh-poc")
CLIENT = os.environ.get("WAI_MCP_CLIENT", "wazuh-ai")
KC_USER = os.environ.get("WAI_MCP_KC_USER", "analyst1")
KC_PASSWORD = os.environ.get("WAI_MCP_KC_PASSWORD", "analyst1")

_STATIC_JWT = os.environ.get("WAI_MCP_JWT", "")
_cached_jwt: str | None = None
_cached_exp: float = 0.0


def _jwt_exp(token: str) -> float:
    try:
        import base64

        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return float(data.get("exp", 0))
    except Exception:
        return time.time() + 300


def _mint_jwt() -> str:
    oidc = httpx.post(
        f"{KC}/realms/{REALM}/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": CLIENT,
            "username": KC_USER,
            "password": KC_PASSWORD,
        },
        timeout=30,
    )
    oidc.raise_for_status()
    exchanged = httpx.post(
        f"{SHIM}/v1/token/exchange",
        headers={"Authorization": f"Bearer {oidc.json()['access_token']}"},
        timeout=30,
    )
    exchanged.raise_for_status()
    return exchanged.json()["access_token"]


def get_jwt() -> str:
    global _cached_jwt, _cached_exp
    if _STATIC_JWT:
        return _STATIC_JWT
    now = time.time()
    if _cached_jwt and now < _cached_exp - 30:
        return _cached_jwt
    token = _mint_jwt()
    _cached_jwt = token
    _cached_exp = _jwt_exp(token)
    return token


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {get_jwt()}"}


def list_tools() -> list[dict[str, Any]]:
    r = httpx.get(f"{SVC}/v1/tools", headers=_headers(), timeout=30)
    r.raise_for_status()
    return r.json()


def call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    r = httpx.post(
        f"{SVC}/v1/tools/{name}",
        json=arguments,
        headers=_headers(),
        timeout=120,
    )
    r.raise_for_status()
    return r.json()


def chat_sync(text: str) -> dict[str, Any]:
    r = httpx.post(
        f"{SVC}/v1/chat/sync",
        json={"text": text},
        headers=_headers(),
        timeout=float(os.environ.get("WAI_EVAL_TIMEOUT_S", "300")),
    )
    r.raise_for_status()
    return r.json()


def main() -> None:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        sys.exit("install MCP deps: pip install -r mcp/requirements.txt")

    mcp = FastMCP("wazuh-ai")

    @mcp.tool()
    def wazuh_chat(text: str) -> str:
        """Ask the wazuh-ai analyst assistant a question about this tenant's alerts."""
        return json.dumps(chat_sync(text), indent=2, default=str)

    @mcp.tool()
    def wazuh_call_tool(name: str, arguments: dict) -> str:
        """Execute one typed wazuh-ai tool (search_alerts, count_alerts, ...)."""
        return json.dumps(call_tool(name, arguments), indent=2, default=str)

    @mcp.tool()
    def wazuh_list_tools() -> str:
        """List the typed tool catalog exposed by the tool service."""
        return json.dumps(list_tools(), indent=2, default=str)

    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
