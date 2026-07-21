"""Shared turn-JWT minting for golden runners (V3.6)."""
from __future__ import annotations

import os

import httpx

SHIM = os.environ.get("WAI_EVAL_SHIM_URL", "http://localhost:8081")
ENV_ID = os.environ.get("WAI_EVAL_ENV_ID", "lab")


def get_turn_jwt(
    user: str,
    password: str,
    *,
    shim: str | None = None,
    env_id: str | None = None,
) -> str:
    """Basic creds → shim exchange → turn JWT."""
    headers: dict[str, str] = {}
    resolved_env = env_id or ENV_ID
    if resolved_env:
        headers["X-Env-Id"] = resolved_env
    r = httpx.post(
        f"{shim or SHIM}/v1/token/exchange",
        auth=(user, password),
        headers=headers,
        timeout=30,
    )
    r.raise_for_status()
    return r.json()["access_token"]
