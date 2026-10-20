"""Port adapter for route-selected browser or MCP identity verification."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping

from ai_soc.contracts.models import ErrorCode, VerifiedPrincipal
from ai_soc.contracts.ports import IdentityVerifier
from ai_soc.identity.alb import (
    AlbAssertionVerifier,
    IdentityError,
    McpBearerVerifier,
    bearer_from_headers,
)


class RouteIdentityVerifier(IdentityVerifier):
    """The trusted route supplies edge mode; no request header can select it."""

    def __init__(self, alb: AlbAssertionVerifier, mcp: McpBearerVerifier) -> None:
        self._alb = alb
        self._mcp = mcp

    async def verify(self, *, headers: Mapping[str, str], edge: str) -> VerifiedPrincipal:
        normalized = {name.lower(): value for name, value in headers.items()}
        try:
            if edge == "browser":
                token = normalized.get("x-amzn-oidc-data")
                if not token:
                    raise IdentityError(ErrorCode.AUTH_REQUIRED)
                if "authorization" in normalized:
                    raise IdentityError()
                return await asyncio.to_thread(self._alb.verify, token)
            if edge == "mcp":
                token = bearer_from_headers(normalized)
                origin = normalized.get("origin")
                return await asyncio.to_thread(self._mcp.verify, token, origin=origin)
        except IdentityError:
            raise
        raise IdentityError(ErrorCode.AUTH_INVALID)
