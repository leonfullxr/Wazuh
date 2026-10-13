"""Request authentication, rate limiting, CORS and Origin header validation."""

import logging
import os
from datetime import datetime, timezone
from typing import Any, List, Optional
from urllib.parse import urlparse

from fastapi import HTTPException, Request

from wazuh_mcp.config import get_config
from wazuh_mcp.security import security_manager

logger = logging.getLogger(__name__)


async def verify_authentication(authorization: Optional[str], config) -> Optional[Any]:
    """Authenticate the request and record the outcome metric (success|failure)."""
    from wazuh_mcp.monitoring import record_auth_attempt

    try:
        token = await _do_verify_authentication(authorization, config)
        record_auth_attempt(True)
        return token
    except HTTPException:
        record_auth_attempt(False)
        raise


async def _do_verify_authentication(authorization: Optional[str], config) -> Optional[Any]:
    """
    Verify authentication based on configured auth mode.

    Returns AuthToken if authenticated (None for authless mode).
    Raises HTTPException if authentication fails.
    Supports: authless (none), bearer token, and OAuth modes.
    """
    from wazuh_mcp.auth import AuthToken

    from . import state

    # Authless mode - no authentication required
    if config.is_authless:
        # Return a synthetic token with scopes based on AUTHLESS_ALLOW_WRITE
        allow_write = os.getenv("AUTHLESS_ALLOW_WRITE", "false").lower() in ("true", "1", "yes")
        scopes = ["wazuh:read", "wazuh:write"] if allow_write else ["wazuh:read"]
        return AuthToken(
            token="authless",
            api_key_id="authless",
            created_at=datetime.now(timezone.utc),
            scopes=scopes,
        )

    # Point OAuth clients at the protected resource metadata (RFC 9728) when the
    # issuer URL is configured - enables automatic authorization server discovery
    www_authenticate = "Bearer"
    if config.is_oauth and getattr(config, "OAUTH_ISSUER_URL", ""):
        www_authenticate = f'Bearer resource_metadata="{config.OAUTH_ISSUER_URL}/.well-known/oauth-protected-resource"'

    # Authentication required
    if not authorization:
        raise HTTPException(
            status_code=401, detail="Authorization header required", headers={"WWW-Authenticate": www_authenticate}
        )

    # OAuth mode
    if config.is_oauth:
        if state._oauth_manager:
            token = authorization.replace("Bearer ", "") if authorization.startswith("Bearer ") else authorization
            token_obj = state._oauth_manager.validate_access_token(token)
            subject = getattr(token_obj, "subject", None) if token_obj else None
            key_obj = None
            if subject and getattr(token_obj, "subject_kind", None) == "api_key":
                # Same binding as bearer JWTs: removing, deactivating or expiring the API key the
                # user signed in with ends their OAuth tokens too, not just at TTL expiry.
                from wazuh_mcp.auth import usable_api_key

                key_obj = usable_api_key(subject)
                if key_obj is None:
                    token_obj = None
            if token_obj:
                # Return AuthToken with OAuth scopes (fail closed to read-only)
                scope_str = getattr(token_obj, "scope", "") or ""
                scopes = scope_str.split() if scope_str else ["wazuh:read"]
                if key_obj is not None:
                    from wazuh_mcp.auth import current_key_scopes

                    scopes = current_key_scopes(scopes, key_obj)
                # Per-user principal for RBAC audit, rate limiting and session bounds: the API key
                # the user signed in with, or the person the IdP authenticated. Tokens minted
                # before sign-in existed carry only the (shared) client id.
                subject = getattr(token_obj, "subject", None)
                client = getattr(token_obj, "client_id", None)
                oauth_principal = f"{client}:{subject}" if subject and client else (subject or client)
                return AuthToken(
                    token=token,
                    api_key_id=f"oauth:{oauth_principal}" if oauth_principal else "oauth",
                    created_at=datetime.now(timezone.utc),
                    scopes=scopes,
                )
        raise HTTPException(
            status_code=401, detail="Invalid or expired OAuth token", headers={"WWW-Authenticate": www_authenticate}
        )

    # Bearer token mode (default)
    try:
        from wazuh_mcp.auth import verify_bearer_token

        return await verify_bearer_token(authorization)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e), headers={"WWW-Authenticate": "Bearer"})


# CORS middleware for remote access with security
def validate_cors_origins(origins_config: str) -> List[str]:
    """Validate and parse CORS origins configuration."""
    if not origins_config or origins_config.strip() == "*":
        # Only allow wildcard in development
        if get_config().ENVIRONMENT == "development":
            return ["*"]
        else:
            # In production, default to common Claude origins
            return ["https://claude.ai", "https://claude.anthropic.com"]

    origins = []
    for origin in origins_config.split(","):
        origin = origin.strip()
        # Validate origin format
        if origin.startswith(("http://", "https://")) or origin == "*":
            # Parse and validate URL structure
            if origin != "*":
                try:
                    parsed = urlparse(origin)
                    if parsed.netloc:
                        origins.append(origin)
                except ValueError as e:
                    logger.debug(f"Skipping invalid origin '{origin}': {e}")
                    continue
            else:
                origins.append(origin)

    return origins if origins else ["https://claude.ai"]


def validate_origin_header(origin: Optional[str], allowed_origins_config: str) -> None:
    """
    Validate Origin header per MCP 2025-11-25 spec.

    Per spec: "Servers MUST validate the Origin header on all incoming connections
    to prevent DNS rebinding attacks. If the Origin header is present and invalid,
    servers MUST respond with HTTP 403 Forbidden."

    Note: If Origin header is NOT present, that's acceptable (no 403).
    Only reject if Origin IS present but invalid.

    Args:
        origin: The Origin header value (may be None)
        allowed_origins_config: Comma-separated list of allowed origins

    Raises:
        HTTPException: 403 if Origin is present but not in allowed list
    """
    # Per 2025-11-25 spec: only validate if Origin is present
    if not origin:
        return  # No Origin header = acceptable

    # Parse allowed origins
    allowed_origins_list = allowed_origins_config.split(",") if allowed_origins_config else []

    # Check if origin is allowed (exact match only for security)
    for allowed in allowed_origins_list:
        allowed = allowed.strip()
        if allowed == "*":
            # Honor the wildcard bypass ONLY in development. In production a literal "*"
            # must not disable DNS-rebinding protection - the CORS layer already refuses
            # it there (validate_cors_origins), so keep the two layers consistent and
            # require an exact match instead of blanket-allowing every Origin.
            if get_config().ENVIRONMENT == "development":
                return
            continue
        if allowed == origin:
            return  # Exact match

    # Origin present but not in allowed list - per spec MUST return 403
    raise HTTPException(status_code=403, detail=f"Origin not allowed: {origin}")


def _rate_limit_key(request: Request, auth_token: Any = None) -> str:
    """Derive a rate-limit bucket key.

    Prefer the authenticated principal so distinct clients get distinct buckets even
    behind a shared TLS-terminating reverse proxy (where request.client.host is the
    proxy for every request). Combine it with the trusted-proxy-aware client IP so
    authless/oauth callers on different real IPs still separate.
    """
    ip = security_manager.get_client_ip(request)
    api_key_id = getattr(auth_token, "api_key_id", None) or "anon"
    return f"{api_key_id}|{ip}"


async def _authenticate(request: Request, authorization: Optional[str]) -> Any:
    """verify_authentication, with failed attempts counted against a per-IP bucket.

    The MCP endpoints rate-limit per principal *after* authenticating, so bad tokens were
    never limited at all (250 x 401 in a row). A client that keeps failing now gets 429."""
    from . import state
    try:
        return await verify_authentication(authorization, state.config)
    except HTTPException as exc:
        if exc.status_code == 401:
            allowed, retry_after = state.rate_limiter.is_allowed(f"authfail|{security_manager.get_client_ip(request)}")
            if not allowed:
                raise _rate_limited_response(retry_after)
        raise


def _rate_limited_response(retry_after: Optional[int]) -> HTTPException:
    """Record the rate-limit metric and build the 429 response."""
    from wazuh_mcp.monitoring import record_rate_limit_hit

    record_rate_limit_hit("mcp")
    headers = {"Retry-After": str(retry_after)} if retry_after else {}
    return HTTPException(status_code=429, detail="Rate limit exceeded", headers=headers)
