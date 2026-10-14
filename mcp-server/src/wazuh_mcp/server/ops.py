"""Operational HTTP routes: health, readiness, metrics, OAuth metadata and the token endpoint."""

import json
import logging
import time
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from wazuh_mcp import __version__
from wazuh_mcp.auth import create_access_token
from wazuh_mcp.security import MAX_JSON_DEPTH, memory_manager, parse_json_body_safe
from wazuh_mcp.session_store import RedisSessionStore

from . import state
from .constants import MCP_PROTOCOL_VERSION, MODERN_PROTOCOL_VERSIONS, SUPPORTED_PROTOCOL_VERSIONS

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/health")
async def health_check():
    """Liveness probe: 200 whenever the server process is up and serving.

    Deliberately does NOT check Wazuh / Indexer reachability. A SIEM outage must
    not mark the MCP server itself unhealthy - that would fail the container
    healthcheck and restart-loop a perfectly live server. Use /ready for
    dependency/readiness checks.
    """
    return JSONResponse(
        content={
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": __version__,
            # Latest revision served; the legacy value is only what initialize offers
            "mcp_protocol_version": MODERN_PROTOCOL_VERSIONS[0],
            "legacy_handshake_protocol_version": MCP_PROTOCOL_VERSION,
            "supported_protocol_versions": SUPPORTED_PROTOCOL_VERSIONS,
        },
        status_code=200,
    )


# /ready is unauthenticated and exempt from rate limiting (probes must always answer), but each
# evaluation calls the Wazuh Manager - using the client's shared request budget - and walks the
# session store. Serve a briefly cached result and let only one probe run at a time, so a flood
# of /ready can't starve real tool calls.
READY_CACHE_SECONDS = 5.0


@router.get("/ready")
async def readiness_check():
    """Readiness probe with detailed component status.

    Verifies Wazuh Manager (and Indexer, if configured) reachability and memory headroom,
    and returns 503 when any is unhealthy. Intended for load-balancer / orchestrator
    readiness gating, not for liveness (see /health). Results are cached for
    READY_CACHE_SECONDS.
    """
    async with state._ready_lock:
        now = time.monotonic()
        if state._ready_cache is None or now - state._ready_cache[0] >= READY_CACHE_SECONDS:
            state._ready_cache = (now, await _evaluate_readiness())
        response = state._ready_cache[1]
    return JSONResponse(content=json.loads(response.body), status_code=response.status_code)


def _manager_failure_reason(exc: Exception) -> str:
    """Coarse category for /ready, which is unauthenticated: no host names or messages."""
    text = str(exc).lower()
    # The client raises this message only after finding ssl.SSLCertVerificationError in the chain
    if "tls certificate verification failed" in text:
        return "tls_verification_failed"
    if "401" in text or "403" in text or "authenticat" in text or "credential" in text:
        return "authentication_failed"
    if isinstance(exc, (httpx.TimeoutException, httpx.ConnectError)) or "timeout" in text or "connect" in text:
        return "unreachable"
    return "error"


async def _evaluate_readiness() -> JSONResponse:
    try:
        # Test Wazuh connectivity with an UNCACHED probe so a fresh Manager outage
        # isn't masked by the 5-minute cache on get_manager_info().
        wazuh_status = "healthy"
        manager_reason = None
        try:
            await state.wazuh_client.ping_manager()
            if state._last_manager_failure is not None:
                logger.info("Wazuh Manager is reachable again")
            state._last_manager_failure = None
        except Exception as e:
            wazuh_status = "unhealthy"
            manager_reason = _manager_failure_reason(e)
            # Log the full cause once per change, not on every probe; /ready only says why in brief
            if str(e) != state._last_manager_failure:
                logger.error(f"Readiness: Wazuh Manager check failed: {e}")
            state._last_manager_failure = str(e)

        # Test Wazuh Indexer connectivity (if configured)
        indexer_status = "not_configured"
        if state.wazuh_client._indexer_client:
            try:
                health = await state.wazuh_client._indexer_client.health_check()
                hs = health.get("status")
                if hs in ("green", "yellow"):
                    indexer_status = "healthy"
                elif hs == "red":
                    indexer_status = "degraded"
                else:
                    # health_check() swallows connection errors and returns
                    # status="unavailable" (or None) instead of raising, so an Indexer
                    # outage surfaces here - not in the except below. Treat it as
                    # unhealthy so readiness degrades instead of silently staying 200.
                    indexer_status = "unhealthy"
            except Exception:
                indexer_status = "unhealthy"

        # Check session count. Redis expires keys itself, and fetching every session there
        # (SCAN + one GET per key) made /ready take seconds with many sessions.
        if isinstance(state._session_store, RedisSessionStore):
            total_sessions = active_sessions = await state._session_store.count()
        else:
            all_sessions = await state.sessions.get_all()
            total_sessions = len(all_sessions)
            active_sessions = len([s for s in all_sessions.values() if not s.is_expired()])

        # Build auth info
        auth_info = {
            "mode": state.config.AUTH_MODE,
            "bearer_enabled": state.config.is_bearer,
            "oauth_enabled": state.config.is_oauth,
            "authless": state.config.is_authless,
        }
        if state.config.is_oauth:
            auth_info["oauth_dcr"] = state.config.OAUTH_ENABLE_DCR
            auth_info["oauth_endpoints"] = ["/oauth/authorize", "/oauth/token", "/oauth/register"]
            auth_info["oauth_discovery"] = "/.well-known/oauth-authorization-server"

        # Determine overall status from component health. The Indexer backs every
        # alert/vuln tool, so when it is configured any non-healthy state (unhealthy,
        # degraded/red, unknown) must degrade readiness - otherwise the orchestrator
        # keeps routing traffic to a node whose core tools all fail.
        # Over MAX_MEMORY_MB the security middleware 503s every non-probe request; report it
        # here too so the orchestrator stops routing to (and can recycle) this node.
        memory_status = "healthy" if memory_manager.check_memory_usage() else "over_limit"

        if wazuh_status != "healthy":
            overall_status = "degraded"
        elif indexer_status not in ("healthy", "not_configured"):
            overall_status = "degraded"
        elif memory_status != "healthy":
            overall_status = "degraded"
        else:
            overall_status = "healthy"

        status_code = 200 if overall_status == "healthy" else 503
        return JSONResponse(
            content={
                "status": overall_status,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": __version__,
                # Latest revision served; the legacy value is only what initialize offers
                "mcp_protocol_version": MODERN_PROTOCOL_VERSIONS[0],
                "legacy_handshake_protocol_version": MCP_PROTOCOL_VERSION,
                "supported_protocol_versions": SUPPORTED_PROTOCOL_VERSIONS,
                "transport": {"streamable_http": "enabled"},
                "clusters": {
                    "multi_cluster": state.cluster_registry.multi_cluster,
                    "default": state.cluster_registry.default_id,
                    "configured": state.cluster_registry.cluster_ids,
                },
                "authentication": auth_info,
                "services": {
                    "wazuh_manager": wazuh_status,
                    **({"wazuh_manager_reason": manager_reason} if manager_reason else {}),
                    "wazuh_indexer": indexer_status,
                    "memory": memory_status,
                    "mcp": "healthy",
                },
                "vulnerability_tools": {
                    "available": state.wazuh_client._indexer_client is not None,
                    "note": (
                        "Vulnerability tools require Wazuh Indexer (4.8.0+). Set WAZUH_INDEXER_HOST to enable."
                        if not state.wazuh_client._indexer_client
                        else "Wazuh Indexer configured"
                    ),
                },
                "metrics": {"active_sessions": active_sessions, "total_sessions": total_sessions},
                "endpoints": {
                    "recommended": "/mcp (Streamable HTTP - 2026-07-28 + legacy)",
                    "authentication": (
                        "/auth/token" if state.config.is_bearer else ("/oauth/token" if state.config.is_oauth else None)
                    ),
                    "monitoring": ["/health", "/ready", "/metrics"],
                },
            },
            status_code=status_code,
        )
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            content={"status": "unhealthy", "timestamp": datetime.now(timezone.utc).isoformat()},
            status_code=503,
        )


@router.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

    from wazuh_mcp.monitoring import REGISTRY

    return Response(content=generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)


# OAuth 2.0 Discovery Endpoint (RFC 8414)
@router.get("/.well-known/oauth-authorization-server")
async def oauth_metadata(request: Request):
    """
    OAuth 2.0 Authorization Server Metadata endpoint.
    Required for Claude Desktop OAuth integration.
    """
    if not state.config.is_oauth or not state._oauth_manager:
        raise HTTPException(status_code=404, detail="OAuth not enabled. Set AUTH_MODE=oauth to enable.")

    return JSONResponse(state._oauth_manager.get_metadata(request))


# OAuth 2.0 Protected Resource Metadata (RFC 9728) - required by the MCP
# authorization spec since 2025-06-18 and carried forward in 2026-07-28
@router.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource_metadata(request: Request):
    """Protected resource metadata so clients can locate the authorization server."""
    if not state.config.is_oauth or not state._oauth_manager:
        raise HTTPException(status_code=404, detail="OAuth not enabled. Set AUTH_MODE=oauth to enable.")

    issuer = state._oauth_manager.get_issuer_url(request)
    return JSONResponse(
        {
            "resource": f"{issuer}/mcp",
            "authorization_servers": [issuer],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["wazuh:read", "wazuh:write"],
            "resource_documentation": f"{issuer}/docs",
        }
    )


# Authentication endpoint for API key validation
@router.post("/auth/token")
async def get_auth_token(request: Request):
    """Get JWT token using API key.

    Accepts API key in request body as JSON: {"api_key": "wazuh_..."}
    Validates against configured API keys (MCP_API_KEY env var or auto-generated).
    """
    try:
        try:
            body = parse_json_body_safe(await request.body(), max_depth=MAX_JSON_DEPTH)
        except (json.JSONDecodeError, ValueError):
            raise HTTPException(status_code=400, detail="Invalid JSON")
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="Request body must be a JSON object")
        api_key = body.get("api_key")

        if not api_key:
            raise HTTPException(status_code=400, detail="API key required")

        # Validate API key format
        if not isinstance(api_key, str) or not api_key.startswith("wazuh_"):
            raise HTTPException(status_code=401, detail="Invalid API key format")

        # Validate against auth_manager (handles MCP_API_KEY env var and auto-generated keys)
        from wazuh_mcp.auth import auth_manager

        key_obj = auth_manager.validate_api_key(api_key)
        if not key_obj:
            raise HTTPException(status_code=401, detail="Invalid API key")

        # Mint the JWT with the API key's actual scopes (fail closed to read-only),
        # so a read-only key cannot be upgraded to write at token issuance.
        granted_scopes = key_obj.scopes or ["wazuh:read"]
        lifetime = timedelta(hours=state.config.TOKEN_LIFETIME_HOURS)
        token = create_access_token(
            data={
                # sub carries the key id so distinct keys are distinguishable principals
                "sub": getattr(key_obj, "id", None) or "wazuh_mcp_user",
                "iat": datetime.now(timezone.utc).timestamp(),
                "scope": " ".join(granted_scopes),
            },
            secret_key=state.config.AUTH_SECRET_KEY,
            expires_delta=lifetime,
        )

        return {"access_token": token, "token_type": "bearer", "expires_in": int(lifetime.total_seconds())}

    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    except HTTPException:
        raise  # Re-raise HTTP exceptions as-is
    except Exception as e:
        logger.error(f"Token generation error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
