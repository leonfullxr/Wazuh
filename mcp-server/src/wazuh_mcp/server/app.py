"""FastAPI application: lifespan, middleware stack and router registration."""

import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from wazuh_mcp import __version__
from wazuh_mcp.api.wazuh_client import WazuhClient
from wazuh_mcp.config import get_config
from wazuh_mcp.monitoring import setup_monitoring_middleware
from wazuh_mcp.security import security_middleware
from wazuh_mcp.session_store import SessionStoreUnavailable

from . import ops, state, transport
from .constants import CORS_MAX_AGE_SECONDS, MCP_PROTOCOL_VERSION

logger = logging.getLogger(__name__)


# Lifespan context manager for startup/shutdown events (modern FastAPI pattern)
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle with proper startup and shutdown handling."""

    # === STARTUP ===
    # Attach the log sanitizer to the emitting handlers (not the root logger, whose
    # filters are skipped for propagated child-logger records) to prevent credential leakage.
    from wazuh_mcp.security import install_log_sanitizer

    install_log_sanitizer()

    # Fail at startup, not on the first tool call: an empty WAZUH_HOST would otherwise surface much
    # later as "Request URL is missing an 'http://' or 'https://' protocol".
    _startup_cfg = get_config()
    _missing = [
        name
        for name, value in (
            ("WAZUH_HOST", _startup_cfg.WAZUH_HOST),
            ("WAZUH_USER", _startup_cfg.WAZUH_USER),
            ("WAZUH_PASS", _startup_cfg.WAZUH_PASS),
        )
        if not value
    ]
    if _missing:
        from wazuh_mcp.config import ConfigurationError

        raise ConfigurationError(f"Required Wazuh Manager settings are not set: {', '.join(_missing)}")

    logger.info(f"Wazuh MCP v{__version__} starting up...")
    logger.info(f"MCP Protocol: {MCP_PROTOCOL_VERSION}")
    logger.info(f"Wazuh Host: {get_config().WAZUH_HOST}")
    logger.info(f"CORS Origins: {get_config().ALLOWED_ORIGINS}")
    logger.info(f"Auth Mode: {get_config().AUTH_MODE}")

    # Log Indexer configuration status
    cfg = get_config()
    if cfg.WAZUH_INDEXER_HOST:
        logger.info(f"Wazuh Indexer: {cfg.WAZUH_INDEXER_HOST}:{cfg.WAZUH_INDEXER_PORT}")
    else:
        logger.warning("Wazuh Indexer not configured. Vulnerability tools require Wazuh 4.8.0+")
        logger.warning("   Set WAZUH_INDEXER_HOST, WAZUH_INDEXER_USER, WAZUH_INDEXER_PASS to enable.")

    # Initialize OAuth if enabled
    if cfg.is_oauth:
        try:
            from wazuh_mcp.oauth import create_oauth_router, init_oauth_manager

            state._oauth_manager = init_oauth_manager(cfg)
            oauth_router = create_oauth_router(state._oauth_manager)
            app.include_router(oauth_router)
            logger.info("OAuth 2.0 with DCR initialized")
            logger.info("   OAuth endpoints: /oauth/authorize, /oauth/token, /oauth/register")
            logger.info("   Discovery: /.well-known/oauth-authorization-server")
        except Exception as e:
            logger.error(f"OAuth initialization failed: {e}")

    # Log auth mode status
    if cfg.is_authless:
        logger.warning("Running in AUTHLESS mode - no authentication required!")
    elif cfg.is_bearer:
        logger.info("Bearer token authentication enabled")
        # Display auto-generated API key if not configured via environment
        if not os.getenv("MCP_API_KEY"):
            from wazuh_mcp.auth import auth_manager

            default_key = auth_manager.get_default_api_key()
            if default_key and cfg.ENVIRONMENT == "development":
                # Printed outside logging on purpose: the log sanitizer (rightly) redacts
                # wazuh_* keys, which left the banner showing "wazuh_[REDACTED]" and the
                # generated key unusable. Development only.
                print(
                    f"\nAuto-generated API key for this process (dev only):\n   {default_key}\n"
                    "   Read-only. Exchange it at POST /auth/token. For a stable key, or write access,\n"
                    "   set MCP_API_KEY (and MCP_API_KEY_SCOPES).\n",
                    file=sys.stderr,
                    flush=True,
                )
            elif default_key:
                logger.warning(
                    "No MCP_API_KEY set: a temporary read-only key was generated and is not shown in "
                    "production. Set MCP_API_KEY (and MCP_API_KEY_SCOPES) to authenticate clients."
                )

    # Start background session cleanup task (runs every 5 minutes regardless of traffic)
    async def _background_session_cleanup():
        while True:
            await asyncio.sleep(300)
            try:
                expired = await state.sessions.cleanup_expired()
                if expired > 0:
                    logger.debug(f"Background cleanup: removed {expired} expired sessions")
                    active = await state.sessions.get_all()
                    stale = [k for k in state._initialized_sessions if k not in active]
                    for k in stale:
                        state._initialized_sessions.pop(k, None)
            except Exception as e:
                logger.error(f"Background session cleanup error: {e}")

    _cleanup_task = asyncio.create_task(_background_session_cleanup())

    # Start background system metrics collection (CPU/memory gauges for /metrics).
    try:
        from wazuh_mcp.monitoring import metrics_collector

        await metrics_collector.start_collection()
        logger.info("System metrics collection started")
    except Exception as e:
        logger.error(f"Failed to start metrics collection: {e}")

    # Scaling caveat: the OAuth token/refresh store, the revocation denylist, and the
    # rate limiters are all per-process, in-memory state. Across multiple workers/replicas
    # a token revoked on one node is still accepted on another (the stateless-JWT fallback),
    # refresh-replay detection is per-node, and rate-limit buckets don't aggregate. Until a
    # shared store (e.g. Redis) backs these, deploy a SINGLE worker or pin clients to one
    # node with sticky sessions. Warn loudly when a multi-worker env var is detected.
    _worker_count = os.getenv("WEB_CONCURRENCY") or os.getenv("UVICORN_WORKERS") or os.getenv("GUNICORN_WORKERS")
    try:
        _multi_worker = int(_worker_count) > 1 if _worker_count else False
    except (TypeError, ValueError):
        _multi_worker = False
    if _multi_worker:
        logger.warning(
            "Multiple workers detected (%s) but OAuth token/revocation state and rate limiting "
            "are per-process. Token revocation and rate limits will NOT be consistent across workers. "
            "Run a single worker, add sticky sessions, or back these stores with Redis.",
            _worker_count,
        )
    elif cfg.is_oauth:
        logger.info(
            "OAuth token store, revocation denylist, and rate limiter are per-process. "
            "Deploy a single worker (or a shared store) so revocation and rate limits stay consistent."
        )

    # Initialize Wazuh client (will be available after yield)
    logger.info("Server startup complete with high availability features enabled")

    yield  # Server is running

    # === SHUTDOWN ===
    logger.info("Wazuh MCP initiating graceful shutdown...")

    # Cancel background session cleanup
    _cleanup_task.cancel()
    try:
        await _cleanup_task
    except asyncio.CancelledError:
        pass

    # Stop metrics collection
    try:
        from wazuh_mcp.monitoring import metrics_collector

        await metrics_collector.stop_collection()
    except Exception as e:
        logger.debug(f"Metrics collection stop error: {e}")

    try:
        # Initiate graceful shutdown (waits for active connections)
        await state.shutdown_manager.initiate_shutdown()

        # Clear and cleanup auth manager
        from wazuh_mcp.auth import auth_manager

        auth_manager.cleanup_expired()
        auth_manager.tokens.clear()
        logger.info("Authentication tokens cleared")

        # Release the identity-provider HTTP client (OAuth mode with OAUTH_IDP_ISSUER)
        if state._oauth_manager is not None and state._oauth_manager.idp is not None:
            await state._oauth_manager.idp.aclose()

        # Do NOT clear the session store on shutdown. In-memory sessions vanish with the process
        # anyway, and a shared Redis store is the whole point of multi-instance deployments -
        # wiping it here would 404 every OTHER instance's live sessions on a single pod restart or
        # rolling deploy. Redis TTL handles expiry. Just close this instance's backend connection.
        if hasattr(state.sessions._store, "close"):
            await state.sessions._store.close()
        logger.info("Session store backend closed (sessions preserved for other instances)")

        # Close Wazuh clients (all configured clusters) to release HTTP connections
        await state.cluster_registry.close()
        logger.info("Wazuh client(s) closed")

        # Cleanup rate limiter
        if hasattr(state.rate_limiter, "cleanup"):
            state.rate_limiter.cleanup()

        # Close connection pools
        from wazuh_mcp.security import connection_pool_manager

        await connection_pool_manager.close_all()
        logger.info("Connection pools closed")

        # Force garbage collection
        import gc

        gc.collect()
        logger.info("Garbage collection completed")

    except Exception as e:
        logger.error(f"Error during shutdown: {e}")
    finally:
        logger.info("Graceful shutdown completed")


# Initialize FastAPI app for MCP compliance
app = FastAPI(
    title="Wazuh MCP",
    description="MCP-compliant remote server for Wazuh SIEM integration. Supports Streamable HTTP, SSE, OAuth, and authless modes.",
    version=__version__,
    docs_url="/docs",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


@app.exception_handler(SessionStoreUnavailable)
async def _session_store_unavailable(request: Request, exc: SessionStoreUnavailable):
    # A Redis outage is a server-side 503, not "session not found" (404 tells clients to re-init)
    return JSONResponse(
        status_code=503,
        content={"error": "Session store unavailable; retry shortly"},
        headers={"Retry-After": "5"},
    )


async def get_wazuh_client() -> WazuhClient:
    """Get the global Wazuh client instance.

    Used by monitoring health checks to access client state.
    """
    return state.wazuh_client


# Register monitoring middleware for request tracking and correlation IDs
app.middleware("http")(setup_monitoring_middleware())

# Register security middleware for security headers and request validation
app.middleware("http")(security_middleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=state.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],  # Added DELETE for session management
    allow_headers=[
        "Accept",
        "Accept-Language",
        "Content-Language",
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "MCP-Protocol-Version",  # MCP protocol version header
        "MCP-Session-Id",  # Session ID header
        "Mcp-Method",  # 2026-07-28: required on every request
        "Mcp-Name",  # 2026-07-28: required on tools/call, prompts/get, resources/read
        "Last-Event-ID",  # SSE reconnection header
    ],  # Specific headers only, no wildcard
    expose_headers=["MCP-Session-Id", "MCP-Protocol-Version", "Content-Type"],
    max_age=CORS_MAX_AGE_SECONDS,
)

app.include_router(transport.router)
app.include_router(ops.router)


if __name__ == "__main__":
    import uvicorn

    config = get_config()

    uvicorn.run(app, host=config.MCP_HOST, port=config.MCP_PORT, log_level=config.LOG_LEVEL.lower(), access_log=True)
