"""Runtime singletons and mutable module state, read at call time through this module."""

import asyncio
import logging
import os
from collections import OrderedDict
from typing import Dict, Optional, Tuple

from fastapi.responses import JSONResponse

from wazuh_mcp.api.wazuh_client import WazuhClient
from wazuh_mcp.config import WazuhConfig, get_config, validate_positive_int
from wazuh_mcp.resilience import GracefulShutdown
from wazuh_mcp.security import RateLimiter
from wazuh_mcp.session_store import create_session_store

from .constants import RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SECONDS
from .http_security import validate_cors_origins
from .sessions import SessionManager

logger = logging.getLogger(__name__)

# OAuth manager (initialized on startup if needed)
_oauth_manager = None
MAX_SESSIONS = get_config().MAX_SESSIONS
MAX_SESSIONS_PER_PRINCIPAL = get_config().MAX_SESSIONS_PER_PRINCIPAL


# Initialize session manager with pluggable backend
# Will use Redis if REDIS_URL is set, otherwise in-memory
_session_store = create_session_store()
sessions = SessionManager(_session_store)

# Track last session cleanup time (run at most every 60 seconds, not every request)
_last_session_cleanup: float = 0.0


# Get configuration
config = get_config()

# Create Wazuh configuration from server config.
# Effective TLS verification is computed in ServerConfig (wazuh_tls_verify): httpx has no
# "verify-but-accept-self-signed" middle ground, so WAZUH_ALLOW_SELF_SIGNED=true means
# no verification at all. The supported way to trust a private CA or a self-signed
# Manager certificate is WAZUH_CA_BUNDLE. The API password is sent with HTTP Basic on
# every (re)authentication, so an unverified channel exposes it to any on-path attacker.
if config.wazuh_tls_verification_disabled:
    _tls_msg = (
        "TLS certificate verification for the Wazuh Manager is DISABLED "
        "(WAZUH_VERIFY_SSL=false or WAZUH_ALLOW_SELF_SIGNED=true). The API credentials travel "
        "over an unauthenticated channel. Reissue the Manager API certificate with a subjectAltName "
        "for WAZUH_HOST and set WAZUH_CA_BUNDLE (docs/configuration.md#manager-tls)."
    )
    if config.ENVIRONMENT == "production":
        logger.error(_tls_msg)
    else:
        logger.warning(_tls_msg)
wazuh_config = WazuhConfig(
    wazuh_host=config.WAZUH_HOST,
    wazuh_user=config.WAZUH_USER,
    wazuh_pass=config.WAZUH_PASS,
    wazuh_port=config.WAZUH_PORT,
    verify_ssl=config.wazuh_tls_verify,
    # Wazuh Indexer settings (required for vulnerability tools in Wazuh 4.8.0+)
    wazuh_indexer_host=config.WAZUH_INDEXER_HOST if config.WAZUH_INDEXER_HOST else None,
    wazuh_indexer_port=config.WAZUH_INDEXER_PORT,
    wazuh_indexer_user=config.WAZUH_INDEXER_USER if config.WAZUH_INDEXER_USER else None,
    wazuh_indexer_pass=config.WAZUH_INDEXER_PASS if config.WAZUH_INDEXER_PASS else None,
    wazuh_indexer_ssl=config.WAZUH_INDEXER_SSL,
    wazuh_indexer_verify_ssl=config.wazuh_indexer_tls_verify,
    request_timeout_seconds=config.REQUEST_TIMEOUT_SECONDS,
    max_connections=config.MAX_CONNECTIONS,
    max_alerts_per_query=config.MAX_ALERTS_PER_QUERY,
)

# Initialize Wazuh client
wazuh_client = WazuhClient(wazuh_config)

# Multi-cluster registry (opt-in via WAZUH_CLUSTERS_FILE / ./config/clusters.json).
# Without a clusters file this holds only the env-configured client and nothing changes.
from wazuh_mcp.clusters import load_cluster_registry  # noqa: E402

cluster_registry = load_cluster_registry(wazuh_client)


# Initialize rate limiter
# Honour RATE_LIMIT_REQUESTS / RATE_LIMIT_WINDOW here too (validated at startup in security.py);
# the MCP endpoints used hard-coded constants, so the documented knobs never reached them.
rate_limiter = RateLimiter(
    max_requests=validate_positive_int(
        os.getenv("RATE_LIMIT_REQUESTS", str(RATE_LIMIT_REQUESTS)), "RATE_LIMIT_REQUESTS"
    ),
    window_seconds=validate_positive_int(
        os.getenv("RATE_LIMIT_WINDOW", str(RATE_LIMIT_WINDOW_SECONDS)), "RATE_LIMIT_WINDOW", max_val=86400
    ),
)

# Initialize graceful shutdown manager
shutdown_manager = GracefulShutdown()
logger.info("Graceful shutdown manager initialized")

allowed_origins = validate_cors_origins(config.ALLOWED_ORIGINS)


# Track initialized sessions (OrderedDict for O(1) eviction of oldest entries)
_initialized_sessions: OrderedDict[str, bool] = OrderedDict()

# Current log level for logging/setLevel
_current_log_level: str = "info"


_TOOL_ARGUMENT_NAMES: Optional[Dict[str, frozenset]] = None
_ready_cache: Optional[Tuple[float, JSONResponse]] = None
_ready_lock = asyncio.Lock()


_last_manager_failure: Optional[str] = None
