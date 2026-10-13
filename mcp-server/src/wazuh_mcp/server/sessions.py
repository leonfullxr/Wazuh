"""MCP session model, session manager and bounded session creation."""

import asyncio
import logging
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from wazuh_mcp.session_store import RedisSessionStore, SessionStore

from .constants import SESSION_TIMEOUT_MINUTES

logger = logging.getLogger(__name__)


# Client-supplied metadata kept per session is bounded: only these clientInfo keys are
# stored, each truncated, and capabilities are reduced to their top-level names. The
# request body may be up to 1 MB and a fresh session is minted for every POST that lacks
# a session id, so storing the raw objects let one authenticated principal push gigabytes
# into the process (30 min TTL, ~100 req/min).
_CLIENT_INFO_KEYS = ("name", "version", "title")
_CLIENT_INFO_MAX_LEN = 128
_CAPABILITIES_MAX_KEYS = 32
# Principal ids that stand for "everyone" rather than one caller (authless mode, or an
# OAuth token without client_id/sub). Capping those per principal would cap the whole
# deployment and let one client evict its colleagues, so only the global bound applies.
_SHARED_PRINCIPALS = frozenset({"authless", "oauth", "anon", "unknown"})


def _bounded_client_info(raw: Any) -> Dict[str, str]:
    """Copy of clientInfo keeping only _CLIENT_INFO_KEYS, each stringified and truncated to _CLIENT_INFO_MAX_LEN."""
    if not isinstance(raw, dict):
        return {}
    out: Dict[str, str] = {}
    for key in _CLIENT_INFO_KEYS:
        value = raw.get(key)
        if isinstance(value, (str, int, float)):
            out[key] = str(value)[:_CLIENT_INFO_MAX_LEN]
    return out


def _bounded_capabilities(raw: Any) -> Dict[str, bool]:
    """Top-level capability names only (bounded count), so stored sessions stay small."""
    if not isinstance(raw, dict):
        return {}
    return {str(k)[:64]: True for k in list(raw.keys())[:_CAPABILITIES_MAX_KEYS]}


class MCPSession:
    """MCP Session Management for Remote MCP Server."""

    def __init__(self, session_id: str, origin: Optional[str] = None):
        self.session_id = session_id
        self.origin = origin
        self.created_at = datetime.now(timezone.utc)
        self.last_activity = self.created_at
        self.capabilities = {}
        self.client_info = {}
        self.authenticated = False
        # Principal that created the session (for the per-principal cap); set by the endpoints.
        self.principal: Optional[str] = None

    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = datetime.now(timezone.utc)

    def is_expired(self, timeout_minutes: Optional[int] = None) -> bool:
        """Check if session is expired.

        Defaults to the store's TTL: with Redis that is SESSION_TTL_SECONDS, which a fixed
        30 minutes here must not override (a longer TTL would expire sessions Redis still holds)."""
        from . import state
        if timeout_minutes is None:
            timeout = timedelta(seconds=getattr(state._session_store, "ttl_seconds", SESSION_TIMEOUT_MINUTES * 60))
        else:
            timeout = timedelta(minutes=timeout_minutes)
        return datetime.now(timezone.utc) - self.last_activity > timeout

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary."""
        return {
            "session_id": self.session_id,
            "origin": self.origin,
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "capabilities": self.capabilities,
            "client_info": self.client_info,
            "principal": self.principal,
            "authenticated": self.authenticated,
        }


# Session management with pluggable backend (serverless-ready)
class SessionManager:
    """
    Session manager with pluggable storage backend.
    Supports both in-memory (default) and Redis (serverless-ready) backends.
    """

    def __init__(self, store: SessionStore):
        self._store = store
        self._lock = threading.RLock()  # For synchronous operations
        logger.info(f"SessionManager initialized with {type(store).__name__}")

    def _session_from_dict(self, data: Dict[str, Any]) -> MCPSession:
        """Reconstruct MCPSession from dictionary."""
        session = MCPSession(data["session_id"], data.get("origin"))
        session.created_at = datetime.fromisoformat(data["created_at"].replace("Z", "+00:00"))
        session.last_activity = datetime.fromisoformat(data["last_activity"].replace("Z", "+00:00"))
        session.capabilities = _bounded_capabilities(data.get("capabilities", {}))
        session.client_info = _bounded_client_info(data.get("client_info", {}))
        session.principal = data.get("principal")
        session.authenticated = data.get("authenticated", False)
        return session

    async def get(self, session_id: str) -> Optional[MCPSession]:
        """Get session by ID."""
        data = await self._store.get(session_id)
        if data:
            return self._session_from_dict(data)
        return None

    async def set(self, session_id: str, session: MCPSession) -> bool:
        """Store session."""
        return await self._store.set(session_id, session.to_dict())

    def _run_sync(self, coro):
        """Run coroutine synchronously, handling existing event loop safely."""
        try:
            asyncio.get_running_loop()
            # If we get here, there's a running loop - this is not safe
            raise RuntimeError(
                "Synchronous SessionManager methods cannot be called from async context. "
                "Use async methods like 'await sessions.get()' instead."
            )
        except RuntimeError as e:
            # Re-raise if this is our own "cannot be called from async" error
            if "Synchronous SessionManager" in str(e):
                raise
            # No running loop - safe to create one
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(coro)
            finally:
                loop.close()

    def __getitem__(self, session_id: str) -> MCPSession:
        """Synchronous dict-like access (blocks). Not for use in async context."""
        session = self._run_sync(self.get(session_id))
        if session is None:
            raise KeyError(f"Session {session_id} not found")
        return session

    def __setitem__(self, session_id: str, session: MCPSession) -> None:
        """Synchronous dict-like access (blocks). Not for use in async context."""
        self._run_sync(self.set(session_id, session))

    def __delitem__(self, session_id: str) -> None:
        """Synchronous delete (blocks). Not for use in async context."""
        self._run_sync(self.remove(session_id))

    def __contains__(self, session_id: str) -> bool:
        """Check if session exists (synchronous for use with 'in' operator)."""
        return self._run_sync(self._store.exists(session_id))

    async def remove(self, session_id: str) -> bool:
        """Remove session by ID."""
        return await self._store.delete(session_id)

    def pop(self, session_id: str, default=None) -> Optional[MCPSession]:
        """Remove and return session (synchronous, blocks). Not for use in async context."""

        async def _pop():
            session = await self.get(session_id)
            if session:
                await self.remove(session_id)
                return session
            return default

        return self._run_sync(_pop())

    async def clear(self) -> bool:
        """Clear all sessions."""
        return await self._store.clear()

    def values(self) -> List[MCPSession]:
        """Get all session values (synchronous, blocks). Not for use in async context."""
        sessions_dict = self._run_sync(self.get_all())
        return list(sessions_dict.values())

    def keys(self) -> List[str]:
        """Get all session keys (synchronous, blocks). Not for use in async context."""
        sessions_dict = self._run_sync(self.get_all())
        return list(sessions_dict.keys())

    async def get_all(self) -> Dict[str, MCPSession]:
        """Get all sessions as dictionary."""
        data_dict = await self._store.get_all()
        return {sid: self._session_from_dict(data) for sid, data in data_dict.items()}

    async def cleanup_expired(self, timeout_minutes: int = 30) -> int:
        """Remove expired sessions and return count."""
        return await self._store.cleanup_expired(timeout_minutes=timeout_minutes)

    async def count(self) -> int:
        """Number of stored sessions (cheap; no payload fetch)."""
        return await self._store.count()


def _principal_of(auth_token: Any) -> Optional[str]:
    """The api_key_id of an auth token (the session-bounding principal), or None when unauthenticated."""
    return getattr(auth_token, "api_key_id", None) if auth_token is not None else None


async def _enforce_session_bounds(principal: Optional[str]) -> None:
    """Keep the session store bounded so a session-minting flood cannot exhaust memory.

    Cheap path first: a key count. The full scan only runs once the store holds at
    least MAX_SESSIONS_PER_PRINCIPAL entries (below that nobody can be over their cap)
    or is at MAX_SESSIONS. Expired sessions are reclaimed first; if the store is still
    full, the least recently active sessions are evicted (they only need to
    re-initialize). The per-principal cap applies to real principals only (see
    _SHARED_PRINCIPALS); "principal" is the API key / OAuth client, not a person.
    """
    from . import state
    if isinstance(state._session_store, RedisSessionStore):
        # Redis expires sessions itself and holds them outside this process; counting them
        # meant a keyspace SCAN plus one GET per session on every new session (~1000 round
        # trips at MAX_SESSIONS). Metadata is still bounded when the session is created.
        return
    total = await state.sessions.count()
    per_principal = bool(principal) and principal not in _SHARED_PRINCIPALS
    if total < state.MAX_SESSIONS and (not per_principal or total < state.MAX_SESSIONS_PER_PRINCIPAL):
        return  # fast path: no bound can be exceeded by one more session

    active = await state.sessions.get_all()
    if per_principal:
        mine = sorted(
            (s for s in active.values() if getattr(s, "principal", None) == principal),
            key=lambda s: s.last_activity,
        )
        excess = len(mine) - (state.MAX_SESSIONS_PER_PRINCIPAL - 1)
        for victim in mine[: max(0, excess)]:
            await state.sessions.remove(victim.session_id)
            state._initialized_sessions.pop(victim.session_id, None)
            active.pop(victim.session_id, None)
    if len(active) >= state.MAX_SESSIONS:
        reclaimed = await state.sessions.cleanup_expired()
        if reclaimed:
            active = await state.sessions.get_all()
    if len(active) >= state.MAX_SESSIONS:
        oldest = sorted(active.values(), key=lambda s: s.last_activity)
        for victim in oldest[: len(active) - state.MAX_SESSIONS + 1]:
            await state.sessions.remove(victim.session_id)
            state._initialized_sessions.pop(victim.session_id, None)
        logger.warning(f"Session store at MAX_SESSIONS={state.MAX_SESSIONS}; evicted least recently active sessions")


def _is_initialize(body: Any) -> bool:
    """True if a JSON-RPC body (single or batch) contains an initialize request."""
    items = body if isinstance(body, list) else [body]
    return any(isinstance(item, dict) and item.get("method") == "initialize" for item in items)


async def get_or_create_session(
    session_id: Optional[str], origin: Optional[str], persist: bool = True, principal: Optional[str] = None
) -> MCPSession:
    """Get existing session or create new one.

    persist=False builds a throwaway session for a request that isn't an initialize: the
    spec assigns session ids only on the InitializeResult, and storing one for every
    session-less request grew the store by (rate limit x session TTL) per client. Stored
    sessions are subject to the MAX_SESSIONS / MAX_SESSIONS_PER_PRINCIPAL bounds."""
    from . import state

    if not session_id and not persist:
        return MCPSession(str(uuid.uuid4()), origin)

    if session_id:
        existing_session = await state.sessions.get(session_id)
        if existing_session:
            existing_session.update_activity()
            await state.sessions.set(session_id, existing_session)
            return existing_session

    await _enforce_session_bounds(principal)

    # Always generate server-side session IDs to prevent session fixation attacks.
    # Client-provided session IDs are only used to look up existing sessions above.
    new_session_id = str(uuid.uuid4())
    session = MCPSession(new_session_id, origin)
    session.principal = principal
    await state.sessions.set(new_session_id, session)
    from wazuh_mcp.monitoring import record_session_event

    record_session_event("created")

    # Cleanup expired sessions periodically (at most every 60 seconds)
    now = time.time()
    if now - state._last_session_cleanup > 60:
        state._last_session_cleanup = now
        try:
            expired_count = await state.sessions.cleanup_expired()
            if expired_count > 0:
                from wazuh_mcp.monitoring import record_session_event

                for _ in range(expired_count):
                    record_session_event("expired")
                logger.debug(f"Cleaned up {expired_count} expired sessions")
                # Sync _initialized_sessions with active sessions
                active = await state.sessions.get_all()
                stale_keys = [k for k in state._initialized_sessions if k not in active]
                for k in stale_keys:
                    state._initialized_sessions.pop(k, None)
        except Exception as e:
            logger.error(f"Session cleanup error: {e}")

    return session
