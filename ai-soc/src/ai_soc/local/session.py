"""Authenticate a single local operator using a private sign-in key file."""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from hmac import compare_digest
from secrets import token_hex
from threading import Lock

from pydantic import HttpUrl

from ai_soc.contracts.models import ErrorCode, VerifiedPrincipal
from ai_soc.identity.alb import IdentityError

SESSION_COOKIE = "__Host-soc-session"
OWNER_GROUP = "local-operator"
ISSUER = HttpUrl("https://local.ai-soc.invalid")
SESSION_SECONDS = 8 * 60 * 60
IDLE_SECONDS = 30 * 60


@dataclass
class _Session:
    digest: bytes
    started: datetime
    last_seen: datetime
    expires: datetime


class LocalSessions:
    def __init__(self, key: str, secret: bytes) -> None:
        if len(key) != 64 or any(char not in "0123456789abcdef" for char in key):
            raise ValueError("invalid local sign-in key")
        self.owner_key = sha256(b"ai-soc.local.owner\0" + secret).hexdigest()
        self._key_digest = sha256(key.encode()).digest()
        self._session: _Session | None = None
        self._lock = Lock()

    def sign_in(self, key: str) -> str | None:
        if not compare_digest(sha256(key.encode()).digest(), self._key_digest):
            return None
        token = token_hex(32)
        now = datetime.now(UTC)
        with self._lock:
            self._session = _Session(
                sha256(token.encode()).digest(),
                now,
                now,
                now + timedelta(seconds=SESSION_SECONDS),
            )
        return token

    @staticmethod
    def _cookie(headers: Mapping[str, str]) -> str:
        cookies: list[str] = []
        for part in headers.get("cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == SESSION_COOKIE:
                cookies.append(value)
        if len(cookies) != 1 or len(cookies[0]) != 64:
            return ""
        return cookies[0]

    def sign_out(self, headers: Mapping[str, str]) -> None:
        digest = sha256(self._cookie(headers).encode()).digest()
        with self._lock:
            if self._session and compare_digest(digest, self._session.digest):
                self._session = None

    def _principal(self, headers: Mapping[str, str], *, touch: bool) -> VerifiedPrincipal | None:
        digest = sha256(self._cookie(headers).encode()).digest()
        now = datetime.now(UTC)
        with self._lock:
            session = self._session
            if session is None or not compare_digest(digest, session.digest):
                return None
            if now >= session.expires or now - session.last_seen >= timedelta(seconds=IDLE_SECONDS):
                self._session = None
                return None
            if touch:
                session.last_seen = now
            return VerifiedPrincipal(
                issuer=ISSUER,
                sub=OWNER_GROUP,
                owner_key=self.owner_key,
                groups=(OWNER_GROUP,),
                edge="browser",
                authenticated_at=session.started,
                expires_at=session.expires,
                assertion_hash=session.digest.hex(),
            )

    def authenticated(self, headers: Mapping[str, str]) -> bool:
        return self._principal(headers, touch=False) is not None

    async def verify(self, *, headers: Mapping[str, str], edge: str) -> VerifiedPrincipal:
        principal = self._principal(headers, touch=True) if edge == "browser" else None
        if principal is None:
            raise IdentityError(ErrorCode.AUTH_REQUIRED)
        return principal
