"""Stateless browser CSRF nonce and origin binding shared across replicas."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from uuid import uuid4

from ai_soc.application.errors import ServiceFailure
from ai_soc.contracts.errors import public_error
from ai_soc.contracts.models import ErrorCode


class CsrfTokens:
    def __init__(self, secret: bytes, *, origin: str, ttl_seconds: int = 600) -> None:
        if len(secret) < 32 or ttl_seconds < 1 or ttl_seconds > 600:
            raise ValueError("CSRF secret or lifetime is invalid")
        self._secret = secret
        self._origin = origin.rstrip("/")
        self._ttl = ttl_seconds

    def issue(
        self, *, owner_key: str, assertion_expires_at: datetime, now: datetime
    ) -> tuple[str, str]:
        nonce = secrets.token_bytes(32)
        expires = min(now + timedelta(seconds=self._ttl), assertion_expires_at)
        if expires <= now:
            raise self._failure()
        nonce_text = self._b64(nonce)
        issued = int(now.timestamp())
        expiry = int(expires.timestamp())
        body = f"{owner_key}\0{self._origin}\0{nonce_text}\0{issued}\0{expiry}".encode()
        signature = hmac.new(self._secret, body, hashlib.sha256).digest()
        envelope = f"{nonce_text}.{issued}.{expiry}.{self._b64(signature)}"
        return envelope, envelope

    def verify(
        self,
        token: str,
        cookie: str,
        *,
        owner_key: str,
        origin: str | None,
        now: datetime,
    ) -> None:
        try:
            if not hmac.compare_digest(cookie, token):
                raise ValueError("csrf header does not match cookie")
            if origin != self._origin:
                raise ValueError("origin mismatch")
            nonce_text, issued_raw, expiry_raw, signature_raw = token.split(".", 3)
            issued, expiry = int(issued_raw), int(expiry_raw)
            current = int(now.timestamp())
            if expiry <= current or issued > current or expiry - issued > self._ttl:
                raise ValueError("expired csrf token")
            nonce = self._decode(nonce_text)
            if len(nonce) != 32:
                raise ValueError("invalid nonce")
            body = f"{owner_key}\0{self._origin}\0{nonce_text}\0{issued}\0{expiry}".encode()
            expected = hmac.new(self._secret, body, hashlib.sha256).digest()
            supplied = self._decode(signature_raw)
            if not hmac.compare_digest(expected, supplied):
                raise ValueError("signature mismatch")
        except (ValueError, UnicodeError):
            raise self._failure() from None

    @staticmethod
    def _b64(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    @staticmethod
    def _decode(value: str) -> bytes:
        return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))

    @staticmethod
    def _failure() -> ServiceFailure:
        return ServiceFailure(
            public_error(
                ErrorCode.CSRF_DENIED, "Browser request validation failed.", trace_id=str(uuid4())
            )
        )
