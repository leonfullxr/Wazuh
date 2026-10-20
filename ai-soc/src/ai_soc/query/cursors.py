"""Owner/site/policy/content-bound AEAD pagination cursors."""

from __future__ import annotations

import base64
import binascii
import json
import secrets
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ai_soc.contracts.models import CursorPayload, ErrorCode


class CursorError(ValueError):
    def __init__(self, code: ErrorCode = ErrorCode.CURSOR_EXPIRED) -> None:
        self.code = code
        super().__init__(code.value)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class CursorCipher:
    """Stateless cursor sealing with bounded previous-key rotation."""

    def __init__(
        self,
        *,
        keys: Mapping[str, bytes],
        current_key_id: str,
        now: Callable[[], datetime],
        max_token_bytes: int = 8192,
        max_plaintext_bytes: int = 5500,
        lifetime: timedelta = timedelta(seconds=300),
    ) -> None:
        copied = dict(keys)
        if current_key_id not in copied or any(len(key) != 32 for key in copied.values()):
            raise ValueError("cursor keys must be configured 256-bit keys")
        if len(copied) > 2 or lifetime <= timedelta(0) or lifetime > timedelta(seconds=300):
            raise ValueError("cursor rotation and lifetime exceed supported bounds")
        self._keys = copied
        self._current = current_key_id
        self._now = now
        self.max_token_bytes = max_token_bytes
        self.max_plaintext_bytes = max_plaintext_bytes
        self.lifetime = lifetime

    @property
    def current_key_id(self) -> str:
        return self._current

    def seal(self, payload: CursorPayload) -> str:
        now = self._now().astimezone(UTC)
        if (
            payload.key_id != self._current
            or payload.expires_at <= now
            or payload.expires_at > now + self.lifetime
        ):
            raise CursorError()
        plain = payload.model_dump_json(exclude_none=False).encode("utf-8")
        if len(plain) > self.max_plaintext_bytes:
            raise CursorError(ErrorCode.EVIDENCE_LIMIT)
        nonce = secrets.token_bytes(12)
        aad = f"soc.cursor.v1\0{self._current}".encode()
        encrypted = AESGCM(self._keys[self._current]).encrypt(nonce, plain, aad)
        token = f"v1.{self._current}.{_b64(nonce + encrypted)}"
        if len(token.encode("ascii")) > self.max_token_bytes:
            raise CursorError(ErrorCode.EVIDENCE_LIMIT)
        return token

    def open(
        self,
        token: str,
        *,
        owner_key: str,
        environment_id: str,
        policy_hash: str,
        content_sha: str,
        now: datetime | None = None,
    ) -> CursorPayload:
        if not token or len(token.encode("utf-8")) > self.max_token_bytes:
            raise CursorError(ErrorCode.BAD_REQUEST)
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != "v1":
            raise CursorError(ErrorCode.BAD_REQUEST)
        key_id = parts[1]
        if key_id not in self._keys:
            raise CursorError(ErrorCode.CURSOR_EXPIRED)
        payload_b64 = parts[2]
        try:
            if payload_b64 != _b64(_unb64(payload_b64)):
                raise CursorError(ErrorCode.BAD_REQUEST)
            raw = _unb64(payload_b64)
            if len(raw) < 12 + 16:
                raise CursorError(ErrorCode.BAD_REQUEST)
            aad = f"soc.cursor.v1\0{key_id}".encode()
            plaintext = AESGCM(self._keys[key_id]).decrypt(raw[:12], raw[12:], aad)
            if len(plaintext) > self.max_plaintext_bytes:
                raise CursorError(ErrorCode.BAD_REQUEST)
            payload = CursorPayload.model_validate_json(plaintext, strict=True)
        except CursorError:
            raise
        except (InvalidTag, ValueError, TypeError, json.JSONDecodeError, binascii.Error) as exc:
            raise CursorError(ErrorCode.BAD_REQUEST) from exc
        current = (now or self._now()).astimezone(UTC)
        if payload.key_id != key_id or payload.expires_at <= current:
            raise CursorError(ErrorCode.CURSOR_EXPIRED)
        if (
            payload.owner_key != owner_key
            or payload.environment_id != environment_id
            or payload.policy_hash != policy_hash
            or payload.content_sha != content_sha
        ):
            raise CursorError(ErrorCode.CURSOR_EXPIRED)
        return payload
