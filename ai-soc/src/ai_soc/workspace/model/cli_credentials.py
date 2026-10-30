"""Bounded reader for the local ChatGPT CLI credential snapshot."""

from __future__ import annotations

import base64
import json
import math
import os
import re
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

MAX_AUTH_FILE_BYTES = 65536
EXPIRY_MARGIN_SECONDS = 120
_ACCOUNT_ID = re.compile(r"[A-Za-z0-9_-]{1,256}\Z")


class CredentialError(RuntimeError):
    """Static credential failure; never carries auth file contents."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class BrokerCredentials:
    access_token: str = field(repr=False)
    account_id: str = field(repr=False)

    @property
    def headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.access_token}",
            "ChatGPT-Account-ID": self.account_id,
        }


def load_credentials(
    path: str | Path,
    *,
    deadline_seconds: float = 120.0,
    now: float | None = None,
) -> BrokerCredentials:
    """Read a stable, protected ChatGPT snapshot through a no-follow file descriptor.

    JWT payload parsing is only a local expiry/FedRAMP gate, not signature
    verification. The ID token is parsed locally only for its FedRAMP bit and is
    never returned or forwarded; the access token is only sent to fixed TLS.
    """
    if not _finite_number(deadline_seconds) or deadline_seconds < 0 or deadline_seconds > 120:
        raise CredentialError("auth_unavailable")
    if now is not None and not _finite_number(now):
        raise CredentialError("auth_unavailable")
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        descriptor = os.open(os.fspath(path), flags)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_size > MAX_AUTH_FILE_BYTES
        ):
            raise CredentialError("auth_unavailable")
        raw = _read_bounded(descriptor)
        after = os.fstat(descriptor)
        if len(raw) > MAX_AUTH_FILE_BYTES or _snapshot_changed(info, after):
            raise CredentialError("auth_unavailable")
        decoded: object = json.loads(raw, object_pairs_hook=_unique_pairs)
        value = cast(dict[str, Any], decoded) if isinstance(decoded, dict) else None
        if not isinstance(value, dict) or not _is_chatgpt_mode(value):
            raise CredentialError("auth_mode_unsupported")
        tokens_value = value.get("tokens")
        tokens = cast(dict[str, Any], tokens_value) if isinstance(tokens_value, dict) else None
        if not isinstance(tokens, dict):
            raise CredentialError("auth_unavailable")
        access_token = tokens.get("access_token")
        account_id = tokens.get("account_id")
        if (
            not isinstance(access_token, str)
            or not 1 <= len(access_token) <= 8192
            or any(char.isspace() or ord(char) < 0x21 for char in access_token)
            or not isinstance(account_id, str)
            or _ACCOUNT_ID.fullmatch(account_id) is None
        ):
            raise CredentialError("auth_unavailable")
        claims = _jwt_payload(access_token)
        expires = claims.get("exp")
        instant = time.time() if now is None else now
        if (
            type(expires) is not int
            or expires <= instant + deadline_seconds + EXPIRY_MARGIN_SECONDS
        ):
            raise CredentialError("auth_refresh_required")
        id_token = tokens.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            raise CredentialError("auth_mode_unsupported")
        if _is_fedramp_id_token(id_token):
            raise CredentialError("auth_mode_unsupported")
        return BrokerCredentials(access_token, account_id)
    except CredentialError:
        raise
    except (OSError, ValueError, TypeError, RecursionError):
        raise CredentialError("auth_unavailable") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _is_chatgpt_mode(auth: dict[str, Any]) -> bool:
    mode = auth.get("auth_mode")
    if mode is None:
        return not any(
            key in auth and auth[key] is not None
            for key in (
                "OPENAI_API_KEY",
                "personal_access_token",
                "bedrock_api_key",
                "bedrock_access_keys",
                "agent_identity",
            )
        )
    return mode == "chatgpt"


def _is_fedramp_id_token(token: str) -> bool:
    claims = _jwt_payload(token)
    auth_value = claims.get("https://api.openai.com/auth")
    if auth_value is None:
        return False
    if not isinstance(auth_value, dict):
        raise CredentialError("auth_mode_unsupported")
    auth = cast(dict[str, Any], auth_value)
    is_fedramp = auth.get("chatgpt_account_is_fedramp", False)
    if type(is_fedramp) is not bool:
        raise CredentialError("auth_mode_unsupported")
    return is_fedramp


def _finite_number(value: object) -> bool:
    if type(value) is int:
        return abs(value) <= 1_000_000_000_000
    return type(value) is float and math.isfinite(value)


def _read_bounded(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total <= MAX_AUTH_FILE_BYTES:
        chunk = os.read(descriptor, min(8192, MAX_AUTH_FILE_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _snapshot_changed(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ctime_ns != after.st_ctime_ns
        or before.st_mode != after.st_mode
        or before.st_uid != after.st_uid
    )


def _jwt_payload(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise CredentialError("auth_unavailable")
    try:
        encoded = parts[1]
        decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        value = json.loads(decoded, object_pairs_hook=_unique_pairs)
    except (ValueError, TypeError, RecursionError):
        raise CredentialError("auth_unavailable") from None
    if not isinstance(value, dict):
        raise CredentialError("auth_unavailable")
    return cast(dict[str, Any], value)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result
