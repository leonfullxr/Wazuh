"""Short-lived, per-site KMS-backed analyst JWT issuance."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import uuid4

from pydantic import SecretStr

from ai_soc.contracts.models import (
    AuthorizedSite,
    CallKind,
    ErrorCode,
    ExecutionContext,
    IndexerCredential,
    VerifiedPrincipal,
)


class KmsSigner(Protocol):
    def sign(self, **kwargs: object) -> Mapping[str, object]: ...


class BrokerError(RuntimeError):
    def __init__(self, code: ErrorCode = ErrorCode.TOKEN_BROKER_UNAVAILABLE) -> None:
        self.code = code
        super().__init__(code.value)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class KmsIndexerTokenBroker:
    """Creates RS256 claims only from a verified principal and authorized site."""

    def __init__(
        self,
        kms: KmsSigner,
        *,
        key_ids: Mapping[str, str],
        now: Callable[[], datetime],
        lifetime: timedelta = timedelta(seconds=120),
    ) -> None:
        if lifetime <= timedelta(0) or lifetime > timedelta(seconds=120):
            raise ValueError("indexer token lifetime must be in (0,120s]")
        self._kms = kms
        self._key_ids = dict(key_ids)
        self._now = now
        self._lifetime = lifetime

    async def issue(
        self,
        principal: VerifiedPrincipal,
        site: AuthorizedSite,
        *,
        execution: ExecutionContext,
    ) -> IndexerCredential:
        now = self._now()
        if now.tzinfo is None or now.utcoffset() is None or principal.expires_at <= now:
            raise BrokerError(ErrorCode.AUTH_EXPIRED)
        if (
            execution.owner_key != principal.owner_key
            or execution.environment_id != site.config.environment_id
            or execution.deadline_at <= now
        ):
            raise BrokerError(ErrorCode.FORBIDDEN)
        try:
            execution.cancel.raise_if_cancelled()
        except Exception as exc:
            raise BrokerError(ErrorCode.FORBIDDEN) from exc
        if principal.edge not in ("browser", "mcp", "fixture") or not principal.sub:
            raise BrokerError(ErrorCode.FORBIDDEN)
        if not site.backend_roles:
            raise BrokerError(ErrorCode.SITE_DENIED)
        if site.config.environment_id not in self._key_ids:
            raise BrokerError()
        key_id = self._key_ids[site.config.environment_id]
        if not key_id or len(key_id) > 256 or "\n" in key_id:
            raise BrokerError()
        issued = int(now.timestamp())
        expiry = min(
            issued + int(self._lifetime.total_seconds()), int(principal.expires_at.timestamp())
        )
        if expiry <= issued:
            raise BrokerError(ErrorCode.AUTH_EXPIRED)
        header = {"alg": "RS256", "typ": "JWT", "kid": key_id}
        claims = {
            "iss": site.config.jwt_issuer,
            "aud": site.config.jwt_audience,
            "sub": principal.sub,
            "backend_roles": list(site.backend_roles),
            "iat": issued,
            "nbf": issued,
            "exp": expiry,
            "jti": str(uuid4()),
        }
        header_part = _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
        claims_part = _b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
        signing_input = f"{header_part}.{claims_part}"
        digest = hashlib.sha256(signing_input.encode("ascii")).digest()
        try:
            execution.calls.claim(CallKind.kms)
            response = await asyncio.to_thread(
                self._kms.sign,
                KeyId=site.config.kms_signing_key_arn,
                Message=digest,
                MessageType="DIGEST",
                SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
            )
            signature = response.get("Signature")
            if not isinstance(signature, (bytes, bytearray)) or not signature:
                raise BrokerError()
        except BrokerError:
            raise
        except Exception as exc:
            raise BrokerError() from exc
        token = f"{signing_input}.{_b64url(bytes(signature))}"
        return IndexerCredential(
            bearer_token=SecretStr(token),
            expires_at=datetime.fromtimestamp(expiry, UTC),
            key_id=key_id,
        )
