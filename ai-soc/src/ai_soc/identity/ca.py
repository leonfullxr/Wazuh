"""Pinned per-site CA loading and redirect-free HTTP transport construction."""

from __future__ import annotations

import hashlib
import ssl
from dataclasses import dataclass
from typing import Protocol

import httpx

from ai_soc.contracts.models import AuthorizedSite, ErrorCode


class SecretVersionReader(Protocol):
    def get_secret_value(self, *, secret_id: str, version_id: str) -> str: ...


class CAConfigurationError(ValueError):
    def __init__(self) -> None:
        self.code = ErrorCode.CA_UNTRUSTED
        super().__init__(self.code.value)


@dataclass(frozen=True, slots=True)
class SiteTransport:
    environment_id: str
    policy_hash: str
    client: httpx.AsyncClient


def build_site_transport(
    site: AuthorizedSite,
    secrets: SecretVersionReader,
    *,
    timeout_seconds: float = 10.0,
) -> SiteTransport:
    """Build an isolated transport using exactly the configured secret version/hash."""
    config = site.config
    try:
        pem = secrets.get_secret_value(
            secret_id=config.ca_secret_arn,
            version_id=config.ca_secret_version,
        )
        encoded = pem.encode("utf-8")
        if hashlib.sha256(encoded).hexdigest() != config.ca_sha256:
            raise CAConfigurationError()
        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cadata=pem)
        if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
            raise CAConfigurationError()
        client = httpx.AsyncClient(
            base_url=config.indexer_origin,
            verify=context,
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(timeout_seconds, connect=timeout_seconds),
            limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
            headers={"accept": "application/json"},
        )
    except CAConfigurationError:
        raise
    except Exception as exc:
        raise CAConfigurationError() from exc
    return SiteTransport(
        environment_id=config.environment_id, policy_hash=site.policy_hash, client=client
    )
