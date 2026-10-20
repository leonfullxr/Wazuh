from __future__ import annotations

from datetime import UTC, datetime

from ai_soc.identity.alb import McpBearerVerifier
from ai_soc.live.keys import mcp_key_resolver
from tests.unit.live.live_boot_fixture import _sealed

NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)


def test_live_sealed_keycloak_shape_boots_mcp_verifier() -> None:
    document = _sealed()
    assert document.mcp.issuer.endswith("/realms/soc")
    assert "openid-connect/certs" in document.mcp.jwks_uri
    resolver = mcp_key_resolver(document.mcp.jwks_uri)
    McpBearerVerifier(
        issuer=document.mcp.issuer,
        resource=document.mcp.resource,
        jwks_uri=document.mcp.jwks_uri,
        key_resolver=resolver,
        now=lambda: NOW,
        allowed_origins=frozenset(document.mcp_allowed_origins),
    )
