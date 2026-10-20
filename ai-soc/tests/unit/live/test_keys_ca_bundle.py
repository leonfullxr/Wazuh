from __future__ import annotations

import ssl
from unittest.mock import patch

from ai_soc.live.keys import _verify_context, mcp_key_resolver


def test_mcp_key_resolver_uses_injected_ca_bundle(tmp_path) -> None:
    bundle = tmp_path / "bundle.pem"
    bundle.write_text("not-a-real-bundle", encoding="utf-8")
    with patch.object(ssl.SSLContext, "load_verify_locations") as load_locations:
        with patch("ai_soc.live.keys.httpx.Client"):
            mcp_key_resolver(
                "https://issuer.example.test/protocol/openid-connect/certs",
                ca_bundle_path=str(bundle),
            )
    load_locations.assert_called_once_with(cafile=str(bundle))


def test_verify_context_loads_bundle_when_configured(tmp_path) -> None:
    bundle = tmp_path / "ca.pem"
    bundle.write_text("pem", encoding="utf-8")
    with patch.object(ssl.SSLContext, "load_verify_locations") as load_locations:
        _verify_context(str(bundle))
    load_locations.assert_called_once_with(cafile=str(bundle))
