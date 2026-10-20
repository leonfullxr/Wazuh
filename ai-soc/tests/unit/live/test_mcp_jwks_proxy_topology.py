from __future__ import annotations

import httpx
import pytest

from ai_soc.live.keys import alb_key_resolver, mcp_key_resolver


def test_mcp_jwks_ignores_alb_proxy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOC_ALB_PUBLIC_KEY_HTTPS_PROXY", "http://alb-proxy:443")
    monkeypatch.delenv("SOC_MCP_JWKS_HTTPS_PROXY", raising=False)
    captured: list[dict[str, object]] = []
    real_client = httpx.Client

    def spy(*args: object, **kwargs: object) -> httpx.Client:
        captured.append(dict(kwargs))
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", spy)
    mcp_key_resolver("https://kc.lab/realms/soc/protocol/openid-connect/certs")
    assert captured[-1]["proxy"] is None


def test_mcp_jwks_uses_explicit_jwks_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOC_MCP_JWKS_HTTPS_PROXY", "http://jwks-proxy:443")
    captured: list[dict[str, object]] = []
    real_client = httpx.Client

    def spy(*args: object, **kwargs: object) -> httpx.Client:
        captured.append(dict(kwargs))
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", spy)
    mcp_key_resolver("https://kc.lab/realms/soc/protocol/openid-connect/certs")
    assert captured[-1]["proxy"] == "http://jwks-proxy:443"


def test_alb_resolver_still_uses_alb_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOC_ALB_PUBLIC_KEY_HTTPS_PROXY", "http://alb-proxy:443")
    monkeypatch.delenv("SOC_MCP_JWKS_HTTPS_PROXY", raising=False)
    assert alb_key_resolver("us-east-1") is not None
