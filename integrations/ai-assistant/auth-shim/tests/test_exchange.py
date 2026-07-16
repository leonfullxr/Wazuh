"""Auth-shim exchange audit and rate limiting."""
from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.env_registry import EnvEntry
from app.main import app
from app.rate_limit import ExchangeRateLimiter


@pytest.fixture(autouse=True)
def _registry(monkeypatch):
    monkeypatch.setattr(
        "app.main.ENV_REGISTRY",
        {"lab": EnvEntry(env_id="lab", indexer_url="https://wazuh.indexer:9200")},
    )
    monkeypatch.setattr(
        "app.main._LIMITER",
        ExchangeRateLimiter(per_user_per_minute=20, per_ip_per_minute=60),
    )


@pytest.fixture
def client():
    return TestClient(app)


def _basic(user: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def test_exchange_rejects_bad_password(client, capsys):
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    with patch("app.main.httpx.post", return_value=mock_resp):
        r = client.post("/v1/token/exchange", headers=_basic("analyst1", "nope"))
    assert r.status_code == 401
    out = capsys.readouterr().out
    assert "exchange_credentials_rejected" in out


def test_exchange_rejects_missing_role(client, capsys):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "user_name": "viewer1",
        "backend_roles": ["wazuh_readonly"],
    }
    with patch("app.main.httpx.post", return_value=mock_resp):
        r = client.post("/v1/token/exchange", headers=_basic("viewer1", "viewer1"))
    assert r.status_code == 403
    assert "exchange_role_rejected" in capsys.readouterr().out


def test_exchange_rate_limited(client, monkeypatch, capsys):
    monkeypatch.setattr(
        "app.main._LIMITER",
        ExchangeRateLimiter(per_user_per_minute=2, per_ip_per_minute=100),
    )
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "user_name": "analyst1",
        "backend_roles": ["wazuh_ai_analyst"],
    }
    with patch("app.main.httpx.post", return_value=mock_resp):
        for _ in range(2):
            assert client.post("/v1/token/exchange", headers=_basic("analyst1", "ok")).status_code == 200
        r = client.post("/v1/token/exchange", headers=_basic("analyst1", "ok"))
    assert r.status_code == 429
    assert "exchange_rate_limited" in capsys.readouterr().out


def test_exchange_success_audited(client, capsys):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "user_name": "analyst1",
        "backend_roles": ["wazuh_ai_analyst", "wazuh_ai_operator"],
    }
    with patch("app.main.httpx.post", return_value=mock_resp):
        r = client.post("/v1/token/exchange", headers=_basic("analyst1", "ok"))
    assert r.status_code == 200
    assert r.json()["access_token"]
    assert "exchange_succeeded" in capsys.readouterr().out
