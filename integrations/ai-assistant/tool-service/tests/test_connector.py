"""Connector surface response shape (V3.1b)."""
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app import env_registry
from app.env_registry import EnvConfig
from app.main import app


@pytest.fixture(autouse=True)
def _env_key(monkeypatch):
    monkeypatch.setattr(
        env_registry,
        "ENV_REGISTRY",
        {
            "lab": EnvConfig(
                env_id="lab",
                gateway_key="connector-test-key",
                indexer_url="https://wazuh.indexer:9200",
                reader_basic="wazuh_ai_env_reader:secret",
            )
        },
    )


@pytest.fixture
def client():
    return TestClient(app)


async def _fake_turn(prompt, principal, conversation_id):
    yield {"event": "token", "data": {"text": "Hello from gateway"}}
    yield {
        "event": "done",
        "data": {
            "verifiability": "typed tools, verified by construction · checks: dry_run",
            "lanes": [1],
            "checks": ["dry_run"],
            "tools_called": ["count_alerts"],
            "usage": {"in": 1, "out": 2},
            "corrections": [],
            "conversation_id": conversation_id,
        },
    }


def test_connector_analyze_requires_env_key(client):
    r = client.post("/v1/connector/analyze", json={"parameters": {"prompt": "Hi"}})
    assert r.status_code == 422  # missing header


def test_connector_analyze_rejects_bad_key(client):
    r = client.post(
        "/v1/connector/analyze",
        json={"parameters": {"prompt": "Hi"}},
        headers={"X-Env-Key": "bad"},
    )
    assert r.status_code == 401


def test_connector_analyze_returns_upstream_shape(client, monkeypatch):
    monkeypatch.setattr("app.main.run_turn", _fake_turn)
    r = client.post(
        "/v1/connector/analyze",
        json={"parameters": {"prompt": "Hi"}},
        headers={"X-Env-Key": "connector-test-key"},
    )
    assert r.status_code == 200
    body = r.json()
    assert "output" in body
    msg = body["output"]["message"]
    assert "Hello from gateway" in msg
    assert "environment-scoped identity" in msg
