"""Multi-environment JWT verification (V3.2)."""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from app import auth, env_registry
from app.config import CFG
from app.env_registry import EnvConfig


@pytest.fixture(autouse=True)
def _registry(monkeypatch):
    registry = {
        "lab": EnvConfig(env_id="lab", gateway_key="k1", indexer_url="https://i:9200"),
        "lab-b": EnvConfig(
            env_id="lab-b", gateway_key="k2", indexer_url="https://i:9200", enabled=False
        ),
    }
    monkeypatch.setattr(env_registry, "ENV_REGISTRY", registry)
    monkeypatch.setattr(auth, "ENV_REGISTRY", registry)


def _claims(tenant: str) -> dict:
    return {
        "sub": "analyst1",
        "backend_roles": [CFG.access_role],
        "tenant": tenant,
    }


def test_unknown_tenant_rejected(monkeypatch):
    monkeypatch.setattr(auth.jwt, "decode", lambda *a, **k: _claims("other-tenant"))
    with pytest.raises(HTTPException) as exc:
        auth.user_from_token("fake.token.here")
    assert exc.value.status_code == 403


def test_disabled_env_rejected(monkeypatch):
    monkeypatch.setattr(auth.jwt, "decode", lambda *a, **k: _claims("lab-b"))
    with pytest.raises(HTTPException) as exc:
        auth.user_from_token("fake.token.here")
    assert exc.value.status_code == 503
