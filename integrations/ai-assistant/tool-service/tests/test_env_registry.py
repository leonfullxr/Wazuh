"""Environment registry and connector auth (V3.1a/D43)."""
import os

import pytest

from app import env_registry
from app.env_registry import EnvConfig, resolve_by_key


@pytest.fixture(autouse=True)
def _reset_registry(monkeypatch):
    monkeypatch.setattr(
        env_registry,
        "ENV_REGISTRY",
        {
            "lab": EnvConfig(
                env_id="lab",
                gateway_key="test-gateway-key",
                indexer_url="https://wazuh.indexer:9200",
                reader_basic="wazuh_ai_env_reader:secret",
            )
        },
    )


def test_resolve_by_key_matches():
    env = resolve_by_key("test-gateway-key")
    assert env is not None
    assert env.env_id == "lab"


def test_resolve_by_key_rejects_wrong_key():
    assert resolve_by_key("wrong-key") is None


def test_resolve_by_key_rejects_empty():
    assert resolve_by_key("") is None


def test_fallback_reader_from_env(monkeypatch):
    monkeypatch.delenv("WAI_ENVS_FILE", raising=False)
    monkeypatch.setenv("WAI_ENV_LAB_KEY", "from-env-key")
    monkeypatch.setenv("WAI_ENV_LAB_READER", "reader:pass")
    envs = env_registry.load_environments()
    assert envs["lab"].gateway_key == "from-env-key"
    assert envs["lab"].reader_basic == "reader:pass"
