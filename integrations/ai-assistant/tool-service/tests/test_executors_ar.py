"""Active-response executor safety tests (R6.1)."""
import pytest

from app.actions.executors import _require_agent_id, execute_active_response_action
from app.actions.schemas import ActiveResponseParams
from app.auth import User
from app.env_registry import EnvConfig


def test_require_agent_id_rejects_empty():
    with pytest.raises(ValueError, match="agent_id is required"):
        _require_agent_id("")


def test_active_response_uses_agents_list_query_param(monkeypatch):
    import asyncio

    captured: dict = {}

    async def _fake_token(env, cred):
        return "tok"

    async def _fake_put(self, url, **kwargs):
        captured["url"] = url
        captured["params"] = kwargs.get("params")
        captured["json"] = kwargs.get("json")

        class R:
            status_code = 200
            text = "ok"

        return R()

    monkeypatch.setattr("app.actions.executors._wazuh_api_token", _fake_token)
    monkeypatch.setattr("httpx.AsyncClient.put", _fake_put)

    env = EnvConfig(
        env_id="lab",
        gateway_key="k",
        indexer_url="https://indexer:9200",
        manager_api_url="https://manager:55000",
        ar_executor_basic="ar:secret",
        actions_tiers=("active_response",),
    )
    params = ActiveResponseParams(
        agent_id="005",
        command="restart-ossec",
        reason="Golden test dry-run for AR targeting",
    )

    async def _run():
        return await execute_active_response_action(
            params,
            env,
            User(sub="op", roles=["wazuh_ai_responder"], raw_jwt=""),
        )

    result = asyncio.run(_run())
    assert result.ok is True
    assert captured["params"] == {"agents_list": "005"}
    assert "agents" not in (captured["json"] or {})
    assert captured["json"]["command"] == "restart-ossec"
