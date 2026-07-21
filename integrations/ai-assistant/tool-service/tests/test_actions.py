"""Actions v1.5 propose/confirm flow (D20/D35)."""
import asyncio
import json

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.actions.proposals import confirm_proposal, create_proposal, reset_store_for_tests
from app.actions.schemas import CreateDashboardParams
from app.auth import User, verify_jwt
from app.config import CFG
from app.main import app
from app.principal import EnvPrincipal


@pytest.fixture(autouse=True)
def _clean_store():
    reset_store_for_tests()
    yield
    reset_store_for_tests()


@pytest.fixture
def actions_on(monkeypatch):
    monkeypatch.setattr(CFG, "actions_enabled", True)


@pytest.fixture
def actions_propose_mode(monkeypatch):
    monkeypatch.setattr(CFG, "actions_enabled", True)
    monkeypatch.setattr(CFG, "actions_direct", False)


def test_create_proposal_returns_pending_payload(actions_propose_mode):
    payload = create_proposal(
        "propose_create_dashboard",
        CreateDashboardParams(title="Brute force GeoIP", template="brute_force_geoip"),
        EnvPrincipal("lab"),
    )
    assert payload["status"] == "pending"
    assert payload["proposal_id"]
    assert "NOT executed" in payload["note"]
    assert payload["confirm_path"].startswith("/v1/actions/")


def test_confirm_requires_operator_role():
    prop = create_proposal(
        "propose_create_dashboard",
        CreateDashboardParams(title="Test dash", template="brute_force_geoip"),
        User(sub="analyst1", roles=["wazuh_ai_analyst"], raw_jwt="t"),
    )
    user = User(sub="analyst1", roles=["wazuh_ai_analyst"], raw_jwt="t")

    async def _run():
        with pytest.raises(HTTPException) as exc:
            await confirm_proposal(prop["proposal_id"], user, "idem-key-001")
        assert exc.value.status_code == 403

    asyncio.run(_run())


def test_confirm_without_executor_creds_returns_not_configured(monkeypatch):
    from app.env_registry import ENV_REGISTRY, EnvConfig

    monkeypatch.setitem(
        ENV_REGISTRY,
        "lab",
        EnvConfig(
            env_id="lab",
            gateway_key="k",
            indexer_url="https://indexer:9200",
            dashboard_executor_basic="",
        ),
    )
    prop = create_proposal(
        "propose_create_dashboard",
        CreateDashboardParams(title="Test dash", template="brute_force_geoip"),
        User(
            sub="op1",
            roles=["wazuh_ai_analyst", CFG.operator_role],
            raw_jwt="t",
        ),
    )
    user = User(
        sub="op1",
        roles=["wazuh_ai_analyst", CFG.operator_role],
        raw_jwt="t",
    )

    async def _run():
        proposal, result = await confirm_proposal(prop["proposal_id"], user, "idem-key-002")
        assert proposal.status == "confirmed"
        assert result.ok is False
        assert result.status == "not_configured"

    asyncio.run(_run())


def test_confirm_idempotent_replay(monkeypatch):
    from app.actions.schemas import RestartAgentParams
    from app.env_registry import ENV_REGISTRY, EnvConfig

    monkeypatch.setitem(
        ENV_REGISTRY,
        "lab",
        EnvConfig(
            env_id="lab",
            gateway_key="k",
            indexer_url="https://indexer:9200",
            actions_tiers=("dashboard", "manager"),
        ),
    )

    roles = ["wazuh_ai_analyst", CFG.responder_role]
    prop = create_proposal(
        "propose_restart_agent",
        RestartAgentParams(agent_id="001", reason="Agent unresponsive after patch window"),
        User(sub="op1", roles=roles, raw_jwt="t"),
    )
    user = User(sub="op1", roles=roles, raw_jwt="t")

    async def _run():
        _, r1 = await confirm_proposal(prop["proposal_id"], user, "idem-key-003")
        _, r2 = await confirm_proposal(prop["proposal_id"], user, "idem-key-003")
        assert r1.status == r2.status

    asyncio.run(_run())


def test_actions_api_confirm_403_for_analyst():
    prop = create_proposal(
        "propose_create_dashboard",
        CreateDashboardParams(title="API test", template="brute_force_geoip"),
        User(sub="analyst1", roles=["wazuh_ai_analyst"], raw_jwt="t"),
    )
    app.dependency_overrides[verify_jwt] = lambda: User(
        sub="analyst1", roles=["wazuh_ai_analyst"], raw_jwt="t"
    )
    client = TestClient(app)
    r = client.post(
        f"/v1/actions/{prop['proposal_id']}/confirm",
        json={"idempotency_key": "key-api-1"},
    )
    app.dependency_overrides.clear()
    assert r.status_code == 403


def test_actions_api_propose_requires_enabled(monkeypatch):
    monkeypatch.setattr(CFG, "actions_enabled", False)
    app.dependency_overrides[verify_jwt] = lambda: User(
        sub="analyst1", roles=["wazuh_ai_analyst"], raw_jwt="t"
    )
    client = TestClient(app)
    r = client.post(
        "/v1/actions/propose",
        json={
            "action": "create_dashboard",
            "params": {"title": "Disabled test", "template": "brute_force_geoip"},
        },
    )
    app.dependency_overrides.clear()
    assert r.status_code == 503


def test_actions_api_propose_and_confirm(actions_propose_mode, monkeypatch):
    from app.env_registry import EnvConfig, ENV_REGISTRY

    monkeypatch.setitem(
        ENV_REGISTRY,
        "lab",
        EnvConfig(
            env_id="lab",
            gateway_key="k",
            indexer_url="https://indexer:9200",
            dashboard_api_url="https://dashboard:5601",
            dashboard_executor_basic="writer:secret",
        ),
    )

    async def _fake_write(env, objects, cred):
        from app.actions.types import ActionResult

        return ActionResult(
            ok=True,
            status="created",
            message="ok",
            details={"object_id": objects[-1]["id"], "title": "Brute force"},
        )

    monkeypatch.setattr(
        "app.actions.executors._write_saved_objects",
        _fake_write,
    )

    app.dependency_overrides[verify_jwt] = lambda: User(
        sub="op1",
        roles=["wazuh_ai_analyst", CFG.operator_role],
        env_id="lab",
        raw_jwt="t",
    )
    client = TestClient(app)
    r = client.post(
        "/v1/actions/propose",
        json={
            "action": "create_dashboard",
            "params": {
                "title": "Brute force GeoIP",
                "template": "brute_force_geoip",
            },
        },
    )
    assert r.status_code == 200
    pid = r.json()["proposal_id"]
    c = client.post(
        f"/v1/actions/{pid}/confirm",
        json={"idempotency_key": "api-propose-confirm-1"},
    )
    app.dependency_overrides.clear()
    assert c.status_code == 200
    assert c.json()["result"]["ok"] is True


def test_actions_api_propose_executes_when_direct(actions_on, monkeypatch):
    from app.env_registry import EnvConfig, ENV_REGISTRY

    monkeypatch.setattr(CFG, "actions_direct", True)
    monkeypatch.setitem(
        ENV_REGISTRY,
        "lab",
        EnvConfig(
            env_id="lab",
            gateway_key="k",
            indexer_url="https://indexer:9200",
            dashboard_api_url="https://dashboard:5601",
            dashboard_executor_basic="writer:secret",
        ),
    )

    async def _fake_write(env, objects, cred):
        from app.actions.types import ActionResult

        return ActionResult(
            ok=True,
            status="created",
            message="ok",
            details={"object_id": objects[-1]["id"], "title": "Brute force"},
        )

    monkeypatch.setattr(
        "app.actions.executors._write_saved_objects",
        _fake_write,
    )

    app.dependency_overrides[verify_jwt] = lambda: User(
        sub="op1",
        roles=["wazuh_ai_analyst", CFG.operator_role],
        env_id="lab",
        raw_jwt="t",
    )
    client = TestClient(app)
    r = client.post(
        "/v1/actions/propose",
        json={
            "action": "create_dashboard",
            "params": {
                "title": "Brute force GeoIP",
                "template": "brute_force_geoip",
            },
        },
    )
    app.dependency_overrides.clear()
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["status"] == "created"
    assert "proposal_id" not in body


def test_brute_force_geoip_bundle_shape():
    from app.actions.dashboard_templates import build_dashboard_bundle
    from app.actions.fields import FIELD_COUNTRY, FIELD_DST_USER, FIELD_SRC_IP
    from app.actions.schemas import CreateDashboardParams

    objs = build_dashboard_bundle(
        CreateDashboardParams(title="BF test", template="brute_force_geoip")
    )
    assert len(objs) == 6
    types = [o["document"]["type"] for o in objs]
    assert types.count("visualization") == 5
    assert types[-1] == "dashboard"
    bundle = json.dumps(
        [o["document"]["visualization"]["visState"] for o in objs if o["document"]["type"] == "visualization"]
    )
    assert FIELD_COUNTRY in bundle
    assert FIELD_DST_USER in bundle
    assert FIELD_SRC_IP in bundle
    assert ".keyword" not in bundle


def test_actions_api_get_proposal(actions_on):
    prop = create_proposal(
        "propose_create_dashboard",
        CreateDashboardParams(title="View me", template="brute_force_geoip"),
        User(sub="analyst1", roles=["wazuh_ai_analyst"], raw_jwt="t"),
    )
    app.dependency_overrides[verify_jwt] = lambda: User(
        sub="analyst1", roles=["wazuh_ai_analyst"], raw_jwt="t"
    )
    client = TestClient(app)
    r = client.get(f"/v1/actions/{prop['proposal_id']}")
    app.dependency_overrides.clear()
    assert r.status_code == 200
    assert r.json()["preview"]


def test_conversational_no_rejects_pending(actions_propose_mode, monkeypatch):
    from app.loop import _conversational_confirm_events

    monkeypatch.setattr(CFG, "actions_conversational", True)
    user = User(
        sub="op1",
        roles=["wazuh_ai_analyst", CFG.operator_role],
        raw_jwt="t",
        env_id="lab",
    )
    prop = create_proposal(
        "propose_create_dashboard",
        CreateDashboardParams(title="Cancel me", template="brute_force_geoip"),
        user,
        conversation_id="conv-cancel",
    )
    gen = _conversational_confirm_events("no", user, "conv-cancel", 0.0)
    assert gen is not None

    async def _collect():
        out = []
        async for ev in gen:
            out.append(ev)
        return out

    events = asyncio.run(_collect())
    done = next(e for e in events if e["event"] == "done")
    assert "cancel" in done["data"]["verifiability"].casefold()
    from app.actions.proposals import get_proposal

    assert get_proposal(prop["proposal_id"]).status == "rejected"


def test_conversational_yes_ambiguous_lists_proposals(actions_propose_mode, monkeypatch):
    from app.loop import _conversational_confirm_events

    monkeypatch.setattr(CFG, "actions_conversational", True)
    user = User(
        sub="op1",
        roles=["wazuh_ai_analyst", CFG.operator_role],
        raw_jwt="t",
        env_id="lab",
    )
    create_proposal(
        "propose_create_dashboard",
        CreateDashboardParams(title="One", template="brute_force_geoip"),
        user,
        conversation_id="conv-multi",
    )
    create_proposal(
        "propose_create_dashboard",
        CreateDashboardParams(title="Two", template="brute_force_geoip"),
        user,
        conversation_id="conv-multi",
    )
    gen = _conversational_confirm_events("yes", user, "conv-multi", 0.0)
    assert gen is not None

    async def _collect():
        out = []
        async for ev in gen:
            out.append(ev)
        return out

    events = asyncio.run(_collect())
    text = next(e for e in events if e["event"] == "token")["data"]["text"]
    assert "pending" in text.casefold() or "pendientes" in text.casefold()
