"""
OAuth authorization now requires the user to log in with an API key.

/oauth/authorize must not auto-approve every request, or anyone who could reach the server would get
a wazuh:read wazuh:write token. These tests drive the real router over HTTP: the login form,
key-bounded scopes, per-user token identity, and refresh-replay revoking one grant only.
"""

import base64
import hashlib
import secrets
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi import FastAPI

from wazuh_mcp import auth
from wazuh_mcp.oauth import OAuthManager, create_oauth_router

REDIRECT = "https://claude.ai/api/mcp/auth_callback"


@pytest.fixture
def env(monkeypatch):
    mgr = OAuthManager(
        SimpleNamespace(
            AUTH_SECRET_KEY="test-secret-key-at-least-32-characters-long",
            OAUTH_ENABLE_DCR=True,
            OAUTH_ACCESS_TOKEN_TTL=3600,
            OAUTH_REFRESH_TOKEN_TTL=86400,
            OAUTH_AUTHORIZATION_CODE_TTL=600,
            OAUTH_ISSUER_URL="https://mcp.example",
        )
    )
    keys = auth.AuthManager()
    keys.api_keys = {}  # only the two keys below
    monkeypatch.setattr(auth, "auth_manager", keys)
    reader = keys.create_api_key("reader", scopes=["wazuh:read"])
    writer = keys.create_api_key("writer", scopes=["wazuh:read", "wazuh:write"])
    app = FastAPI()
    app.include_router(create_oauth_router(mgr))
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://mcp.example")
    return SimpleNamespace(mgr=mgr, client=client, reader=reader, writer=writer, keys=keys)


def _pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _params(challenge, scope="wazuh:read wazuh:write"):
    return {
        "response_type": "code",
        "client_id": "claude-desktop",
        "redirect_uri": REDIRECT,
        "scope": scope,
        "state": "s1",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }


async def _login(env, api_key, scope="wazuh:read wazuh:write"):
    verifier, challenge = _pkce()
    r = await env.client.post("/oauth/authorize", data={**_params(challenge, scope), "api_key": api_key})
    if r.status_code != 303:
        return r, None
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    tokens = (
        await env.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": "claude-desktop",
                "redirect_uri": REDIRECT,
                "code_verifier": verifier,
            },
        )
    ).json()
    return r, tokens


class TestNoAnonymousGrant:
    @pytest.mark.asyncio
    async def test_authorize_shows_login_instead_of_issuing_a_code(self, env):
        _, challenge = _pkce()
        r = await env.client.get("/oauth/authorize", params=_params(challenge))
        assert r.status_code == 200
        assert "location" not in r.headers
        assert 'name="api_key"' in r.text
        assert r.headers["x-frame-options"] == "DENY"
        assert "no-store" in r.headers["cache-control"]
        assert not env.mgr.authorization_codes

    @pytest.mark.asyncio
    async def test_bad_key_gets_no_code(self, env):
        r, tokens = await _login(env, "wazuh_" + "x" * 43)
        assert r.status_code == 401 and tokens is None
        assert not env.mgr.authorization_codes

    @pytest.mark.asyncio
    async def test_unregistered_redirect_is_not_followed(self, env):
        _, challenge = _pkce()
        params = {**_params(challenge), "redirect_uri": "https://evil.example/cb", "api_key": env.writer}
        r = await env.client.post("/oauth/authorize", data=params)
        assert r.status_code == 400 and "location" not in r.headers

    @pytest.mark.asyncio
    async def test_login_form_escapes_reflected_input(self, env):
        _, challenge = _pkce()
        r = await env.client.get("/oauth/authorize", params={**_params(challenge), "state": '"><script>x</script>'})
        assert "<script>x" not in r.text


class TestKeyBoundScopes:
    @pytest.mark.asyncio
    async def test_read_key_cannot_obtain_write(self, env):
        r, tokens = await _login(env, env.reader, scope="wazuh:read wazuh:write")
        assert r.status_code == 303
        assert tokens["scope"] == "wazuh:read"

    @pytest.mark.asyncio
    async def test_write_key_gets_write_and_its_identity(self, env):
        _, tokens = await _login(env, env.writer)
        assert tokens["scope"] == "wazuh:read wazuh:write"
        token = env.mgr.validate_access_token(tokens["access_token"])
        writer_id = env.keys.validate_api_key(env.writer).id
        assert token.subject == writer_id

    @pytest.mark.asyncio
    async def test_identity_survives_refresh(self, env):
        _, tokens = await _login(env, env.writer)
        refreshed = env.mgr.refresh_access_token(tokens["refresh_token"], "claude-desktop")
        token = env.mgr.validate_access_token(refreshed["access_token"])
        assert token.subject == env.keys.validate_api_key(env.writer).id


class TestReplayRevokesOneGrant:
    @pytest.mark.asyncio
    async def test_one_users_replay_does_not_log_out_others(self, env):
        _, alice = await _login(env, env.reader)
        _, bob = await _login(env, env.writer)
        bob_rotated = env.mgr.refresh_access_token(bob["refresh_token"], "claude-desktop")
        with pytest.raises(ValueError, match="invalid_grant"):
            env.mgr.refresh_access_token(bob["refresh_token"], "claude-desktop")  # replay

        # Bob's grant is burned...
        assert env.mgr.validate_access_token(bob_rotated["access_token"]) is None
        with pytest.raises(ValueError):
            env.mgr.refresh_access_token(bob_rotated["refresh_token"], "claude-desktop")
        # ...Alice, on the same shared public client, is untouched
        assert env.mgr.validate_access_token(alice["access_token"]) is not None
        assert env.mgr.refresh_access_token(alice["refresh_token"], "claude-desktop")["access_token"]


class TestDcrInputs:
    @pytest.mark.parametrize(
        "extra",
        [{"grant_types": ["password"]}, {"grant_types": ["client_credentials"]}, {"token_endpoint_auth_method": "x"}],
    )
    def test_unsupported_dcr_inputs_rejected(self, env, extra):
        with pytest.raises(ValueError):
            env.mgr.register_client({"redirect_uris": [REDIRECT], **extra})


@pytest.mark.asyncio
@pytest.mark.parametrize("redirect", ["https://client.example/cb?x=a%2Fb&x=two", "https://client.example/cb?", "https://client.example/cb?x=1&"])
async def test_redirect_query_preserved_and_exact_exchange(env, redirect):
    env.mgr.clients["claude-desktop"].redirect_uris.append(redirect)
    verifier, challenge = _pkce()
    params = {**_params(challenge), "redirect_uri": redirect, "api_key": env.writer}
    response = await env.client.post("/oauth/authorize", data=params)
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith(redirect)
    query = parse_qs(urlparse(location).query)
    assert len(query["code"]) == len(query["iss"]) == len(query["state"]) == 1
    code = query["code"][0]
    tokens = env.mgr.exchange_code_for_tokens(code, "claude-desktop", redirect, verifier)
    assert tokens["access_token"]
    response = await env.client.post("/oauth/authorize", data=params)
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
    with pytest.raises(ValueError, match="invalid_grant"):
        env.mgr.exchange_code_for_tokens(code, "claude-desktop", redirect + "x", verifier)
    response = await env.client.post("/oauth/authorize", data={**params, "code_challenge_method": "plain"})
    assert response.status_code == 303
    assert response.headers["location"].startswith(redirect)
    assert parse_qs(urlparse(response.headers["location"]).query)["error"] == ["invalid_request"]


@pytest.mark.asyncio
@pytest.mark.parametrize("query", ["%63ode=x", "StAtE", "x=1&ERROR_URI=x", "x=1&x=2&iss=x"])
async def test_reserved_redirect_keys_rejected_at_registration_and_authorization(env, query):
    redirect = "https://client.example/cb?" + query
    registration = await env.client.post("/oauth/register", json={"redirect_uris": [redirect]})
    assert registration.status_code == 400
    assert registration.json()["error"] == "invalid_redirect_uri"
    env.mgr.clients["claude-desktop"].redirect_uris.append(redirect)
    _, challenge = _pkce()
    response = await env.client.post("/oauth/authorize", data={**_params(challenge), "redirect_uri": redirect, "api_key": env.writer})
    assert response.status_code == 400 and "location" not in response.headers


@pytest.mark.asyncio
async def test_consent_page_names_scopes_and_can_deny(env):
    _, challenge = _pkce()
    page = await env.client.get("/oauth/authorize", params=_params(challenge))
    assert page.status_code == 200
    assert 'name="decision" value="deny"' in page.text
    assert "wazuh:write" in page.text
    assert "active responses" in page.text
    assert "claude.ai" in page.text
    assert "color-scheme: light dark" in page.text
    assert "align-items: safe center" in page.text
    denied = await env.client.post(
        "/oauth/authorize", data={**_params(challenge), "decision": "deny"}
    )
    assert denied.status_code == 303
    query = parse_qs(urlparse(denied.headers["location"]).query)
    assert query["error"] == ["access_denied"]
    assert query["state"] == ["s1"]
    assert "code" not in query
    assert not env.mgr.authorization_codes


@pytest.mark.asyncio
async def test_unknown_client_is_html_for_browsers(env):
    _, challenge = _pkce()
    params = {**_params(challenge), "client_id": '"><script>alert(1)</script>'}
    page = await env.client.get("/oauth/authorize", params=params, headers={"Accept": "text/html"})
    assert page.status_code == 401
    assert page.headers["content-type"].startswith("text/html")
    assert "<script>alert" not in page.text
    assert "not recognized" in page.text
    api = await env.client.get("/oauth/authorize", params=params)
    assert api.status_code == 401
    assert api.json()["error"] == "invalid_client"
