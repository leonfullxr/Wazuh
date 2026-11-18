"""Local browser authentication and bootstrap boundary regressions."""

from __future__ import annotations

from collections.abc import Callable
from http.cookies import SimpleCookie
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ai_soc.local.app import create_local_app
from ai_soc.workspace.runtime import LabAssessmentSettings, PipelineConfig, PipelineSite

ORIGIN = "http://127.0.0.1:8123"
OWNER_KEY = "a" * 64
SESSION_COOKIE = "__Host-soc-session"
CSRF_COOKIE = "__Host-soc-csrf"


def _config(tmp_path: Path, *, model_enabled: bool = False) -> PipelineConfig:
    assessment = (
        LabAssessmentSettings(
            enabled=True,
            base_url="http://127.0.0.1:11434/v1",
            model="local-test-model",
            credential_file=tmp_path / "model-credential",
        )
        if model_enabled
        else None
    )
    return PipelineConfig(
        database_env_file=tmp_path / "database.env",
        sites=(
            PipelineSite(
                site_id="local-site",
                label="Local site",
                wazuh_version="4.14.7",
                indexer_url="https://indexer.invalid",
                ca_file=tmp_path / "indexer-ca.pem",
                credential_file=tmp_path / "indexer-credential.json",
                expected_roles=("read-only",),
                full_visibility_attestation="owner-qualified full visibility",
                lab_assessment=assessment,
            ),
        ),
    )


def _forbidden_dsn() -> str:
    raise AssertionError("local authentication and bootstrap must not open the workspace database")


def _app(
    tmp_path: Path,
    *,
    model_enabled: bool = False,
    dsn: Callable[[], str] = _forbidden_dsn,
):
    assets = tmp_path / "assets"
    assets.mkdir(exist_ok=True)
    (assets / "index.html").write_text("<h1>Local AI SOC</h1>")
    return create_local_app(
        _config(tmp_path, model_enabled=model_enabled),
        dsn=dsn,
        origin=ORIGIN,
        key=OWNER_KEY,
        secret=b"local-test-secret-material-32-bytes",
        assets=assets,
    )


def _client(app, *, peer: str = "127.0.0.1") -> TestClient:
    return TestClient(app, base_url=ORIGIN, client=(peer, 12345))


def _login(client: TestClient) -> str:
    response = client.post(
        "/v1/local/session",
        json={"key": OWNER_KEY},
        headers={"Origin": ORIGIN},
    )
    assert response.status_code == 204
    return response.cookies[SESSION_COOKIE]


def _cookie_header(session: str) -> dict[str, str]:
    # The production cookie is Secure. HTTP TestClient correctly retains it but
    # does not send it, so the loopback-browser contract is exercised explicitly.
    return {"Cookie": f"{SESSION_COOKIE}={session}"}


def _set_cookie(response, name: str):
    parsed = SimpleCookie()
    for value in response.headers.get_list("set-cookie"):
        parsed.load(value)
    return parsed[name]


@pytest.mark.parametrize("model_enabled", [False, True])
def test_public_session_status_discloses_only_auth_and_model_switch(
    tmp_path: Path, model_enabled: bool
) -> None:
    with _client(_app(tmp_path, model_enabled=model_enabled)) as client:
        response = client.get("/v1/local/session")

    assert response.status_code == 200
    assert response.json() == {
        "authenticated": False,
        "model_enabled": model_enabled,
    }
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("path", ["/v1/bootstrap", "/v1/workspace/sites"])
def test_application_routes_require_local_session_before_workspace_access(
    tmp_path: Path, path: str
) -> None:
    with _client(_app(tmp_path)) as client:
        response = client.get(path)

    assert response.status_code == 401
    assert SESSION_COOKIE not in response.headers.get("set-cookie", "")


def test_owner_key_exchange_sets_bounded_host_cookie_without_echoing_key(tmp_path: Path) -> None:
    with _client(_app(tmp_path)) as client:
        response = client.post(
            "/v1/local/session",
            json={"key": OWNER_KEY},
            headers={"Origin": ORIGIN},
        )

    assert response.status_code == 204
    cookie = _set_cookie(response, SESSION_COOKIE)
    assert cookie.value
    assert cookie.value != OWNER_KEY
    assert cookie["secure"]
    assert cookie["httponly"]
    assert cookie["samesite"].lower() == "strict"
    assert cookie["path"] == "/"
    assert not cookie["domain"]
    assert OWNER_KEY not in response.headers.get("set-cookie", "")
    assert OWNER_KEY not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_wrong_owner_key_is_denied_without_issuing_a_session(tmp_path: Path) -> None:
    with _client(_app(tmp_path)) as client:
        response = client.post(
            "/v1/local/session",
            json={"key": "wrong-owner-key"},
            headers={"Origin": ORIGIN},
        )

    assert response.status_code == 401
    assert SESSION_COOKIE not in response.headers.get("set-cookie", "")


def test_foreign_origin_cannot_exchange_the_owner_key(tmp_path: Path) -> None:
    with _client(_app(tmp_path)) as client:
        response = client.post(
            "/v1/local/session",
            json={"key": OWNER_KEY},
            headers={"Origin": "http://attacker.invalid"},
        )

    assert response.status_code == 403
    assert SESSION_COOKIE not in response.headers.get("set-cookie", "")


@pytest.mark.parametrize(
    ("base_url", "peer"),
    [
        ("http://localhost:8123", "127.0.0.1"),
        ("http://127.0.0.1:8124", "127.0.0.1"),
        (ORIGIN, "192.0.2.10"),
    ],
)
def test_session_boundary_requires_exact_numeric_authority_and_loopback_peer(
    tmp_path: Path, base_url: str, peer: str
) -> None:
    app = _app(tmp_path)
    with TestClient(app, base_url=base_url, client=(peer, 12345)) as client:
        response = client.get("/v1/local/session")

    assert response.status_code == 403


def test_authenticated_session_reuses_bootstrap_and_principal_bound_csrf(tmp_path: Path) -> None:
    with _client(_app(tmp_path)) as client:
        session = _login(client)
        status = client.get("/v1/local/session", headers=_cookie_header(session))
        bootstrap = client.get("/v1/bootstrap", headers=_cookie_header(session))

    assert status.status_code == 200
    assert status.json() == {"authenticated": True, "model_enabled": False}
    assert bootstrap.status_code == 200
    body = bootstrap.json()
    assert body["mode"] == "local"
    assert body["provenance"] is None
    assert isinstance(body["csrf_token"], str) and body["csrf_token"]
    csrf = _set_cookie(bootstrap, CSRF_COOKIE)
    assert csrf.value
    assert csrf["secure"]
    assert csrf["httponly"]
    assert csrf["samesite"].lower() == "strict"
    assert bootstrap.headers["cache-control"] == "no-store"


def test_logout_requires_exact_origin_and_revokes_the_opaque_session(tmp_path: Path) -> None:
    with _client(_app(tmp_path)) as client:
        session = _login(client)
        foreign = client.delete(
            "/v1/local/session",
            headers={**_cookie_header(session), "Origin": "http://attacker.invalid"},
        )
        still_authenticated = client.get("/v1/local/session", headers=_cookie_header(session))
        logout = client.delete(
            "/v1/local/session",
            headers={**_cookie_header(session), "Origin": ORIGIN},
        )
        after = client.get("/v1/local/session", headers=_cookie_header(session))

    assert foreign.status_code == 403
    assert still_authenticated.json()["authenticated"] is True
    assert logout.status_code == 204
    assert after.status_code == 200
    assert after.json()["authenticated"] is False


def test_process_restart_invalidates_an_existing_session(tmp_path: Path) -> None:
    first = _app(tmp_path)
    with _client(first) as client:
        session = _login(client)
        assert (
            client.get("/v1/local/session", headers=_cookie_header(session)).json()["authenticated"]
            is True
        )

    restarted = _app(tmp_path)
    with _client(restarted) as client:
        response = client.get("/v1/local/session", headers=_cookie_header(session))

    assert response.status_code == 200
    assert response.json() == {"authenticated": False, "model_enabled": False}
