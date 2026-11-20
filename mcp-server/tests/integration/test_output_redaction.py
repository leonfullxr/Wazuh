import json
import secrets
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from wazuh_mcp import server
from wazuh_mcp.auth import AuthToken
from wazuh_mcp.clusters import ClusterRegistry
from wazuh_mcp.gcf_format import render_result
from wazuh_mcp.server.output import sanitize_output
from wazuh_mcp.server.sessions import MCPSession


def test_recursive_redaction_and_nonmutation(monkeypatch):
    source = {
        "Password": None,
        "access-token": {"x": "v"},
        "PWD": "/tmp",
        "password_hint": "safe",
        "items": [{"api_key": "secretvalue", "message": 'password="hunter2" Bearer abc123 https://u:p@example.com'}],
    }
    cleaned = sanitize_output(source)
    assert cleaned["Password"] == cleaned["access-token"] == "[REDACTED]"
    assert cleaned["PWD"] == "/tmp" and cleaned["password_hint"] == "safe"
    assert all(secret not in json.dumps(cleaned) for secret in ("secretvalue", "hunter2", "abc123", "u:p"))
    assert source["Password"] is None and source["items"][0]["api_key"] == "secretvalue"
    monkeypatch.setenv("RESPONSE_FORMAT", "json")
    assert json.loads(render_result("Result", source, compact=False).split("\n", 1)[1]) == cleaned


def test_depth_and_opaque_values_are_not_exposed():
    result = sanitize_output({"a": {"b": "secret"}, "opaque": object()}, max_depth=1)
    assert "secret" not in json.dumps(result) and "object at" not in json.dumps(result)


@pytest.mark.asyncio
async def test_resource_and_tool_redaction_and_unexpected_errors(monkeypatch):
    client = type("Client", (), {})()
    client.get_manager_info = AsyncMock(
        return_value={"data": {"client_secret": "sentinel", "note": "token=secretvalue"}}
    )
    client.get_rules_summary = AsyncMock(return_value={"data": {"password": "sentinel"}})
    monkeypatch.setattr(server.state, "cluster_registry", ClusterRegistry({"default": client}, "default", False))
    session = MCPSession("s", None)
    session._auth_token = AuthToken(
        token="t", api_key_id="test", created_at=datetime.now(timezone.utc), scopes=["wazuh:read"]
    )
    request = server.jsonrpc.MCPRequest(
        jsonrpc="2.0", id=1, method="resources/read", params={"uri": "wazuh://manager/info"}
    )
    result = await server.dispatch.process_mcp_request(request, session)
    data = json.loads(result.result["contents"][0]["text"])
    assert data["data"]["client_secret"] == "[REDACTED]" and "secretvalue" not in json.dumps(data)
    tool = await server.tool_calls.handle_tools_call({"name": "get_wazuh_rules_summary"}, session)
    assert "sentinel" not in json.dumps(tool)
    client.get_rules_summary.side_effect = ValueError("opaque-sentinel")
    tool = await server.tool_calls.handle_tools_call({"name": "get_wazuh_rules_summary"}, session)
    assert tool["isError"] and tool["content"][0]["text"] == "Tool execution failed."


def test_gcf_and_json_fallback_encode_same_redacted_value(monkeypatch):
    gcf = pytest.importorskip("gcf")
    sample_value = secrets.token_hex(12)
    sample = {"data": [{"password": sample_value, "note": r"{\"token\":\"two words\"}"}, {"password": None, "note": "ok"}]}
    expected = sanitize_output(sample)
    monkeypatch.setenv("RESPONSE_FORMAT", "gcf")
    encoded = render_result("Result", sample, compact=False).split("\n", 1)[1]
    assert gcf.decode_generic(encoded) == expected
    monkeypatch.setattr(gcf, "encode_generic", lambda _: (_ for _ in ()).throw(ValueError("sentinel")))
    fallback = render_result("Result", sample, compact=False).split("\n", 1)[1]
    assert json.loads(fallback) == expected
    assert "two words" not in fallback and sample_value not in fallback


def test_bounded_unterminated_credentials_and_safe_key_collisions():
    from wazuh_mcp.server.output import _compact_alert

    text = _compact_alert({"full_log": 'password="' + "a" * 400})["full_log"]
    assert "aaaa" not in text
    value = sanitize_output({"token=first": 1, "token=second": 2})
    assert len(value) == 2 and list(value.values()) == [1, 2]
    assert sanitize_output("x" * 100, max_chars=10).startswith("[Truncated")
    assert sanitize_output(float("nan")).startswith("[Truncated")


@pytest.mark.asyncio
async def test_dispatch_does_not_expose_unclassified_value_error(monkeypatch):
    async def failing(params, session):
        raise ValueError("opaque-sensitive-sentinel")

    monkeypatch.setitem(server.dispatch.MCP_METHODS, "resources/list", failing)
    request = server.jsonrpc.MCPRequest(jsonrpc="2.0", id=1, method="resources/list", params={})
    response = await server.dispatch.process_mcp_request(request, MCPSession("s", None))
    assert response.error["code"] == -32602
    assert "sentinel" not in json.dumps(response.error)


def test_empty_nodes_and_encoding_overhead_cannot_break_json_budget():
    from wazuh_mcp.server.output import render_json

    assert len(sanitize_output([{}] * 1000, max_chars=25)) < 30
    payload = render_json({"records": ["\\u0000" * 8] * 10}, max_chars=40)
    assert "Truncated" in json.dumps(json.loads(payload))


def test_safe_scalars_aliases_and_ordinary_prose():
    from datetime import date
    from uuid import UUID

    result = sanitize_output({"secret_key": None, "db_password": 1, "api_token": [], "PWD": "/tmp", "note": "basic authentication and bearer of bad news; pwd=private123", "near": "notpassword=visible db_password=hidden123 secret_key=hidden456 api_token=hidden789" , "date": date(2026, 1, 2), "id": UUID(int=0)})
    assert all(result[k] == "[REDACTED]" for k in ("secret_key", "db_password", "api_token"))
    assert result["PWD"] == "/tmp" and result["near"].startswith("notpassword=visible")
    assert all(value not in result["near"] for value in ("hidden123", "hidden456", "hidden789"))
    assert "basic authentication and bearer of bad news" in result["note"]
    assert "private123" not in result["note"]
    assert result["date"] == "2026-01-02" and result["id"] == str(UUID(int=0))
    assert sanitize_output({3: "numeric", "3": "string", None: "none", True: "bool", 2.5: "float"}) == {"3": "numeric", "3 [2]": "string", "null": "none", "true": "bool", "2.5": "float"}


@pytest.mark.asyncio
async def test_real_rules_summary_survives_tool_resource_and_gcf(monkeypatch):
    from wazuh_mcp.api.wazuh_client import WazuhClient
    from wazuh_mcp.config import WazuhConfig

    client = WazuhClient(WazuhConfig(wazuh_host="localhost", wazuh_user="test", wazuh_pass="test"))
    client._request = AsyncMock(return_value={"data": {"affected_items": [{"level": 3, "groups": ["syslog"]}, {"level": 5, "groups": ["auth"]}], "total_affected_items": 2}})
    monkeypatch.setattr(server.state, "cluster_registry", ClusterRegistry({"default": client}, "default", False))
    session = MCPSession("s", None)
    session._auth_token = AuthToken(token="t", api_key_id="test", created_at=datetime.now(timezone.utc), scopes=["wazuh:read"])
    tool = await server.tool_calls.handle_tools_call({"name": "get_wazuh_rules_summary"}, session)
    assert json.loads(tool["content"][0]["text"].split("\n", 1)[1])["data"]["by_level"] == {"3": 1, "5": 1}
    request = server.jsonrpc.MCPRequest(jsonrpc="2.0", id=1, method="resources/read", params={"uri": "wazuh://rules/summary"})
    resource = await server.dispatch.process_mcp_request(request, session)
    assert json.loads(resource.result["contents"][0]["text"])["data"]["by_level"] == {"3": 1, "5": 1}
    gcf = pytest.importorskip("gcf")
    monkeypatch.setenv("RESPONSE_FORMAT", "gcf")
    encoded = render_result("Rules", await client.get_rules_summary(), compact=True).split("\n", 1)[1]
    assert gcf.decode_generic(encoded)["data"]["by_level"] == {"3": 1, "5": 1}


def test_standalone_all_letter_credentials_and_prose():
    from wazuh_mcp.server.output import _sanitize_output_text

    text = _sanitize_output_text("Bearer abcdefgh Basic eHlz; basic authentication and bearer of bad news")
    assert "abcdefgh" not in text and "eHlz" not in text
    assert "basic authentication and bearer of bad news" in text
    assert "authentication" not in _sanitize_output_text("Authorization: Basic authentication")


def test_credential_prefixes_in_text_and_structured_keys():
    from wazuh_mcp.server.output import _sanitize_output_text

    text = "--password=one --token=two user_password=three MYSQL_ROOT_PASSWORD=four X-Auth-Token: five notpassword=visible"
    redacted = _sanitize_output_text(text)
    assert all(value not in redacted for value in ("one", "two", "three", "four", "five"))
    assert "notpassword=visible" in redacted
    result = sanitize_output({"user_password": "one", "AWS_SESSION_TOKEN": "two", "X-Auth-Token": "three", "PWD": "/tmp", "notpassword": "visible", "password_hint": "also visible", "user_pwd": "four"})
    assert all(result[k] == "[REDACTED]" for k in ("user_password", "AWS_SESSION_TOKEN", "X-Auth-Token", "user_pwd"))
    assert result["PWD"] == "/tmp" and result["notpassword"] == "visible" and result["password_hint"] == "also visible"
    long_key = "x_" * 10000 + "PASSWORD"
    assert sanitize_output({long_key: "secret"})[long_key] == "[REDACTED]"


def test_dotted_camelcase_and_separate_flags():
    from wazuh_mcp.server.output import _sanitize_output_text

    value = sanitize_output({"opensearch.password": "one", "adminPassword": "two", "authToken": "three", "PWD": "/tmp", "password_hint": "safe"})
    assert all(value[k] == "[REDACTED]" for k in ("opensearch.password", "adminPassword", "authToken"))
    assert value["PWD"] == "/tmp" and value["password_hint"] == "safe"
    text = _sanitize_output_text("--password abcdef --token 'other value' --api-key=hello notpassword=visible")
    assert all(x not in text for x in ("abcdef", "other value", "hello"))
    assert "notpassword=visible" in text
    sample_value = secrets.token_hex(12)
    assert _sanitize_output_text(f"--password --token {sample_value}") == "--password --token [REDACTED]"
