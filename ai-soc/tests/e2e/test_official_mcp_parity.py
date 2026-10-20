from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from http.cookies import SimpleCookie
from pathlib import Path

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = ROOT / "tests/e2e"
G053_FIXTURE = ROOT / "tests/unit/application/data/g053_provider_token_cases.json"
G053_FIXTURE_SHA256 = "21598a271610d1986d7a575aad0ebf96289e19c9bbb57dc5b7a46c518a386e19"


def _parity_projection(value: object, path: str = "$") -> object:
    request_scoped = {
        "question_id",
        "followup_id",
        "trace_id",
        "feedback_receipt",
        "evidence_id",
        "evidence_ids",
        "scope_hash",
        "snapshot_key",
    }
    if isinstance(value, dict):
        return {
            key: _parity_projection(item, f"{path}.{key}")
            for key, item in value.items()
            if key not in request_scoped and not (key == "key" and path.endswith(".snapshot"))
        }
    if isinstance(value, list):
        return [_parity_projection(item, f"{path}[{index}]") for index, item in enumerate(value)]
    return value


def _parity_differences(left: object, right: object, path: str = "$") -> list[str]:
    if isinstance(left, dict) and isinstance(right, dict):
        differences: list[str] = []
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                differences.append(f"{path}.{key}: missing on one edge")
            else:
                differences.extend(_parity_differences(left[key], right[key], f"{path}.{key}"))
        return differences
    if isinstance(left, list) and isinstance(right, list):
        if len(left) != len(right):
            return [f"{path}: list lengths differ ({len(left)} != {len(right)})"]
        return [
            difference
            for index, (left_item, right_item) in enumerate(zip(left, right, strict=True))
            for difference in _parity_differences(left_item, right_item, f"{path}[{index}]")
        ]
    return [] if left == right else [f"{path}: {left!r} != {right!r}"]


@pytest.fixture(scope="module")
def fixture_service() -> Iterator[str]:
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    base_url = f"http://127.0.0.1:{port}"
    environment = os.environ.copy()
    environment["SOC_FIXTURE_ORIGIN"] = base_url
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "fixture_server:app",
            "--app-dir",
            str(FIXTURE_DIR),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=ROOT,
        env=environment,
        stdout=None,
        stderr=None,
    )
    try:
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError("fixture Uvicorn process exited before readiness")
            try:
                response = httpx.get(f"{base_url}/health/live", timeout=0.25)
            except httpx.HTTPError:
                time.sleep(0.05)
                continue
            if response.status_code == 200:
                break
        else:
            raise RuntimeError("fixture Uvicorn server did not become ready")
        yield base_url
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


@pytest.mark.parametrize("variant", ["positive", "negative", "boundary", "failure"])
@pytest.mark.asyncio
async def test_official_mcp_client_matches_actual_application_rest_answer(
    fixture_service: str,
    variant: str,
    record_property: Callable[[str, str], None],
) -> None:
    fixture = json.loads(G053_FIXTURE.read_text(encoding="utf-8"))
    assert hashlib.sha256(G053_FIXTURE.read_bytes()).hexdigest() == G053_FIXTURE_SHA256
    scenario = fixture["cases"][variant]
    record_property("acceptance_ids", "G053")
    record_property("case_id", "B5-G053.provider-token-application")
    record_property("variant", variant)
    record_property("fixture_sha256", G053_FIXTURE_SHA256)
    async with httpx.AsyncClient(base_url=fixture_service, timeout=5) as rest:
        bootstrap = await rest.get(
            "/v1/bootstrap", headers={"X-SOC-Fixture-Token": "fixture-browser-token"}
        )
        assert bootstrap.status_code == 200
        cookie = SimpleCookie()
        cookie.load(bootstrap.headers["set-cookie"])
        csrf_cookie = cookie["__Host-soc-csrf"].value
        request = {"question": f"g053:{variant}", "environment_id": "alpha"}
        answer = await rest.post(
            "/v1/questions",
            json=request,
            headers={
                "X-SOC-Fixture-Token": "fixture-browser-token",
                "X-SOC-CSRF": bootstrap.json()["csrf_token"],
                "Cookie": f"__Host-soc-csrf={csrf_cookie}",
                "Origin": fixture_service,
            },
        )
        assert answer.status_code == 200
        expected = answer.json()
        assert fixture["hostile_first_token"] not in answer.text
        assert "PRIVATE-CONVERSE-TIMEOUT:" not in answer.text

    async with httpx.AsyncClient(
        headers={
            "Authorization": "Bearer fixture-mcp-token",
            "Origin": fixture_service,
        },
        timeout=5,
    ) as mcp_http:
        async with streamable_http_client(f"{fixture_service}/mcp", http_client=mcp_http) as (
            read_stream,
            write_stream,
            _session_id,
        ):
            async with ClientSession(read_stream, write_stream) as session:
                initialized = await session.initialize()
                assert initialized.protocolVersion == "2025-11-25"
                tools = await session.list_tools()
                assert {tool.name for tool in tools.tools} == {
                    "soc_ask",
                    "soc_page",
                    "soc_feedback",
                }
                result = await session.call_tool(
                    "soc_ask",
                    {"request": request},
                )

    assert result.isError is not True
    actual = result.structuredContent
    assert isinstance(actual, dict)
    actual_text = json.dumps(actual, sort_keys=True)
    assert fixture["hostile_first_token"] not in actual_text
    assert "PRIVATE-CONVERSE-TIMEOUT:" not in actual_text
    differences = _parity_differences(_parity_projection(actual), _parity_projection(expected))
    assert not differences, "\n".join(differences[:30])
    vpn = next(block for block in actual["blocks"] if block["topic_id"] == "vpn")
    assert vpn["judgment"]["state"] == scenario["expected_judgment_state"]
