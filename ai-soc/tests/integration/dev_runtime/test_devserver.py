from __future__ import annotations

import asyncio
import base64
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from ai_soc import devserver
from ai_soc.content import builder

REPO = Path(__file__).resolve().parents[3]
DEMO = REPO / "examples" / "content-seed" / "run_fixture_demo.py"
LDAP_QUESTION = "LDAP is not working. Recommend what to check next."
LIVE_CASES = (
    ("SOC_SERVICE_CONFIG_PATH", "/unused/service.json"),
    ("SOC_SERVICE_CONFIG_JSON", "synthetic-live-value"),
    ("AWS_ACCESS_KEY_ID", "synthetic-live-value"),
    ("AWS_SECRET_ACCESS_KEY", "synthetic-live-value"),
    ("AWS_SESSION_TOKEN", "synthetic-live-value"),
    ("AWS_PROFILE", "synthetic-live-value"),
    ("AWS_WEB_IDENTITY_TOKEN_FILE", "/unused/token"),
    ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/unused"),
    ("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://127.0.0.1:9/unused"),
    ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:9"),
    ("SOC_INDEXER_ENDPOINT_URL", "https://indexer.example.test"),
    ("SOC_MODE", "synthetic-live-value"),
)


def _env() -> dict[str, str]:
    return {
        "PATH": f"{Path(sys.executable).parent}{os.pathsep}{os.environ['PATH']}",
        "PYTHONPATH": str(REPO / "src"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
    }


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _launch(
    pack: Path, credentials: Path, port: int, log: Path, **environment: str
) -> subprocess.Popen[str]:
    with log.open("w", encoding="utf-8") as handle:
        return subprocess.Popen(
            [
                sys.executable,
                "-m",
                "ai_soc.devserver",
                "--pack",
                str(pack),
                "--credentials",
                str(credentials),
                "--port",
                str(port),
            ],
            cwd=REPO,
            env={**_env(), **environment},
            stdout=handle,
            stderr=subprocess.STDOUT,
            text=True,
        )


def _wait_ready(port: int, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if process.poll() is not None:
            pytest.fail(f"synthetic server exited early with status {process.returncode}")
        try:
            if httpx.get(f"http://127.0.0.1:{port}/health/ready", timeout=1).status_code == 200:
                return
        except httpx.TransportError:
            pass
        time.sleep(0.2)
    pytest.fail("synthetic server did not become ready")


def _stop(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.kill()
        process.wait(timeout=10)


def _exit_status(process: subprocess.Popen[str]) -> int:
    try:
        return process.wait(timeout=30)
    finally:
        _stop(process)


def _refused(port: int) -> None:
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=1).close()


def _run_refusal(
    pack: Path, credentials: Path, log: Path, **environment: str
) -> subprocess.Popen[str]:
    port = _free_port()
    process = _launch(pack, credentials, port, log, **environment)
    assert _exit_status(process) == 2
    _refused(port)
    assert not credentials.exists()
    return process


@pytest.fixture(scope="module")
def prepared() -> Iterator[Path]:
    work = REPO / "build" / f"dev-runtime-test-{uuid.uuid4().hex}"
    result = subprocess.run(
        [sys.executable, str(DEMO), "--work-dir", str(work)],
        cwd=REPO,
        env=_env(),
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    try:
        yield work
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_fixture_server_serves_rest_and_mcp_over_http(prepared: Path) -> None:
    port = _free_port()
    credentials = prepared / "credentials-flow.json"
    process = _launch(prepared / "build-a", credentials, port, prepared / "flow.log")
    try:
        _wait_ready(port, process)
        values = json.loads(credentials.read_text(encoding="utf-8"))
        assert sorted(values) == sorted(
            [
                "alb_assertion",
                "alb_header_name",
                "base_url",
                "browser_origin",
                "expires_at",
                "mcp_bearer",
                "mcp_origin",
                "mcp_url",
                "principal_sub",
            ]
        )
        assert values["principal_sub"] == "synthetic-analyst"
        identity = {
            values["alb_header_name"]: values["alb_assertion"],
            "Origin": values["browser_origin"],
        }
        with httpx.Client(base_url=values["base_url"], headers=identity, timeout=60) as client:
            bootstrap = client.get("/v1/bootstrap")
            assert bootstrap.status_code == 200
            cookie = bootstrap.headers["set-cookie"].split(";", 1)[0]
            guarded: dict[str, str] = {
                "Cookie": cookie,
                "x-soc-csrf": bootstrap.json()["csrf_token"],
            }
            question = {
                "question": LDAP_QUESTION,
                "environment_id": "synthetic",
                "timezone": "UTC",
                "model_id": "synthetic-model",
            }
            answer_response = client.post("/v1/questions", headers=guarded, json=question)
            assert answer_response.status_code == 200
            answer: dict[str, Any] = answer_response.json()
            block = answer["blocks"][0]
            assert block["topic_id"] == "ldap"
            assert block["tables"][0]["count"]["value"] == 2
            assert block["judgment"]["state"] == "validated"
            assert "2" in block["judgment"]["sentences"][0]["text"]
            for example_question, expected_topic in (
                ("Investigate authentication review.", "auth_review"),
                ("Investiga revision de vulnerabilidades.", "vuln_review"),
            ):
                example_response = client.post(
                    "/v1/questions",
                    headers=guarded,
                    json={**question, "question": example_question},
                )
                assert example_response.status_code == 200
                example_block = example_response.json()["blocks"][0]
                assert example_block["topic_id"] == expected_topic
                assert example_block["checks"]
                assert all(item["outcome"] != "denied" for item in example_block["checks"])
                if expected_topic == "auth_review":
                    outcomes = {
                        item["check_id"]: item["outcome"] for item in example_block["checks"]
                    }
                    assert outcomes["auth_recency"] == "passed"
                if expected_topic == "vuln_review":
                    assert example_block["tables"][0]["rows"]
            feedback = {
                "question_id": answer["question_id"],
                "environment_id": "synthetic",
                "feedback_receipt": answer["feedback_receipt"],
                "kind": "wrong",
            }
            for _ in range(2):
                assert (
                    client.post("/v1/feedback", headers=guarded, json=feedback).status_code == 202
                )
            assert (
                client.post("/v1/questions", headers={"Cookie": cookie}, json=question).status_code
                == 403
            )
            anonymous = httpx.post(f"{values['base_url']}/v1/questions", json=question, timeout=10)
            assert anonymous.status_code in (401, 403)

        mcp_headers = {
            "Authorization": f"Bearer {values['mcp_bearer']}",
            "Origin": values["mcp_origin"],
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        initialized = httpx.post(
            values["mcp_url"],
            headers=mcp_headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "devserver-test", "version": "1"},
                },
            },
            timeout=60,
        )
        assert initialized.status_code == 200
        called = httpx.post(
            values["mcp_url"],
            headers=mcp_headers,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "soc_ask",
                    "arguments": {
                        "request": {
                            "question": LDAP_QUESTION,
                            "environment_id": "synthetic",
                            "model_id": "synthetic-model",
                        }
                    },
                },
            },
            timeout=60,
        )
        assert called.status_code == 200
        result = called.json()["result"]
        assert result.get("isError") is not True
        mcp_answer = json.loads(result["content"][0]["text"])
        assert mcp_answer["blocks"][0]["topic_id"] == "ldap"

        process.send_signal(signal.SIGINT)
        assert process.wait(timeout=15) == 0
        assert not credentials.exists()
    finally:
        _stop(process)


@pytest.mark.parametrize(("name", "value"), LIVE_CASES)
def test_live_or_cloud_environment_is_refused_before_binding(
    prepared: Path, name: str, value: str
) -> None:
    credentials = prepared / f"credentials-{name}.json"
    process = _run_refusal(
        prepared / "build-a", credentials, prepared / f"refusal-{name}.log", **{name: value}
    )
    message = (prepared / f"refusal-{name}.log").read_text(encoding="utf-8")
    assert process.returncode == 2
    assert f"ERROR: refusing live configuration in {name}" in message
    assert value not in message


def test_existing_credentials_file_is_never_overwritten(prepared: Path) -> None:
    credentials = prepared / "credentials-existing.json"
    credentials.write_text("keep\n", encoding="utf-8")
    try:
        port = _free_port()
        process = _launch(prepared / "build-a", credentials, port, prepared / "existing.log")
        assert _exit_status(process) == 2
        _refused(port)
        assert credentials.read_text(encoding="utf-8") == "keep\n"
        assert "credentials file already exists" in (prepared / "existing.log").read_text(
            encoding="utf-8"
        )
    finally:
        credentials.unlink(missing_ok=True)


@pytest.mark.parametrize("port", [0, 65536])
def test_port_outside_the_loopback_range_is_refused(prepared: Path, port: int) -> None:
    credentials = prepared / f"credentials-port-{port}.json"
    process = _launch(prepared / "build-a", credentials, port, prepared / f"port-{port}.log")
    assert _exit_status(process) == 2
    assert "--port must be between 1 and 65535" in (prepared / f"port-{port}.log").read_text(
        encoding="utf-8"
    )
    assert not credentials.exists()


def _copy_pack(prepared: Path, name: str) -> Path:
    pack = prepared / name
    shutil.copytree(prepared / "build-a", pack)
    for item in pack.rglob("*"):
        item.chmod(0o644 if item.is_file() else 0o755)
    return pack


def _rewrite_provenance(pack: Path, **changes: str) -> None:
    provenance = json.loads((pack / "provenance.json").read_text(encoding="utf-8"))
    provenance.update(changes)
    (pack / "provenance.json").write_text(json.dumps(provenance), encoding="utf-8")


def _skip_pack_verifiers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub both verifier entry points so the devserver's own provenance guards are what runs."""

    def accept(pack: Path, contract_version: str = "1") -> None:
        return None

    monkeypatch.setattr(devserver, "verify_content_pack", accept)
    monkeypatch.setattr(builder, "verify_content_pack", accept)


@pytest.mark.parametrize("mutation", ["provenance-content", "provenance-mode", "manifest-file"])
def test_tampered_pack_is_refused_before_binding(prepared: Path, mutation: str) -> None:
    pack = _copy_pack(prepared, f"tampered-{mutation}")
    try:
        if mutation == "manifest-file":
            topic = pack / "pack" / "topics" / "ldap.json"
            topic.write_bytes(topic.read_bytes() + b" ")
        else:
            provenance = json.loads((pack / "provenance.json").read_text(encoding="utf-8"))
            if mutation == "provenance-content":
                provenance["content_sha"] = "0" * 40
            else:
                provenance["mode"] = "live"
            (pack / "provenance.json").write_text(json.dumps(provenance), encoding="utf-8")
        credentials = prepared / f"credentials-{mutation}.json"
        log = prepared / f"tamper-{mutation}.log"
        process = _launch(pack, credentials, _free_port(), log)
        assert _exit_status(process) == 2
        assert log.read_text(encoding="utf-8").startswith("ERROR:")
        assert not credentials.exists()
    finally:
        shutil.rmtree(pack, ignore_errors=True)


def test_devserver_verifies_the_pack_before_reading_it(
    prepared: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class VerifierReached(Exception):
        pass

    def refuse(pack: Path, contract_version: str = "1") -> None:
        raise VerifierReached

    monkeypatch.setattr(devserver, "verify_content_pack", refuse)
    with pytest.raises(VerifierReached):
        devserver._compose(prepared / "build-a", _free_port())


def test_composition_refuses_a_non_fixture_provenance_mode(
    prepared: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _skip_pack_verifiers(monkeypatch)
    pack = _copy_pack(prepared, "mode-check")
    try:
        _rewrite_provenance(pack, mode="live")
        with pytest.raises(ValueError, match="provenance mode must be fixture"):
            devserver._compose(pack, _free_port())
    finally:
        shutil.rmtree(pack, ignore_errors=True)


def test_preparation_refuses_wrong_tree_and_corrupted_signature(prepared: Path) -> None:
    approval = json.loads((prepared / "detached-approval.json").read_text(encoding="utf-8"))
    cli = Path(sys.executable).with_name("ai-soc-content")
    variants = {
        "wrong-tree": {"tree_sha": "0" * 40},
        "corrupted-signature": {"signature": base64.b64encode(b"\x00" * 64).decode("ascii")},
    }
    for label, change in variants.items():
        attestation = prepared / f"{label}-approval.json"
        attestation.write_text(json.dumps({**approval, **change}), encoding="utf-8")
        out = prepared / f"out-{label}"
        result = subprocess.run(
            [
                str(cli),
                "build",
                "--source",
                str(prepared / "external-content"),
                "--commit",
                approval["commit"],
                "--attestation",
                str(attestation),
                "--trust-root",
                str(prepared / "fixture-trust-root.json"),
                "--fixture",
                "--out",
                str(out),
            ],
            cwd=REPO,
            env=_env(),
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert result.returncode != 0, label
        assert not out.exists(), label


def test_indexer_stand_in_answers_only_the_allowed_alert_requests() -> None:
    now = datetime.now(UTC)
    window = {
        "@timestamp": {
            "gte": (now - timedelta(hours=24)).isoformat().replace("+00:00", "Z"),
            "lt": now.isoformat().replace("+00:00", "Z"),
        }
    }
    query = {"bool": {"filter": [{"range": window}, {"term": {"rule.groups": "ldap"}}]}}
    bearer = {"authorization": "Bearer synthetic-indexer-token"}

    async def exercise() -> dict[str, object]:
        async with devserver._indexer(devserver._Clock()) as client:
            count = await client.post(
                "/wazuh-alerts-synthetic-*/_count", json={"query": query}, headers=bearer
            )
            unknown_path = await client.post(
                "/wazuh-alerts-synthetic-*/_aggregate", json={"query": query}, headers=bearer
            )
            unknown_method = await client.get("/wazuh-alerts-synthetic-*/_count", headers=bearer)
            wrong_method = await client.request(
                "GET",
                "/wazuh-alerts-synthetic-*/_count",
                json={"query": query},
                headers=bearer,
            )
            with_aggregation = await client.post(
                "/wazuh-alerts-synthetic-*/_count",
                json={"query": query, "aggs": {}},
                headers=bearer,
            )
            anonymous = await client.post("/wazuh-alerts-synthetic-*/_count", json={"query": query})
            long_form = await client.post(
                "/wazuh-alerts-synthetic-*/_count",
                json={
                    "query": {
                        "bool": {
                            "filter": [
                                {"range": window},
                                {"term": {"rule.groups": {"value": "ldap"}}},
                            ]
                        }
                    }
                },
                headers=bearer,
            )
            search = {
                "query": query,
                "size": 10,
                "_source": ["@timestamp"],
                "track_total_hits": True,
            }
            newest_first = await client.post(
                "/wazuh-alerts-synthetic-*/_search",
                json={**search, "sort": [{"@timestamp": {"order": "desc"}}]},
                headers=bearer,
            )
            oldest_first = await client.post(
                "/wazuh-alerts-synthetic-*/_search",
                json={**search, "sort": [{"@timestamp": {"order": "asc"}}]},
                headers=bearer,
            )
            return {
                "count": (count.status_code, count.json()["count"]),
                "unknown_path": unknown_path.status_code,
                "unknown_method": unknown_method.status_code,
                "wrong_method_with_body": wrong_method.status_code,
                "with_aggregation": with_aggregation.status_code,
                "anonymous": anonymous.status_code,
                "long_form_term": long_form.status_code,
                "newest_first": newest_first.status_code,
                "oldest_first": oldest_first.status_code,
            }

    assert asyncio.run(exercise()) == {
        "count": (200, 2),
        "unknown_path": 400,
        "unknown_method": 400,
        "wrong_method_with_body": 400,
        "with_aggregation": 400,
        "anonymous": 401,
        "long_form_term": 400,
        "newest_first": 200,
        "oldest_first": 400,
    }


def test_indexer_stand_in_answers_review_topic_filters() -> None:
    now = datetime.now(UTC)
    window = {
        "@timestamp": {
            "gte": (now - timedelta(hours=24)).isoformat().replace("+00:00", "Z"),
            "lt": now.isoformat().replace("+00:00", "Z"),
        }
    }
    auth_query = {
        "bool": {
            "filter": [
                {"range": window},
                {"term": {"rule.groups": "authentication_failed"}},
            ]
        }
    }
    vuln_query = {
        "bool": {
            "filter": [
                {"range": {"vulnerability.detected_at": window["@timestamp"]}},
                {"terms": {"vulnerability.severity": ["High", "Critical"]}},
            ]
        }
    }
    wrong_vuln_field_for_alerts = {
        "bool": {"filter": [{"term": {"vulnerability.severity": "Critical"}}]}
    }
    wrong_alert_field_for_vulnerabilities = {
        "bool": {"filter": [{"term": {"rule.groups": "ldap"}}]}
    }
    bearer = {"authorization": "Bearer synthetic-indexer-token"}

    async def exercise() -> tuple[int, int, int, int, int, int]:
        async with devserver._indexer(devserver._Clock()) as client:
            auth = await client.post(
                "/wazuh-alerts-synthetic-*/_count",
                json={"query": auth_query},
                headers=bearer,
            )
            vuln = await client.post(
                "/wazuh-vulnerabilities-synthetic-*/_count",
                json={"query": vuln_query},
                headers=bearer,
            )
            refused = await client.post(
                "/wazuh-alerts-synthetic-*/_count",
                json={"query": {"match_all": {}}},
                headers=bearer,
            )
            anonymous = await client.post(
                "/wazuh-vulnerabilities-synthetic-*/_count",
                json={"query": vuln_query},
            )
            alert_with_vulnerability_field = await client.post(
                "/wazuh-alerts-synthetic-*/_count",
                json={"query": wrong_vuln_field_for_alerts},
                headers=bearer,
            )
            vulnerability_with_alert_field = await client.post(
                "/wazuh-vulnerabilities-synthetic-*/_count",
                json={"query": wrong_alert_field_for_vulnerabilities},
                headers=bearer,
            )
            return (
                auth.json()["count"],
                vuln.json()["count"],
                refused.status_code,
                anonymous.status_code,
                alert_with_vulnerability_field.status_code,
                vulnerability_with_alert_field.status_code,
            )

    assert asyncio.run(exercise()) == (2, 2, 400, 401, 400, 400)


def test_indexer_stand_in_sorts_vulnerability_hits_by_their_own_index() -> None:
    now = datetime.now(UTC)
    window = {
        "gte": (now - timedelta(hours=24)).isoformat().replace("+00:00", "Z"),
        "lt": now.isoformat().replace("+00:00", "Z"),
    }
    vuln_search = {
        "query": {"bool": {"filter": [{"range": {"vulnerability.detected_at": window}}]}},
        "size": 10,
        "_source": ["agent.id"],
        "sort": [{"vulnerability.detected_at": {"order": "desc"}}],
        "track_total_hits": True,
    }
    out_of_range_level = {
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": window}},
                    {"range": {"rule.level": {"gte": 17}}},
                ]
            }
        }
    }
    bearer = {"authorization": "Bearer synthetic-indexer-token"}

    async def exercise() -> tuple[list[dict[str, object]], int]:
        async with devserver._indexer(devserver._Clock()) as client:
            search = await client.post(
                "/wazuh-vulnerabilities-synthetic-*/_search", json=vuln_search, headers=bearer
            )
            level = await client.post(
                "/wazuh-alerts-synthetic-*/_count", json=out_of_range_level, headers=bearer
            )
            return search.json()["hits"]["hits"], level.status_code

    hits, level_status = asyncio.run(exercise())
    assert hits
    assert all(hit["sort"][1] == hit["_index"] == devserver._VULN_HIT_INDEX for hit in hits)
    assert level_status == 400
