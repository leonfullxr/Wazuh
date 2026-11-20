import asyncio
import json
import os
import secrets
import subprocess
import sys
from argparse import Namespace
from pathlib import Path

import pytest

from wazuh_mcp import preflight_cli
from wazuh_mcp.config import indexer_environment


def clean_environment():
    env = {key: value for key, value in os.environ.items() if not key.startswith("WAZUH_")}
    env.pop("REQUEST_TIMEOUT_SECONDS", None)
    return env


def test_subprocess_help_and_unconfigured(tmp_path):
    command = [sys.executable, "-m", "wazuh_mcp.preflight_cli"]
    env = clean_environment()
    env["PYTHONPATH"] = str(Path(preflight_cli.__file__).resolve().parents[1])
    help_result = subprocess.run(command + ["--help"], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert help_result.returncode == 0
    assert "--tie-breaker" in help_result.stdout
    result = subprocess.run(
        command + ["--tie-breaker", "event.id"], cwd=tmp_path, env=env, capture_output=True, text=True
    )
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "inconclusive"
    assert result.stderr == ""


def test_environment_selection_matches_indexer_settings(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("WAZUH_INDEXER_HOST", "http://environment-indexer")
    monkeypatch.setenv("WAZUH_INDEXER_PORT", "19200")
    monkeypatch.setenv("WAZUH_INDEXER_USER", "operator")
    monkeypatch.setenv("WAZUH_INDEXER_PASS", secrets.token_hex(12))
    monkeypatch.setenv("WAZUH_INDEXER_SSL", "false")
    monkeypatch.setenv("WAZUH_INDEXER_VERIFY_SSL", "false")
    monkeypatch.setenv("REQUEST_TIMEOUT_SECONDS", "45")
    monkeypatch.delenv("WAZUH_CLUSTERS_FILE", raising=False)
    env = indexer_environment()
    reader = preflight_cli._reader(None)
    assert reader.host == "environment-indexer"
    assert reader.port == env["WAZUH_INDEXER_PORT"]
    assert reader.username == env["WAZUH_INDEXER_USER"]
    assert reader.password == env["WAZUH_INDEXER_PASS"]
    assert reader.verify_ssl is env["WAZUH_INDEXER_VERIFY_SSL"]
    assert reader.scheme == "http" and reader.timeout == 45


@pytest.fixture
def clusters_file(tmp_path, monkeypatch):
    path = tmp_path / "clusters.json"
    entries = []
    for name, port in [("first", 9201), ("second", 9202), ("remote", 9203)]:
        entries.append(
            {
                "id": name,
                "wazuh_host": "manager",
                "wazuh_user": "manager-user",
                "wazuh_pass": "${IDX_PASS}",
                "indexer_host": name,
                "indexer_port": port,
                "indexer_user": "${IDX_USER}",
                "indexer_pass": "${IDX_PASS}",
                "indexer_verify_ssl": False,
                "indexer_ssl": False,
                "request_timeout_seconds": 12,
            }
        )
    entries[-1]["ccs_prefix"] = "eu"
    path.write_text(json.dumps({"default_cluster": "second", "clusters": entries}))
    monkeypatch.setenv("IDX_USER", "named-user")
    monkeypatch.setenv("IDX_PASS", secrets.token_hex(12))
    monkeypatch.setenv("WAZUH_CLUSTERS_FILE", str(path))
    return path


def test_selected_and_configured_default_clusters(clusters_file):
    default = preflight_cli._reader(None)
    assert (default.host, default.port, default.username, default.password) == (
        "second",
        9202,
        "named-user",
        os.environ["IDX_PASS"],
    )
    assert default.verify_ssl is False and default.scheme == "http" and default.timeout == 12
    explicit = preflight_cli._reader("first")
    assert (explicit.host, explicit.port) == ("first", 9201)


@pytest.mark.parametrize("cluster", ["remote", "unknown"])
def test_invalid_cluster_and_ccs_are_inconclusive_without_leaking(clusters_file, cluster):
    args = Namespace(
        cluster=cluster, tie_breaker="event.id", timeout=10, max_pages=5, max_documents=10, max_bytes=1000, page_size=5
    )
    result = asyncio.run(preflight_cli._run(args))
    assert result["status"] == "inconclusive"
    assert os.environ["IDX_PASS"] not in json.dumps(result)
    assert "named-user" not in json.dumps(result)


@pytest.mark.parametrize("status, code", [("pass", 0), ("fail", 1), ("inconclusive", 2)])
def test_exit_mapping_limits_and_cleanup(monkeypatch, capsys, status, code):
    class Reader:
        closed = False

        async def close(self):
            self.closed = True

    reader = Reader()
    monkeypatch.setattr(preflight_cli, "_reader", lambda cluster: reader)

    async def preflight(actual, field, *, limits):
        assert actual is reader and field == "event.id"
        assert (limits.seconds, limits.pages, limits.documents, limits.bytes, limits.page_size) == (5, 6, 7, 800, 9)
        return {"status": status, "reason": "safe"}

    monkeypatch.setattr(preflight_cli, "investigation_preflight", preflight)
    assert (
        preflight_cli.main(
            [
                "--tie-breaker",
                "event.id",
                "--timeout",
                "5",
                "--max-pages",
                "6",
                "--max-documents",
                "7",
                "--max-bytes",
                "800",
                "--page-size",
                "9",
            ]
        )
        == code
    )
    assert reader.closed
    assert json.loads(capsys.readouterr().out)["status"] == status


def test_cleanup_on_preflight_exception(monkeypatch):
    class Reader:
        closed = False

        async def close(self):
            self.closed = True

    reader = Reader()
    monkeypatch.setattr(preflight_cli, "_reader", lambda cluster: reader)

    async def broken(*args, **kwargs):
        raise RuntimeError("backend broke")

    monkeypatch.setattr(preflight_cli, "investigation_preflight", broken)
    args = Namespace(cluster=None, tie_breaker="id", timeout=1, max_pages=1, max_documents=1, max_bytes=1, page_size=1)
    result = asyncio.run(preflight_cli._run(args))
    assert result["status"] == "inconclusive" and "backend broke" not in result["reason"]
    assert reader.closed


@pytest.mark.parametrize("flag", ["--timeout", "--max-pages", "--max-documents", "--max-bytes", "--page-size"])
def test_invalid_limits_exit_before_connecting(monkeypatch, capsys, flag):
    monkeypatch.setattr(preflight_cli, "_reader", lambda cluster: pytest.fail("must not connect"))
    with pytest.raises(SystemExit) as exc:
        preflight_cli.main(["--tie-breaker", "event.id", flag, "0"])
    assert exc.value.code == 2
    assert "positive integer" in capsys.readouterr().err


def test_bad_config_errors_are_redacted(monkeypatch, tmp_path):
    path = tmp_path / "sensitive-path.json"
    path.write_text('{"secret-password":')
    monkeypatch.setenv("WAZUH_CLUSTERS_FILE", str(path))
    args = Namespace(cluster=None, tie_breaker="id", timeout=1, max_pages=1, max_documents=1, max_bytes=1, page_size=1)
    result = asyncio.run(preflight_cli._run(args))
    assert result["status"] == "inconclusive"
    assert "sensitive-path" not in json.dumps(result)
    assert "secret-password" not in json.dumps(result)
