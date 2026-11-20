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
    reader, target = preflight_cli._reader("default")
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
    default, target = preflight_cli._reader(None)
    assert (default.host, default.port, default.username, default.password) == (
        "second",
        9202,
        "named-user",
        os.environ["IDX_PASS"],
    )
    assert default.verify_ssl is False and default.scheme == "http" and default.timeout == 12
    explicit, _ = preflight_cli._reader("first")
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
    monkeypatch.setattr(
        preflight_cli,
        "_reader",
        lambda cluster: (
            reader,
            {
                "cluster_id": "default",
                "config_source": "environment",
                "scheme": "https",
                "host": "localhost",
                "port": 9200,
            },
        ),
    )

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
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == status
    assert output["target"] == {
        "cluster_id": "default",
        "config_source": "environment",
        "scheme": "https",
        "host": "localhost",
        "port": 9200,
        "tie_breaker": "event.id",
    }


def test_cleanup_on_preflight_exception(monkeypatch):
    class Reader:
        closed = False

        async def close(self):
            self.closed = True

    reader = Reader()
    monkeypatch.setattr(
        preflight_cli,
        "_reader",
        lambda cluster: (
            reader,
            {
                "cluster_id": "default",
                "config_source": "environment",
                "scheme": "https",
                "host": "localhost",
                "port": 9200,
            },
        ),
    )

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


def test_implicit_missing_file_requires_explicit_environment_selection(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("WAZUH_CLUSTERS_FILE", raising=False)
    monkeypatch.setenv("WAZUH_INDEXER_HOST", "localhost")
    args = Namespace(
        cluster=None, tie_breaker="event.id", timeout=1, max_pages=1, max_documents=1, max_bytes=1, page_size=1
    )
    result = asyncio.run(preflight_cli._run(args))
    assert result["status"] == "inconclusive"
    assert "--cluster default" in result["reason"]
    reader, target = preflight_cli._reader("default")
    assert target == {
        "cluster_id": "default",
        "config_source": "environment",
        "scheme": "https",
        "host": "localhost",
        "port": 9200,
    }


def test_implicit_file_uses_same_cwd_as_server(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("WAZUH_CLUSTERS_FILE", raising=False)
    (tmp_path / "config").mkdir()
    (tmp_path / "config/clusters.json").write_text(
        json.dumps(
            {
                "default_cluster": "one",
                "clusters": [
                    {
                        "id": "one",
                        "wazuh_host": "manager",
                        "wazuh_user": "user",
                        "wazuh_pass": "password",
                        "indexer_host": "named-indexer",
                    }
                ],
            }
        )
    )
    _, target = preflight_cli._reader(None)
    assert target == {
        "cluster_id": "one",
        "config_source": "file",
        "scheme": "https",
        "host": "named-indexer",
        "port": 9200,
    }


def test_rejects_credentials_in_host_without_leaking(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("WAZUH_CLUSTERS_FILE", raising=False)
    monkeypatch.setenv("WAZUH_INDEXER_HOST", "https://secret-user@private-indexer")
    args = Namespace(
        cluster="default", tie_breaker="event.id", timeout=1, max_pages=1, max_documents=1, max_bytes=1, page_size=1
    )
    result = asyncio.run(preflight_cli._run(args))
    assert result["status"] == "inconclusive"
    assert "secret-user" not in json.dumps(result)


def test_invalid_tie_breaker_is_not_reported_or_connected(monkeypatch):
    monkeypatch.setattr(preflight_cli, "_reader", lambda cluster: pytest.fail("must not connect"))
    args = Namespace(
        cluster="default", tie_breaker="secret/path", timeout=1, max_pages=1, max_documents=1, max_bytes=1, page_size=1
    )
    result = asyncio.run(preflight_cli._run(args))
    assert result["status"] == "fail"
    assert "secret/path" not in json.dumps(result)


def test_indexer_tls_is_independent_of_manager_self_signed(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("WAZUH_CLUSTERS_FILE", raising=False)
    monkeypatch.setenv("WAZUH_INDEXER_HOST", "localhost")
    monkeypatch.setenv("WAZUH_ALLOW_SELF_SIGNED", "true")
    monkeypatch.setenv("WAZUH_CA_BUNDLE", "/tmp/example-ca.pem")
    monkeypatch.setenv("WAZUH_INDEXER_VERIFY_SSL", "true")
    reader, _ = preflight_cli._reader("default")
    assert reader.verify_ssl == "/tmp/example-ca.pem"
    monkeypatch.setenv("WAZUH_INDEXER_VERIFY_SSL", "false")
    reader, _ = preflight_cli._reader("default")
    assert reader.verify_ssl is False


def test_named_indexer_uses_cluster_ca(clusters_file):
    # The named connection stores an httpx verify value (boolean or CA path).
    from certifi import where

    ca = where()
    data = json.loads(clusters_file.read_text())
    data["clusters"][0]["ca_bundle"] = ca
    data["clusters"][0]["indexer_verify_ssl"] = True
    clusters_file.write_text(json.dumps(data))
    reader, target = preflight_cli._reader("first")
    assert reader.verify_ssl == ca
    assert target["config_source"] == "file"


def test_named_endpoint_preserves_explicit_http_scheme(clusters_file):
    data = json.loads(clusters_file.read_text())
    data["clusters"][0]["indexer_host"] = "http://named-indexer"
    data["clusters"][0]["indexer_ssl"] = True
    clusters_file.write_text(json.dumps(data))
    reader, target = preflight_cli._reader("first")
    assert reader.scheme == target["scheme"] == "http"
    assert target["host"] == "named-indexer"


@pytest.mark.parametrize("host", ["secret@host", "bad host", "host?secret", "host;secret", "[invalid]", "host:9999"])
def test_malformed_hosts_are_not_reported(monkeypatch, tmp_path, host):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("WAZUH_CLUSTERS_FILE", raising=False)
    monkeypatch.setenv("WAZUH_INDEXER_HOST", host)
    args = Namespace(
        cluster="default", tie_breaker="event.id", timeout=1, max_pages=1, max_documents=1, max_bytes=1, page_size=1
    )
    result = asyncio.run(preflight_cli._run(args))
    assert result["status"] == "inconclusive"
    assert host not in json.dumps(result)


def test_empty_cluster_file_is_rejected(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("WAZUH_CLUSTERS_FILE", "")
    monkeypatch.setenv("WAZUH_INDEXER_HOST", "localhost")
    args = Namespace(
        cluster=None, tie_breaker="event.id", timeout=1, max_pages=1, max_documents=1, max_bytes=1, page_size=1
    )
    result = asyncio.run(preflight_cli._run(args))
    assert result["status"] == "inconclusive"
    assert "Empty WAZUH_CLUSTERS_FILE" in result["reason"]
