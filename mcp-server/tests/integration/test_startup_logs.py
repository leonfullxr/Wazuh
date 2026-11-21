"""Startup logs have to match the mode that actually started."""

import os
import socket
import subprocess
import sys
import time


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_oauth_startup_log_does_not_claim_dcr_or_ha():
    port = _free_port()
    env = os.environ.copy()
    env.update(
        {
            "WAZUH_HOST": "127.0.0.1",
            "WAZUH_USER": "u",
            "WAZUH_PASS": "p",
            "WAZUH_INDEXER_HOST": "",
            "AUTH_MODE": "oauth",
            "OAUTH_ENABLE_DCR": "false",
            "ENVIRONMENT": "development",
            "MCP_HOST": "127.0.0.1",
            "MCP_PORT": str(port),
            "LOG_LEVEL": "INFO",
        }
    )
    env.pop("OAUTH_IDP_ISSUER", None)
    proc = subprocess.Popen(
        [sys.executable, "-m", "wazuh_mcp"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    output = []
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            output.append(line)
            if "Server startup complete" in line:
                break
        else:
            raise AssertionError("server did not finish starting:\n" + "".join(output))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    text = "".join(output)
    assert "MCP protocols: 2026-07-28 stateless; legacy handshake 2025-11-25" in text
    assert "dynamic client registration is off" in text
    assert "OAuth endpoints: /oauth/authorize, /oauth/token\n" in text or text.rstrip().endswith(
        "OAuth endpoints: /oauth/authorize, /oauth/token"
    )
    assert "/oauth/register" not in text
    assert "with DCR" not in text
    assert "high availability" not in text.lower()
    assert "Redis session store" not in text
    assert "Server startup complete" in text
