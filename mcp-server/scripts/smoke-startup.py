"""Start a packaged server and check local liveness with no external services."""

import json
import os
import socket
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import urlopen


def main():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    env = dict(
        os.environ,
        ENVIRONMENT="development",
        AUTH_MODE="none",
        MCP_HOST="127.0.0.1",
        MCP_PORT=str(port),
        WAZUH_HOST="127.0.0.1",
        WAZUH_USER="smoke",
        WAZUH_PASS="smoke-fixture-only",
        LOG_LEVEL="ERROR",
    )
    cmd = sys.argv[1:] or [sys.executable, "-m", "wazuh_mcp"]
    process = subprocess.Popen(cmd, env=env)
    try:
        until = time.monotonic() + 15
        while process.poll() is None and time.monotonic() < until:
            try:
                with urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as response:
                    data = json.load(response)
                    assert response.status == 200 and data["status"] == "healthy"
                    print(f"MCP {data['version']} local liveness passed")
                    return
            except URLError:
                time.sleep(0.1)
        raise RuntimeError(f"Packaged server failed to start (exit code {process.poll()})")
    finally:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


if __name__ == "__main__":
    main()
