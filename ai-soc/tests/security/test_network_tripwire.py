from __future__ import annotations

import socket
import subprocess
from pathlib import Path

import pytest


def test_external_network_tripwire_rejects_non_loopback() -> None:
    sock = socket.socket()
    try:
        with pytest.raises(RuntimeError, match="external network"):
            sock.connect(("198.51.100.20", 443))
    finally:
        sock.close()


def test_loopback_socket_path_remains_available() -> None:
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    client = socket.socket()
    try:
        client.connect(server.getsockname())
        accepted, _ = server.accept()
        accepted.close()
    finally:
        client.close()
        server.close()


def test_static_child_direct_syscall_cannot_reach_external_or_metadata() -> None:
    probe = Path("build/tool-cache/netprobe-static")
    assert probe.is_file(), "run the locked offline runner to prepare the static syscall probe"
    for address in ("198.51.100.20", "169.254.169.254", "169.254.170.2", "fd00:ec2::254"):
        result = subprocess.run(
            [str(probe.resolve()), address, "443"], capture_output=True, text=True, timeout=3
        )
        assert result.returncode == 10, (address, result.stdout, result.stderr)
        assert "direct syscall denied" in result.stdout


def test_static_child_direct_syscall_can_reach_owned_loopback() -> None:
    probe = Path("build/tool-cache/netprobe-static")
    assert probe.is_file(), "run the locked offline runner to prepare the static syscall probe"
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    result = subprocess.run(
        [str(probe.resolve()), "127.0.0.1", str(server.getsockname()[1])],
        capture_output=True,
        text=True,
        timeout=3,
    )
    accepted, _ = server.accept()
    accepted.close()
    server.close()
    assert result.returncode == 0, result.stdout + result.stderr
