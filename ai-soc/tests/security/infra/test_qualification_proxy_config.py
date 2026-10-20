from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
PROXY_CONFIG = REPO_ROOT / "infra/proxy/squid-qualification.conf"
SNI_HELPER = REPO_ROOT / "infra/proxy/connect-sni-match.sh"
LOCK = REPO_ROOT / "dev/toolchain.lock.json"

CLIENT_SCRIPT = r"""
import socket
import ssl
import sys

case = sys.argv[1]
authority, sni, expectation = {
    "allowed": ("qualification-allowed.test:443", "qualification-allowed.test", "pass"),
    "allowed-second": ("identity-provider.test:443", "identity-provider.test", "pass"),
    "arbitrary": ("attacker.invalid:443", "attacker.invalid", "deny"),
    "ipv4": ("127.0.0.1:443", "127.0.0.1", "deny"),
    "ipv6": ("[::1]:443", None, "deny"),
    "absent-sni": ("qualification-allowed.test:443", None, "deny"),
    "mismatched-sni": ("qualification-allowed.test:443", "attacker.invalid", "deny"),
}[case]
proxy = socket.create_connection(("127.0.0.1", 3128), timeout=5)
proxy.settimeout(5)
proxy.sendall(
    f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode("ascii")
)
response = bytearray()
while b"\r\n\r\n" not in response:
    part = proxy.recv(4096)
    if not part:
        break
    response.extend(part)
status = bytes(response).split(b"\r\n", 1)[0]
if expectation == "deny" and (
    status.startswith(b"HTTP/1.1 403") or status.startswith(b"HTTP/1.0 403")
):
    print(f"{case}: CONNECT denied by Squid")
    raise SystemExit(0)
assert status.startswith(b"HTTP/1.1 200") or status.startswith(b"HTTP/1.0 200"), status
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
try:
    tunneled = context.wrap_socket(proxy, server_hostname=sni)
    request = (
        b"GET / HTTP/1.1\r\nHost: qualification-allowed.test\r\n"
        b"Connection: close\r\n\r\n"
    )
    tunneled.sendall(request)
    received = bytearray()
    while True:
        part = tunneled.recv(4096)
        if not part:
            break
        received.extend(part)
    if expectation == "pass":
        assert b"HTTP/1.1 200 OK" in received and received.endswith(b"local-tls-origin"), received
        print("allowed: TLS passed through Squid to the local TLS origin")
    else:
        assert b"local-tls-origin" not in received, (
            f"{case}: refused target reached local TLS origin"
        )
        print(f"{case}: denied before application data reached the local origin")
except (OSError, ssl.SSLError):
    if expectation != "deny":
        raise
    print(f"{case}: ClientHello rejected by Squid")
"""

ORIGIN_SCRIPT = r"""
import socket
import ssl
import sys

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1], sys.argv[2])
listener = socket.socket(socket.AF_INET6)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
listener.bind(("::", 443))
listener.listen(16)
while True:
    raw, _ = listener.accept()
    try:
        with context.wrap_socket(raw, server_side=True) as client:
            client.recv(8192)
            client.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n"
                b"Connection: close\r\n\r\nlocal-tls-origin"
            )
    except (OSError, ssl.SSLError):
        raw.close()
"""


def _run(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if check and result.returncode:
        raise AssertionError(f"command failed: {args!r}\n{result.stdout}\n{result.stderr}")
    return result


def _locked_image(name: str) -> str:
    images = json.loads(LOCK.read_text(encoding="utf-8"))["images"]
    return next(image["reference"] for image in images if image["name"] == name)


def _require_image(reference: str, name: str) -> None:
    if shutil.which("docker") is None:
        pytest.fail("Docker Engine is required; run make bootstrap before make test-security")
    inspected = _run(["docker", "image", "inspect", reference], check=False)
    if inspected.returncode:
        pytest.fail(
            f"locked {name} image is missing locally; run make bootstrap to prepare it; "
            "the behavioral test never pulls images"
        )


def _write_tls_fixture(tmp_path: Path) -> tuple[Path, Path]:
    key = tmp_path / "test-origin.key"
    cert = tmp_path / "test-origin.crt"
    generated = _run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=qualification-allowed.test",
            "-addext",
            "subjectAltName=DNS:qualification-allowed.test",
        ],
        check=False,
    )
    if generated.returncode:
        pytest.fail(f"openssl is required for the local TLS fixture: {generated.stderr}")
    key.chmod(0o644)
    cert.chmod(0o644)
    return cert, key


def test_real_squid_enforces_connect_and_client_hello_identity(tmp_path: Path) -> None:
    squid_image = _locked_image("squid")
    python_image = _locked_image("python")
    _require_image(squid_image, "Squid")
    _require_image(python_image, "Python fixture")
    if shutil.which("openssl") is None:
        pytest.fail("OpenSSL is required to create the local test CA certificate")

    suffix = f"{os.getpid()}-{secrets.token_hex(4)}"
    network = f"qualification-proxy-{suffix}"
    squid_name = f"qualification-squid-{suffix}"
    origin_name = f"qualification-origin-{suffix}"
    cert, key = _write_tls_fixture(tmp_path)
    hosts = tmp_path / "qualification-allowed-hosts.txt"
    hosts.write_text("qualification-allowed.test\nidentity-provider.test\n", encoding="ascii")
    client_script = tmp_path / "client.py"
    client_script.write_text(CLIENT_SCRIPT, encoding="utf-8")
    origin_script = tmp_path / "origin.py"
    origin_script.write_text(ORIGIN_SCRIPT, encoding="utf-8")

    _run(["docker", "network", "create", "--internal", network])
    try:
        _run(
            [
                "docker",
                "run",
                "--detach",
                "--pull=never",
                "--name",
                squid_name,
                "--network",
                network,
                "--network-alias",
                "qualification-allowed.test",
                "--network-alias",
                "identity-provider.test",
                "--network-alias",
                "attacker.invalid",
                "--env",
                "SQUID_CONFIG_FILE=/etc/squid/squid.conf",
                "--mount",
                f"type=bind,src={PROXY_CONFIG},dst=/etc/squid/squid.conf,readonly",
                "--mount",
                f"type=bind,src={SNI_HELPER},dst=/etc/squid/connect-sni-match.sh,readonly",
                "--mount",
                f"type=bind,src={hosts},dst=/etc/squid/qualification-allowed-hosts.txt,readonly",
                "--mount",
                f"type=bind,src={cert},dst=/etc/squid/proxy.pem,readonly",
                "--mount",
                f"type=bind,src={key},dst=/etc/squid/proxy.key,readonly",
                squid_image,
            ]
        )
        _run(
            [
                "docker",
                "run",
                "--detach",
                "--pull=never",
                "--name",
                origin_name,
                "--network",
                f"container:{squid_name}",
                "--mount",
                f"type=bind,src={cert},dst=/fixture/origin.crt,readonly",
                "--mount",
                f"type=bind,src={key},dst=/fixture/origin.key,readonly",
                "--mount",
                f"type=bind,src={origin_script},dst=/fixture/origin.py,readonly",
                python_image,
                "python",
                "/fixture/origin.py",
                "/fixture/origin.crt",
                "/fixture/origin.key",
            ]
        )
        ready = False
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            probe = _run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--pull=never",
                    "--network",
                    f"container:{squid_name}",
                    python_image,
                    "python",
                    "-c",
                    "import socket; s=socket.create_connection(('127.0.0.1',3128),1); s.close()",
                ],
                check=False,
            )
            if probe.returncode == 0:
                ready = True
                break
            time.sleep(0.5)
        if not ready:
            logs = _run(["docker", "logs", squid_name], check=False)
            pytest.fail(
                f"Squid did not start with the shipped config:\n{logs.stdout}\n{logs.stderr}"
            )

        for case in (
            "allowed",
            "allowed-second",
            "arbitrary",
            "ipv4",
            "ipv6",
            "absent-sni",
            "mismatched-sni",
        ):
            client = _run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--pull=never",
                    "--network",
                    f"container:{squid_name}",
                    "--mount",
                    f"type=bind,src={client_script},dst=/fixture/client.py,readonly",
                    python_image,
                    "python",
                    "/fixture/client.py",
                    case,
                ],
                check=False,
            )
            if client.returncode:
                logs = _run(["docker", "logs", squid_name], check=False)
                origin_logs = _run(["docker", "logs", origin_name], check=False)
                pytest.fail(
                    f"{case}: {client.stdout}\n{client.stderr}\nSquid logs:\n"
                    f"{logs.stdout[-5000:]}\n{logs.stderr[-1000:]}\n"
                    f"Origin logs:\n{origin_logs.stdout}\n{origin_logs.stderr}"
                )
    finally:
        _run(["docker", "rm", "--force", origin_name, squid_name], check=False)
        _run(["docker", "network", "rm", network], check=False)
