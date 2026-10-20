"""LOCAL-ONLY entrypoint smoke helpers for live-boot-check."""

from __future__ import annotations

import json
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from jwt.algorithms import RSAAlgorithm

from ai_soc.api.csrf import CsrfTokens
from ai_soc.contracts.canonical import owner_key
from ai_soc.contracts.models import (
    CursorPayload,
    FetchResult,
    PageRequest,
    ResolvedWindow,
    SiteConfig,
    SnapshotKind,
    SnapshotRef,
    TemplateId,
    VerifiedPrincipal,
)

ROOT = Path(__file__).resolve().parents[1]
STANDIN_SCRIPT = ROOT / "scripts/live_boot_identity_standin.py"
ALB_SIGNER = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/soc/qual"
ISSUER = "https://issuer.example.test"
RESOURCE = "https://soc.example.test/mcp"
BROWSER_ORIGIN = "https://soc.example.test"
ALB_HOST = "public-keys.auth.elb.us-east-1.amazonaws.com"


@dataclass(frozen=True, slots=True)
class StandinTls:
    hostname: str
    cert_pem: str
    key_pem: str


@dataclass(frozen=True, slots=True)
class SmokeKeys:
    mcp_private_pem: str
    mcp_jwks_json: str
    alb_private_pem: str
    alb_public_pem: str
    smoke_ca_pem: str
    issuer_tls: StandinTls
    alb_tls: StandinTls
    indexer_tls: StandinTls
    kms_private_pem: str


def _generate_smoke_ca() -> tuple[rsa.RSAPrivateKey, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SOC Live Boot Smoke CA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert.public_bytes(serialization.Encoding.PEM).decode()


def _tls_material(hostname: str, *, ca_key: rsa.RSAPrivateKey, ca_pem: str) -> StandinTls:
    ca_cert = x509.load_pem_x509_certificate(ca_pem.encode())
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return StandinTls(hostname=hostname, cert_pem=cert_pem, key_pem=key_pem)


def generate_smoke_keys() -> SmokeKeys:
    mcp_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    mcp_private_pem = mcp_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    jwk = json.loads(RSAAlgorithm.to_jwk(mcp_key.public_key()))
    jwk["kid"] = "mcp-kid-1"
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"
    jwks_json = json.dumps({"keys": [jwk]})
    alb_key = ec.generate_private_key(ec.SECP256R1())
    alb_private_pem = alb_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    alb_public_pem = (
        alb_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    kms_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kms_private_pem = kms_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    ca_key, smoke_ca_pem = _generate_smoke_ca()
    return SmokeKeys(
        mcp_private_pem=mcp_private_pem,
        mcp_jwks_json=jwks_json,
        alb_private_pem=alb_private_pem,
        alb_public_pem=alb_public_pem,
        smoke_ca_pem=smoke_ca_pem,
        issuer_tls=_tls_material("issuer.example.test", ca_key=ca_key, ca_pem=smoke_ca_pem),
        alb_tls=_tls_material(ALB_HOST, ca_key=ca_key, ca_pem=smoke_ca_pem),
        indexer_tls=_tls_material("alpha.private.example.test", ca_key=ca_key, ca_pem=smoke_ca_pem),
        kms_private_pem=kms_private_pem,
    )


def augmented_ca_bundle(base_ca: str, keys: SmokeKeys) -> str:
    return base_ca + keys.smoke_ca_pem


def assert_identity_standins_contacted(hit_files: dict[str, Path]) -> None:
    for role, path in hit_files.items():
        try:
            count = int(path.read_text(encoding="utf-8").strip() or "0")
        except ValueError:
            count = 0
        if count < 1:
            raise RuntimeError(f"identity stand-in {role} was not contacted (hits={count})")


def assert_indexer_standin_contacted(hit_file: Path) -> None:
    try:
        hits = len(hit_file.read_text(encoding="utf-8").splitlines())
    except OSError:
        hits = 0
    if hits != 1:
        raise RuntimeError(
            f"local indexer stand-in expected exactly one search request (observed {hits})"
        )


def build_smoke_page_cursor(site: SiteConfig, content_sha: str) -> str:
    from ai_soc.contracts.canonical import owner_key
    from ai_soc.identity.policy import MappedSitePolicy
    from ai_soc.query.cursors import CursorCipher

    now = datetime.now(UTC)
    expires_at = now + timedelta(minutes=4)
    principal = VerifiedPrincipal(
        issuer=ISSUER,
        sub="analyst-007",
        owner_key=owner_key(ISSUER, "analyst-007"),
        groups=("soc",),
        edge="browser",
        authenticated_at=now,
        expires_at=expires_at,
        assertion_hash="a" * 64,
    )
    authorized = MappedSitePolicy((site,), now=lambda: now).authorize(principal, "alpha")
    window = ResolvedWindow(
        start=now - timedelta(hours=1),
        end=now - timedelta(seconds=1),
        semantics="absolute",
        source_text="live boot local indexer smoke window",
        timezone="UTC",
        anchor_at=now,
    )
    cipher = CursorCipher(
        keys={"current": b"k" * 32},
        current_key_id="current",
        now=lambda: now,
    )
    return cipher.seal(
        CursorPayload(
            key_id="current",
            owner_key=principal.owner_key,
            environment_id=site.environment_id,
            policy_hash=authorized.policy_hash,
            content_sha=content_sha,
            question_id=uuid4(),
            topic_id="live-boot-smoke",
            fetch_id="live-boot-smoke",
            template_id=TemplateId.alerts_rows_v1,
            filters=[],
            window=window,
            projection_hash="b" * 64,
            sort_values=[now.isoformat(), "wazuh-alerts-alpha-2026.10.07", "live-boot-prior-row"],
            pit_id="local-live-boot-pit",
            snapshot=SnapshotRef(
                kind=SnapshotKind.pit,
                key="c" * 64,
                at=now,
                expires_at=expires_at,
            ),
            page_size=1,
            expires_at=expires_at,
        )
    )


def _mcp_token(private_pem: str) -> str:
    now = datetime.now(UTC)
    claims = {
        "iss": ISSUER,
        "aud": RESOURCE,
        "sub": "analyst-007",
        "groups": ["soc"],
        "scope": "soc:ask",
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "nbf": int((now - timedelta(seconds=1)).timestamp()),
    }
    return jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": "mcp-kid-1"})


def _alb_token(private_pem: str) -> str:
    now = datetime.now(UTC)
    header = {
        "signer": ALB_SIGNER,
        "iss": ISSUER,
        "client": "soc-client",
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "kid": "alb-kid-1",
    }
    claims = {"sub": "analyst-007", "groups": ["soc"]}
    return jwt.encode(claims, private_pem, algorithm="ES256", headers=header)


def container_ip(name: str) -> str:
    completed = subprocess.run(
        [
            "docker",
            "inspect",
            "-f",
            "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            name,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    ip = completed.stdout.strip()
    if not ip:
        raise RuntimeError(f"could not resolve container IP for {name}")
    return ip


def start_identity_standins(
    network: str,
    docker_env: dict[str, str],
    keys: SmokeKeys,
    *,
    image: str,
    cert_dir: Path,
    project: str,
) -> tuple[dict[str, str], list[str], dict[str, Path]]:
    cert_dir = cert_dir.resolve()
    cert_dir.mkdir(parents=True, exist_ok=True)
    hits_dir = cert_dir / "hits"
    hits_dir.mkdir(parents=True, exist_ok=True)
    names: list[str] = []
    host_map: dict[str, str] = {}
    hit_files: dict[str, Path] = {}
    for role, tls in (
        ("jwks", keys.issuer_tls),
        ("alb", keys.alb_tls),
    ):
        name = f"soclive-id-{role}-{uuid4().hex[:6]}"
        names.append(name)
        cert_file = cert_dir / f"{name}-cert.pem"
        key_file = cert_dir / f"{name}-key.pem"
        cert_file.write_text(tls.cert_pem, encoding="utf-8")
        key_file.write_text(tls.key_pem, encoding="utf-8")
        payload_file = cert_dir / f"{name}-payload"
        if role == "jwks":
            payload_file.write_text(keys.mcp_jwks_json, encoding="utf-8")
            payload_mount = ("/standin-jwks.json", "LOCAL_STANDIN_JWKS_PATH")
        else:
            payload_file.write_text(keys.alb_public_pem, encoding="utf-8")
            payload_mount = ("/standin-alb.pem", "LOCAL_STANDIN_ALB_PEM_PATH")
        env = docker_env.copy()
        hits_file = hits_dir / f"{name}-hits.txt"
        hits_file.write_text("0", encoding="utf-8")
        hit_files[role] = hits_file
        env.update(
            {
                "LOCAL_STANDIN_ROLE": role,
                "LOCAL_STANDIN_HOSTNAME": tls.hostname,
                "LOCAL_STANDIN_PORT": "443",
                "LOCAL_STANDIN_TLS_CERT_PATH": "/standin-cert.pem",
                "LOCAL_STANDIN_TLS_KEY_PATH": "/standin-key.pem",
                payload_mount[1]: payload_mount[0],
                "LOCAL_STANDIN_KID": "alb-kid-1",
                "LOCAL_STANDIN_HITS_PATH": "/standin-hits.txt",
            }
        )
        args = [
            "docker",
            "run",
            "--pull=never",
            "-d",
            "--name",
            name,
            "--network",
            network,
            "--network-alias",
            tls.hostname,
            "--label",
            "com.ai-soc.standin=identity",
            "--label",
            f"com.ai-soc.live-boot-run={project}",
            "--user",
            "0:0",
            "-v",
            f"{STANDIN_SCRIPT.resolve()}:/standin.py:ro",
            "-v",
            f"{cert_file.resolve()}:/standin-cert.pem:ro",
            "-v",
            f"{key_file.resolve()}:/standin-key.pem:ro",
            "-v",
            f"{payload_file.resolve()}:{payload_mount[0]}:ro",
            "-v",
            f"{hits_file.resolve()}:/standin-hits.txt:rw",
        ]
        for key, value in env.items():
            args.extend(["-e", f"{key}={value}"])
        args.extend(
            [
                image,
                "/service/.venv/bin/python",
                "/standin.py",
            ]
        )
        completed = subprocess.run(args, check=False, capture_output=True, text=True)
        if completed.returncode:
            raise RuntimeError(
                f"identity stand-in {name} failed: {(completed.stderr or completed.stdout)[:2000]}"
            )
        running = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", name],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        if running != "true":
            logs = subprocess.run(
                ["docker", "logs", name],
                capture_output=True,
                text=True,
                check=False,
            )
            detail = logs.stderr or logs.stdout
            raise RuntimeError(f"identity stand-in {name} not running: {detail}")
        host_map[tls.hostname] = container_ip(name)
        print(f"LOCAL_STANDIN_IDENTITY: started {name} as https://{tls.hostname}/")
    time.sleep(3.0)
    return host_map, names, hit_files


def run_entrypoint_smoke(base_url: str, keys: SmokeKeys, *, page_cursor: str) -> None:
    host_header = BROWSER_ORIGIN.removeprefix("https://")
    mcp_headers = {
        "Host": host_header,
        "Authorization": f"Bearer {_mcp_token(keys.mcp_private_pem)}",
        "Origin": BROWSER_ORIGIN,
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    init_body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "live-boot-smoke", "version": "1"},
            },
        }
    ).encode()
    init_response = _post(f"{base_url}/mcp", data=init_body, headers=mcp_headers)
    if "error" in init_response:
        raise RuntimeError(f"MCP initialize failed: {init_response}")
    list_body = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).encode()
    response = _post(f"{base_url}/mcp", data=list_body, headers=mcp_headers)
    if "error" in response:
        raise RuntimeError(f"MCP tools/list failed: {response}")
    tool_names = {tool["name"] for tool in response["result"].get("tools", [])}
    if "soc_ask" not in tool_names:
        raise RuntimeError(f"MCP tools/list missing soc_ask: {response}")

    browser_assertion = _alb_token(keys.alb_private_pem)
    now = datetime.now(UTC)
    csrf = CsrfTokens(b"k" * 32, origin=BROWSER_ORIGIN)
    cookie, csrf_token = csrf.issue(
        owner_key=owner_key(ISSUER, "analyst-007"),
        assertion_expires_at=now + timedelta(minutes=5),
        now=now,
    )
    rest_headers = {
        "Host": host_header,
        "x-amzn-oidc-data": browser_assertion,
        "Origin": BROWSER_ORIGIN,
        "Cookie": f"__Host-soc-csrf={cookie}",
        "X-SOC-CSRF": csrf_token,
    }
    page_request = PageRequest(environment_id="alpha", cursor=page_cursor)
    rest_result = _post(
        f"{base_url}/v1/fetches/page",
        data=page_request.model_dump_json().encode(),
        headers={**rest_headers, "Content-Type": "application/json"},
        expected_status=200,
    )
    result = FetchResult.model_validate_json(json.dumps(rest_result))
    if not result.rows:
        raise RuntimeError("login-gated REST page returned no indexer rows")

    asset_path = _first_ui_asset()
    _get(f"{base_url}{asset_path}", headers={"Host": host_header})


def _first_ui_asset() -> str:
    assets = sorted((ROOT / "ui/dist/assets").glob("*"))
    if not assets:
        raise RuntimeError("ui/dist/assets is empty; build UI before live-boot-check")
    return f"/assets/{assets[0].name}"


def _post(
    url: str,
    *,
    data: bytes,
    headers: dict[str, str],
    expected_status: int = 200,
) -> dict[str, object]:
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        response_ctx = urllib.request.urlopen(request, timeout=15)
    except urllib.error.HTTPError as error:
        body = error.read().decode(errors="replace")
        if error.code == expected_status:
            payload = json.loads(body)
            if isinstance(payload, dict):
                return payload
        raise RuntimeError(f"POST {url} returned {error.code}: {body[:500]}") from error
    with response_ctx as response:
        if response.status != expected_status:
            raise RuntimeError(f"POST {url} returned {response.status}")
        return json.loads(response.read().decode())


def _get(url: str, *, headers: dict[str, str]) -> None:
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status != 200:
                raise RuntimeError(f"GET {url} returned {response.status}")
    except urllib.error.HTTPError as error:
        if error.code == 200:
            return
        body = error.read().decode(errors="replace")
        raise RuntimeError(f"GET {url} returned {error.code}: {body[:500]}") from error
