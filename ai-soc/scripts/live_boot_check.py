#!/usr/bin/env python3
"""Local live-boot acceptance: built image, ECS-like container, not AWS validation."""

from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
DOCKER_CONFIG = ROOT / "build/private/docker-config"
COMPOSE = ROOT / "build/tool-cache/docker-compose-v5.5.1/docker-compose"
LOCK_PATH = ROOT / "dev/toolchain.lock.json"
NODE_NPM = ROOT / "build/tool-cache/node-v22.23.3/extracted/bin/npm"
SEED_RUNNER = ROOT / "examples/content-seed/run_fixture_demo.py"
# LOCAL STAND-IN: digest-pinned S3Mock emulates S3 GetObject offline (not a production dependency).
S3_STANDIN_NAME = "s3-standin"
S3_STANDIN_PORT = 9090
TMP_VOLUME_PREFIX = "soclive-task-tmp-"
RUN_OWNERSHIP_LABEL = "com.ai-soc.live-boot-run"
S3_BUCKET = "soc-docs-standin"
S3_ACCESS = "soclocal"
S3_SECRET = "soclocalsecret"


def _run(
    args: list[str],
    *,
    env: dict[str, str],
    timeout: int = 600,
    check: bool = True,
) -> str:
    result = subprocess.run(
        args,
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if check and result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"{' '.join(args[:4])} failed ({result.returncode}): {detail[:2000]}")
    return (result.stdout or "").strip()


def _docker_env() -> dict[str, str]:
    config_path = DOCKER_CONFIG / "config.json"
    if not config_path.is_file():
        raise RuntimeError("run make bootstrap before live-boot-check")
    env = os.environ.copy()
    env["DOCKER_CONFIG"] = str(DOCKER_CONFIG)
    env["DOCKER_HOST"] = "unix:///var/run/docker.sock"
    for name in ("DOCKER_CONTEXT", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY"):
        env.pop(name, None)
    return env


def _loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _ownership_label_args(project: str) -> list[str]:
    return ["--label", f"{RUN_OWNERSHIP_LABEL}={project}"]


def _container_ip(name: str, env: dict[str, str]) -> str:
    address = _run(
        [
            "docker",
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            name,
        ],
        env=env,
    )
    if not address:
        raise RuntimeError(f"could not resolve container IP for {name}")
    return address


def _git_sha() -> str:
    return _run(["git", "rev-parse", "HEAD"], env=os.environ.copy(), timeout=30)


def _source_epoch() -> str:
    return _run(
        ["git", "show", "-s", "--format=%ct", "HEAD"],
        env=os.environ.copy(),
        timeout=30,
    )


def _prepare_pack(work_dir: Path, env: dict[str, str]) -> tuple[Path, dict[str, object]]:
    if work_dir.exists():
        import shutil

        shutil.rmtree(work_dir)
    work_dir.mkdir(parents=True)
    offline_env = env.copy()
    offline_env.update(
        {
            "PYTHONHASHSEED": "0",
            "TZ": "UTC",
            "LC_ALL": "C.UTF-8",
            "SOURCE_DATE_EPOCH": _source_epoch(),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "AWS_EC2_METADATA_DISABLED": "true",
        }
    )
    _run(
        [sys.executable, str(SEED_RUNNER), "--work-dir", str(work_dir)],
        env=offline_env,
        timeout=300,
    )
    pack = work_dir / "build-a"
    manifest = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))
    archive_bytes = (pack / "content.tar").read_bytes()
    archive_sha256 = __import__("hashlib").sha256(archive_bytes).hexdigest()
    return pack, manifest, archive_sha256


def _build_ui(env: dict[str, str]) -> None:
    if (ROOT / "ui/dist").is_dir():
        return
    _run([str(NODE_NPM), "--prefix", "ui", "ci"], env=env, timeout=300)
    _run([str(NODE_NPM), "--prefix", "ui", "run", "build"], env=env, timeout=300)


def _build_service_image(*, content_sha: str, pack_sha256: str) -> str:
    from scripts.reproducible_image import (
        BUILDER,
        BUILDX,
        UV_CACHE,
        _check_cache,
        _ensure_builder,
        _offline_environment,
        _prepared_image_check,
    )

    _check_cache()
    contexts = _prepared_image_check()
    environment = _offline_environment()
    _ensure_builder(environment)
    service_sha = _git_sha()
    tag = f"soc-live-boot-check:{service_sha[:12]}"
    source_epoch = _source_epoch()
    command = [
        str(ROOT / "scripts/run-offline.sh"),
        str(BUILDX),
        "build",
        "--builder",
        BUILDER,
        "--platform",
        "linux/amd64",
        "--pull=false",
        "--load",
        "--build-context",
        f"uv-cache={UV_CACHE}",
        "--build-context",
        f"uv-base={contexts['uv']}",
        "--build-context",
        f"python-base={contexts['python']}",
        "--build-arg",
        f"SERVICE_SHA={service_sha}",
        "--build-arg",
        f"CONTENT_SHA={content_sha}",
        "--build-arg",
        f"PACK_SHA256={pack_sha256}",
        "--build-arg",
        f"SOURCE_DATE_EPOCH={source_epoch}",
        "-t",
        tag,
        "-f",
        "Dockerfile",
        str(ROOT),
    ]
    _run(command, env=environment, timeout=900)
    return tag


def _start_protocol_stack(project: str, env: dict[str, str]) -> tuple[str, int]:
    compose = [str(COMPOSE), "--project-name", project, "--file", str(ROOT / "compose.yaml")]
    dynamodb_port = _loopback_port()
    env = env.copy()
    env["DYNAMODB_LOCAL_PORT"] = str(dynamodb_port)
    env["APP_LOCAL_PORT"] = str(_loopback_port())
    _run(
        [
            *compose,
            "up",
            "--detach",
            "--no-build",
            "--pull",
            "never",
            "dynamodb-local",
            "adot-collector",
        ],
        env=env,
        timeout=120,
    )
    network = _run(
        [
            "docker",
            "network",
            "ls",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--format",
            "{{.Name}}",
        ],
        env=env,
    ).splitlines()[0]
    return network, dynamodb_port


def _prepared_image_reference(name: str) -> str:
    prepared_path = ROOT / "build/tool-cache/container-images.json"
    payload = json.loads(prepared_path.read_text(encoding="utf-8"))
    for entry in payload.get("images", []):
        if entry.get("name") == name:
            reference = entry.get("reference")
            if isinstance(reference, str):
                return reference
    raise RuntimeError(f"prepared image {name} missing; run scripts/prepare_containers.py")


def _start_s3_stand_in(
    network: str, project: str, env: dict[str, str], *, archive: Path, key: str
) -> tuple[str, str]:
    import boto3
    from botocore.config import Config

    name = f"soclive-s3-{uuid4().hex[:8]}"
    host_port = _loopback_port()
    image = _prepared_image_reference(S3_STANDIN_NAME)
    _run(
        [
            "docker",
            "run",
            "--pull=never",
            "-d",
            "--name",
            name,
            "--network",
            network,
            "--label",
            "com.ai-soc.standin=s3",
            *_ownership_label_args(project),
            "--pull=never",
            "-p",
            f"127.0.0.1:{host_port}:{S3_STANDIN_PORT}",
            "-e",
            f"COM_ADOBE_TESTING_S3MOCK_STORE_INITIAL_BUCKETS={S3_BUCKET}",
            "-e",
            "COM_ADOBE_TESTING_S3MOCK_STORE_REGION=us-east-1",
            image,
        ],
        env=env,
        timeout=120,
    )
    endpoint = f"http://127.0.0.1:{host_port}"
    client = boto3.client(
        "s3",
        region_name="us-east-1",
        endpoint_url=endpoint,
        aws_access_key_id=S3_ACCESS,
        aws_secret_access_key=S3_SECRET,
        config=Config(
            signature_version="s3v4",
            retries={"total_max_attempts": 5, "mode": "standard"},
        ),
    )
    for _attempt in range(30):
        try:
            client.put_object(
                Bucket=S3_BUCKET,
                Key=key,
                Body=archive.read_bytes(),
            )
            break
        except Exception:
            time.sleep(0.5)
    else:
        raise RuntimeError("S3 stand-in did not accept pack upload")
    print(f"LOCAL_STANDIN_S3: S3Mock container {name} on {network} (not AWS)")
    return f"http://{name}:{S3_STANDIN_PORT}", name


def _ddb_create_table(port: int, table: str) -> None:
    import boto3
    from botocore.config import Config

    client = boto3.client(
        "dynamodb",
        region_name="us-east-1",
        endpoint_url=f"http://127.0.0.1:{port}",
        aws_access_key_id="LOCALKEY",
        aws_secret_access_key="LOCALSECRET",
        config=Config(retries={"total_max_attempts": 2, "mode": "standard"}),
    )
    client.create_table(
        TableName=table,
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _secret_env(ca_pem: str) -> dict[str, str]:
    key = base64.b64encode(b"k" * 32).decode()
    return {
        "SOC_CURSOR_KEY_ID_CURRENT": "current",
        "SOC_CURSOR_KEY_ID_PREVIOUS": "previous",
        "SOC_CURSOR_AEAD_CURRENT": key,
        "SOC_CURSOR_AEAD_PREVIOUS": key,
        "SOC_RECEIPT_KEY_ID_CURRENT": "current",
        "SOC_RECEIPT_KEY_ID_PREVIOUS": "previous",
        "SOC_FEEDBACK_RECEIPT_CURRENT": key,
        "SOC_FEEDBACK_RECEIPT_PREVIOUS": key,
        "SOC_CSRF_SECRET": key,
        "SOC_SITE_ALPHA_CA": ca_pem,
    }


def _container_env(
    sealed_json: str,
    *,
    network_ddb: str,
    s3_endpoint: str,
    table: str,
    site_ca_pem: str | None = None,
) -> dict[str, str]:
    env = {
        "SOC_MODE": "live",
        "AWS_REGION": "us-east-1",
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_ACCESS_KEY_ID": S3_ACCESS,
        "AWS_SECRET_ACCESS_KEY": S3_SECRET,
        "SOC_SERVICE_CONFIG_JSON": sealed_json,
        "SOC_DYNAMODB_ENDPOINT_URL": "http://dynamodb-local:8000",
        "SOC_S3_ENDPOINT_URL": s3_endpoint,
        "SOC_KMS_ENDPOINT_URL": "http://127.0.0.1:9",
        "SOC_SQS_ENDPOINT_URL": "http://127.0.0.1:9",
        "SOC_BEDROCK_ENDPOINT_URL": "http://127.0.0.1:9",
        "OTEL_EXPORTER_OTLP_ENDPOINT": "http://adot-collector:4317",
        "OTEL_EXPORTER_OTLP_PROTOCOL": "grpc",
        "SOC_CLOUDWATCH_NAMESPACE": "AISOC/Service",
    }
    from tests.unit.live.live_boot_fixture import _CA_PEM

    env.update(_secret_env(site_ca_pem or _CA_PEM))
    print("LOCAL_STANDIN_INDEXER: request stand-in configured for the login-gated page smoke")
    print("LOCAL_STANDIN_SQS/BEDROCK: endpoints set; not exercised by the local smoke")
    print(f"LOCAL_STANDIN_DYNAMODB: dynamodb-local on {network_ddb}")
    return env


def _verify_image_tmp_volume(image: str, docker_env: dict[str, str]) -> None:
    """Require the built image to declare the ECS task's writable /tmp volume."""
    declared = _run(
        ["docker", "image", "inspect", "--format", "{{json .Config.Volumes}}", image],
        env=docker_env,
        timeout=30,
    )
    volumes = json.loads(declared)
    if not isinstance(volumes, dict) or "/tmp" not in volumes:
        raise RuntimeError(f"service image {image} must declare /tmp in Config.Volumes")


def _prepare_fargate_like_tmp_volume(
    volume: str, image: str, docker_env: dict[str, str], *, project: str
) -> None:
    """Root-owned 0755 empty /tmp matches default ECS bind-mount behavior for unnamed volumes."""
    _run(
        [
            "docker",
            "run",
            "--pull=never",
            "--rm",
            *_ownership_label_args(project),
            "--user",
            "0:0",
            "-v",
            f"{volume}:/mnt",
            "--entrypoint",
            "python",
            image,
            "-c",
            "from pathlib import Path; import os, shutil; p=Path('/mnt'); "
            "[(shutil.rmtree(x) if x.is_dir() and not x.is_symlink() else x.unlink()) "
            "for x in p.iterdir()]; os.chown(p, 0, 0); os.chmod(p, 0o755)",
        ],
        env=docker_env,
        timeout=120,
    )


def _verify_fargate_tmp_writable(
    image: str, volume: str, docker_env: dict[str, str], *, project: str
) -> None:
    """Exercise the task user's /tmp access against the root-owned ECS-like volume."""
    _run(
        [
            "docker",
            "run",
            "--pull=never",
            "--rm",
            *_ownership_label_args(project),
            "--user",
            "10001:10001",
            "--read-only",
            "-v",
            f"{volume}:/tmp",
            "--entrypoint",
            "python",
            image,
            "-c",
            "from pathlib import Path; Path('/tmp/fargate-volume-probe').write_text('ok')",
        ],
        env=docker_env,
        timeout=120,
    )


def _start_indexer_standin(
    network: str,
    docker_env: dict[str, str],
    *,
    image: str,
    cert_dir: Path,
    tls: object,
    project: str,
) -> tuple[str, Path, str]:
    from scripts.live_boot_entrypoint_smoke import StandinTls

    if not isinstance(tls, StandinTls):
        raise TypeError("indexer stand-in requires generated TLS material")
    cert_dir = cert_dir.resolve()
    cert_dir.mkdir(parents=True, exist_ok=True)
    name = f"soclive-indexer-{uuid4().hex[:6]}"
    cert_file = cert_dir / f"{name}-cert.pem"
    key_file = cert_dir / f"{name}-key.pem"
    hits_file = cert_dir / f"{name}-hits.txt"
    cert_file.write_text(tls.cert_pem, encoding="utf-8")
    key_file.write_text(tls.key_pem, encoding="utf-8")
    hits_file.write_text("", encoding="utf-8")
    completed = subprocess.run(
        [
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
            "com.ai-soc.standin=indexer",
            *_ownership_label_args(project),
            "--user",
            "0:0",
            "-v",
            f"{(ROOT / 'scripts/live_boot_indexer_standin.py').resolve()}:/standin.py:ro",
            "-v",
            f"{cert_file}:/standin-cert.pem:ro",
            "-v",
            f"{key_file}:/standin-key.pem:ro",
            "-v",
            f"{hits_file}:/standin-hits.txt:rw",
            "-e",
            "LOCAL_STANDIN_TLS_CERT_PATH=/standin-cert.pem",
            "-e",
            "LOCAL_STANDIN_TLS_KEY_PATH=/standin-key.pem",
            "-e",
            "LOCAL_STANDIN_HITS_PATH=/standin-hits.txt",
            image,
            "/service/.venv/bin/python",
            "/standin.py",
        ],
        cwd=ROOT,
        env=docker_env,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            f"local indexer stand-in failed: {(completed.stderr or completed.stdout)[:2000]}"
        )
    running = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", name],
        cwd=ROOT,
        env=docker_env,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if running != "true":
        logs = subprocess.run(
            ["docker", "logs", name],
            env=docker_env,
            capture_output=True,
            text=True,
            check=False,
        )
        raise RuntimeError(f"local indexer stand-in not running: {logs.stderr or logs.stdout}")
    address = _run(
        [
            "docker",
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            name,
        ],
        env=docker_env,
    )
    if not address:
        raise RuntimeError("could not resolve local indexer stand-in address")
    print(f"LOCAL_STANDIN_INDEXER: HTTPS stand-in for https://{tls.hostname}:9200")
    return name, hits_file, address


def _start_kms_standin(
    network: str,
    docker_env: dict[str, str],
    *,
    image: str,
    cert_dir: Path,
    private_key_pem: str,
    project: str,
) -> str:
    cert_dir = cert_dir.resolve()
    cert_dir.mkdir(parents=True, exist_ok=True)
    name = f"soclive-kms-{uuid4().hex[:6]}"
    key_file = cert_dir / f"{name}-key.pem"
    key_file.write_text(private_key_pem, encoding="utf-8")
    completed = subprocess.run(
        [
            "docker",
            "run",
            "--pull=never",
            "-d",
            "--name",
            name,
            "--network",
            network,
            "--network-alias",
            "kms-standin",
            "--label",
            "com.ai-soc.standin=kms",
            *_ownership_label_args(project),
            "--user",
            "0:0",
            "-v",
            f"{(ROOT / 'scripts/live_boot_kms_standin.py').resolve()}:/standin.py:ro",
            "-v",
            f"{key_file}:/standin-key.pem:ro",
            "-e",
            "LOCAL_STANDIN_KMS_PRIVATE_KEY_PATH=/standin-key.pem",
            image,
            "/service/.venv/bin/python",
            "/standin.py",
        ],
        cwd=ROOT,
        env=docker_env,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            f"local KMS stand-in failed: {(completed.stderr or completed.stdout)[:2000]}"
        )
    print("LOCAL_STANDIN_KMS: local Sign protocol endpoint; not AWS")
    return name


def _run_container(
    image: str,
    *,
    name: str,
    network: str,
    env: dict[str, str],
    host_port: int,
    docker_env: dict[str, str],
    project: str,
    detach: bool = True,
    extra_hosts: dict[str, str] | None = None,
) -> str:
    args = ["docker", "run", "--pull=never"]
    if detach:
        args.append("-d")
    tmp_volume = f"{TMP_VOLUME_PREFIX}{uuid4().hex[:12]}"
    _prepare_fargate_like_tmp_volume(tmp_volume, image, docker_env, project=project)
    _verify_fargate_tmp_writable(image, tmp_volume, docker_env, project=project)
    args.extend(
        [
            "--name",
            name,
            *_ownership_label_args(project),
            "--network",
            network,
            "--read-only",
            "-v",
            f"{tmp_volume}:/tmp",
            "--security-opt",
            "no-new-privileges:true",
            "-p",
            f"127.0.0.1:{host_port}:8000",
        ]
    )
    for key, value in env.items():
        args.extend(["-e", f"{key}={value}"])
    for hostname, address in (extra_hosts or {}).items():
        args.extend(["--add-host", f"{hostname}:{address}"])
    args.append(image)
    return _run(args, env=docker_env, check=True)


def _wait_http(url: str, *, expect: int, timeout: float = 60.0) -> None:
    end = time.monotonic() + timeout
    last_error = ""
    while time.monotonic() < end:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == expect:
                    return
                last_error = f"status {response.status}"
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            last_error = str(error)
        time.sleep(1)
    raise RuntimeError(f"{url} did not return {expect}: {last_error}")


def _container_exit_failed(
    image: str,
    *,
    network: str,
    env: dict[str, str],
    docker_env: dict[str, str],
    project: str,
) -> None:
    name = f"soclive-fail-{uuid4().hex[:6]}"
    tmp_volume = f"{TMP_VOLUME_PREFIX}{uuid4().hex[:12]}"
    _prepare_fargate_like_tmp_volume(tmp_volume, image, docker_env, project=project)
    _verify_fargate_tmp_writable(image, tmp_volume, docker_env, project=project)
    args = [
        "docker",
        "run",
        "--pull=never",
        "--rm",
        "--name",
        name,
        *_ownership_label_args(project),
        "--network",
        network,
        "--read-only",
        "-v",
        f"{tmp_volume}:/tmp",
    ]
    for key, value in env.items():
        args.extend(["-e", f"{key}={value}"])
    args.append(image)
    result = subprocess.run(
        args, cwd=ROOT, env=docker_env, capture_output=True, text=True, timeout=90
    )
    if result.returncode == 0:
        raise RuntimeError("expected container startup to fail")


def _pytest_runtime_gate(dynamodb_port: int, docker_env: dict[str, str]) -> None:
    offline = ROOT / "scripts/run-offline.sh"
    env = docker_env.copy()
    env["LIVE_BOOT_CHECK"] = "1"
    env["DYNAMODB_LOCAL_ENDPOINT"] = f"http://127.0.0.1:{dynamodb_port}"
    missing = env.pop("DYNAMODB_LOCAL_ENDPOINT")
    gate_test = "tests/unit/live/test_live_boot_gate.py"
    probe = subprocess.run(
        [
            str(offline),
            "uv",
            "run",
            "--locked",
            "--offline",
            "python",
            "-m",
            "pytest",
            "-q",
            gate_test,
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    if probe.returncode == 0:
        raise RuntimeError("runtime gate must fail when DYNAMODB_LOCAL_ENDPOINT is missing")
    env["DYNAMODB_LOCAL_ENDPOINT"] = missing
    positive_output = _run(
        [
            str(offline),
            "uv",
            "run",
            "--locked",
            "--offline",
            "python",
            "-m",
            "pytest",
            "-q",
            "--strict-markers",
            "-m",
            "live",
            gate_test,
        ],
        env=env,
        timeout=300,
    )
    if "1 passed" not in positive_output:
        raise RuntimeError(
            "runtime gate positive sentinel must execute and pass; "
            f"pytest output was: {positive_output!r}"
        )


def _cleanup(project: str, docker_env: dict[str, str], names: list[str]) -> None:
    compose = [str(COMPOSE), "--project-name", project, "--file", str(ROOT / "compose.yaml")]
    failed = sys.exc_info()[0] is not None
    for name in names:
        if failed and name.startswith("soclive-s3-"):
            logs = subprocess.run(
                ["docker", "logs", name],
                cwd=ROOT,
                env=docker_env,
                capture_output=True,
                text=True,
                check=False,
            )
            detail = logs.stdout + logs.stderr
            print(f"LOCAL_STANDIN_S3_LOGS {name}:\n{detail or '<empty>'}")
        subprocess.run(
            ["docker", "rm", "-f", name],
            cwd=ROOT,
            env=docker_env,
            capture_output=True,
            text=True,
        )
    standins = subprocess.run(
        [
            "docker",
            "ps",
            "-aq",
            "--filter",
            f"label={RUN_OWNERSHIP_LABEL}={project}",
        ],
        cwd=ROOT,
        env=docker_env,
        capture_output=True,
        text=True,
    ).stdout.split()
    for container_id in standins:
        if container_id:
            subprocess.run(
                ["docker", "rm", "-f", container_id],
                cwd=ROOT,
                env=docker_env,
                capture_output=True,
                text=True,
            )
    subprocess.run([*compose, "down", "--remove-orphans", "-v"], cwd=ROOT, env=docker_env)


def main() -> int:
    sys.path.insert(0, str(ROOT))
    from ai_soc.contracts.models import PackManifest
    from tests.unit.live.live_boot_fixture import sealed_document

    docker_env = _docker_env()
    project = f"soclive-{uuid4().hex[:10]}"
    docker_env["DYNAMODB_LOCAL_PORT"] = "18000"
    docker_env["APP_LOCAL_PORT"] = "18001"
    containers: list[str] = []
    try:
        work = ROOT / "build/live-boot-seed"
        pack_dir, manifest_raw, archive_sha = _prepare_pack(work, docker_env)
        manifest = PackManifest.model_validate(manifest_raw)
        docker_env["SERVICE_SHA"] = _git_sha()
        docker_env["CONTENT_SHA"] = manifest.content_sha
        docker_env["SOURCE_DATE_EPOCH"] = _source_epoch()
        _run([sys.executable, str(ROOT / "scripts/prepare_containers.py")], env=docker_env)
        _run(
            [
                "uv",
                "run",
                "--locked",
                "--offline",
                "python",
                str(ROOT / "scripts/reproducible_image.py"),
                "prepare-cache",
                "--uv",
                "uv",
            ],
            env=docker_env,
            timeout=600,
        )
        _build_ui(docker_env)
        image = _build_service_image(
            content_sha=manifest.content_sha,
            pack_sha256=manifest.pack_sha256,
        )
        _verify_image_tmp_volume(image, docker_env)
        network, ddb_port = _start_protocol_stack(project, docker_env)
        s3_key = f"packs/{manifest.content_sha}/content.tar"
        s3_endpoint, s3_name = _start_s3_stand_in(
            network,
            project,
            docker_env,
            archive=pack_dir / "content.tar",
            key=s3_key,
        )
        containers.append(s3_name)
        table = "soc-live-boot-check"
        _ddb_create_table(ddb_port, table)
        service_sha = _git_sha()
        from hashlib import sha256 as _sha256

        from scripts.live_boot_entrypoint_smoke import (
            BROWSER_ORIGIN,
            ISSUER,
            RESOURCE,
            assert_identity_standins_contacted,
            assert_indexer_standin_contacted,
            augmented_ca_bundle,
            build_smoke_page_cursor,
            generate_smoke_keys,
            run_entrypoint_smoke,
            start_identity_standins,
        )
        from tests.unit.live.live_boot_fixture import _CA_PEM

        smoke_keys = generate_smoke_keys()
        ca_pem = augmented_ca_bundle(_CA_PEM, smoke_keys)
        ca_digest = _sha256(ca_pem.encode("utf-8")).hexdigest()
        sealed = sealed_document(
            manifest,
            service_sha=service_sha,
            image_digest="sha256:" + "d" * 64,
            s3_uri=f"s3://{S3_BUCKET}/{s3_key}",
            archive_sha256=archive_sha,
            dynamodb_table=table,
        )
        standin_jwks_uri = f"{ISSUER}/.well-known/jwks.json"
        indexer_ca_pem = smoke_keys.smoke_ca_pem
        indexer_ca_digest = _sha256(indexer_ca_pem.encode("utf-8")).hexdigest()
        site_for_smoke = sealed.service.sites[0].model_copy(
            update={
                "indexer_origin": "https://alpha.private.example.test:9200",
                "ca_sha256": indexer_ca_digest,
            }
        )
        service_for_smoke = sealed.service.model_copy(
            update={"ca_bundle_sha256": ca_digest, "sites": (site_for_smoke,)}
        )
        sealed = sealed.model_copy(
            update={
                "ca_bundle_pem": ca_pem,
                "service": service_for_smoke,
                "alb": sealed.alb.model_copy(update={"issuer": ISSUER}),
                "mcp": sealed.mcp.model_copy(
                    update={
                        "issuer": ISSUER,
                        "resource": RESOURCE,
                        "jwks_uri": standin_jwks_uri,
                    }
                ),
                "browser_origin": BROWSER_ORIGIN,
            }
        )
        identity_hosts, identity_containers, identity_hits = start_identity_standins(
            network,
            docker_env,
            smoke_keys,
            image=image,
            cert_dir=work / "identity-standins",
            project=project,
        )
        containers.extend(identity_containers)
        indexer_name, indexer_hits, indexer_address = _start_indexer_standin(
            network,
            docker_env,
            image=image,
            cert_dir=work / "indexer-standin",
            tls=smoke_keys.indexer_tls,
            project=project,
        )
        containers.append(indexer_name)
        kms_name = _start_kms_standin(
            network,
            docker_env,
            image=image,
            cert_dir=work / "kms-standin",
            private_key_pem=smoke_keys.kms_private_pem,
            project=project,
        )
        containers.append(kms_name)
        sealed_json = sealed.model_dump_json()
        app_port = _loopback_port()
        app_name = f"soclive-app-{uuid4().hex[:6]}"
        containers.append(app_name)
        app_env = _container_env(
            sealed_json,
            network_ddb=network,
            s3_endpoint=s3_endpoint,
            table=table,
            site_ca_pem=indexer_ca_pem,
        )
        app_env["SOC_KMS_ENDPOINT_URL"] = "http://kms-standin:4566"
        _run_container(
            image,
            name=app_name,
            network=network,
            env=app_env,
            host_port=app_port,
            docker_env=docker_env,
            project=project,
            extra_hosts={
                **identity_hosts,
                "alpha.private.example.test": indexer_address,
            },
        )
        try:
            _wait_http(f"http://127.0.0.1:{app_port}/health/live", expect=200)
        except RuntimeError:
            logs = subprocess.run(
                ["docker", "logs", app_name],
                env=docker_env,
                capture_output=True,
                text=True,
            )
            tail = (logs.stdout or logs.stderr or "")[-4000:]
            raise RuntimeError(f"app container logs:\n{tail}") from None
        _wait_http(f"http://127.0.0.1:{app_port}/health/ready", expect=200)
        page_cursor = build_smoke_page_cursor(sealed.service.sites[0], manifest.content_sha)
        run_entrypoint_smoke(f"http://127.0.0.1:{app_port}", smoke_keys, page_cursor=page_cursor)
        assert_identity_standins_contacted(identity_hits)
        assert_indexer_standin_contacted(indexer_hits)
        print(
            "LOCAL_STANDIN_ENTRYPOINT: MCP, login-gated REST page, one TLS indexer fetch, "
            "and UI asset smoke passed"
        )

        bad_config = _container_env(
            "{}",
            network_ddb=network,
            s3_endpoint=s3_endpoint,
            table=table,
        )
        _container_exit_failed(
            image, network=network, env=bad_config, docker_env=docker_env, project=project
        )

        invalid_service = sealed.model_copy(
            update={
                "service": sealed.service.model_copy(update={"guardrail_identifier": "DRAFT"}),
            }
        )
        _container_exit_failed(
            image,
            network=network,
            env=_container_env(
                invalid_service.model_dump_json(),
                network_ddb=network,
                s3_endpoint=s3_endpoint,
                table=table,
                site_ca_pem=indexer_ca_pem,
            ),
            docker_env=docker_env,
            project=project,
        )

        bad_ca = sealed.model_copy(
            update={"service": sealed.service.model_copy(update={"ca_bundle_sha256": "0" * 64})}
        )
        _container_exit_failed(
            image,
            network=network,
            env=_container_env(
                bad_ca.model_dump_json(),
                network_ddb=network,
                s3_endpoint=s3_endpoint,
                table=table,
                site_ca_pem=indexer_ca_pem,
            ),
            docker_env=docker_env,
            project=project,
        )

        bad_pack = sealed.model_copy(
            update={
                "content_pack": sealed.content_pack.model_copy(update={"pack_sha256": "0" * 64})
            }
        )
        _container_exit_failed(
            image,
            network=network,
            env=_container_env(
                bad_pack.model_dump_json(),
                network_ddb=network,
                s3_endpoint=s3_endpoint,
                table=table,
                site_ca_pem=indexer_ca_pem,
            ),
            docker_env=docker_env,
            project=project,
        )

        _pytest_runtime_gate(ddb_port, docker_env)
        print("live-boot-check: passed (local stand-ins only, not AWS validation)")
        return 0
    finally:
        _cleanup(project, docker_env, containers)


if __name__ == "__main__":
    raise SystemExit(main())
