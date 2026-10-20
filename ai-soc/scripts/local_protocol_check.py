#!/usr/bin/env python3
"""Exercise only this checkout's private Compose DynamoDB and ADOT services."""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Protocol, cast
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
DOCKER_CONFIG = ROOT / "build/private/docker-config"
PREPARED_PATH = ROOT / "build/tool-cache/container-images.json"
COMPOSE = ROOT / "build/tool-cache/docker-compose-v5.5.1/docker-compose"
LOCK_PATH = ROOT / "dev/toolchain.lock.json"
IMAGE_FORMAT = "{{.Id}}|{{.Os}}|{{.Architecture}}|{{json .RepoDigests}}"


class DynamoClient(Protocol):
    def list_tables(self) -> Mapping[str, object]: ...

    def create_table(
        self,
        *,
        TableName: str,
        AttributeDefinitions: list[dict[str, str]],
        KeySchema: list[dict[str, str]],
        BillingMode: str,
    ) -> Mapping[str, object]: ...

    def put_item(
        self, *, TableName: str, Item: dict[str, dict[str, str]]
    ) -> Mapping[str, object]: ...

    def get_item(
        self,
        *,
        TableName: str,
        Key: dict[str, dict[str, str]],
        ConsistentRead: bool,
    ) -> Mapping[str, object]: ...

    def delete_table(self, *, TableName: str) -> Mapping[str, object]: ...

    def close(self) -> None: ...


def _select_loopback_ephemeral_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _docker_env() -> dict[str, str]:
    config_path = DOCKER_CONFIG / "config.json"
    if not config_path.is_file() or config_path.read_text() != '{"auths":{}}\n':
        raise RuntimeError("anonymous task-local Docker config is missing or changed")
    env = os.environ.copy()
    env["DOCKER_CONFIG"] = str(DOCKER_CONFIG)
    env["DOCKER_HOST"] = "unix:///var/run/docker.sock"
    env["SOURCE_DATE_EPOCH"] = "0"
    env["SERVICE_SHA"] = "0000000000000000000000000000000000000000"
    env["CONTENT_SHA"] = "1111111111111111111111111111111111111111"
    env["DYNAMODB_LOCAL_PORT"] = str(_select_loopback_ephemeral_port())
    env["APP_LOCAL_PORT"] = str(_select_loopback_ephemeral_port())
    for name in ("DOCKER_CONTEXT", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY"):
        env.pop(name, None)
    for name in tuple(env):
        if name.startswith("AWS_") or name.startswith("SOC_"):
            env.pop(name, None)
    return env


def _run(args: list[str], *, env: dict[str, str], timeout: int = 60) -> str:
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        check=False,
        env=env,
        cwd=ROOT,
        timeout=timeout,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"{Path(args[0]).name} failed ({result.returncode}): {detail[:1000]}")
    return result.stdout.strip()


def _locked_images() -> dict[str, str]:
    lock: object = json.loads(LOCK_PATH.read_text())
    if not isinstance(lock, dict):
        raise ValueError("toolchain lock is not an object")
    image_rows = cast(dict[str, object], lock).get("images")
    if not isinstance(image_rows, list):
        raise ValueError("toolchain lock images are missing")
    images: dict[str, str] = {}
    for raw in cast(list[object], image_rows):
        if not isinstance(raw, dict):
            raise ValueError("invalid toolchain image entry")
        entry = cast(dict[str, object], raw)
        name, reference = entry.get("name"), entry.get("reference")
        if isinstance(name, str) and isinstance(reference, str):
            images[name] = reference
    return images


def _verify_prepared_images() -> dict[str, str]:
    prepared: object = json.loads(PREPARED_PATH.read_text())
    if not isinstance(prepared, dict):
        raise ValueError("prepared container manifest is malformed")
    prepared_rows = cast(dict[str, object], prepared).get("images")
    if not isinstance(prepared_rows, list):
        raise ValueError("prepared container manifest has no images")
    references: dict[str, str] = {}
    for raw in cast(list[object], prepared_rows):
        if not isinstance(raw, dict):
            raise ValueError("malformed prepared image entry")
        entry = cast(dict[str, object], raw)
        name, reference = entry.get("name"), entry.get("reference")
        if isinstance(name, str) and isinstance(reference, str):
            references[name] = reference
    locked = _locked_images()
    if references != locked:
        raise RuntimeError("prepared container image identities differ from the exact lock")
    for name in ("dynamodb-local", "adot-collector", "python"):
        if name not in locked:
            raise RuntimeError(f"required fixture image {name} is not pinned")
    return locked


def _check_container(container_id: str, *, project: str, env: dict[str, str]) -> None:
    output = _run(
        ["docker", "inspect", "--format", "{{json .Config.Labels}}", container_id], env=env
    )
    labels_value: object = json.loads(output)
    if not isinstance(labels_value, dict):
        raise RuntimeError("fixture container has no labels")
    labels = cast(dict[str, object], labels_value)
    if (
        labels.get("com.ai-soc.owner") != "soc-local-compose"
        or labels.get("com.docker.compose.project") != project
    ):
        raise RuntimeError("refusing to operate on a container outside this Compose project")


def _published_loopback_port(value: str, *, expected: int) -> int:
    match = re.fullmatch(r"127\.0\.0\.1:([1-9][0-9]*)", value)
    if match is None or int(match.group(1)) != expected:
        raise RuntimeError("DynamoDB Local must bind only its selected nonzero loopback TCP port")
    return expected


def _check_loopback_binding(container_id: str, *, expected_port: int, env: dict[str, str]) -> None:
    output = _run(
        [
            "docker",
            "inspect",
            "--format",
            "{{json .NetworkSettings.Ports}}|{{json .HostConfig.PortBindings}}",
            container_id,
        ],
        env=env,
    )
    effective_text, configured_text = output.split("|", maxsplit=1)
    effective_value: object = json.loads(effective_text)
    configured_value: object = json.loads(configured_text)
    expected = [{"HostIp": "127.0.0.1", "HostPort": str(expected_port)}]
    for value in (effective_value, configured_value):
        if not isinstance(value, dict):
            raise RuntimeError("DynamoDB Local has no inspectable effective port binding")
        ports = cast(dict[str, object], value)
        if ports.get("8000/tcp") != expected:
            raise RuntimeError("DynamoDB Local binding is not the selected loopback-only TCP port")


def _dynamodb_smoke(port: int) -> str:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError, ConnectionClosedError, EndpointConnectionError

    table = f"B6fixture{uuid4().hex[:12]}"
    create_client = cast(Callable[..., object], vars(boto3).get("client"))
    client = cast(
        DynamoClient,
        create_client(
            "dynamodb",
            region_name="us-east-1",
            endpoint_url=f"http://127.0.0.1:{port}",
            aws_access_key_id="LOCALB6FIXTUREKEY000",
            aws_secret_access_key="B6LOCALFIXTUREONLY0123456789ABCDEFGHIJKL",
            config=Config(connect_timeout=2, read_timeout=3, retries={"total_max_attempts": 1}),
        ),
    )
    created = False
    try:
        end = time.monotonic() + 30
        while True:
            try:
                client.list_tables()
                break
            except (EndpointConnectionError, ConnectionClosedError):
                if time.monotonic() >= end:
                    raise RuntimeError("local DynamoDB endpoint did not become reachable") from None
                time.sleep(0.5)
            except ClientError as error:
                code = error.response.get("Error", {}).get("Code")
                if code not in {"InternalServerError", "ServiceUnavailable", "RequestTimeout"}:
                    raise RuntimeError(
                        f"local DynamoDB readiness returned non-transient error {code!r}"
                    ) from None
                if time.monotonic() >= end:
                    raise RuntimeError(
                        f"local DynamoDB readiness kept returning {code!r}"
                    ) from None
                time.sleep(0.5)
        client.create_table(
            TableName=table,
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
            BillingMode="PAY_PER_REQUEST",
        )
        created = True
        client.put_item(TableName=table, Item={"pk": {"S": "fixture"}, "value": {"S": "ok"}})
        result = client.get_item(
            TableName=table,
            Key={"pk": {"S": "fixture"}},
            ConsistentRead=True,
        )
        item = result.get("Item")
        if not isinstance(item, dict):
            raise RuntimeError("local DynamoDB protocol returned an unexpected fixture item")
        item_map = cast(dict[str, object], item)
        if item_map.get("value") != {"S": "ok"}:
            raise RuntimeError("local DynamoDB protocol returned an unexpected fixture item")
        return table
    finally:
        if created:
            client.delete_table(TableName=table)
        client.close()


def main() -> int:
    env = _docker_env()
    images = _verify_prepared_images()
    run_id = uuid4().hex[:10]
    project = f"socb6-{run_id}"
    compose_args = [str(COMPOSE), "--project-name", project, "--file", "compose.yaml"]
    started = False
    try:
        _run([*compose_args, "config", "--quiet"], env=env)
        started = True
        _run(
            [
                *compose_args,
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
        dynamodb_id = _run([*compose_args, "ps", "--quiet", "dynamodb-local"], env=env)
        adot_id = _run([*compose_args, "ps", "--quiet", "adot-collector"], env=env)
        if not dynamodb_id or not adot_id:
            raise RuntimeError("Compose did not start both local protocol services")
        _check_container(dynamodb_id.splitlines()[0], project=project, env=env)
        _check_container(adot_id.splitlines()[0], project=project, env=env)

        port_text = _run([*compose_args, "port", "dynamodb-local", "8000"], env=env)
        expected_port = int(env["DYNAMODB_LOCAL_PORT"])
        port = _published_loopback_port(port_text, expected=expected_port)
        _check_loopback_binding(dynamodb_id.splitlines()[0], expected_port=expected_port, env=env)
        table = _dynamodb_smoke(port)

        networks = _run(
            [
                "docker",
                "network",
                "ls",
                "--quiet",
                "--filter",
                f"label=com.docker.compose.project={project}",
            ],
            env=env,
        ).splitlines()
        if len(networks) != 1:
            raise RuntimeError("fixture Compose project must own exactly one private network")
        network_id = networks[0]
        labels = _run(
            ["docker", "network", "inspect", "--format", "{{json .Labels}}", network_id], env=env
        )
        label_value: object = json.loads(labels)
        if (
            not isinstance(label_value, dict)
            or cast(dict[str, object], label_value).get("com.docker.compose.project") != project
        ):
            raise RuntimeError("refusing to attach the probe to an unowned network")
        network_name = _run(
            ["docker", "network", "inspect", "--format", "{{.Name}}", network_id], env=env
        )

        site_packages = next((ROOT / ".venv/lib").glob("python*/site-packages"), None)
        if site_packages is None:
            raise RuntimeError("locked host Python environment is missing OTLP protocol packages")
        probe_name = f"socb6-{run_id}-otlp"
        _run(
            [
                "docker",
                "run",
                "--rm",
                "--name",
                probe_name,
                "--label",
                "com.ai-soc.owner=soc-local-compose",
                "--label",
                f"com.docker.compose.project={project}",
                "--network",
                network_name,
                "--read-only",
                "--tmpfs",
                "/tmp:size=4m,noexec,nosuid",
                "--security-opt",
                "no-new-privileges:true",
                "--user",
                "10001:10001",
                "--env",
                "PYTHONDONTWRITEBYTECODE=1",
                "--env",
                "PYTHONPATH=/fixture/site-packages",
                "--mount",
                f"type=bind,source={site_packages},target=/fixture/site-packages,readonly",
                "--mount",
                f"type=bind,source={ROOT / 'scripts/otlp-probe.py'},"
                "target=/fixture/otlp_probe.py,readonly",
                images["python"],
                "python",
                "/fixture/otlp_probe.py",
            ],
            env=env,
            timeout=30,
        )

        evidence = {
            "schema_version": "1",
            "project": project,
            "services": {
                "dynamodb-local": images["dynamodb-local"],
                "adot-collector": images["adot-collector"],
            },
            "dynamodb": {
                "protocol": "boto3",
                "consistent_read": True,
                "temporary_table": table,
                "host_ip": "127.0.0.1",
                "ephemeral_port": port,
                "compose_port_output": port_text,
            },
            "otlp": {
                "protocol": "gRPC",
                "collector": "adot-collector:4317",
                "acknowledged_spans": 1,
            },
            "network": "probe joined only the owned Compose internal network",
        }
        path = ROOT / "build/evidence/local-protocol.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        print(f"local protocol smoke passed for uniquely scoped Compose project {project}")
        print(f"evidence: {path.relative_to(ROOT)}")
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, StopIteration) as exc:
        print(f"LOCAL_PROTOCOL_FAILED: {exc}", file=sys.stderr)
        return 1
    finally:
        if started:
            subprocess.run(
                [*compose_args, "down", "--volumes", "--remove-orphans", "--timeout", "10"],
                capture_output=True,
                text=True,
                check=False,
                env=env,
                timeout=60,
            )


if __name__ == "__main__":
    raise SystemExit(main())
