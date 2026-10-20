#!/usr/bin/env python3
"""Run admission protocol tests with task-owned, digest-pinned local containers."""

from __future__ import annotations

import json
import os
import secrets
import socket
import subprocess
import sys
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[3]
LOCK = ROOT / "dev/toolchain.lock.json"
PREPARED = ROOT / "build/tool-cache/container-images.json"
DOCKER_CONFIG = ROOT / "build/private/docker-config"
OWNER = "soc-b3-admission-runtime"


def _python_mounts(entrypoint: Path) -> list[str]:
    """Read-only binds for the interpreter the venv entrypoint runs.

    Always the resolved interpreter root. When uv links the venv through a
    minor-version directory (cpython-3.12-... -> cpython-3.12.13-...), also the
    linked root, so the entrypoint's own link resolves inside the container.
    Roots under ROOT are already supplied by the repo mount.
    """
    roots = [entrypoint.resolve(strict=True).parents[1]]
    if entrypoint.is_symlink():
        linked = Path(os.path.abspath(entrypoint.parent.resolve() / os.readlink(entrypoint)))
        if linked.parent.name == "bin" and not linked.parent.is_symlink():
            roots.insert(0, linked.parents[1])
    return [
        argument
        for root in dict.fromkeys(roots)
        if not root.is_relative_to(ROOT)
        for argument in ("--mount", f"type=bind,src={root},dst={root},readonly")
    ]


def _run(args: list[str], *, env: dict[str, str], check: bool = True, timeout: int = 60) -> str:
    result = subprocess.run(
        args,
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    if check and result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"{Path(args[0]).name} failed ({result.returncode}): {detail}")
    return result.stdout.strip()


def _port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _references() -> dict[str, str]:
    lock_value: object = json.loads(LOCK.read_text(encoding="utf-8"))
    prepared_value: object = json.loads(PREPARED.read_text(encoding="utf-8"))
    if not isinstance(lock_value, dict) or not isinstance(prepared_value, dict):
        raise RuntimeError("pinned image registries are not objects")
    lock_images = cast(dict[str, object], lock_value).get("images")
    prepared_images = cast(dict[str, object], prepared_value).get("images")
    if not isinstance(lock_images, list) or not isinstance(prepared_images, list):
        raise RuntimeError("pinned image registries are missing image rows")

    def rows(value: list[object]) -> dict[str, str]:
        output: dict[str, str] = {}
        for raw in value:
            if not isinstance(raw, dict):
                raise RuntimeError("pinned image row is malformed")
            row = cast(dict[str, object], raw)
            name, reference = row.get("name"), row.get("reference")
            if isinstance(name, str) and isinstance(reference, str):
                output[name] = reference
        return output

    locked = rows(cast(list[object], lock_images))
    actual = rows(cast(list[object], prepared_images))
    if actual != locked:
        raise RuntimeError("prepared image identities differ from the repository lock")
    if not {"python", "dynamodb-local"} <= locked.keys():
        raise RuntimeError("the frozen Python or DynamoDB Local image is not prepared")
    return locked


def _assert_owned(container: str, env: dict[str, str]) -> None:
    raw = _run(["docker", "inspect", "--format", "{{json .Config.Labels}}", container], env=env)
    labels_value: object = json.loads(raw)
    if not isinstance(labels_value, dict):
        raise RuntimeError("fixture container has no labels")
    labels = cast(dict[str, object], labels_value)
    if labels.get("com.ai-soc.owner") != OWNER:
        raise RuntimeError("refusing to manage a container without this task's ownership label")


def main() -> int:
    config = DOCKER_CONFIG / "config.json"
    if config.read_text(encoding="utf-8") != '{"auths":{}}\n':
        raise RuntimeError("task-local anonymous Docker config is missing or changed")
    env = os.environ.copy()
    env["DOCKER_CONFIG"] = str(DOCKER_CONFIG)
    env["DOCKER_HOST"] = "unix:///var/run/docker.sock"
    env.pop("DOCKER_CONTEXT", None)
    env.pop("DOCKER_CERT_PATH", None)
    env.pop("DOCKER_TLS_VERIFY", None)
    references = _references()
    suffix = secrets.token_hex(6)
    network = f"b3-admission-{suffix}"
    dynamo = f"b3-admission-ddb-{suffix}"
    port = _port()
    network_created = False
    container_created = False
    try:
        _run(
            [
                "docker",
                "network",
                "create",
                "--driver",
                "bridge",
                "--opt",
                "com.docker.network.bridge.enable_ip_masquerade=false",
                "--label",
                f"com.ai-soc.owner={OWNER}",
                "--label",
                "com.ai-soc.scope=admission-runtime-tests",
                network,
            ],
            env=env,
        )
        network_created = True
        network_document = json.loads(_run(["docker", "network", "inspect", network], env=env))
        if not isinstance(network_document, list) or not network_document:
            raise RuntimeError("created fixture network could not be inspected")
        network_row = cast(dict[str, object], network_document[0])
        if (
            network_row.get("Driver") != "bridge"
            or network_row.get("Internal") is not False
            or network_row.get("Options")
            != {"com.docker.network.bridge.enable_ip_masquerade": "false"}
            or cast(dict[str, object], network_row.get("Labels", {})).get("com.ai-soc.owner")
            != OWNER
        ):
            raise RuntimeError("fixture network differs from the scoped no-masquerade bridge")
        launch = [
            "docker",
            "run",
            "--detach",
            "--name",
            dynamo,
            "--label",
            f"com.ai-soc.owner={OWNER}",
            "--label",
            "com.ai-soc.scope=admission-runtime-tests",
            "--network",
            network,
            "--publish",
            f"127.0.0.1:{port}:8000",
            "--workdir",
            "/home/dynamodblocal",
            "--read-only",
            "--tmpfs",
            "/tmp:exec,size=64m,nosuid",
            "--security-opt",
            "no-new-privileges:true",
            references["dynamodb-local"],
            "-Djava.library.path=/home/dynamodblocal/DynamoDBLocal_lib",
            "-jar",
            "DynamoDBLocal.jar",
            "-sharedDb",
            "-inMemory",
            "-disableTelemetry",
        ]
        print("DYNAMODB_DOCKER_LAUNCH=" + json.dumps(launch))
        _run(launch, env=env)
        container_created = True
        _assert_owned(dynamo, env)

        repo = str(ROOT)
        python_mounts = _python_mounts(ROOT / ".venv" / "bin" / "python")
        probe = [
            "docker",
            "run",
            "--rm",
            "--label",
            f"com.ai-soc.owner={OWNER}",
            "--label",
            "com.ai-soc.scope=admission-runtime-readiness",
            "--network",
            f"container:{dynamo}",
            "--mount",
            f"type=bind,src={repo},dst={repo},readonly",
            *python_mounts,
            "--workdir",
            repo,
            "--env",
            "AWS_EC2_METADATA_DISABLED=true",
            "--env",
            "AWS_DEFAULT_REGION=us-east-1",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            "--entrypoint",
            f"{repo}/.venv/bin/python",
            references["python"],
            "tests/integration/admission_runtime/probe.py",
        ]
        print("DYNAMODB_READINESS_PROBE=" + json.dumps(probe))
        print("DYNAMODB_READINESS=" + _run(probe, env=env, timeout=45))

        inspection = _run(
            [
                "docker",
                "inspect",
                "--format",
                "{{json .State}}|{{json .HostConfig.PortBindings}}|{{json .NetworkSettings.Ports}}",
                dynamo,
            ],
            env=env,
        )
        state_text, host_config_text, network_settings_text = inspection.split("|", maxsplit=2)
        state_value: object = json.loads(state_text)
        host_config_value: object = json.loads(host_config_text)
        network_settings_value: object = json.loads(network_settings_text)
        logs = _run(["docker", "logs", dynamo], env=env)
        print("DYNAMODB_STATE=" + json.dumps(state_value, sort_keys=True))
        print("DYNAMODB_HOSTCONFIG_PORTBINDINGS=" + json.dumps(host_config_value))
        print("DYNAMODB_NETWORKSETTINGS_PORTS=" + json.dumps(network_settings_value))
        print("DYNAMODB_LOGS=" + logs)

        if (
            not isinstance(state_value, dict)
            or cast(dict[str, object], state_value).get("Running") is not True
        ):
            raise RuntimeError("DynamoDB Local exited before readiness completed")
        if not isinstance(host_config_value, dict) or not isinstance(network_settings_value, dict):
            raise RuntimeError("DynamoDB Local configured/effective port maps are malformed")
        binding = cast(dict[str, object], network_settings_value).get("8000/tcp")
        expected = [{"HostIp": "127.0.0.1", "HostPort": str(port)}]
        if binding != expected:
            raise RuntimeError(
                "DynamoDB Local effective binding differs after protocol readiness: "
                f"expected {expected!r}, got {binding!r}; "
                f"HostConfig.PortBindings={host_config_value!r}; logs={logs!r}"
            )

        # The fixture runner shares only DynamoDB Local's isolated network namespace.
        command = [
            "docker",
            "run",
            "--rm",
            "--network",
            f"container:{dynamo}",
            "--mount",
            f"type=bind,src={repo},dst={repo},readonly",
            *python_mounts,
            "--workdir",
            repo,
            "--env",
            "DYNAMODB_LOCAL_ENDPOINT=http://127.0.0.1:8000",
            "--env",
            "AWS_EC2_METADATA_DISABLED=true",
            "--env",
            "AWS_DEFAULT_REGION=us-east-1",
            "--entrypoint",
            f"{repo}/.venv/bin/python",
            references["python"],
            "-m",
            "pytest",
            "tests/integration/admission_runtime",
            "-q",
            "--strict-markers",
            "-p",
            "no:cacheprovider",
            "-m",
            "not live",
            *sys.argv[1:],
        ]
        result = subprocess.run(command, cwd=ROOT, env=env, check=False)
        return result.returncode
    finally:
        if container_created:
            _assert_owned(dynamo, env)
            _run(["docker", "rm", "--force", dynamo], env=env)
        if network_created:
            labels_raw = _run(
                ["docker", "network", "inspect", "--format", "{{json .Labels}}", network],
                env=env,
            )
            labels_value: object = json.loads(labels_raw)
            if (
                not isinstance(labels_value, dict)
                or cast(dict[str, object], labels_value).get("com.ai-soc.owner") != OWNER
            ):
                raise RuntimeError(
                    "refusing to remove a network without this task's ownership label"
                )
            _run(["docker", "network", "rm", network], env=env)


if __name__ == "__main__":
    raise SystemExit(main())
