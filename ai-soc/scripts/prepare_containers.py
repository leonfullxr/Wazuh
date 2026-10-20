#!/usr/bin/env python3
"""Prepare only digest-pinned public fixture/build images without HOME credentials."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "dev/toolchain.lock.json"
PREPARED_PATH = ROOT / "build/tool-cache/container-images.json"
DOCKER_CONFIG = ROOT / "build/private/docker-config"
IMAGE_ARCHIVES = ROOT / "build/private/image-docker-archives"
OCI_LAYOUTS = ROOT / "build/private/image-oci-layouts"
IMAGE_FORMAT = "{{.Id}}|{{.Os}}|{{.Architecture}}|{{json .RepoDigests}}"
OCI_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_MEDIA_TYPE = "application/vnd.oci.image.layer.v1.tar"


def _object(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    mapping = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in mapping):
        raise ValueError(f"{label} keys must be strings")
    return cast(dict[str, object], mapping)


def _images() -> list[tuple[str, str]]:
    lock = _object(json.loads(LOCK_PATH.read_text()), label="toolchain lock")
    raw_images = lock.get("images")
    if not isinstance(raw_images, list):
        raise ValueError("toolchain lock images must be a list")
    images: list[tuple[str, str]] = []
    for raw in cast(list[object], raw_images):
        entry = _object(raw, label="toolchain image")
        name, reference = entry.get("name"), entry.get("reference")
        if not isinstance(name, str) or not isinstance(reference, str):
            raise ValueError("toolchain image needs string name and reference")
        if re.search(r"@sha256:[0-9a-f]{64}$", reference) is None:
            raise ValueError(f"{name} image is not SHA-256 digest pinned")
        images.append((name, reference))
    if not images or len({name for name, _ in images}) != len(images):
        raise ValueError("toolchain image names must be nonempty and unique")
    return images


def _run(args: list[str], *, env: dict[str, str]) -> str:
    result = subprocess.run(args, capture_output=True, text=True, check=False, env=env)
    if result.returncode:
        message = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"{Path(args[0]).name} failed ({result.returncode}): {message}")
    return result.stdout.strip()


def _docker_environment() -> dict[str, str]:
    DOCKER_CONFIG.mkdir(parents=True, exist_ok=True)
    config_path = DOCKER_CONFIG / "config.json"
    anonymous_config = '{"auths":{}}\n'
    if config_path.exists():
        if config_path.read_text() != anonymous_config:
            raise RuntimeError("task-local Docker config is not anonymous; refusing to reuse it")
    else:
        config_path.write_text(anonymous_config)
    config_path.chmod(0o600)
    env = os.environ.copy()
    env["DOCKER_CONFIG"] = str(DOCKER_CONFIG)
    env["DOCKER_HOST"] = "unix:///var/run/docker.sock"
    env.pop("DOCKER_CONTEXT", None)
    env.pop("DOCKER_CERT_PATH", None)
    env.pop("DOCKER_TLS_VERIFY", None)
    return env


def _inspect(reference: str, *, env: dict[str, str]) -> dict[str, object]:
    output = _run(["docker", "image", "inspect", "--format", IMAGE_FORMAT, reference], env=env)
    parts = output.split("|", maxsplit=3)
    if len(parts) != 4:
        raise RuntimeError(f"Docker returned malformed image metadata for {reference}")
    image_id, os_name, architecture, raw_digests = parts
    repo_digests_value: object = json.loads(raw_digests)
    if not isinstance(repo_digests_value, list) or not all(
        isinstance(value, str) for value in cast(list[object], repo_digests_value)
    ):
        raise RuntimeError(f"Docker returned malformed repository digests for {reference}")
    repo_digests = cast(list[str], repo_digests_value)
    expected_digest = reference.rsplit("@", maxsplit=1)[1]
    if os_name != "linux" or architecture != "amd64":
        raise RuntimeError(f"{reference} is {os_name}/{architecture}, expected linux/amd64")
    if not any(digest.endswith(f"@{expected_digest}") for digest in repo_digests):
        raise RuntimeError(f"local image does not report the locked digest for {reference}")
    return {
        "reference": reference,
        "image_id": image_id,
        "platform": f"{os_name}/{architecture}",
        "repo_digests": repo_digests,
    }


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _write_blob(layout: Path, payload: bytes) -> dict[str, object]:
    digest = _sha256(payload)
    destination = layout / "blobs/sha256" / digest
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(payload)
    return {"digest": f"sha256:{digest}", "size": len(payload)}


def prepare_local_oci_layout(
    *, name: str, reference: str, image_id: str, env: dict[str, str]
) -> tuple[Path, str]:
    """Convert a locally verified Docker save archive to a BuildKit-readable OCI layout."""
    if name not in {"uv", "python"}:
        raise ValueError(f"unexpected BuildKit base image name: {name}")
    archive_path = IMAGE_ARCHIVES / f"{name}.tar"
    layout = OCI_LAYOUTS / name
    IMAGE_ARCHIVES.mkdir(parents=True, exist_ok=True)
    if layout.exists():
        shutil.rmtree(layout)
    _run(["docker", "image", "save", "--output", str(archive_path), reference], env=env)

    with tarfile.open(archive_path, mode="r:") as archive:
        manifest_member = archive.extractfile("manifest.json")
        if manifest_member is None:
            raise RuntimeError(f"Docker save archive for {name} has no manifest.json")
        docker_manifests: object = json.loads(manifest_member.read())
        if not isinstance(docker_manifests, list):
            raise RuntimeError(f"Docker save archive for {name} must contain one image")
        manifest_entries = cast(list[object], docker_manifests)
        if len(manifest_entries) != 1:
            raise RuntimeError(f"Docker save archive for {name} must contain one image")
        docker_manifest = _object(manifest_entries[0], label=f"{name} Docker archive manifest")
        config_path = docker_manifest.get("Config")
        layer_paths = docker_manifest.get("Layers")
        if not isinstance(config_path, str) or not isinstance(layer_paths, list):
            raise RuntimeError(f"Docker save archive for {name} has an invalid manifest")
        config_stream = archive.extractfile(config_path)
        if config_stream is None:
            raise RuntimeError(f"Docker save archive for {name} is missing its image config")
        config_payload = config_stream.read()
        if f"sha256:{_sha256(config_payload)}" != image_id:
            raise RuntimeError(f"Docker save config for {name} differs from its inspected image ID")
        config: object = json.loads(config_payload)
        config_value = _object(config, label=f"{name} image config")
        rootfs = _object(config_value.get("rootfs"), label=f"{name} rootfs config")
        diff_ids = rootfs.get("diff_ids")
        if not isinstance(diff_ids, list):
            raise RuntimeError(f"Docker save layer inventory for {name} is malformed")
        layers, uncompressed_digests = cast(list[object], layer_paths), cast(list[object], diff_ids)
        if len(uncompressed_digests) != len(layers):
            raise RuntimeError(
                f"Docker save layer inventory for {name} differs from rootfs diff IDs"
            )

        layer_descriptors: list[dict[str, object]] = []
        for layer_path, diff_id in zip(layers, uncompressed_digests, strict=True):
            if not isinstance(layer_path, str) or not isinstance(diff_id, str):
                raise RuntimeError(f"Docker save layer inventory for {name} is malformed")
            layer_stream = archive.extractfile(layer_path)
            if layer_stream is None:
                raise RuntimeError(f"Docker save archive for {name} is missing layer {layer_path}")
            layer_payload = layer_stream.read()
            layer_digest = f"sha256:{_sha256(layer_payload)}"
            if layer_digest != diff_id:
                raise RuntimeError(f"Docker save layer {layer_path} for {name} is not its diff ID")
            descriptor = _write_blob(layout, layer_payload)
            layer_descriptors.append({"mediaType": OCI_LAYER_MEDIA_TYPE, **descriptor})

        config_descriptor = _write_blob(layout, config_payload)
        config_descriptor["mediaType"] = OCI_CONFIG_MEDIA_TYPE
        manifest_payload = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": OCI_MANIFEST_MEDIA_TYPE,
                "config": config_descriptor,
                "layers": layer_descriptors,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        manifest_descriptor = _write_blob(layout, manifest_payload)
        manifest_digest = cast(str, manifest_descriptor["digest"])
        index = {
            "schemaVersion": 2,
            "mediaType": OCI_INDEX_MEDIA_TYPE,
            "manifests": [
                {
                    "mediaType": OCI_MANIFEST_MEDIA_TYPE,
                    **manifest_descriptor,
                    "platform": {"architecture": "amd64", "os": "linux"},
                    "annotations": {"org.opencontainers.image.ref.name": name},
                }
            ],
        }

    layout.mkdir(parents=True, exist_ok=True)
    (layout / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}\n')
    (layout / "index.json").write_text(
        json.dumps(index, sort_keys=True, separators=(",", ":")) + "\n"
    )
    return layout, manifest_digest


def main() -> int:
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument(
            "--offline-only",
            action="store_true",
            help="require every pinned image to be present locally; never pull",
        )
        arguments = parser.parse_args()
        env = _docker_environment()
        daemon = _run(
            ["docker", "version", "--format", "{{.Client.Version}}|{{.Server.Version}}"], env=env
        )
        versions = daemon.split("|", maxsplit=1)
        if len(versions) != 2 or not all(versions):
            raise RuntimeError("Docker Engine client/server version identity is unavailable")
        buildx_path = ROOT / "build/tool-cache/docker-buildx-v0.37.1/buildx"
        buildx_version = _run([str(buildx_path), "version"], env=env)
        if "v0.37.1" not in buildx_version:
            raise RuntimeError(f"unexpected Buildx version: {buildx_version}")
        records: list[dict[str, object]] = []
        for name, reference in _images():
            inspected = subprocess.run(
                ["docker", "image", "inspect", "--format", IMAGE_FORMAT, reference],
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
            if inspected.returncode:
                if arguments.offline_only:
                    raise RuntimeError(
                        f"pinned {name} image is not locally prepared; offline mode will not pull"
                    )
                _run(["docker", "pull", "--platform=linux/amd64", reference], env=env)
            record = _inspect(reference, env=env)
            record["name"] = name
            if name in {"uv", "python"}:
                image_id = record.get("image_id")
                if not isinstance(image_id, str):
                    raise RuntimeError(f"prepared {name} image has no image ID")
                layout, manifest_digest = prepare_local_oci_layout(
                    name=name,
                    reference=reference,
                    image_id=image_id,
                    env=env,
                )
                record["oci_layout"] = layout.relative_to(ROOT).as_posix()
                record["oci_manifest_digest"] = manifest_digest
            records.append(record)
        output = {
            "schema_version": "1",
            "registry_auth": "anonymous-task-local-docker-config",
            "docker_client_version": versions[0],
            "docker_server_version": versions[1],
            "buildx_version": buildx_version,
            "images": records,
        }
        PREPARED_PATH.parent.mkdir(parents=True, exist_ok=True)
        PREPARED_PATH.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
        print(f"prepared {len(records)} digest-pinned linux/amd64 images")
        print(f"Docker Engine client/server: {versions[0]}/{versions[1]}")
        print(f"Buildx: {buildx_version}")
        print(f"evidence: {PREPARED_PATH.relative_to(ROOT)}")
        return 0
    except (OSError, ValueError, RuntimeError, IndexError) as exc:
        print(f"NOT_PREPARED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
