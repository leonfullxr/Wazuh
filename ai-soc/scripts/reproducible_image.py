#!/usr/bin/env python3
"""Prepare locked image dependencies and prove offline OCI reproducibility."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[1]
BUILDER = "soc-image-builder-42aa9203"
BUILDX = ROOT / "build/tool-cache/docker-buildx-v0.37.1/buildx"
DOCKER_CONFIG = ROOT / "build/private/docker-config"
BUILDX_CONFIG = ROOT / "build/private/buildx-config"
UV_CACHE = ROOT / "build/private/image-uv-cache"
CACHE_MANIFEST = ROOT / "build/private/image-uv-cache.json"
PREPARED_IMAGES = ROOT / "build/tool-cache/container-images.json"
LOCK_FILE = ROOT / "dev/toolchain.lock.json"
HEX = re.compile(r"^[0-9a-f]{64}$")
TMPFS_ROOT = Path("/dev/shm")
TMPFS_REQUIRED_FREE_BYTES = 2 * 1024 * 1024 * 1024
DURABLE_COPY_RESERVE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ImageIdentity:
    config_digest: str
    layer_digests: tuple[str, ...]
    content_revision: str
    pack_sha256: str


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    raw = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in raw):
        raise ValueError(f"{label} keys must be strings")
    return cast(dict[str, object], raw)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tree_digest(root: Path) -> tuple[str, int, int]:
    digest = hashlib.sha256()
    count = 0
    total_bytes = 0
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix().encode()
        if path.is_symlink():
            payload = os.readlink(path).encode()
            kind = b"L"
        elif path.is_file():
            payload = path.read_bytes()
            kind = b"F"
            total_bytes += len(payload)
        else:
            continue
        digest.update(kind + len(relative).to_bytes(8, "big") + relative)
        digest.update(len(payload).to_bytes(8, "big") + payload)
        count += 1
    return digest.hexdigest(), count, total_bytes


def prepare_cache(uv_executable: str) -> None:
    python = ROOT / ".venv/bin/python"
    if not python.is_file():
        raise RuntimeError("run make bootstrap to prepare the locked Python environment first")
    UV_CACHE.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment.pop("SOC_B6_TMPFS_SCRATCH_ROOT", None)
    for key in (
        "UV_OFFLINE",
        "UV_INDEX",
        "UV_INDEX_URL",
        "UV_EXTRA_INDEX_URL",
        "UV_CONFIG_FILE",
        "PIP_INDEX_URL",
        "PIP_EXTRA_INDEX_URL",
        "VIRTUAL_ENV",
    ):
        environment.pop(key, None)
    environment["UV_CACHE_DIR"] = str(UV_CACHE)
    environment["UV_PROJECT_ENVIRONMENT"] = str(ROOT / "build/private/image-prepare-venv")
    command = [
        uv_executable,
        "sync",
        "--no-config",
        "--default-index",
        "https://pypi.org/simple",
        "--keyring-provider",
        "disabled",
        "--python",
        str(python),
        "--no-managed-python",
        "--no-python-downloads",
        "--locked",
        "--no-dev",
        "--no-editable",
        "--compile-bytecode",
    ]
    subprocess.run(command, cwd=ROOT, env=environment, check=True)
    cache_digest, file_count, byte_count = _tree_digest(UV_CACHE)
    lock_digest = _sha((ROOT / "uv.lock").read_bytes())
    version = subprocess.run(
        [uv_executable, "--version"],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if "0.11.28" not in version:
        raise RuntimeError(f"unexpected uv version for the image cache: {version}")
    record = {
        "schema_version": "1",
        "registry": "https://pypi.org/simple",
        "uv_version": version,
        "uv_lock_sha256": lock_digest,
        "cache_tree_sha256": cache_digest,
        "cache_file_count": file_count,
        "cache_bytes": byte_count,
    }
    CACHE_MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    CACHE_MANIFEST.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"prepared offline image cache: {file_count} files, {byte_count} bytes")
    print(f"cache evidence: {CACHE_MANIFEST.relative_to(ROOT)}")


def _check_cache() -> dict[str, object]:
    record = _mapping(json.loads(CACHE_MANIFEST.read_text()), "image cache manifest")
    digest, count, byte_count = _tree_digest(UV_CACHE)
    if record.get("uv_lock_sha256") != _sha((ROOT / "uv.lock").read_bytes()):
        raise RuntimeError("prepared image cache was made for a different uv.lock")
    if record.get("cache_tree_sha256") != digest:
        raise RuntimeError("prepared image cache tree differs from its recorded digest")
    if record.get("cache_file_count") != count or record.get("cache_bytes") != byte_count:
        raise RuntimeError("prepared image cache size differs from its manifest")
    return record


def _prepared_image_check() -> dict[str, str]:
    lock = _mapping(json.loads(LOCK_FILE.read_text()), "toolchain lock")
    prepared = _mapping(json.loads(PREPARED_IMAGES.read_text()), "prepared image ledger")
    locked_raw, prepared_raw = lock.get("images"), prepared.get("images")
    if not isinstance(locked_raw, list) or not isinstance(prepared_raw, list):
        raise ValueError("toolchain and prepared image ledgers need images lists")
    prepared_by_name: dict[str, dict[str, object]] = {}
    for item in cast(list[object], prepared_raw):
        entry = _mapping(item, "prepared image")
        name = entry.get("name")
        if not isinstance(name, str):
            raise ValueError("prepared image has no name")
        prepared_by_name[name] = entry
    contexts: dict[str, str] = {}
    for item in cast(list[object], locked_raw):
        locked = _mapping(item, "locked image")
        name, reference = locked.get("name"), locked.get("reference")
        if not isinstance(name, str) or not isinstance(reference, str):
            raise ValueError("locked image needs name and reference")
        observed = prepared_by_name.get(name)
        if observed is None or observed.get("reference") != reference:
            raise RuntimeError(f"prepared {name} image does not match its digest-pinned lock")
        if observed.get("platform") != "linux/amd64":
            raise RuntimeError(f"prepared {name} image is not linux/amd64")
        if name not in {"uv", "python"}:
            continue
        layout_relative, manifest_digest = (
            observed.get("oci_layout"),
            observed.get("oci_manifest_digest"),
        )
        if not isinstance(layout_relative, str) or not isinstance(manifest_digest, str):
            raise RuntimeError(f"prepared {name} image has no offline OCI layout")
        if not manifest_digest.startswith("sha256:") or not HEX.fullmatch(
            manifest_digest.removeprefix("sha256:")
        ):
            raise RuntimeError(f"prepared {name} OCI manifest digest is malformed")
        layout = (ROOT / layout_relative).resolve()
        if not layout.is_relative_to(ROOT.resolve()):
            raise RuntimeError(f"prepared {name} OCI layout escaped the repository checkout")
        layout_marker = json.loads((layout / "oci-layout").read_text())
        if (
            _mapping(layout_marker, f"{name} OCI layout marker").get("imageLayoutVersion")
            != "1.0.0"
        ):
            raise RuntimeError(f"prepared {name} OCI layout version is unsupported")
        index = _mapping(json.loads((layout / "index.json").read_text()), f"{name} OCI index")
        manifests = index.get("manifests")
        if not isinstance(manifests, list):
            raise RuntimeError(f"prepared {name} OCI layout must contain one manifest")
        manifest_entries = cast(list[object], manifests)
        if len(manifest_entries) != 1:
            raise RuntimeError(f"prepared {name} OCI layout must contain one manifest")
        descriptor = _mapping(manifest_entries[0], f"{name} OCI descriptor")
        if descriptor.get("digest") != manifest_digest:
            raise RuntimeError(f"prepared {name} OCI index digest differs from its manifest")
        manifest_path = layout / "blobs/sha256" / manifest_digest.removeprefix("sha256:")
        manifest_payload = manifest_path.read_bytes()
        if _sha(manifest_payload) != manifest_digest.removeprefix("sha256:"):
            raise RuntimeError(f"prepared {name} OCI manifest blob has a digest mismatch")
        image_id = observed.get("image_id")
        if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
            raise RuntimeError(f"prepared {name} image ID is malformed")
        image_manifest = _mapping(json.loads(manifest_payload), f"{name} OCI manifest")
        config_descriptor = _mapping(image_manifest.get("config"), f"{name} OCI config")
        if config_descriptor.get("digest") != image_id:
            raise RuntimeError(f"prepared {name} OCI config differs from its verified image ID")
        config_path = layout / "blobs/sha256" / image_id.removeprefix("sha256:")
        config_payload = config_path.read_bytes()
        if _sha(config_payload) != image_id.removeprefix("sha256:"):
            raise RuntimeError(f"prepared {name} OCI config blob has a digest mismatch")
        config = _mapping(json.loads(config_payload), f"{name} image config")
        rootfs = _mapping(config.get("rootfs"), f"{name} image rootfs")
        raw_diff_ids, raw_layers = rootfs.get("diff_ids"), image_manifest.get("layers")
        if not isinstance(raw_diff_ids, list) or not isinstance(raw_layers, list):
            raise RuntimeError(f"prepared {name} OCI layer inventory is malformed")
        diff_ids, layers = cast(list[object], raw_diff_ids), cast(list[object], raw_layers)
        if len(diff_ids) != len(layers):
            raise RuntimeError(f"prepared {name} OCI layer inventory differs from its config")
        for diff_id, raw_layer in zip(diff_ids, layers, strict=True):
            if not isinstance(diff_id, str):
                raise RuntimeError(f"prepared {name} OCI diff ID is malformed")
            layer_descriptor = _mapping(raw_layer, f"{name} OCI layer")
            layer_digest, layer_size = layer_descriptor.get("digest"), layer_descriptor.get("size")
            if (
                not isinstance(layer_digest, str)
                or not layer_digest.startswith("sha256:")
                or not isinstance(layer_size, int)
            ):
                raise RuntimeError(f"prepared {name} OCI layer descriptor is malformed")
            layer_path = layout / "blobs/sha256" / layer_digest.removeprefix("sha256:")
            layer_payload = layer_path.read_bytes()
            if (
                len(layer_payload) != layer_size
                or f"sha256:{_sha(layer_payload)}" != layer_digest
                or layer_digest != diff_id
            ):
                raise RuntimeError(f"prepared {name} OCI layer bytes differ from its digest")
        contexts[name] = f"oci-layout://{layout}@{manifest_digest}"
    if set(contexts) != {"uv", "python"}:
        raise RuntimeError("prepared offline OCI contexts for both uv and python are required")
    return contexts


def _ensure_builder(environment: dict[str, str]) -> None:
    instances = BUILDX_CONFIG / "instances"
    instance_path = instances / BUILDER
    if instance_path.is_file():
        return
    lock = _mapping(json.loads(LOCK_FILE.read_text()), "toolchain lock")
    images = lock.get("images")
    if not isinstance(images, list):
        raise ValueError("toolchain lock is missing its image list")
    buildkit_reference: str | None = None
    for raw in cast(list[object], images):
        entry = _mapping(raw, "locked image")
        if entry.get("name") == "buildkit":
            reference = entry.get("reference")
            if isinstance(reference, str):
                buildkit_reference = reference
    if buildkit_reference is None:
        raise RuntimeError("toolchain lock has no BuildKit image")
    docker = ["docker", "image", "inspect", buildkit_reference]
    inspected = subprocess.run(
        [str(ROOT / "scripts/run-offline.sh"), *docker],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if inspected.returncode:
        raise RuntimeError("locked BuildKit image is not locally prepared; run make bootstrap")
    _offline_command(
        [
            "create",
            "--name",
            BUILDER,
            "--driver",
            "docker-container",
            "--driver-opt",
            f"image={buildkit_reference}",
            "--platform",
            "linux/amd64",
            "--bootstrap",
        ],
        environment=environment,
    )
    if not instance_path.is_file():
        raise RuntimeError("Buildx did not persist its task-owned builder configuration")


def _offline_environment() -> dict[str, str]:
    DOCKER_CONFIG.mkdir(parents=True, exist_ok=True)
    config = DOCKER_CONFIG / "config.json"
    if not config.exists():
        config.write_text('{"auths":{}}\n')
        config.chmod(0o600)
    if config.read_text() != '{"auths":{}}\n':
        raise RuntimeError("task-local Docker config is not anonymous")
    environment = os.environ.copy()
    environment["DOCKER_CONFIG"] = str(DOCKER_CONFIG)
    environment["BUILDX_CONFIG"] = str(BUILDX_CONFIG)
    environment["BUILDKIT_PROGRESS"] = "plain"
    for key in ("DOCKER_CONTEXT", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY"):
        environment.pop(key, None)
    return environment


def _offline_command(arguments: list[str], *, environment: dict[str, str]) -> None:
    wrapper = ROOT / "scripts/run-offline.sh"
    subprocess.run([str(wrapper), str(BUILDX), *arguments], cwd=ROOT, env=environment, check=True)


def prune_builder_cache(environment: dict[str, str], artifact_dir: Path, *, label: str) -> None:
    if label not in {"after-first", "after-second", "after-third"}:
        raise ValueError("builder cache prune label is not an image boundary")
    wrapper = ROOT / "scripts/run-offline.sh"
    inventory = [str(wrapper), str(BUILDX), "du", "--builder", BUILDER, "--verbose"]
    before = subprocess.run(
        inventory,
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    (artifact_dir / f"builder-cache-{label}-before.txt").write_text(before, encoding="utf-8")
    _offline_command(["prune", "--builder", BUILDER, "--all", "--force"], environment=environment)
    after = subprocess.run(
        inventory,
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    (artifact_dir / f"builder-cache-{label}-after.txt").write_text(after, encoding="utf-8")


def require_tmpfs_capacity(free_bytes: int) -> None:
    if free_bytes < TMPFS_REQUIRED_FREE_BYTES:
        raise RuntimeError(
            f"tmpfs needs at least {TMPFS_REQUIRED_FREE_BYTES} free bytes; observed {free_bytes}"
        )


def create_tmpfs_scratch(base: Path, run_id: str) -> tuple[Path, int]:
    resolved = base.resolve(strict=True)
    expected = TMPFS_ROOT.resolve(strict=True)
    if resolved != expected:
        raise ValueError(f"image scratch base must be the task-authorized tmpfs {expected}")
    mount_types = {
        fields[2]
        for line in Path("/proc/mounts").read_text(encoding="utf-8").splitlines()
        if len(fields := line.split()) >= 3 and fields[1] == str(expected)
    }
    if "tmpfs" not in mount_types:
        raise RuntimeError(f"image scratch base is not mounted as tmpfs: {expected}")
    safe_run_id = re.fullmatch(r"[0-9]{8}T[0-9]{12}Z", run_id)
    if safe_run_id is None:
        raise ValueError("image scratch run ID is malformed")
    free_bytes = shutil.disk_usage(expected).free
    require_tmpfs_capacity(free_bytes)
    scratch = expected / f"soc-image-repro-{run_id}"
    if scratch.exists() or scratch.is_symlink():
        raise RuntimeError(f"unique image scratch path already exists: {scratch}")
    scratch.mkdir(mode=0o700)
    if scratch.resolve(strict=True).parent != expected:
        raise RuntimeError("created image scratch directory escaped tmpfs")
    return scratch, free_bytes


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def inventory_tmpfs_scratch(root: Path) -> list[dict[str, object]]:
    expected_parent = TMPFS_ROOT.resolve(strict=True)
    resolved = root.resolve(strict=True)
    if resolved.parent != expected_parent or not resolved.name.startswith("soc-image-repro-"):
        raise ValueError("refusing to inventory a path outside the unique tmpfs namespace")
    inventory: list[dict[str, object]] = []
    for path in sorted(resolved.rglob("*")):
        if path.is_symlink():
            raise RuntimeError(f"unexpected symlink in image scratch: {path}")
        if path.is_file():
            inventory.append(
                {
                    "path": path.relative_to(resolved).as_posix(),
                    "size_bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
    return inventory


def remove_tmpfs_scratch(root: Path) -> None:
    expected_parent = TMPFS_ROOT.resolve(strict=True)
    resolved = root.resolve(strict=True)
    if resolved.parent != expected_parent or not resolved.name.startswith("soc-image-repro-"):
        raise ValueError("refusing to remove a path outside the unique tmpfs namespace")
    shutil.rmtree(resolved)
    if resolved.exists():
        raise RuntimeError("task-owned tmpfs scratch cleanup did not complete")


def persist_oci_archives(
    scratch_images: Path, artifact_dir: Path, outputs: tuple[str, ...]
) -> dict[str, dict[str, object]]:
    required = sum((scratch_images / f"{name}.oci.tar").stat().st_size for name in outputs)
    durable_free = shutil.disk_usage(artifact_dir).free
    if durable_free < required + DURABLE_COPY_RESERVE_BYTES:
        raise RuntimeError(
            "durable evidence filesystem lacks space for verified OCI archives: "
            f"need {required + DURABLE_COPY_RESERVE_BYTES} bytes, observed {durable_free}"
        )
    artifacts: dict[str, dict[str, object]] = {}
    for name in outputs:
        source = scratch_images / f"{name}.oci.tar"
        destination = artifact_dir / source.name
        source_digest = sha256_file(source)
        shutil.copyfile(source, destination)
        destination_digest = sha256_file(destination)
        if (
            destination_digest != source_digest
            or destination.stat().st_size != source.stat().st_size
        ):
            raise RuntimeError(
                f"durable OCI archive copy differs from verified tmpfs output: {name}"
            )
        artifacts[name] = {
            "path": str(destination.relative_to(ROOT)),
            "sha256": destination_digest,
            "size_bytes": destination.stat().st_size,
        }
    return artifacts


def _descriptor_blob(archive: tarfile.TarFile, descriptor: object, label: str) -> bytes:
    entry = _mapping(descriptor, label)
    digest, size = entry.get("digest"), entry.get("size")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise ValueError(f"{label} must have a sha256 descriptor")
    hex_digest = digest.removeprefix("sha256:")
    if not HEX.fullmatch(hex_digest) or not isinstance(size, int) or size < 0:
        raise ValueError(f"{label} has an invalid descriptor")
    member = archive.extractfile(f"blobs/sha256/{hex_digest}")
    if member is None:
        raise ValueError(f"OCI archive is missing {label} blob")
    payload = member.read()
    if len(payload) != size or _sha(payload) != hex_digest:
        raise ValueError(f"OCI archive has a corrupt {label} blob")
    return payload


def read_oci_identity(path: Path) -> ImageIdentity:
    with tarfile.open(path, mode="r:") as archive:
        index_stream = archive.extractfile("index.json")
        if index_stream is None:
            raise ValueError(f"{path} is missing OCI index.json")
        index = _mapping(json.loads(index_stream.read()), "OCI index")
        manifests = index.get("manifests")
        if not isinstance(manifests, list):
            raise ValueError("OCI index manifests must be a list")
        manifest_entries = cast(list[object], manifests)
        if len(manifest_entries) != 1:
            raise ValueError("OCI index must contain exactly one image manifest")
        manifest = _mapping(
            json.loads(_descriptor_blob(archive, manifest_entries[0], "manifest")), "manifest"
        )
        config = _mapping(
            json.loads(_descriptor_blob(archive, manifest.get("config"), "config")), "config"
        )
        raw_layers = manifest.get("layers")
        if not isinstance(raw_layers, list):
            raise ValueError("OCI manifest layers must be a list")
        layer_digests_list: list[str] = []
        for layer in cast(list[object], raw_layers):
            layer_entry = _mapping(layer, "layer")
            _descriptor_blob(archive, layer_entry, "layer")
            layer_digest = layer_entry.get("digest")
            if not isinstance(layer_digest, str):
                raise ValueError("OCI layer descriptor is missing its digest")
            layer_digests_list.append(layer_digest)
        layer_digests = tuple(layer_digests_list)
        image_config = _mapping(config.get("config"), "image config")
        labels = _mapping(image_config.get("Labels"), "image labels")
        content_revision = labels.get("org.ai-soc.content.revision")
        pack_sha256 = labels.get("org.ai-soc.content.pack.sha256")
        if not isinstance(content_revision, str):
            raise ValueError("OCI image is missing its content revision label")
        if not isinstance(pack_sha256, str) or not HEX.fullmatch(pack_sha256):
            raise ValueError("OCI image is missing its content pack digest label")
        descriptor = _mapping(manifest.get("config"), "config descriptor")
        config_digest = descriptor.get("digest")
        if not isinstance(config_digest, str):
            raise ValueError("OCI config descriptor is missing its digest")
        return ImageIdentity(config_digest, layer_digests, content_revision, pack_sha256)


def verify_image_set(first: ImageIdentity, second: ImageIdentity, changed: ImageIdentity) -> None:
    if (
        first.config_digest != second.config_digest
        or first.layer_digests != second.layer_digests
        or first.content_revision != second.content_revision
        or first.pack_sha256 != second.pack_sha256
    ):
        raise RuntimeError("clean OCI builds differ in config or layer digests")
    if changed.content_revision == first.content_revision:
        raise RuntimeError("changed approved content commit did not reach the OCI config")
    if changed.pack_sha256 == first.pack_sha256:
        raise RuntimeError("changed approved content pack digest did not reach the OCI config")
    if changed.config_digest == first.config_digest:
        raise RuntimeError("changed approved content did not change the OCI config digest")
    if changed.layer_digests != first.layer_digests:
        raise RuntimeError("content provenance-only change unexpectedly changed service layers")


def _git(*arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments], cwd=ROOT, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def _copy_context(destination: Path, timestamp: int, *, generated_assets_epoch: int) -> None:
    archive_bytes = subprocess.run(
        ["git", "archive", "--format=tar", "HEAD"], cwd=ROOT, check=True, capture_output=True
    ).stdout
    destination.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as source:
        source.extractall(destination, filter="data")
    ui_dist = ROOT / "ui/dist"
    if not ui_dist.is_dir():
        raise RuntimeError("run make ui-build to build the pinned ui/dist input first")
    shutil.copytree(ui_dist, destination / "ui/dist")
    for directory, subdirectories, files in os.walk(destination, topdown=False, followlinks=False):
        for name in files + subdirectories:
            path = Path(directory) / name
            try:
                os.utime(path, (timestamp, timestamp), follow_symlinks=False)
            except (NotImplementedError, OSError):
                if not path.is_symlink():
                    raise
        os.utime(directory, (timestamp, timestamp))
    normalize_generated_asset_timestamps(destination / "ui/dist", generated_assets_epoch)


def normalize_generated_asset_timestamps(assets: Path, source_epoch: int) -> None:
    # BuildKit 0.33.1 preserves older mtimes in COPY layers when rewriting an OCI export.
    # Pin generated UI input to SOURCE_DATE_EPOCH so all independent contexts agree.
    for path in sorted(assets.rglob("*"), reverse=True):
        os.utime(path, (source_epoch, source_epoch), follow_symlinks=False)
    os.utime(assets, (source_epoch, source_epoch))


def build_images(scratch_base: Path) -> Path:
    _check_cache()
    image_contexts = _prepared_image_check()
    if _git("status", "--porcelain", "--untracked-files=all", "--", "."):
        raise RuntimeError("commit source changes before producing image identity evidence")
    service_sha = _git("rev-parse", "HEAD")
    source_epoch = int(_git("show", "-s", "--format=%ct", "HEAD"))
    environment = _offline_environment()
    _ensure_builder(environment)
    context_config = _mapping(
        json.loads((BUILDX_CONFIG / "instances" / BUILDER).read_text()), "Buildx instance"
    )
    if context_config.get("Name") != BUILDER:
        raise RuntimeError("task-owned Buildx instance name differs from the pinned builder")
    nodes = context_config.get("Nodes")
    if not isinstance(nodes, list) or not nodes:
        raise RuntimeError("task-owned Buildx builder has no nodes")
    first_node = _mapping(cast(list[object], nodes)[0], "Buildx node")
    driver_options = _mapping(first_node.get("DriverOpts"), "Buildx driver options")
    lock = _mapping(json.loads(LOCK_FILE.read_text()), "toolchain lock")
    lock_images = lock.get("images")
    if not isinstance(lock_images, list):
        raise RuntimeError("toolchain lock must contain an images list")
    buildkit_entries = [
        _mapping(image, "locked image")
        for image in cast(list[object], lock_images)
        if _mapping(image, "locked image").get("name") == "buildkit"
    ]
    if len(buildkit_entries) != 1:
        raise RuntimeError("toolchain lock must contain exactly one BuildKit image")
    locked_buildkit = buildkit_entries[0].get("reference")
    configured_buildkit = driver_options.get("image")
    if not isinstance(locked_buildkit, str) or configured_buildkit != locked_buildkit:
        raise RuntimeError("task-owned builder does not use the locked BuildKit image")
    inspection = subprocess.run(
        [str(ROOT / "scripts/run-offline.sh"), str(BUILDX), "inspect", BUILDER],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if (
        "Status:                running" not in inspection
        or "BuildKit version:      v0.33.1" not in inspection
    ):
        raise RuntimeError(
            "pinned task-owned BuildKit builder is not running at the locked version"
        )

    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    artifact_dir = ROOT / "build/evidence/image-repro" / f"{service_sha}-{run_id}"
    artifact_dir.mkdir(parents=True)
    scratch_root, scratch_free_bytes = create_tmpfs_scratch(scratch_base, run_id)
    environment["SOC_B6_TMPFS_SCRATCH_ROOT"] = str(scratch_root)
    scratch_images = scratch_root / "oci"
    scratch_images.mkdir()
    context_root = scratch_root / "contexts"
    context_root.mkdir(parents=True)
    scratch_record_path = artifact_dir / "tmpfs-scratch.json"
    scratch_record: dict[str, object] = {
        "schema_version": "1",
        "state": "in_progress",
        "base": str(scratch_base.resolve()),
        "path": str(scratch_root),
        "required_free_bytes": TMPFS_REQUIRED_FREE_BYTES,
        "preflight_free_bytes": scratch_free_bytes,
    }
    scratch_record_path.write_text(json.dumps(scratch_record, indent=2, sort_keys=True) + "\n")
    control_dir = artifact_dir / "content-control"
    content_control = subprocess.run(
        [
            str(ROOT / "scripts/run-offline.sh"),
            sys.executable,
            str(ROOT / "scripts/image_content_control.py"),
            "--output",
            str(control_dir),
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if content_control.returncode:
        raise RuntimeError(
            "verified synthetic content control failed: "
            + (content_control.stderr or content_control.stdout).strip()
        )
    control_record = _mapping(
        json.loads((control_dir / "control.json").read_text()), "content control"
    )
    base_content = _mapping(control_record.get("base"), "base content pack")
    changed_content = _mapping(control_record.get("changed"), "changed content pack")
    base_content_sha, base_pack_sha = (
        base_content.get("content_sha"),
        base_content.get("pack_sha256"),
    )
    changed_content_sha, changed_pack_sha = (
        changed_content.get("content_sha"),
        changed_content.get("pack_sha256"),
    )
    if not all(
        isinstance(value, str) and HEX.fullmatch(value)
        for value in (base_pack_sha, changed_pack_sha)
    ):
        raise RuntimeError("verified synthetic pack SHA-256 values are malformed")
    if not all(
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value)
        for value in (base_content_sha, changed_content_sha)
    ):
        raise RuntimeError("verified synthetic content commit identities are malformed")
    contexts = (context_root / "first", context_root / "second", context_root / "changed")
    timestamps = (source_epoch - 86400, source_epoch + 86400, source_epoch + 172800)
    for context, timestamp in zip(contexts, timestamps, strict=True):
        _copy_context(context, timestamp, generated_assets_epoch=source_epoch)

    identities: list[ImageIdentity] = []
    for number, (context, output) in enumerate(
        zip(contexts, ("first", "second", "changed"), strict=True)
    ):
        content_value = changed_content_sha if number == 2 else base_content_sha
        pack_value = changed_pack_sha if number == 2 else base_pack_sha
        oci_path = scratch_images / f"{output}.oci.tar"
        metadata_path = artifact_dir / f"{output}.metadata.json"
        arguments = [
            "build",
            "--builder",
            BUILDER,
            "--platform",
            "linux/amd64",
            "--pull=false",
            "--no-cache",
            "--network=none",
            "--build-context",
            f"uv-cache={UV_CACHE}",
            "--build-context",
            f"uv-base={image_contexts['uv']}",
            "--build-context",
            f"python-base={image_contexts['python']}",
            "--build-arg",
            f"SERVICE_SHA={service_sha}",
            "--build-arg",
            f"CONTENT_SHA={content_value}",
            "--build-arg",
            f"PACK_SHA256={pack_value}",
            "--build-arg",
            f"SOURCE_DATE_EPOCH={source_epoch}",
            "--output",
            f"type=oci,rewrite-timestamp=true,dest={oci_path}",
            "--metadata-file",
            str(metadata_path),
            "--file",
            "Dockerfile",
            str(context),
        ]
        _offline_command(arguments, environment=environment)
        identities.append(read_oci_identity(oci_path))
        boundary = "third" if output == "changed" else output
        prune_builder_cache(environment, artifact_dir, label=f"after-{boundary}")
    first, second, changed = identities
    verify_image_set(first, second, changed)
    if (
        first.content_revision != base_content_sha
        or first.pack_sha256 != base_pack_sha
        or second.content_revision != base_content_sha
        or second.pack_sha256 != base_pack_sha
        or changed.content_revision != changed_content_sha
        or changed.pack_sha256 != changed_pack_sha
    ):
        raise RuntimeError("OCI labels do not match their independently verified content packs")
    scratch_inventory = inventory_tmpfs_scratch(scratch_root)
    inventory_path = artifact_dir / "tmpfs-inventory.json"
    inventory_path.write_text(
        json.dumps(scratch_inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    archive_records = persist_oci_archives(
        scratch_images, artifact_dir, ("first", "second", "changed")
    )
    metadata_records = {
        name: {
            "path": str((artifact_dir / f"{name}.metadata.json").relative_to(ROOT)),
            "sha256": sha256_file(artifact_dir / f"{name}.metadata.json"),
            "size_bytes": (artifact_dir / f"{name}.metadata.json").stat().st_size,
        }
        for name in ("first", "second", "changed")
    }
    scratch_record.update(
        {
            "state": "complete_and_persisted",
            "inventory": str(inventory_path.relative_to(ROOT)),
            "archive_sha256": {name: record["sha256"] for name, record in archive_records.items()},
        }
    )
    scratch_record_path.write_text(
        json.dumps(scratch_record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    result = {
        "schema_version": "1",
        "service_sha": service_sha,
        "content_sha": base_content_sha,
        "pack_sha256": base_pack_sha,
        "changed_content_sha": changed_content_sha,
        "changed_pack_sha256": changed_pack_sha,
        "content_control": str((control_dir / "control.json").relative_to(ROOT)),
        "source_date_epoch": source_epoch,
        "builder": BUILDER,
        "buildkit": "v0.33.1",
        "platform": "linux/amd64",
        "network": "none",
        "pull": False,
        "no_cache": True,
        "context_mtime_epochs": list(timestamps),
        "builder_cache_prunes": ["after-first", "after-second", "after-third"],
        "tmpfs_scratch": scratch_record,
        "tmpfs_inventory": str(inventory_path.relative_to(ROOT)),
        "oci_archives": archive_records,
        "build_metadata": metadata_records,
        "oci": {
            name: asdict(identity)
            for name, identity in zip(("first", "second", "changed"), identities, strict=True)
        },
        "result": "two clean builds match; verified changed pack changes provenance config only",
    }
    evidence = artifact_dir / "result.json"
    evidence.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    scratch_record["result"] = str(evidence.relative_to(ROOT))
    scratch_record_path.write_text(
        json.dumps(scratch_record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    remove_tmpfs_scratch(scratch_root)
    print(f"reproducible OCI evidence: {evidence.relative_to(ROOT)}")
    print(
        f"SERVICE_SHA={service_sha} CONTENT_SHA={base_content_sha} "
        f"PACK_SHA256={base_pack_sha} SOURCE_DATE_EPOCH={source_epoch}"
    )
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare_parser = subparsers.add_parser("prepare-cache")
    prepare_parser.add_argument("--uv", default="uv")
    build_parser = subparsers.add_parser("build")
    build_parser.add_argument("--scratch-root", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        if arguments.command == "prepare-cache":
            prepare_cache(cast(str, arguments.uv))
        else:
            build_images(cast(Path, arguments.scratch_root))
        return 0
    except (
        OSError,
        subprocess.CalledProcessError,
        RuntimeError,
        ValueError,
        tarfile.TarError,
    ) as exc:
        print(f"IMAGE_REPRODUCIBILITY_FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
