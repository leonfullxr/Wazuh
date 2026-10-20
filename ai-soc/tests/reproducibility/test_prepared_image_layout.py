from __future__ import annotations

import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path
from typing import cast

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from scripts import prepare_containers  # noqa: E402


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _docker_save_archive(path: Path, *, corrupt_diff_id: bool = False) -> str:
    layer = b"one locally saved image layer\n"
    layer_digest = _sha256(layer)
    diff_id = "0" * 64 if corrupt_diff_id else layer_digest
    config = json.dumps(
        {"rootfs": {"type": "layers", "diff_ids": [f"sha256:{diff_id}"]}},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    config_digest = _sha256(config)
    docker_manifest = json.dumps(
        [{"Config": "config.json", "Layers": ["layer/layer.tar"]}],
        separators=(",", ":"),
    ).encode()
    with tarfile.open(path, mode="w:") as archive:
        for name, payload in (
            ("manifest.json", docker_manifest),
            ("config.json", config),
            ("layer/layer.tar", layer),
        ):
            info = tarfile.TarInfo(name)
            info.mode = 0o644
            info.size = len(payload)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(payload))
    return f"sha256:{config_digest}"


def _stub_docker_save(monkeypatch: pytest.MonkeyPatch, archive: Path) -> None:
    def save(arguments: list[str], *, env: dict[str, str]) -> str:
        del env
        output = Path(arguments[arguments.index("--output") + 1])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(archive.read_bytes())
        return ""

    monkeypatch.setattr(prepare_containers, "_run", save)


def test_verified_docker_save_becomes_local_oci_layout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "docker-save.tar"
    image_id = _docker_save_archive(source)
    monkeypatch.setattr(prepare_containers, "IMAGE_ARCHIVES", tmp_path / "archives")
    monkeypatch.setattr(prepare_containers, "OCI_LAYOUTS", tmp_path / "layouts")
    _stub_docker_save(monkeypatch, source)

    layout, manifest_digest = prepare_containers.prepare_local_oci_layout(
        name="uv",
        reference="ghcr.io/astral-sh/uv@sha256:" + "a" * 64,
        image_id=image_id,
        env={},
    )

    index = json.loads((layout / "index.json").read_text())
    descriptor = cast(dict[str, object], index["manifests"][0])
    assert descriptor["digest"] == manifest_digest
    manifest_path = layout / "blobs/sha256" / manifest_digest.removeprefix("sha256:")
    manifest = json.loads(manifest_path.read_text())
    layer = cast(dict[str, object], manifest["layers"][0])
    layer_path = layout / "blobs/sha256" / str(layer["digest"]).removeprefix("sha256:")
    assert layer_path.read_bytes() == b"one locally saved image layer\n"


def test_local_oci_prep_rejects_archive_layers_that_do_not_match_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "docker-save.tar"
    image_id = _docker_save_archive(source, corrupt_diff_id=True)
    monkeypatch.setattr(prepare_containers, "IMAGE_ARCHIVES", tmp_path / "archives")
    monkeypatch.setattr(prepare_containers, "OCI_LAYOUTS", tmp_path / "layouts")
    _stub_docker_save(monkeypatch, source)

    with pytest.raises(RuntimeError, match="diff ID"):
        prepare_containers.prepare_local_oci_layout(
            name="uv",
            reference="ghcr.io/astral-sh/uv@sha256:" + "a" * 64,
            image_id=image_id,
            env={},
        )


def test_prep_refuses_unbounded_image_names() -> None:
    with pytest.raises(ValueError, match="unexpected BuildKit base image"):
        prepare_containers.prepare_local_oci_layout(
            name="other",
            reference="example.invalid/image@sha256:" + "a" * 64,
            image_id="sha256:" + "b" * 64,
            env={},
        )
