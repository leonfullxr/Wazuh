from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from subprocess import CompletedProcess

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from scripts.reproducible_image import (  # noqa: E402
    BUILDER,
    TMPFS_REQUIRED_FREE_BYTES,
    create_tmpfs_scratch,
    inventory_tmpfs_scratch,
    normalize_generated_asset_timestamps,
    prune_builder_cache,
    read_oci_identity,
    remove_tmpfs_scratch,
    require_tmpfs_capacity,
    verify_image_set,
)


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _write_oci(
    path: Path,
    *,
    content_revision: str,
    pack_sha256: str = "a" * 64,
    layer: bytes = b"fixture-layer",
) -> None:
    config = json.dumps(
        {
            "config": {
                "Labels": {
                    "org.ai-soc.content.revision": content_revision,
                    "org.ai-soc.content.pack.sha256": pack_sha256,
                }
            }
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    config_digest = _digest(config)
    layer_digest = _digest(layer)
    manifest = json.dumps(
        {
            "config": {"digest": f"sha256:{config_digest}", "size": len(config)},
            "layers": [{"digest": f"sha256:{layer_digest}", "size": len(layer)}],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    manifest_digest = _digest(manifest)
    index = json.dumps(
        {"manifests": [{"digest": f"sha256:{manifest_digest}", "size": len(manifest)}]},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    blobs = {
        f"blobs/sha256/{config_digest}": config,
        f"blobs/sha256/{layer_digest}": layer,
        f"blobs/sha256/{manifest_digest}": manifest,
        "index.json": index,
    }
    with tarfile.open(path, mode="w:") as archive:
        for name, payload in sorted(blobs.items()):
            info = tarfile.TarInfo(name)
            info.mode = 0o644
            info.size = len(payload)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(payload))


def test_oci_parser_verifies_config_and_layer_content_digests(tmp_path: Path) -> None:
    image = tmp_path / "image.oci.tar"
    _write_oci(image, content_revision="a" * 40)

    identity = read_oci_identity(image)

    expected_config = json.dumps(
        {
            "config": {
                "Labels": {
                    "org.ai-soc.content.revision": "a" * 40,
                    "org.ai-soc.content.pack.sha256": "a" * 64,
                }
            }
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    assert identity.config_digest == f"sha256:{_digest(expected_config)}"
    assert identity.layer_digests == (f"sha256:{_digest(b'fixture-layer')}",)
    assert identity.content_revision == "a" * 40


def test_generated_asset_timestamp_normalization_preserves_bytes_across_contexts(
    tmp_path: Path,
) -> None:
    epoch = 1_791_063_373
    contexts = (tmp_path / "first", tmp_path / "second")
    for index, context in enumerate(contexts):
        assets = context / "ui/dist"
        nested = assets / "assets"
        nested.mkdir(parents=True)
        (assets / "index.html").write_bytes(b"<main>synthetic generated fixture</main>\n")
        (nested / "app.js").write_bytes(b"export const fixture = true;\n")
        varying_epoch = epoch + (index + 1) * 86_400
        for path in (nested / "app.js", nested, assets):
            os.utime(path, (varying_epoch, varying_epoch))

    before = [
        {
            path.relative_to(context): path.read_bytes()
            for path in (context / "ui/dist").rglob("*")
            if path.is_file()
        }
        for context in contexts
    ]
    for context in contexts:
        normalize_generated_asset_timestamps(context / "ui/dist", epoch)

    after = [
        {
            path.relative_to(context): path.read_bytes()
            for path in (context / "ui/dist").rglob("*")
            if path.is_file()
        }
        for context in contexts
    ]
    assert before == after
    for context in contexts:
        assert all(path.stat().st_mtime == epoch for path in (context / "ui/dist").rglob("*"))
        assert (context / "ui/dist").stat().st_mtime == epoch


def test_oci_set_requires_matching_clean_builds_and_verified_content_provenance_control(
    tmp_path: Path,
) -> None:
    first_path = tmp_path / "first.oci.tar"
    second_path = tmp_path / "second.oci.tar"
    changed_path = tmp_path / "changed.oci.tar"
    _write_oci(first_path, content_revision="a" * 40)
    _write_oci(second_path, content_revision="a" * 40)
    _write_oci(
        changed_path,
        content_revision="b" * 40,
        pack_sha256="b" * 64,
    )

    verify_image_set(
        read_oci_identity(first_path),
        read_oci_identity(second_path),
        read_oci_identity(changed_path),
    )

    _write_oci(second_path, content_revision="a" * 40, layer=b"different-layer")
    with pytest.raises(RuntimeError, match="differ in config or layer digests"):
        verify_image_set(
            read_oci_identity(first_path),
            read_oci_identity(second_path),
            read_oci_identity(changed_path),
        )


def test_oci_parser_rejects_corrupt_descriptor_blob(tmp_path: Path) -> None:
    image = tmp_path / "bad.oci.tar"
    _write_oci(image, content_revision="c" * 40)
    corrupt = tmp_path / "corrupt.oci.tar"
    with tarfile.open(image, mode="r:") as source, tarfile.open(corrupt, mode="w:") as target:
        for member in source.getmembers():
            payload = source.extractfile(member)
            assert payload is not None
            data = payload.read()
            if member.name == "blobs/sha256/" + _digest(b"fixture-layer"):
                data += b"tampered"
            info = tarfile.TarInfo(member.name)
            info.mode = member.mode
            info.size = len(data)
            info.mtime = member.mtime
            target.addfile(info, io.BytesIO(data))

    with pytest.raises(ValueError, match="corrupt layer blob"):
        read_oci_identity(corrupt)


def test_image_boundary_prune_is_limited_to_the_task_owned_builder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts import reproducible_image

    observed: list[list[str]] = []

    def fake_run(arguments: list[str], **kwargs: object) -> CompletedProcess[str]:
        del kwargs
        observed.append(arguments)
        return CompletedProcess(arguments, 0, f"inventory {len(observed)}", "")

    def fake_offline(arguments: list[str], *, environment: dict[str, str]) -> None:
        del environment
        observed.append(arguments)

    monkeypatch.setattr(reproducible_image.subprocess, "run", fake_run)
    monkeypatch.setattr(reproducible_image, "_offline_command", fake_offline)

    prune_builder_cache({"DOCKER_CONFIG": "task-local"}, tmp_path, label="after-first")

    assert observed[1] == ["prune", "--builder", BUILDER, "--all", "--force"]
    assert (tmp_path / "builder-cache-after-first-before.txt").read_text() == "inventory 1"
    assert (tmp_path / "builder-cache-after-first-after.txt").read_text() == "inventory 3"
    with pytest.raises(ValueError, match="not an image boundary"):
        prune_builder_cache({}, tmp_path, label="unscoped")


def test_tmpfs_preflight_is_bounded_and_rejects_non_tmpfs_scratch(
    tmp_path: Path,
) -> None:
    require_tmpfs_capacity(TMPFS_REQUIRED_FREE_BYTES)
    with pytest.raises(RuntimeError, match="needs at least"):
        require_tmpfs_capacity(TMPFS_REQUIRED_FREE_BYTES - 1)
    with pytest.raises(ValueError, match="task-authorized tmpfs"):
        create_tmpfs_scratch(tmp_path, "20261003T221500000000Z")


def test_tmpfs_scratch_inventory_and_cleanup_are_confined_to_unique_namespace() -> None:
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    scratch, observed_free = create_tmpfs_scratch(Path("/dev/shm"), run_id)
    try:
        fixture = scratch / "oci/fixture.oci.tar"
        fixture.parent.mkdir()
        fixture.write_bytes(b"synthetic tmpfs archive\n")
        inventory = inventory_tmpfs_scratch(scratch)

        assert observed_free >= TMPFS_REQUIRED_FREE_BYTES
        assert inventory == [
            {
                "path": "oci/fixture.oci.tar",
                "size_bytes": len(b"synthetic tmpfs archive\n"),
                "sha256": _digest(b"synthetic tmpfs archive\n"),
            }
        ]
    finally:
        remove_tmpfs_scratch(scratch)
    assert not scratch.exists()
