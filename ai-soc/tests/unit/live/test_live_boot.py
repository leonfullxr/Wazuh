from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from ai_soc.live.env import load_sealed_document
from ai_soc.live.pack import acquire_content_pack
from ai_soc.live.readiness import LiveReadiness
from ai_soc.live.sealed import ContentPackLocation
from tests.unit.live.live_boot_fixture import _catalog, _provenance, _sealed


def test_sealed_document_rejects_missing_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOC_SERVICE_CONFIG_JSON", raising=False)
    monkeypatch.delenv("SOC_SERVICE_CONFIG_PATH", raising=False)
    with pytest.raises(ValueError, match="exactly one"):
        load_sealed_document()


def test_readiness_reprobes_dynamodb_after_cache_expires(tmp_path: Path) -> None:
    document = _sealed()
    catalog = _catalog(document.provenance)
    pack_dir = tmp_path / "pack"
    pack_dir.mkdir()
    probe = {"ok": True}

    readiness = LiveReadiness(
        document=document,
        catalog=catalog,
        pack_dir=pack_dir,
        dynamodb_probe=lambda: probe["ok"],
        dynamodb_cache_seconds=0.0,
    )
    assert readiness.ready()
    probe["ok"] = False
    assert not readiness.ready()


def test_readiness_fails_closed_when_pack_is_removed(tmp_path: Path) -> None:
    document = _sealed()
    catalog = _catalog(document.provenance)
    pack_dir = tmp_path / "pack"
    pack_dir.mkdir()
    readiness = LiveReadiness(
        document=document,
        catalog=catalog,
        pack_dir=pack_dir,
        dynamodb_probe=lambda: True,
    )
    assert readiness.ready()
    broken = LiveReadiness(
        document=document,
        catalog=catalog,
        pack_dir=Path("/tmp/missing-pack"),
        dynamodb_probe=lambda: True,
    )
    assert not broken.ready()


def test_readiness_deadline_keeps_one_background_probe_and_caches_result(tmp_path: Path) -> None:
    document = _sealed()
    catalog = _catalog(document.provenance)
    pack_dir = tmp_path / "pack"
    pack_dir.mkdir()
    started = threading.Event()
    release = threading.Event()
    calls = 0

    def probe() -> bool:
        nonlocal calls
        calls += 1
        started.set()
        release.wait(timeout=2.0)
        return True

    readiness = LiveReadiness(
        document=document,
        catalog=catalog,
        pack_dir=pack_dir,
        dynamodb_probe=probe,
        dynamodb_cache_seconds=1.0,
        probe_deadline_seconds=0.01,
    )
    try:
        assert not readiness.ready()
        assert started.wait(timeout=0.5)
        assert not readiness.ready()
        assert calls == 1
        release.set()
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline and not readiness.ready():
            time.sleep(0.005)
        assert readiness.ready()
        assert calls == 1
    finally:
        release.set()
        readiness.close()


def test_readiness_does_not_use_an_expired_cached_probe_after_timeout(tmp_path: Path) -> None:
    document = _sealed()
    catalog = _catalog(document.provenance)
    pack_dir = tmp_path / "pack"
    pack_dir.mkdir()
    calls = 0
    release = threading.Event()

    def probe() -> bool:
        nonlocal calls
        calls += 1
        if calls == 1:
            return True
        release.wait(timeout=2.0)
        return False

    readiness = LiveReadiness(
        document=document,
        catalog=catalog,
        pack_dir=pack_dir,
        dynamodb_probe=probe,
        dynamodb_cache_seconds=0.01,
        probe_deadline_seconds=0.01,
    )
    try:
        assert readiness.ready()
        time.sleep(0.02)
        assert not readiness.ready()
        assert calls == 2
    finally:
        release.set()
        readiness.close()


def test_readiness_rejects_background_probe_completed_past_cache_lifetime(
    tmp_path: Path,
) -> None:
    document = _sealed()
    catalog = _catalog(document.provenance)
    pack_dir = tmp_path / "pack"
    pack_dir.mkdir()
    started = threading.Event()
    release = threading.Event()
    calls = 0

    def probe() -> bool:
        nonlocal calls
        calls += 1
        if calls == 1:
            started.set()
            release.wait(timeout=2.0)
            return True
        return False

    readiness = LiveReadiness(
        document=document,
        catalog=catalog,
        pack_dir=pack_dir,
        dynamodb_probe=probe,
        dynamodb_cache_seconds=0.02,
        probe_deadline_seconds=0.005,
    )
    try:
        assert not readiness.ready()
        assert started.wait(timeout=0.5)
        release.set()
        deadline = time.monotonic() + 0.5
        while (
            readiness._probe_future is None or not readiness._probe_future.done()
        ) and time.monotonic() < deadline:
            time.sleep(0.001)
        time.sleep(0.04)
        assert not readiness.ready()
        assert calls == 1
        assert not readiness.ready()
        assert calls == 2
    finally:
        release.set()
        readiness.close()


def test_pack_digest_guard_rejects_mismatch(tmp_path: Path) -> None:
    provenance = _provenance()
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1",
                "service_contract_version": "1",
                "source_repository": "https://example.test/content",
                "content_sha": "a" * 40,
                "source_tree_sha256": "b" * 64,
                "pack_sha256": "a" * 64,
                "docs_manifest_sha256": "c" * 64,
                "cue_pack_sha": "d" * 64,
                "review_attestation": "https://example.test/review.json",
                "files": [],
            }
        ),
        encoding="utf-8",
    )
    location = ContentPackLocation(uri=f"file://{tmp_path}", pack_sha256="b" * 64)
    with pytest.raises(ValueError, match="manifest digest mismatch"):
        acquire_content_pack(location, provenance)


def test_s3_archive_digest_rejects_tampered_bytes(tmp_path: Path) -> None:
    provenance = _provenance()
    archive = tmp_path / "content.tar"
    archive.write_bytes(b"not-a-real-tar")
    digest = "a" * 64
    location = ContentPackLocation(
        uri="s3://bucket/packs/sha/content.tar",
        pack_sha256=digest,
    )

    def get_object(**_kwargs: object) -> dict[str, object]:
        return {"Body": type("Body", (), {"read": lambda self: archive.read_bytes()})()}

    with pytest.raises(ValueError, match="archive digest mismatch"):
        acquire_content_pack(location, provenance, s3_get_object=get_object)
