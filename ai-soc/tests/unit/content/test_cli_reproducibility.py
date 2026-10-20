from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import TypeAdapter

from ai_soc.content.builder import ContentBuildError, approval_payload, cue_catalog_digest
from ai_soc.content.catalog import load_content_catalog
from ai_soc.content.pointers import document_pointer
from ai_soc.contracts.models import (
    BuildProvenance,
    CueCatalog,
    DetachedApproval,
    HTTPSUrl,
    PackManifest,
)

G032_FIXTURE = Path(__file__).parent / "data/b2_g032_authority_variants.json"
HTTPS_URL: TypeAdapter[HTTPSUrl] = TypeAdapter(HTTPSUrl)


def _record_g032(record_property: Callable[[str, str], None], variant: str) -> None:
    record_property("acceptance_ids", "G032")
    record_property("case_id", "B2-G032.authority")
    record_property("variant", variant)
    record_property("fixture_sha256", hashlib.sha256(G032_FIXTURE.read_bytes()).hexdigest())


def _run_git(source: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(source), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _write_source(source: Path, fixture: dict[str, str]) -> None:
    markdown = fixture["markdown"]
    document_hash = hashlib.sha256(markdown.encode()).hexdigest()
    (source / "content/manifest.yaml").write_text(
        "schema_version: '1'\n"
        "repository: https://example.test/repository\n"
        "license: CC-BY-4.0\n"
        "default_language: en\n"
        "topics: [ldap]\n"
        "cue_files: {en: content/cues/routing.yaml, es: content/cues/routing.yaml}\n"
        "docs_origin: https://docs.example.test\n",
        encoding="utf-8",
    )
    (source / "content/topics/ldap.yaml").write_text(
        "topic_id: ldap\n"
        "name: {en: LDAP, es: LDAP}\n"
        "aliases:\n"
        "  - alias_id: ldap_en\n"
        "    language: en\n"
        "    text: LDAP\n"
        "    normalized: ldap\n"
        "    boundary: word\n"
        "    topic_id: ldap\n"
        "public_document:\n"
        "  document_id: ldap_setup\n"
        "  language: en\n"
        f"  source_path: {fixture['source_path']}\n"
        f"  heading: {fixture['heading']}\n"
        f"  anchor: {fixture['anchor']}\n  sha256: {document_hash}\n"
        f"  published_path: {fixture['published_path']}\n"
        "playbook_id: null\n"
        "finding_template_ids: []\n"
        "fetch_bindings: []\n",
        encoding="utf-8",
    )
    cue_catalog: dict[str, object] = {
        "version": "1",
        "sha256": "",
        "cues": [
            {
                "cue_id": "fetch_en",
                "language": "en",
                "text": "alerts",
                "normalized": "alerts",
                "kind": "fetch",
                "boundary": "word",
            },
            {
                "cue_id": "fetch_es",
                "language": "es",
                "text": "alertas",
                "normalized": "alertas",
                "kind": "fetch",
                "boundary": "word",
            },
        ],
        "aliases": [],
        "ambiguities": [],
    }
    cue_catalog["sha256"] = "0" * 64
    cue_catalog["sha256"] = cue_catalog_digest(CueCatalog.model_validate(cue_catalog))
    (source / "content/cues/routing.yaml").write_text(
        yaml.safe_dump(cue_catalog, sort_keys=False), encoding="utf-8"
    )
    (source / "public-docs/en/ldap.md").write_text(markdown, encoding="utf-8")


@pytest.mark.parametrize("variant", ["positive", "failure"])
def test_cli_builds_approved_git_tree_twice_without_source_mutation(
    tmp_path: Path, record_property: Callable[[str, str], None], variant: str
) -> None:
    _record_g032(record_property, variant)
    fixture = json.loads(G032_FIXTURE.read_text(encoding="utf-8"))["positive"]
    source = tmp_path / "external-content"
    (source / "content/topics").mkdir(parents=True)
    (source / "content/cues").mkdir(parents=True)
    (source / "public-docs/en").mkdir(parents=True)
    _write_source(source, fixture)
    _run_git(source, "init", "--quiet")
    _run_git(source, "config", "user.name", "Synthetic Fixture")
    _run_git(source, "config", "user.email", "fixture@example.test")
    _run_git(source, "add", "content", "public-docs")
    _run_git(source, "commit", "--quiet", "-m", "synthetic fixture content")
    commit = _run_git(source, "rev-parse", "HEAD")
    tree = _run_git(source, "rev-parse", "HEAD^{tree}")

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    approval = DetachedApproval(
        repository=HTTPS_URL.validate_python("https://example.test/repository"),
        commit=commit,
        tree_sha=tree,
        reviewer_ids=["synthetic-reviewer"],
        review_record=HTTPS_URL.validate_python("https://reviews.example.test/record/1"),
        policy_id="fixture-content-review-v1",
        approved_at=datetime(2026, 10, 3, 12, tzinfo=UTC),
        signature="pending",
        key_id="fixture-ed25519",
        mode="fixture",
    )
    signature = private_key.sign(approval_payload(approval))
    approval = approval.model_copy(update={"signature": base64.b64encode(signature).decode()})
    approval_file = tmp_path / "approval.json"
    approval_file.write_text(approval.model_dump_json(), encoding="utf-8")
    trust_file = tmp_path / "trust.json"
    trust_file.write_text(
        json.dumps({"fixture-ed25519": base64.b64encode(public_key).decode()}),
        encoding="utf-8",
    )

    before_status = _run_git(source, "status", "--porcelain")
    outputs = [tmp_path / "pack-a", tmp_path / "pack-b"]
    for output in outputs:
        completed = subprocess.run(
            [
                str(Path(sys.executable).with_name("ai-soc-content")),
                "build",
                "--source",
                str(source),
                "--commit",
                commit,
                "--attestation",
                str(approval_file),
                "--trust-root",
                str(trust_file),
                "--fixture",
                "--out",
                str(output),
            ],
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONHASHSEED": "0", "TZ": "UTC"},
        )
        assert completed.returncode == 0, completed.stderr
    first = {
        path.relative_to(outputs[0]).as_posix(): path.read_bytes()
        for path in outputs[0].rglob("*")
        if path.is_file()
    }
    second = {
        path.relative_to(outputs[1]).as_posix(): path.read_bytes()
        for path in outputs[1].rglob("*")
        if path.is_file()
    }
    assert first == second
    assert _run_git(source, "status", "--porcelain") == before_status
    assert not (source / "build").exists()
    pack_manifest = PackManifest.model_validate_json((outputs[0] / "manifest.json").read_bytes())
    provenance = BuildProvenance(
        service_sha="0" * 40,
        content_repository="https://example.test/repository",
        content_sha=commit,
        pack_sha256=pack_manifest.pack_sha256,
        image_digest="sha256:" + "3" * 64,
        docs_origin="https://docs.example.test",
        docs_manifest_sha256=pack_manifest.docs_manifest_sha256,
    )
    if variant == "failure":
        topic_file = outputs[0] / "pack/topics/ldap.json"
        topic_file.chmod(0o600)
        topic_file.write_bytes(topic_file.read_bytes() + b" ")
        with pytest.raises(ContentBuildError, match="manifest file hash mismatch"):
            load_content_catalog(outputs[0], provenance=provenance)
        return
    catalog = load_content_catalog(outputs[0], provenance=provenance)
    prompt = catalog.topic_context("ldap", language="en")
    packed_topic = json.loads((outputs[0] / "pack/topics/ldap.json").read_text())
    assert packed_topic["schema_version"] == "1"
    loaded_topic = catalog.topic("ldap")
    assert loaded_topic is not None and loaded_topic.schema_version == "1"
    pointer = document_pointer(
        loaded_topic,
        language="en",
        content_sha=commit,
        docs_origin="https://docs.example.test",
    )
    assert pointer is not None
    assert pointer.source_path == fixture["source_path"]
    assert pointer.heading == fixture["heading"]
    assert str(pointer.url) == (
        f"https://docs.example.test/commits/{commit}/en/ldap.html#synthetic-ldap-setup"
    )
    assert prompt.document_section == fixture["expected_section"]
    assert prompt.missing == ["playbook"]
