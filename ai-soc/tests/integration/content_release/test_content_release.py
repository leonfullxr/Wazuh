from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, NotRequired, TypedDict

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import TypeAdapter

from ai_soc.content.builder import approval_payload
from ai_soc.content.catalog import load_content_catalog
from ai_soc.content.pointers import document_pointer
from ai_soc.contracts.canonical import canonical_bytes
from ai_soc.contracts.models import (
    BuildProvenance,
    CompareCountStep,
    DetachedApproval,
    FindingTemplate,
    HTTPSUrl,
    IntegerOperand,
    LocaleText,
    PackManifest,
    PlaybookDefinition,
    SolvedCase,
    SourceManifest,
    TopicDefinition,
)

FIXTURE = Path(__file__).parent / "data/content_release_cases.json"
G048_FIXTURE = Path(__file__).parent / "data/g048_pack_provenance_cases.json"
G054_FIXTURE = Path(__file__).parent / "data/g054_approved_source_cases.json"
G055_FIXTURE = Path(__file__).parent / "data/g055_document_identity_cases.json"
SOLVED_VARIANT = Literal["positive", "negative", "boundary", "failure"]


class AnonymizationFixture(TypedDict):
    reviewer_id: str
    date: str


class SolvedCaseFixture(TypedDict):
    schema_version: Literal["1"]
    case_id: str
    topic_id: str
    synthetic: bool
    description: str
    promotion_status: Literal["candidate", "approved"]
    anonymization_attestation: AnonymizationFixture
    review_record: NotRequired[str]


class ExpectedFixture(TypedDict):
    first_context: str
    revised_context: str
    dirty_error: str
    stale_provenance_error: str
    tampered_pack_error: str
    missing_case_review_error: str
    secret_error: str


class GitContentFixture(TypedDict):
    schema_version: Literal["1"]
    repository: str
    source_path: str
    published_path: str
    heading: str
    anchor: str
    base_document: str


class G048Case(TypedDict):
    action: str
    expected_identical_pack: NotRequired[bool]
    path: NotRequired[str]
    expected_context: NotRequired[str]
    expected_error: NotRequired[str]
    expected_published_path: NotRequired[str]
    changed_bytes: NotRequired[str]


class G054Case(TypedDict):
    action: str
    expected_repository: NotRequired[str]
    expected_topics: NotRequired[list[str]]
    untracked_topic_id: NotRequired[str]
    expected_error: NotRequired[str]


class G055Case(TypedDict):
    action: str
    expected_source_path: NotRequired[str]
    expected_heading: NotRequired[str]
    expected_anchor: NotRequired[str]
    expected_url_prefix: NotRequired[str]
    expected_error: NotRequired[str]
    expected_document: NotRequired[str]
    expected_context: NotRequired[str]
    expected_path: NotRequired[str]
    path: NotRequired[str]


class ContentReleaseFixture(GitContentFixture):
    revised_document: str
    dirty_document: str
    solved_cases: dict[SOLVED_VARIANT, SolvedCaseFixture]
    expected: ExpectedFixture


class G048Fixture(GitContentFixture):
    revised_document: str
    cases: dict[SOLVED_VARIANT, G048Case]


class G054Fixture(GitContentFixture):
    revised_document: str
    dirty_document: str
    untracked_topic_path: str
    untracked_topic: str
    cases: dict[SOLVED_VARIANT, G054Case]


class G055Fixture(GitContentFixture):
    revised_document: str
    revised_heading: str
    revised_anchor: str
    revised_published_path: str
    invalid_declared_sha256: str
    cases: dict[SOLVED_VARIANT, G055Case]


class PackProvenanceFixture(TypedDict):
    source_repository: str
    content_sha: str
    source_tree_sha256: str
    pack_sha256: str
    docs_manifest_sha256: str
    cue_pack_sha: str
    approval_key_id: str
    mode: Literal["fixture", "live"]


FIXTURE_ADAPTER: TypeAdapter[ContentReleaseFixture] = TypeAdapter(ContentReleaseFixture)
G048_FIXTURE_ADAPTER: TypeAdapter[G048Fixture] = TypeAdapter(G048Fixture)
G054_FIXTURE_ADAPTER: TypeAdapter[G054Fixture] = TypeAdapter(G054Fixture)
G055_FIXTURE_ADAPTER: TypeAdapter[G055Fixture] = TypeAdapter(G055Fixture)
PACK_PROVENANCE_ADAPTER: TypeAdapter[PackProvenanceFixture] = TypeAdapter(PackProvenanceFixture)
HTTPS_URL_ADAPTER: TypeAdapter[HTTPSUrl] = TypeAdapter(HTTPSUrl)


def _fixture() -> ContentReleaseFixture:
    value: object = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return FIXTURE_ADAPTER.validate_python(value)


def _scope_fixture[FixtureT](path: Path, adapter: TypeAdapter[FixtureT]) -> FixtureT:
    value: object = json.loads(path.read_text(encoding="utf-8"))
    return adapter.validate_python(value)


def _g048_fixture() -> G048Fixture:
    return _scope_fixture(G048_FIXTURE, G048_FIXTURE_ADAPTER)


def _g054_fixture() -> G054Fixture:
    return _scope_fixture(G054_FIXTURE, G054_FIXTURE_ADAPTER)


def _g055_fixture() -> G055Fixture:
    return _scope_fixture(G055_FIXTURE, G055_FIXTURE_ADAPTER)


def _case_text(case: Mapping[str, object], key: str) -> str:
    value = case.get(key)
    if not isinstance(value, str):
        raise AssertionError(f"fixture case field {key!r} must be a string")
    return value


def _case_texts(case: Mapping[str, object], key: str) -> list[str]:
    value = case.get(key)
    if not isinstance(value, list):
        raise AssertionError(f"fixture case field {key!r} must be a list of strings")
    return TypeAdapter(list[str]).validate_python(value)


def _case_flag(case: Mapping[str, object], key: str) -> bool:
    value = case.get(key)
    if not isinstance(value, bool):
        raise AssertionError(f"fixture case field {key!r} must be a boolean")
    return value


def _record_integration_case(record_property: Callable[[str, str], None], *, variant: str) -> None:
    record_property("acceptance_ids", "GN04")
    record_property("case_id", "B2-GN04.reviewed-synthetic-release")
    record_property("variant", variant)
    record_property("fixture_sha256", _sha256(FIXTURE.read_bytes()))


def _record_scope_case(
    record_property: Callable[[str, str], None],
    *,
    requirement: str,
    case_id: str,
    variant: str,
    fixture: Path,
) -> None:
    record_property("acceptance_ids", requirement)
    record_property("case_id", case_id)
    record_property("variant", variant)
    record_property("fixture_sha256", _sha256(fixture.read_bytes()))


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _run_git(source: Path, *args: str, env: dict[str, str]) -> str:
    result = subprocess.run(
        ["git", "-C", str(source), *args],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    if result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr}")
    return result.stdout.strip()


def _git_env() -> dict[str, str]:
    return {
        **os.environ,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }


def _new_source(tmp_path: Path, *, fixture: GitContentFixture | None = None) -> Path:
    cases = fixture or _fixture()
    source = tmp_path / "external-content"
    seed = Path(__file__).resolve().parents[3] / "examples/content-seed"
    shutil.copytree(seed / "content", source / "content")
    shutil.copytree(seed / "public-docs", source / "public-docs")
    manifest_path = source / "content/manifest.yaml"
    manifest = SourceManifest.model_validate(
        yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    )
    manifest = manifest.model_copy(
        update={"repository": HTTPS_URL_ADAPTER.validate_python(cases["repository"])}
    )
    manifest_path.write_text(
        yaml.safe_dump(manifest.model_dump(mode="json", exclude_none=True), sort_keys=False),
        encoding="utf-8",
    )
    document = source / cases["source_path"]
    document.write_text(cases["base_document"], encoding="utf-8")
    _set_document_digest(source, cases, document.read_bytes())
    env = _git_env()
    _run_git(source, "init", "--quiet", "--initial-branch=main", env=env)
    _run_git(source, "config", "user.name", "Synthetic Release Fixture", env=env)
    _run_git(source, "config", "user.email", "fixture@example.test", env=env)
    _commit(source, "approved synthetic content release one", 1_791_063_373, env=env)
    return source


def _commit(source: Path, message: str, timestamp: int, *, env: dict[str, str]) -> str:
    _run_git(source, "add", "-A", env=env)
    commit_env = {
        **env,
        "GIT_AUTHOR_DATE": f"@{timestamp} +0000",
        "GIT_COMMITTER_DATE": f"@{timestamp} +0000",
    }
    result = subprocess.run(
        [
            "git",
            "-C",
            str(source),
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            message,
        ],
        check=False,
        capture_output=True,
        text=True,
        env=commit_env,
        timeout=30,
    )
    if result.returncode != 0:
        raise AssertionError(f"synthetic commit failed: {result.stderr}")
    return _run_git(source, "rev-parse", "HEAD", env=env)


def _set_document_digest(source: Path, fixture: GitContentFixture, document_bytes: bytes) -> None:
    topic_path = source / "content/topics/ldap.yaml"
    topic = TopicDefinition.model_validate(yaml.safe_load(topic_path.read_text(encoding="utf-8")))
    public_document = topic.public_document
    if public_document is None:
        raise AssertionError("seed topic should have a public document")
    if public_document.source_path != fixture["source_path"]:
        raise AssertionError("seed topic document path differs from the independent fixture")
    revised_document = public_document.model_copy(
        update={
            "heading": fixture["heading"],
            "anchor": fixture["anchor"],
            "published_path": fixture["published_path"],
            "sha256": _sha256(document_bytes),
        }
    )
    revised_topic = topic.model_copy(update={"public_document": revised_document})
    topic_path.write_text(
        yaml.safe_dump(revised_topic.model_dump(mode="json", exclude_none=True), sort_keys=False),
        encoding="utf-8",
    )


def _signed_approval(
    source: Path,
    commit: str,
    tmp_path: Path,
    private_key: Ed25519PrivateKey,
    *,
    fixture: GitContentFixture,
) -> tuple[Path, Path]:
    env = _git_env()
    tree_sha = _run_git(source, "rev-parse", f"{commit}^{{tree}}", env=env)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    approval = DetachedApproval(
        repository=HTTPS_URL_ADAPTER.validate_python(fixture["repository"]),
        commit=commit,
        tree_sha=tree_sha,
        reviewer_ids=["synthetic-content-reviewer"],
        review_record=HTTPS_URL_ADAPTER.validate_python(
            "https://reviews.example.test/synthetic-content/approval"
        ),
        policy_id="synthetic-content-release-v1",
        approved_at=datetime(2026, 10, 4, 12, tzinfo=UTC),
        signature="pending",
        key_id="synthetic-content-release-key",
        mode="fixture",
    )
    signature = private_key.sign(approval_payload(approval))
    signed = approval.model_copy(update={"signature": base64.b64encode(signature).decode("ascii")})
    approval_path = tmp_path / f"approval-{commit}.json"
    trust_path = tmp_path / "trust-root.json"
    approval_path.write_text(signed.model_dump_json() + "\n", encoding="utf-8")
    trust_path.write_text(
        json.dumps({signed.key_id: base64.b64encode(public_key).decode("ascii")}, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    return approval_path, trust_path


def _content_cli() -> Path:
    executable = Path(sys.executable).with_name("ai-soc-content")
    if not executable.is_file():
        raise AssertionError("locked ai-soc-content executable is unavailable")
    return executable


def _build(
    source: Path,
    commit: str,
    approval: Path,
    trust_root: Path,
    out: Path,
    *,
    timeout: int = 30,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            str(_content_cli()),
            "build",
            "--source",
            str(source),
            "--commit",
            commit,
            "--attestation",
            str(approval),
            "--trust-root",
            str(trust_root),
            "--fixture",
            "--out",
            str(out),
        ],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull},
        timeout=timeout,
    )


def _runtime_provenance(pack: Path, *, fixture: GitContentFixture) -> BuildProvenance:
    manifest = PackManifest.model_validate_json((pack / "manifest.json").read_bytes())
    provenance_file = PACK_PROVENANCE_ADAPTER.validate_python(
        json.loads((pack / "provenance.json").read_bytes())
    )
    if provenance_file["source_repository"] != fixture["repository"]:
        raise AssertionError("provenance repository differs from the signed fixture repository")
    return BuildProvenance(
        service_sha="1" * 40,
        content_repository=fixture["repository"],
        content_sha=manifest.content_sha,
        pack_sha256=manifest.pack_sha256,
        image_digest="sha256:" + "2" * 64,
        docs_origin="https://docs.example.test",
        docs_manifest_sha256=manifest.docs_manifest_sha256,
    )


def _pack_files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _rehash_pack_for_legacy_catalog_case(
    pack: Path,
    *,
    dangling_prerequisite: bool,
    duplicate_playbook: bool = False,
    duplicate_check_declaration: bool = False,
) -> None:
    """Create a correctly hashed topic-named template artifact for legacy load checks."""
    manifest = PackManifest.model_validate_json((pack / "manifest.json").read_bytes())
    files = {item.path: (pack / item.path).read_bytes() for item in manifest.files}
    new_path = "pack/finding-templates/ldap_visible_count.json"
    legacy_path = "pack/finding-templates/ldap.json"
    if new_path in files:
        files[legacy_path] = files.pop(new_path)
    template_data = json.loads(files[legacy_path])
    if dangling_prerequisite:
        template_data["required_check_outcomes"] = [
            {"check_id": "undeclared_check", "outcome": "passed"}
        ]
        files[legacy_path] = canonical_bytes(template_data)
    if duplicate_check_declaration:
        template_data["required_check_outcomes"] = [
            {"check_id": "ldap_duplicate_check", "outcome": "passed"}
        ]
        files[legacy_path] = canonical_bytes(template_data)
        playbook_path = "pack/playbooks/ldap.json"
        playbook = PlaybookDefinition.model_validate_json(files[playbook_path])
        label = LocaleText(en="Duplicate check", es="Chequeo duplicado")
        duplicate_steps = [
            CompareCountStep(
                kind="compare_count",
                step_id=f"duplicate_check_step_{index}",
                label=label,
                check_id="ldap_duplicate_check",
                left_fetch_id="ldap_recent_alert_count",
                op="gte",
                right=IntegerOperand(kind="literal", value=0),
            )
            for index in (1, 2)
        ]
        playbook = playbook.model_copy(update={"steps": [*playbook.steps, *duplicate_steps]})
        files[playbook_path] = canonical_bytes(playbook.model_dump(mode="json", exclude_none=False))
    if duplicate_playbook:
        files["pack/playbooks/ldap_shadow.json"] = files["pack/playbooks/ldap.json"]
    file_entries = [
        {"path": path, "sha256": _sha256(data), "bytes": len(data)}
        for path, data in sorted(files.items())
    ]
    pack_records = {
        path: _sha256(data) for path, data in sorted(files.items()) if path.startswith("pack/")
    }
    manifest_data = manifest.model_dump(mode="json", exclude_none=False)
    manifest_data["files"] = file_entries
    manifest_data["pack_sha256"] = _sha256(canonical_bytes(pack_records))
    manifest_bytes = canonical_bytes(manifest_data)
    provenance_data = json.loads((pack / "provenance.json").read_bytes())
    provenance_data["pack_sha256"] = manifest_data["pack_sha256"]
    (pack / "provenance.json").chmod(0o600)
    (pack / "provenance.json").write_bytes(canonical_bytes(provenance_data))
    (pack / "manifest.json").chmod(0o600)
    (pack / "manifest.json").write_bytes(manifest_bytes)
    old_path = pack / new_path
    if old_path.exists():
        old_path.unlink()
    legacy_file = pack / legacy_path
    legacy_file.parent.mkdir(parents=True, exist_ok=True)
    legacy_file.write_bytes(files[legacy_path])
    legacy_file.chmod(0o444)
    for path, data in files.items():
        if path == legacy_path:
            continue
        target = pack / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            target.chmod(0o600)
        target.write_bytes(data)
        target.chmod(0o444)
    archive_members = {
        **files,
        "docs-manifest.json": (pack / "docs-manifest.json").read_bytes(),
        "provenance.json": (pack / "provenance.json").read_bytes(),
        "manifest.json": manifest_bytes,
    }
    archive_path = pack / "content.tar"
    archive_path.chmod(0o600)
    with tarfile.open(archive_path, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for path, data in sorted(archive_members.items()):
            info = tarfile.TarInfo(path)
            info.size = len(data)
            info.mtime = 0
            info.mode = 0o444
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    archive_path.chmod(0o444)
    archive_hash_path = pack / "archive.sha256"
    archive_hash_path.chmod(0o600)
    archive_hash_path.write_text(_sha256(archive_path.read_bytes()) + "\n", encoding="ascii")
    archive_hash_path.chmod(0o444)


@pytest.mark.parametrize("variant", ["positive", "negative", "boundary", "failure"])
def test_g048_pack_and_provenance_contract(
    tmp_path: Path,
    variant: SOLVED_VARIANT,
    record_property: Callable[[str, str], None],
) -> None:
    _record_scope_case(
        record_property,
        requirement="G048",
        case_id="B2-G048.content-release",
        variant=variant,
        fixture=G048_FIXTURE,
    )
    fixture = _g048_fixture()
    case = fixture["cases"][variant]
    source = _new_source(tmp_path, fixture=fixture)
    key = Ed25519PrivateKey.generate()
    commit = _run_git(source, "rev-parse", "HEAD", env=_git_env())
    approval, trust = _signed_approval(source, commit, tmp_path, key, fixture=fixture)
    pack = tmp_path / "g048-pack"
    result = _build(source, commit, approval, trust, pack)
    assert result.returncode == 0, result.stderr
    manifest = PackManifest.model_validate_json((pack / "manifest.json").read_bytes())
    provenance = _runtime_provenance(pack, fixture=fixture)
    catalog = load_content_catalog(pack, provenance=provenance)

    if variant == "positive":
        second = tmp_path / "g048-repeat"
        repeated = _build(source, commit, approval, trust, second)
        assert repeated.returncode == 0, repeated.stderr
        assert _case_flag(case, "expected_identical_pack") is True
        assert _pack_files(pack) == _pack_files(second)
    elif variant == "negative":
        (source / fixture["source_path"]).write_text(fixture["revised_document"], encoding="utf-8")
        artifact = tmp_path / "g048-artifact"
        shutil.copytree(pack, artifact)
        asset = artifact / _case_text(case, "path")
        asset.chmod(0o600)
        asset.write_text(_case_text(case, "changed_bytes"), encoding="utf-8")
        assert catalog.topic_context("ldap", language="en").document_section == _case_text(
            case, "expected_context"
        )
        with pytest.raises(ValueError, match=_case_text(case, "expected_error")):
            load_content_catalog(artifact, provenance=provenance)
    elif variant == "boundary":
        doc = source / fixture["source_path"]
        doc.write_text(fixture["revised_document"], encoding="utf-8")
        _set_document_digest(source, fixture, doc.read_bytes())
        new_commit = _commit(
            source, "approved G048 document revision", 1_791_063_374, env=_git_env()
        )
        new_approval, _ = _signed_approval(source, new_commit, tmp_path, key, fixture=fixture)
        revised = tmp_path / "g048-revised"
        rebuilt = _build(source, new_commit, new_approval, trust, revised)
        assert rebuilt.returncode == 0, rebuilt.stderr
        new_manifest = PackManifest.model_validate_json((revised / "manifest.json").read_bytes())
        new_catalog = load_content_catalog(
            revised, provenance=_runtime_provenance(revised, fixture=fixture)
        )
        assert new_manifest.content_sha != manifest.content_sha
        assert new_manifest.pack_sha256 != manifest.pack_sha256
        assert new_manifest.docs_manifest_sha256 != manifest.docs_manifest_sha256
        assert new_catalog.topic_context("ldap", language="en").document_section == _case_text(
            case, "expected_context"
        )
    else:
        doc = source / fixture["source_path"]
        doc.write_text(fixture["revised_document"], encoding="utf-8")
        _set_document_digest(source, fixture, doc.read_bytes())
        new_commit = _commit(source, "new G048 provenance", 1_791_063_375, env=_git_env())
        new_approval, _ = _signed_approval(source, new_commit, tmp_path, key, fixture=fixture)
        revised = tmp_path / "g048-new-provenance"
        rebuilt = _build(source, new_commit, new_approval, trust, revised)
        assert rebuilt.returncode == 0, rebuilt.stderr
        with pytest.raises(ValueError, match=_case_text(case, "expected_error")):
            load_content_catalog(pack, provenance=_runtime_provenance(revised, fixture=fixture))


@pytest.mark.parametrize("variant", ["positive", "negative", "boundary", "failure"])
def test_g054_detached_approval_binds_exact_git_tree(
    tmp_path: Path,
    variant: SOLVED_VARIANT,
    record_property: Callable[[str, str], None],
) -> None:
    _record_scope_case(
        record_property,
        requirement="G054",
        case_id="B2-G054.approval-release",
        variant=variant,
        fixture=G054_FIXTURE,
    )
    fixture = _g054_fixture()
    case = fixture["cases"][variant]
    source = _new_source(tmp_path, fixture=fixture)
    key = Ed25519PrivateKey.generate()
    commit = _run_git(source, "rev-parse", "HEAD", env=_git_env())
    approval, trust = _signed_approval(source, commit, tmp_path, key, fixture=fixture)
    output = tmp_path / f"g054-{variant}"

    if variant in {"positive", "negative"}:
        if variant == "negative":
            (source / fixture["untracked_topic_path"]).write_text(
                fixture["untracked_topic"], encoding="utf-8"
            )
        result = _build(source, commit, approval, trust, output)
        assert result.returncode == 0, result.stderr
        catalog = load_content_catalog(
            output, provenance=_runtime_provenance(output, fixture=fixture)
        )
        expected_topics = sorted(("ldap", "auth_review", "vuln_review"))
        assert [topic.topic_id for topic in catalog.topics()] == expected_topics
        if variant == "positive":
            assert catalog.manifest().content_repository == _case_text(case, "expected_repository")
        else:
            assert _case_text(case, "untracked_topic_id") not in expected_topics
            assert "pack/topics/dns.json" not in _pack_files(output)
    elif variant == "boundary":
        doc = source / fixture["source_path"]
        doc.write_text(fixture["revised_document"], encoding="utf-8")
        _set_document_digest(source, fixture, doc.read_bytes())
        changed = _commit(source, "unapproved G054 revision", 1_791_063_375, env=_git_env())
        result = _build(source, changed, approval, trust, output)
        assert result.returncode == 2
        assert _case_text(case, "expected_error") in result.stderr
        assert not output.exists()
    else:
        (source / fixture["source_path"]).write_text(fixture["dirty_document"], encoding="utf-8")
        result = _build(source, commit, approval, trust, output)
        assert result.returncode == 2
        assert _case_text(case, "expected_error") in result.stderr
        assert not output.exists()


@pytest.mark.parametrize("variant", ["positive", "negative", "boundary", "failure"])
def test_g055_exact_public_document_identity(
    tmp_path: Path,
    variant: SOLVED_VARIANT,
    record_property: Callable[[str, str], None],
) -> None:
    _record_scope_case(
        record_property,
        requirement="G055",
        case_id="B2-G055.docs-promotion",
        variant=variant,
        fixture=G055_FIXTURE,
    )
    fixture = _g055_fixture()
    case = fixture["cases"][variant]
    source = _new_source(tmp_path, fixture=fixture)
    key = Ed25519PrivateKey.generate()
    if variant == "negative":
        path = source / "content/topics/ldap.yaml"
        topic = TopicDefinition.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
        public_document = topic.public_document
        assert public_document is not None
        invalid = public_document.model_copy(update={"sha256": fixture["invalid_declared_sha256"]})
        path.write_text(
            yaml.safe_dump(
                topic.model_copy(update={"public_document": invalid}).model_dump(
                    mode="json", exclude_none=True
                ),
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        _commit(source, "invalid G055 declared document digest", 1_791_063_372, env=_git_env())
    commit = _run_git(source, "rev-parse", "HEAD", env=_git_env())
    approval, trust = _signed_approval(source, commit, tmp_path, key, fixture=fixture)
    output = tmp_path / f"g055-{variant}"
    result = _build(source, commit, approval, trust, output)

    if variant == "negative":
        assert result.returncode == 2
        assert _case_text(case, "expected_error") in result.stderr
        assert not output.exists()
        return
    assert result.returncode == 0, result.stderr
    manifest = PackManifest.model_validate_json((output / "manifest.json").read_bytes())
    provenance = _runtime_provenance(output, fixture=fixture)
    catalog = load_content_catalog(output, provenance=provenance)
    if variant == "positive":
        topic = catalog.topic("ldap")
        assert topic is not None
        pointer = document_pointer(
            topic, language="en", content_sha=commit, docs_origin="https://docs.example.test"
        )
        assert pointer is not None
        assert pointer.source_path == _case_text(case, "expected_source_path")
        assert pointer.heading == _case_text(case, "expected_heading")
        assert pointer.anchor == _case_text(case, "expected_anchor")
        assert str(pointer.url).startswith(_case_text(case, "expected_url_prefix"))
        docs = json.loads((output / "docs-manifest.json").read_bytes())
        document_paths = (
            "en/ldap.html",
            "en/auth-review.html",
            "en/vulnerability-review.html",
        )
        assert docs["files"] == {
            path: _sha256((output / "docs" / path).read_bytes()) for path in document_paths
        }
        assert manifest.docs_manifest_sha256 == _sha256(
            json.dumps(docs["files"], sort_keys=True, separators=(",", ":")).encode()
        )
    elif variant == "boundary":
        doc = source / fixture["source_path"]
        doc.write_text(_case_text(case, "expected_document"), encoding="utf-8")
        _set_document_digest(source, fixture, doc.read_bytes())
        new_commit = _commit(
            source, "approved G055 document revision", 1_791_063_374, env=_git_env()
        )
        new_approval, _ = _signed_approval(source, new_commit, tmp_path, key, fixture=fixture)
        revised = tmp_path / "g055-revised"
        rebuilt = _build(source, new_commit, new_approval, trust, revised)
        assert rebuilt.returncode == 0, rebuilt.stderr
        new_manifest = PackManifest.model_validate_json((revised / "manifest.json").read_bytes())
        new_catalog = load_content_catalog(
            revised, provenance=_runtime_provenance(revised, fixture=fixture)
        )
        assert new_manifest.docs_manifest_sha256 != manifest.docs_manifest_sha256
        assert new_catalog.topic_context("ldap", language="en").document_section == _case_text(
            case, "expected_context"
        )
        revised_topic = new_catalog.topic("ldap")
        assert revised_topic is not None
        pointer = document_pointer(
            revised_topic,
            language="en",
            content_sha=new_commit,
            docs_origin="https://docs.example.test",
        )
        assert pointer is not None
        assert str(pointer.url).endswith(
            f"/{_case_text(case, 'expected_path')}#{fixture['revised_anchor']}"
        )
    elif variant == "failure":
        asset = output / _case_text(case, "path")
        asset.chmod(0o600)
        asset.write_text("tampered public docs asset\n", encoding="utf-8")
        with pytest.raises(ValueError, match=_case_text(case, "expected_error")):
            load_content_catalog(output, provenance=provenance)


@pytest.mark.parametrize("variant", ["positive", "negative", "boundary", "failure"])
def test_solved_case_release_requires_reviewed_anonymization(
    tmp_path: Path,
    variant: SOLVED_VARIANT,
    record_property: Callable[[str, str], None],
) -> None:
    fixture = _fixture()
    _record_integration_case(record_property, variant=variant)
    source = _new_source(tmp_path, fixture=fixture)
    solved_case: SolvedCaseFixture = fixture["solved_cases"][variant]
    typed_case = SolvedCase.model_validate(solved_case)
    case_file = source / "content/solved-cases/ldap.yaml"
    case_file.write_text(
        yaml.safe_dump(typed_case.model_dump(mode="json", exclude_none=False), sort_keys=False),
        encoding="utf-8",
    )
    commit = _commit(source, f"synthetic solved-case {variant}", 1_791_063_380, env=_git_env())
    approval, trust_root = _signed_approval(
        source, commit, tmp_path, Ed25519PrivateKey.generate(), fixture=fixture
    )
    output = tmp_path / f"solved-case-{variant}"
    result = _build(source, commit, approval, trust_root, output)

    if variant in {"positive", "boundary"}:
        assert result.returncode == 0, result.stderr
        packed_case = json.loads((output / "pack/solved-cases/ldap.json").read_bytes())
        assert packed_case["synthetic"] is True
        assert packed_case["promotion_status"] == "approved"
        assert packed_case["anonymization_attestation"]["reviewer_id"] == (
            "synthetic-anonymization-reviewer"
        )
        assert "review_record" in packed_case
        if variant == "boundary":
            assert packed_case["anonymization_attestation"]["date"] == "2024-02-29"
        return

    assert result.returncode == 2
    assert not output.exists()
    if variant == "negative":
        assert fixture["expected"]["missing_case_review_error"] in result.stderr
    else:
        assert fixture["expected"]["secret_error"] in result.stderr


def test_content_release_requires_detached_approval_file(tmp_path: Path) -> None:
    fixture = _fixture()
    source = _new_source(tmp_path, fixture=fixture)
    commit = _run_git(source, "rev-parse", "HEAD", env=_git_env())
    output = tmp_path / "missing-detached-approval"
    result = _build(
        source,
        commit,
        tmp_path / "missing-approval.json",
        tmp_path / "missing-trust-root.json",
        output,
    )
    assert result.returncode == 2
    assert not output.exists()
    assert "No such file or directory" in result.stderr


def test_approved_build_preserves_all_topic_finding_templates(tmp_path: Path) -> None:
    fixture = _fixture()
    source = _new_source(tmp_path, fixture=fixture)
    first_path = source / "content/finding-templates/ldap_visible_count.yaml"
    first_data = yaml.safe_load(first_path.read_text(encoding="utf-8"))
    first = FindingTemplate.model_validate_json(json.dumps(first_data))
    second_data = {
        **first_data,
        "template_id": "t_q7m4p9",
        "texts": {
            "en": "The approved second LDAP example preserves {ldap_recent_alert_count}.",
            "es": "El segundo ejemplo aprobado de LDAP conserva {ldap_recent_alert_count}.",
        },
    }
    second = FindingTemplate.model_validate_json(json.dumps(second_data))
    (source / "content/finding-templates/t_q7m4p9.yaml").write_text(
        yaml.safe_dump(second_data, sort_keys=False), encoding="utf-8"
    )

    topic_path = source / "content/topics/ldap.yaml"
    topic_data = yaml.safe_load(topic_path.read_text(encoding="utf-8"))
    topic_data["finding_template_ids"].append(second.template_id)
    topic_path.write_text(yaml.safe_dump(topic_data, sort_keys=False), encoding="utf-8")
    commit = _commit(source, "approved multi-template LDAP catalog", 1_791_063_376, env=_git_env())
    key = Ed25519PrivateKey.generate()
    approval, trust = _signed_approval(source, commit, tmp_path, key, fixture=fixture)

    output = tmp_path / "multi-template-pack"
    result = _build(source, commit, approval, trust, output)
    assert result.returncode == 0, result.stderr
    manifest = PackManifest.model_validate_json((output / "manifest.json").read_bytes())
    expected_paths = {
        "pack/finding-templates/ldap_visible_count.json",
        "pack/finding-templates/t_q7m4p9.json",
    }
    template_paths = {
        item.path for item in manifest.files if item.path.startswith("pack/finding-templates/")
    }
    actual_paths = {
        path.relative_to(output).as_posix()
        for path in (output / "pack/finding-templates").glob("*.json")
    }
    assert expected_paths <= template_paths
    assert actual_paths == template_paths

    packed = {
        path.stem: FindingTemplate.model_validate_json(path.read_bytes())
        for path in (output / "pack/finding-templates").glob("*.json")
        if path.stem in {first.template_id, second.template_id}
    }
    expected = {first.template_id: first, second.template_id: second}
    assert set(packed) == set(expected)
    for template_id, definition in expected.items():
        assert packed[template_id].model_dump(mode="json") == definition.model_dump(mode="json")

    provenance = _runtime_provenance(output, fixture=fixture)
    catalog = load_content_catalog(output, provenance=provenance)
    loaded = {template.template_id: template for template in catalog.finding_templates("ldap")}
    assert set(loaded) == set(expected)
    for template_id, definition in expected.items():
        assert loaded[template_id].model_dump(mode="json") == definition.model_dump(mode="json")

    repeated = tmp_path / "multi-template-repeat"
    repeated_result = _build(source, commit, approval, trust, repeated)
    assert repeated_result.returncode == 0, repeated_result.stderr
    assert _pack_files(output) == _pack_files(repeated)


@pytest.mark.parametrize(
    ("group", "record_id", "expected_path"),
    [
        ("playbooks", "ldap_other_checks", "pack/playbooks/ldap.json"),
        ("expectations", "ldap_other_expectation", "pack/expectations/ldap.json"),
    ],
)
def test_approved_build_rejects_same_topic_sibling_record_collision(
    tmp_path: Path, group: str, record_id: str, expected_path: str
) -> None:
    fixture = _fixture()
    source = _new_source(tmp_path, fixture=fixture)
    first_path = source / f"content/{group}/ldap.yaml"
    second_data = yaml.safe_load(first_path.read_text(encoding="utf-8"))
    id_field = "playbook_id" if group == "playbooks" else "expectation_id"
    second_data[id_field] = record_id
    (source / f"content/{group}/ldap_other.yaml").write_text(
        yaml.safe_dump(second_data, sort_keys=False), encoding="utf-8"
    )
    commit = _commit(
        source, f"approved same-topic {group} collision", 1_791_063_377, env=_git_env()
    )
    approval, trust = _signed_approval(
        source, commit, tmp_path, Ed25519PrivateKey.generate(), fixture=fixture
    )
    output = tmp_path / f"colliding-{group}"
    result = _build(source, commit, approval, trust, output)
    assert result.returncode == 2
    assert f"duplicate generated content pack path: {expected_path}" in result.stderr
    assert not output.exists()


def test_hash_valid_legacy_layout_loads_only_with_valid_prerequisite_references(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    source = _new_source(tmp_path, fixture=fixture)
    commit = _run_git(source, "rev-parse", "HEAD", env=_git_env())
    approval, trust = _signed_approval(
        source, commit, tmp_path, Ed25519PrivateKey.generate(), fixture=fixture
    )
    valid_pack = tmp_path / "legacy-valid"
    invalid_pack = tmp_path / "legacy-invalid"
    duplicate_playbook_pack = tmp_path / "legacy-duplicate-playbook"
    duplicate_check_pack = tmp_path / "legacy-duplicate-check"
    for output in (valid_pack, invalid_pack, duplicate_playbook_pack, duplicate_check_pack):
        result = _build(source, commit, approval, trust, output)
        assert result.returncode == 0, result.stderr

    _rehash_pack_for_legacy_catalog_case(valid_pack, dangling_prerequisite=False)
    valid_catalog = load_content_catalog(
        valid_pack, provenance=_runtime_provenance(valid_pack, fixture=fixture)
    )
    assert [item.template_id for item in valid_catalog.finding_templates("ldap")] == [
        "ldap_visible_count"
    ]

    _rehash_pack_for_legacy_catalog_case(invalid_pack, dangling_prerequisite=True)
    with pytest.raises(ValueError, match="finding template requires an undeclared playbook check"):
        load_content_catalog(
            invalid_pack, provenance=_runtime_provenance(invalid_pack, fixture=fixture)
        )

    _rehash_pack_for_legacy_catalog_case(
        duplicate_playbook_pack,
        dangling_prerequisite=False,
        duplicate_playbook=True,
    )
    with pytest.raises(ValueError, match="duplicate approved playbook IDs"):
        load_content_catalog(
            duplicate_playbook_pack,
            provenance=_runtime_provenance(duplicate_playbook_pack, fixture=fixture),
        )

    _rehash_pack_for_legacy_catalog_case(
        duplicate_check_pack,
        dangling_prerequisite=False,
        duplicate_check_declaration=True,
    )
    with pytest.raises(ValueError, match="duplicated playbook check"):
        load_content_catalog(
            duplicate_check_pack,
            provenance=_runtime_provenance(duplicate_check_pack, fixture=fixture),
        )
