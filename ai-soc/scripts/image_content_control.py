#!/usr/bin/env python3
"""Build two approved synthetic packs and record their exact content provenance."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import TypeAdapter

from ai_soc.contracts.models import DetachedApproval, HTTPSUrl

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_EPOCH = 1_791_028_800
SHA256_LENGTH = 64
GIT_SHA_LENGTH = 40


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    raw = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in raw):
        raise ValueError(f"{label} keys must be strings")
    return cast(dict[str, object], raw)


def _run(arguments: list[str], *, cwd: Path, env: dict[str, str]) -> str:
    result = subprocess.run(
        arguments,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        message = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"{Path(arguments[0]).name} failed ({result.returncode}): {message}")
    return result.stdout.strip()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _tree_sha256(files: dict[str, bytes]) -> str:
    encoded = {name: _sha256(payload) for name, payload in files.items()}
    canonical = json.dumps(
        encoded,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return _sha256(canonical)


def _manifest(pack: Path) -> dict[str, object]:
    manifest = _mapping(json.loads((pack / "manifest.json").read_bytes()), "pack manifest")
    provenance = _mapping(json.loads((pack / "provenance.json").read_bytes()), "pack provenance")
    for field, length in (
        ("content_sha", GIT_SHA_LENGTH),
        ("source_tree_sha256", SHA256_LENGTH),
        ("pack_sha256", SHA256_LENGTH),
        ("docs_manifest_sha256", SHA256_LENGTH),
    ):
        value = manifest.get(field)
        if not isinstance(value, str) or len(value) != length:
            raise ValueError(f"pack manifest has an invalid {field}")
    if any(
        provenance.get(field) != manifest.get(field) for field in ("content_sha", "pack_sha256")
    ):
        raise ValueError("built pack provenance differs from its verified manifest")
    return manifest


def _canonical_approval_payload(approval: DetachedApproval) -> bytes:
    """Independently encode the frozen JSON signature payload consumed by the CLI."""
    values = approval.model_dump(mode="json", exclude={"signature"})
    return json.dumps(
        values,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _changed_approval(source: Path, work_dir: Path, commit: str, tree: str) -> tuple[Path, Path]:
    manifest = _mapping(
        yaml.safe_load((source / "content/manifest.yaml").read_text(encoding="utf-8")),
        "synthetic source manifest",
    )
    repository = manifest.get("repository")
    if not isinstance(repository, str):
        raise ValueError("synthetic source manifest must name its repository")
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    unsigned = DetachedApproval(
        repository=cast(HTTPSUrl, TypeAdapter(HTTPSUrl).validate_python(repository)),
        commit=commit,
        tree_sha=tree,
        reviewer_ids=["synthetic-image-control-reviewer"],
        review_record=cast(
            HTTPSUrl,
            TypeAdapter(HTTPSUrl).validate_python("https://example.test/synthetic-image-review/1"),
        ),
        policy_id="synthetic-content-fixture-v1",
        approved_at=datetime.fromtimestamp(FIXTURE_EPOCH + 86_400, tz=UTC),
        signature="pending",
        key_id="ephemeral-image-fixture-ed25519",
        mode="fixture",
    )
    signature = private_key.sign(_canonical_approval_payload(unsigned))
    signed = unsigned.model_copy(update={"signature": base64.b64encode(signature).decode("ascii")})
    approval_path = work_dir / "changed-detached-approval.json"
    trust_path = work_dir / "changed-fixture-trust-root.json"
    approval_path.write_text(signed.model_dump_json() + "\n", encoding="utf-8")
    trust_path.write_text(
        json.dumps(
            {signed.key_id: base64.b64encode(public_key).decode("ascii")},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    return approval_path, trust_path


def _build_changed_pack(
    *, base_source: Path, work_dir: Path, env: dict[str, str]
) -> tuple[Path, Path]:
    source = work_dir / "changed-external-content"
    shutil.copytree(base_source, source, ignore=shutil.ignore_patterns(".git"))
    document = source / "public-docs/en/ldap.md"
    document.write_bytes(
        document.read_bytes() + b"\nSynthetic image control: reviewed content variant B.\n"
    )
    topic_path = source / "content/topics/ldap.yaml"
    topic = _mapping(yaml.safe_load(topic_path.read_text(encoding="utf-8")), "LDAP topic")
    public_document = _mapping(topic.get("public_document"), "LDAP public document")
    public_document["sha256"] = _sha256(document.read_bytes())
    topic["public_document"] = public_document
    topic_path.write_text(
        yaml.safe_dump(topic, sort_keys=False, allow_unicode=True), encoding="utf-8"
    )
    _run(["git", "init", "--quiet", "--initial-branch=main"], cwd=source, env=env)
    _run(["git", "config", "user.name", "Synthetic Content Fixture"], cwd=source, env=env)
    _run(["git", "config", "user.email", "fixture@example.test"], cwd=source, env=env)
    _run(["git", "add", "content", "public-docs", "LICENSE", "REVIEW.md"], cwd=source, env=env)
    commit_env = {
        **env,
        "GIT_AUTHOR_DATE": f"@{FIXTURE_EPOCH + 86_400} +0000",
        "GIT_COMMITTER_DATE": f"@{FIXTURE_EPOCH + 86_400} +0000",
    }
    _run(
        [
            "git",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "synthetic content variant",
        ],
        cwd=source,
        env=commit_env,
    )
    commit = _run(["git", "rev-parse", "HEAD"], cwd=source, env=env)
    tree = _run(["git", "rev-parse", "HEAD^{tree}"], cwd=source, env=env)
    if _run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=source, env=env):
        raise RuntimeError("changed synthetic content source is not clean after its commit")

    approval, trust = _changed_approval(source, work_dir, commit, tree)
    cli = shutil.which("ai-soc-content")
    if cli is None:
        raise RuntimeError("ai-soc-content is unavailable in the locked environment")
    common = [
        "--source",
        str(source),
        "--commit",
        commit,
        "--attestation",
        str(approval),
        "--trust-root",
        str(trust),
        "--fixture",
    ]
    _run([cli, "validate", *common], cwd=ROOT, env=env)
    pack = work_dir / "changed-pack"
    _run([cli, "build", *common, "--out", str(pack)], cwd=ROOT, env=env)
    _run([cli, "verify", "--pack", str(pack), "--contract-version", "1"], cwd=ROOT, env=env)
    if _run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=source, env=env):
        raise RuntimeError("content CLI changed its approved source tree")
    return source, pack


def prepare_control(output: Path) -> dict[str, object]:
    output = output.resolve()
    if output.exists() and any(output.iterdir()):
        raise RuntimeError("content control output directory must be empty")
    output.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(
        {
            "PYTHONHASHSEED": "0",
            "TZ": "UTC",
            "LC_ALL": "C.UTF-8",
            "SOURCE_DATE_EPOCH": str(FIXTURE_EPOCH),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "AWS_CONFIG_FILE": os.devnull,
            "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
            "AWS_EC2_METADATA_DISABLED": "true",
        }
    )
    demo = output / "base-demo"
    seed_runner = ROOT / "examples/content-seed/run_fixture_demo.py"
    result = subprocess.run(
        [sys.executable, str(seed_runner), "--work-dir", str(demo)],
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise RuntimeError(f"base content fixture failed ({result.returncode}): {result.stderr}")
    base_source = demo / "external-content"
    base_pack = demo / "build-a"
    changed_source, changed_pack = _build_changed_pack(
        base_source=base_source,
        work_dir=output,
        env=env,
    )
    base_manifest = _manifest(base_pack)
    changed_manifest = _manifest(changed_pack)
    base_files, changed_files = _files(base_pack), _files(changed_pack)
    changed_paths = sorted(
        name
        for name in set(base_files) | set(changed_files)
        if base_files.get(name) != changed_files.get(name)
    )
    if not changed_paths or base_manifest["content_sha"] == changed_manifest["content_sha"]:
        raise RuntimeError("approved source change did not change content pack bytes and identity")
    if base_manifest["pack_sha256"] == changed_manifest["pack_sha256"]:
        raise RuntimeError("approved source change did not change the verified pack digest")
    if base_manifest["docs_manifest_sha256"] == changed_manifest["docs_manifest_sha256"]:
        raise RuntimeError("approved document change did not change the docs manifest digest")
    if not any(path.startswith("docs/") for path in changed_paths):
        raise RuntimeError("approved document change did not alter emitted documentation bytes")

    report: dict[str, object] = {
        "schema_version": "1",
        "approval_mode": "fixture",
        "base": {
            "content_sha": base_manifest["content_sha"],
            "source_tree_sha256": base_manifest["source_tree_sha256"],
            "pack_sha256": base_manifest["pack_sha256"],
            "docs_manifest_sha256": base_manifest["docs_manifest_sha256"],
            "pack_tree_sha256": _tree_sha256(base_files),
        },
        "changed": {
            "content_sha": changed_manifest["content_sha"],
            "source_tree_sha256": changed_manifest["source_tree_sha256"],
            "pack_sha256": changed_manifest["pack_sha256"],
            "docs_manifest_sha256": changed_manifest["docs_manifest_sha256"],
            "pack_tree_sha256": _tree_sha256(changed_files),
            "approved_source": str(changed_source.relative_to(output)),
        },
        "different_pack_paths": changed_paths,
        "image_build_args": {
            "base_content_sha": base_manifest["content_sha"],
            "base_pack_sha256": base_manifest["pack_sha256"],
            "changed_content_sha": changed_manifest["content_sha"],
            "changed_pack_sha256": changed_manifest["pack_sha256"],
        },
        "changed_approval_sha256": _sha256(
            (output / "changed-detached-approval.json").read_bytes()
        ),
    }
    (output / "control.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        prepare_control(args.output)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"CONTENT_CONTROL_FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
