"""Build the synthetic seed through the approved Git-content CLI, twice offline."""

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
from typing import Any

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_soc.content.builder import approval_payload
from ai_soc.contracts.canonical import canonical_bytes
from ai_soc.contracts.models import DetachedApproval, PackManifest

FIXTURE_EPOCH = 1_791_028_800
FIXTURE_TIME = datetime.fromtimestamp(FIXTURE_EPOCH, tz=UTC)


def _run(command: list[str], *, cwd: Path | None = None, env: dict[str, str]) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n{completed.stderr}"
        )
    return completed.stdout.strip()


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _fixture_env() -> dict[str, str]:
    path = os.environ.get("PATH")
    if path is None:
        raise RuntimeError("PATH is required to invoke the locked local CLI")
    return {
        "PATH": path,
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


def _service_root(seed_dir: Path) -> Path:
    """Resolve the checkout from the tracked seed layout, without consulting Git."""
    root = seed_dir.resolve().parents[1]
    if not (root / "pyproject.toml").is_file() or not (root / "src/ai_soc/content").is_dir():
        raise RuntimeError("seed source is not inside an AI SOC service checkout")
    return root


def _detached_approval(source: Path, commit: str, tree: str, work_dir: Path) -> tuple[Path, Path]:
    manifest = yaml.safe_load((source / "content/manifest.yaml").read_text(encoding="utf-8"))
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    approval = DetachedApproval(
        repository=manifest["repository"],
        commit=commit,
        tree_sha=tree,
        reviewer_ids=["synthetic-fixture-reviewer"],
        review_record="https://example.test/synthetic-review/1",
        policy_id="synthetic-content-fixture-v1",
        approved_at=FIXTURE_TIME,
        signature="pending",
        key_id="ephemeral-fixture-ed25519",
        mode="fixture",
    )
    signature = private_key.sign(approval_payload(approval))
    signed = approval.model_copy(update={"signature": base64.b64encode(signature).decode("ascii")})
    approval_path = work_dir / "detached-approval.json"
    trust_root_path = work_dir / "fixture-trust-root.json"
    approval_path.write_text(signed.model_dump_json() + "\n", encoding="utf-8")
    trust_root_path.write_text(
        json.dumps({signed.key_id: base64.b64encode(public_key).decode("ascii")}, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    return approval_path, trust_root_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--work-dir",
        required=True,
        type=Path,
        help="new disposable directory inside the service checkout, outside the seed source",
    )
    args = parser.parse_args()
    work_dir = args.work_dir.expanduser().resolve()
    source_seed = Path(__file__).resolve().parent
    checkout = _service_root(source_seed)
    if checkout not in work_dir.parents:
        raise RuntimeError("work directory must be inside the service checkout")
    if source_seed in work_dir.parents or work_dir == source_seed:
        raise RuntimeError("work directory must not overlap the tracked seed source")
    if work_dir.exists() and any(work_dir.iterdir()):
        raise RuntimeError("work directory must be new or empty")
    work_dir.mkdir(parents=True, exist_ok=True)
    source = work_dir / "external-content"
    source.mkdir()
    for name in ("content", "public-docs"):
        shutil.copytree(source_seed / name, source / name)
    for name in ("LICENSE", "REVIEW.md"):
        shutil.copy2(source_seed / name, source / name)

    env = {**_fixture_env(), "TMPDIR": str(work_dir)}
    cli = shutil.which("ai-soc-content")
    if cli is None:
        raise RuntimeError("ai-soc-content is unavailable; run this script through locked uv")
    _run(
        [
            cli,
            "import-kev",
            "--source",
            str(source / "content/kev/raw-cisa-kev.json"),
            "--retrieved-at",
            "2026-10-02T10:00:00Z",
            "--policy",
            str(source_seed / "kev-policy.json"),
            "--notice",
            str(source_seed / "kev-notice.json"),
            "--out-dir",
            str(source / "content/kev"),
        ],
        env=env,
    )
    _run(["git", "init", "--quiet", "--initial-branch=main"], cwd=source, env=env)
    _run(["git", "config", "user.name", "Synthetic Content Fixture"], cwd=source, env=env)
    _run(["git", "config", "user.email", "fixture@example.test"], cwd=source, env=env)
    _run(["git", "add", "content", "public-docs", "LICENSE", "REVIEW.md"], cwd=source, env=env)
    commit_env = {
        **env,
        "GIT_AUTHOR_DATE": f"@{FIXTURE_EPOCH} +0000",
        "GIT_COMMITTER_DATE": f"@{FIXTURE_EPOCH} +0000",
    }
    _run(
        [
            "git",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "synthetic content fixture",
        ],
        cwd=source,
        env=commit_env,
    )
    commit = _run(["git", "rev-parse", "HEAD"], cwd=source, env=env)
    tree = _run(["git", "rev-parse", "HEAD^{tree}"], cwd=source, env=env)
    status_before = _run(
        ["git", "status", "--porcelain", "--untracked-files=all"], cwd=source, env=env
    )
    if status_before:
        raise RuntimeError("disposable source is not clean after its ordinary Git commit")

    approval, trust = _detached_approval(source, commit, tree, work_dir)
    common = [
        cli,
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
    validation = _run([cli, "validate", *common[1:]], env=env)
    output_a = work_dir / "build-a"
    output_b = work_dir / "build-b"
    build_a = _run([cli, "build", *common[1:], "--out", str(output_a)], env=env)
    build_b = _run([cli, "build", *common[1:], "--out", str(output_b)], env=env)
    _run([cli, "verify", "--pack", str(output_a), "--contract-version", "1"], env=env)
    _run([cli, "verify", "--pack", str(output_b), "--contract-version", "1"], env=env)

    files_a = _files(output_a)
    files_b = _files(output_b)
    if files_a != files_b:
        raise RuntimeError("two builds from the same approved commit differ")
    status_after = _run(
        ["git", "status", "--porcelain", "--untracked-files=all"], cwd=source, env=env
    )
    if status_after != status_before:
        raise RuntimeError("content CLI mutated the disposable Git source")
    manifest = PackManifest.model_validate_json((output_a / "manifest.json").read_bytes())
    provenance: dict[str, Any] = json.loads((output_a / "provenance.json").read_bytes())
    if manifest.content_sha != commit or provenance.get("content_sha") != commit:
        raise RuntimeError("pack or provenance content commit differs from approved source")
    required_outputs = {
        "docs/en/ldap.html",
        "docs/en/auth-review.html",
        "docs/en/vulnerability-review.html",
        "pack/context/ldap-en.json",
        "pack/context/auth_review-en.json",
        "pack/context/vuln_review-en.json",
        "pack/context/ldap-es.json",
        "pack/expectations/ldap.json",
        "pack/expectations/auth_review.json",
        "pack/expectations/vuln_review.json",
        "pack/finding-templates/ldap_visible_count.json",
        "pack/finding-templates/auth_count.json",
        "pack/finding-templates/vuln_count.json",
        "pack/golden/G010.en.doc.json",
        "pack/playbooks/ldap.json",
        "pack/playbooks/auth_review.json",
        "pack/playbooks/vuln_review.json",
        "pack/topic-cards/ldap.json",
        "pack/topic-cards/auth_review.json",
        "pack/topic-cards/vuln_review.json",
        "pack/topics/ldap.json",
        "pack/topics/auth_review.json",
        "pack/topics/vuln_review.json",
        "pack/kev/cisa-kev.json",
    }
    if not required_outputs <= files_a.keys():
        raise RuntimeError("built pack omits a required topic, doc, card, or playbook source")
    topic: dict[str, Any] = json.loads(files_a["pack/topics/ldap.json"])
    if topic["public_document"]["sha256"] != _digest(
        (source / "public-docs/en/ldap.md").read_bytes()
    ):
        raise RuntimeError("packed topic pointer digest differs from its public document source")
    context: dict[str, Any] = json.loads(files_a["pack/context/ldap-en.json"])
    source_document = (source / "public-docs/en/ldap.md").read_text(encoding="utf-8")
    if context["content_sha"] != commit or context["document_section"] != source_document:
        raise RuntimeError("topic context is not bound to the approved document commit and bytes")
    golden: dict[str, Any] = json.loads(files_a["pack/golden/G010.en.doc.json"])
    if (
        golden["case_id"] != "G010.en.doc"
        or golden["expected"]["payload"]["topic_plans"][0]["topic_id"] != "ldap"
    ):
        raise RuntimeError("independent G010 document-only expected topic was changed")
    if b"synthetic-ldap-setup-example" not in files_a["docs/en/ldap.html"]:
        raise RuntimeError("public document output omits the reviewed heading anchor")

    summary = {
        "approval_mode": "fixture",
        "approval_sha256": _digest(approval.read_bytes()),
        "build_a": build_a,
        "build_b": build_b,
        "build_file_count": len(files_a),
        "build_tree_sha256": _digest(
            canonical_bytes({name: _digest(data) for name, data in files_a.items()})
        ),
        "content_commit": commit,
        "content_tree": tree,
        "docs_manifest_sha256": manifest.docs_manifest_sha256,
        "emitted_public_document_sha256": _digest(files_a["docs/en/ldap.html"]),
        "fixture_labels_source": (
            "G010.en.doc copied byte-for-byte from docs/golden_examples.json"
        ),
        "provenance_content_commit": provenance["content_sha"],
        "source_status_after": status_after,
        "trust_root_sha256": _digest(trust.read_bytes()),
        "validation": validation,
        "work_dir": str(work_dir),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(2) from error
