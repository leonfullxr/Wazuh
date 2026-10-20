from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import cast
from uuid import uuid4

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from scripts.image_content_control import prepare_control  # noqa: E402


def test_distinct_approved_content_commits_change_pack_docs_and_image_provenance() -> None:
    output = REPO_ROOT / "build/evidence" / f"image-content-control-{uuid4().hex}"
    output.mkdir(parents=True)
    try:
        prepare_control(output)
        report = json.loads((output / "control.json").read_text())
        base = cast(dict[str, object], report["base"])
        changed = cast(dict[str, object], report["changed"])
        different_paths = cast(list[str], report["different_pack_paths"])

        assert report["approval_mode"] == "fixture"
        assert base["content_sha"] != changed["content_sha"]
        assert base["source_tree_sha256"] != changed["source_tree_sha256"]
        assert base["pack_sha256"] != changed["pack_sha256"]
        assert base["docs_manifest_sha256"] != changed["docs_manifest_sha256"]
        assert base["pack_tree_sha256"] != changed["pack_tree_sha256"]
        assert "docs/en/ldap.html" in different_paths
        assert report["image_build_args"]["base_content_sha"] == base["content_sha"]
        assert report["image_build_args"]["base_pack_sha256"] == base["pack_sha256"]
        assert report["image_build_args"]["changed_content_sha"] == changed["content_sha"]
        assert report["image_build_args"]["changed_pack_sha256"] == changed["pack_sha256"]
        approval = output / "changed-detached-approval.json"
        trust_root = output / "changed-fixture-trust-root.json"
        assert approval.is_file() and trust_root.is_file()
        assert not any(path.name.startswith("private") for path in output.rglob("*"))
    finally:
        shutil.rmtree(output)
