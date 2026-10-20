from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from ai_soc.content.catalog import ContentCatalog, load_content_catalog
from ai_soc.contracts.models import BuildProvenance


@dataclass(frozen=True, slots=True)
class BuiltSeed:
    root: Path
    source: Path
    pack: Path
    catalog: ContentCatalog
    provenance: BuildProvenance


def build_seed(tmp_path: Path) -> BuiltSeed:
    """Build the tracked synthetic content seed through its real CLI runner."""
    checkout = Path(__file__).parents[3]
    script = checkout / "examples/content-seed/run_fixture_demo.py"
    root = checkout / "build" / "content-fixture-tests" / f"{tmp_path.name}-{uuid4().hex}"
    result = subprocess.run(
        [sys.executable, str(script), "--work-dir", str(root)],
        check=False,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PATH": f"{checkout / '.venv/bin'}:{os.environ.get('PATH', '')}",
        },
    )
    if result.returncode != 0:
        raise AssertionError(f"content seed CLI failed: {result.stderr}")
    summary = json.loads(result.stdout)
    if summary["approval_mode"] != "fixture" or summary["source_status_after"]:
        raise AssertionError("seed runner did not preserve the clean fixture source")
    pack = root / "build-a"
    provenance_data = json.loads((pack / "provenance.json").read_bytes())
    manifest = json.loads((pack / "manifest.json").read_bytes())
    provenance = BuildProvenance(
        service_sha="0" * 40,
        content_repository=provenance_data["source_repository"],
        content_sha=provenance_data["content_sha"],
        pack_sha256=provenance_data["pack_sha256"],
        image_digest="sha256:" + "3" * 64,
        docs_origin="https://docs.example.test",
        docs_manifest_sha256=provenance_data["docs_manifest_sha256"],
    )
    if provenance.pack_sha256 != manifest["pack_sha256"]:
        raise AssertionError("seed pack manifest and provenance disagree")
    return BuiltSeed(
        root=root,
        source=root / "external-content",
        pack=pack,
        catalog=load_content_catalog(pack, provenance=provenance),
        provenance=provenance,
    )
