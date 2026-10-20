#!/usr/bin/env python3
"""Check that the task-owned platform tool lock is exact and locally prepared."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "dev/toolchain.lock.json"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    if not LOCK_PATH.exists():
        print("platform toolchain lock is missing", file=sys.stderr)
        return 1
    lock = json.loads(LOCK_PATH.read_text())
    missing: list[str] = []
    preparation = lock["preparation"]
    if preparation.get("prepared") is not True:
        missing.append("network preparation has not completed")
    for tool in lock["tools"]:
        executable = ROOT / tool["path"]
        if not executable.is_file():
            missing.append(f"{tool['name']} {tool['version']} binary absent at {tool['path']}")
            continue
        result = subprocess.run(
            [str(executable), *tool["version_args"]],
            capture_output=True,
            text=True,
            check=False,
        )
        output = result.stdout + result.stderr
        if result.returncode != 0 or tool["version"] not in output:
            missing.append(f"{tool['name']} expected {tool['version']}; observed {output.strip()}")
        archive = ROOT / tool["archive_path"]
        if not archive.is_file():
            missing.append(f"{tool['name']} source archive absent at {tool['archive_path']}")
        elif digest(archive) != tool["archive_sha256"]:
            missing.append(f"{tool['name']} source archive hash differs from the platform lock")
    for image in lock["images"]:
        if re.search(r"@sha256:[0-9a-f]{64}$", image["reference"]) is None:
            missing.append(f"{image['name']} must be digest pinned")
    container_preparation = ROOT / "build/tool-cache/container-images.json"
    if not container_preparation.is_file():
        missing.append("digest-pinned local container images are not prepared")
    else:
        prepared_value: object = json.loads(container_preparation.read_text())
        if not isinstance(prepared_value, dict):
            missing.append("local container preparation manifest is malformed")
        else:
            prepared_manifest = cast(dict[object, object], prepared_value)
            prepared_images = prepared_manifest.get("images")
            if not isinstance(prepared_images, list):
                missing.append("local container preparation manifest lacks images")
            else:
                prepared_rows = cast(list[object], prepared_images)
                prepared_references: set[str] = set()
                for raw_image in prepared_rows:
                    if not isinstance(raw_image, dict):
                        continue
                    image_map = cast(dict[object, object], raw_image)
                    reference = image_map.get("reference")
                    if isinstance(reference, str):
                        prepared_references.add(reference)
                locked_references = {image["reference"] for image in lock["images"]}
                if prepared_references != locked_references:
                    missing.append("prepared local image digests differ from the platform lock")
    provider_lock = ROOT / "infra/.terraform.lock.hcl"
    if not provider_lock.is_file() or digest(provider_lock) != preparation.get(
        "provider_lock_sha256"
    ):
        missing.append("locked Terraform provider checksums are missing or changed")
    provider_mirror = (
        ROOT
        / "build/tool-cache/terraform/mirror/registry.terraform.io/hashicorp/aws"
        / "terraform-provider-aws_6.67.0_linux_amd64.zip"
    )
    terraform_config = ROOT / "build/tool-cache/terraform.tfrc"
    if not provider_mirror.is_file() or not terraform_config.is_file():
        missing.append("offline Terraform provider mirror or CLI config is missing")
    scanner_database = ROOT / "build/tool-cache/trivy-cache/db/trivy.db"
    if not scanner_database.is_file() or digest(scanner_database) != preparation.get(
        "scanner_database_digest"
    ):
        missing.append("prepared Trivy database bytes are missing or changed")
    if missing:
        print("\n".join(f"NOT_PREPARED: {item}" for item in missing), file=sys.stderr)
        return 1
    print(f"platform cache verified: {digest(LOCK_PATH)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
