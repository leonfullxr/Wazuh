#!/usr/bin/env python3
"""Reject local-only files and escaping links from the staged service tree."""

from __future__ import annotations

import posixpath
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
LOCAL_DIRS = {
    ".credentials",
    ".review",
    ".secrets",
    ".venv",
    "__pycache__",
    "internal",
    "node_modules",
    "tests",
}
LOCAL_PREFIXES = (
    "scripts/evaluation/",
    "contracts/v1/tooling/",
    "web/src/mocks/",
    "web/e2e/",
)
LOCAL_FILES = {
    "AGENTS.md",
    "contracts/v1/freeze.json",
    "scripts/coverage.py",
    "scripts/junit_capture.py",
    "scripts/local_protocol_check.py",
    "scripts/otlp-probe.py",
    "scripts/qualification_wheel_check.py",
    "scripts/workspace/serve_lab.py",
    "src/ai_soc/contracts/freeze.py",
    "src/ai_soc/workspace/evaluation.py",
    "src/ai_soc/workspace/lab_check.py",
    "src/ai_soc/workspace/replay.py",
    "web/public/mockServiceWorker.js",
    "web/src/main-mock.tsx",
    "web/src/test-setup.ts",
    "web/vite.live.config.ts",
}


def local_path(name: str) -> bool:
    return (
        bool(LOCAL_DIRS.intersection(name.split("/")))
        or name in LOCAL_FILES
        or name.startswith(LOCAL_PREFIXES)
        or name.startswith("scripts/live_boot")
        or (name.startswith("web/playwright") and name.endswith(".config.ts"))
        or (name.startswith("web/src/") and name.endswith((".test.ts", ".test.tsx")))
    )


def main() -> int:
    result = subprocess.run(
        ["git", "ls-files", "--stage", "-z", "--", "."],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    violations: list[str] = []
    try:
        compose = yaml.safe_load((ROOT / "docker-compose.workspace.yml").read_text())
        secret_file = compose["secrets"]["pg_password"]["file"]
        if secret_file != "${WS_PG_SECRET_FILE:?}":
            violations.append("workspace database secret must use the required private file path")
    except (OSError, KeyError, TypeError, yaml.YAMLError):
        violations.append("workspace database secret configuration is missing or invalid")
    for entry in result.stdout.split(b"\0"):
        if not entry:
            continue
        metadata, raw_name = entry.split(b"\t", 1)
        mode, object_id, _stage = metadata.decode().split()
        name = raw_name.decode()
        if local_path(name):
            violations.append(f"local-only path: {name}")
        if mode == "120000":
            target = subprocess.run(
                ["git", "cat-file", "blob", object_id],
                cwd=ROOT,
                check=True,
                capture_output=True,
            ).stdout.decode()
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
            if posixpath.isabs(target) or resolved == ".." or resolved.startswith("../"):
                violations.append(f"symlink escapes service: {name}")
    if violations:
        print("Production index contains local-only paths:", file=sys.stderr)
        for violation in violations:
            print(violation, file=sys.stderr)
        return 1
    print("Production index contains no local-only paths or escaping symlinks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
