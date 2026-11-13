"""Install or dispatch the opt-in ai-soc pre-commit hook in the parent Git repository."""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
MARKER = "# ai-soc managed pre-commit v1"


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args])


def hook_text(project: Path) -> str:
    import shlex

    script = shlex.quote(str(project / "scripts/agent_checks.py"))
    return f"#!/bin/sh\n{MARKER}\nexec python3 {script} dispatch\n"


def install(project: Path, repo: Path, dry_run: bool = False) -> list[str]:
    project, repo = project.resolve(), repo.resolve()
    if (
        project != repo / "ai-soc"
        or Path(git(repo, "rev-parse", "--show-toplevel").decode().strip()).resolve() != repo
    ):
        raise ValueError("unexpected_repository")
    configured = subprocess.run(
        ["git", "-C", str(repo), "config", "--get", "core.hooksPath"],
        capture_output=True,
        check=False,
    )
    if configured.returncode == 0 or configured.returncode != 1:
        raise ValueError("alternate_hooks_or_config_error")
    hook_dir = Path(git(repo, "rev-parse", "--git-path", "hooks").decode().strip())
    if not hook_dir.is_absolute():
        hook_dir = repo / hook_dir
    hook = hook_dir / "pre-commit"
    desired = hook_text(project).encode()
    if hook.is_symlink() or (hook.exists() and hook.read_bytes() != desired):
        raise ValueError(f"existing_unrelated_file: {hook.name}")
    if not dry_run:
        hook.parent.mkdir(parents=True, exist_ok=True)
        if not hook.exists():
            with hook.open("xb") as stream:
                stream.write(desired)
        hook.chmod(0o755)
    return ["hook_ready"]


def relevant(paths: list[str]) -> bool:
    return any(
        path.startswith("ai-soc/") or path == ".github/workflows/ai-soc-ci.yml" for path in paths
    )


def dispatch(project: Path) -> int:
    repo = project.parent
    paths = os.fsdecode(
        git(repo, "diff", "--cached", "--name-only", "-z", "--diff-filter=ACDMRTUXB")
    ).split("\0")
    if not relevant(paths):
        print("ai-soc checks: skipped (unrelated changes)")
        return 0
    status = subprocess.run(["make", "ci-check"], cwd=project, check=False).returncode
    if status:
        return status
    if (project / "internal/tools/agent_environment/scope.json").is_file():
        return subprocess.run(["make", "agent-check"], cwd=project, check=False).returncode
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["install", "check", "dispatch"])
    args = parser.parse_args()
    if args.command == "dispatch":
        return dispatch(PROJECT)
    try:
        print(", ".join(install(PROJECT, PROJECT.parent, dry_run=args.command == "check")))
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"installation refused: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
