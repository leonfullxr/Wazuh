"""Behavior of the opt-in installer in disposable repositories."""

import subprocess
from pathlib import Path

import pytest

from scripts.agent_checks import dispatch, install, relevant


def repo_at(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    project = repo / "ai-soc"
    project.mkdir()
    return repo, project


def test_unrelated_changes_skip(tmp_path: Path) -> None:
    repo, project = repo_at(tmp_path)
    (repo / "other").write_text("other")
    subprocess.run(["git", "-C", str(repo), "add", "other"], check=True)
    assert not relevant(["other"])
    assert dispatch(project) == 0


def test_installer_preserves_unrelated_hook(tmp_path: Path) -> None:
    repo, project = repo_at(tmp_path)
    hook = repo / ".git/hooks/pre-commit"
    hook.write_text("unrelated\n")
    with pytest.raises(ValueError, match="existing_unrelated_file"):
        install(project, repo)
    assert hook.read_text() == "unrelated\n"


def test_installer_is_idempotent_and_checks_alternate_hooks(tmp_path: Path) -> None:
    repo, project = repo_at(tmp_path)
    hook = repo / ".git/hooks/pre-commit"
    hook.unlink(missing_ok=True)
    install(project, repo, dry_run=True)
    assert not hook.exists()
    install(project, repo)
    assert hook.read_text().startswith("#!/bin/sh\n# ai-soc managed pre-commit v1\n")
    install(project, repo)
    subprocess.run(["git", "-C", str(repo), "config", "core.hooksPath", "hooks"], check=True)
    with pytest.raises(ValueError, match="alternate_hooks"):
        install(project, repo)
