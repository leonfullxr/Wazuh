from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
_run_path = ROOT / "tests/integration/admission_runtime/run.py"
_run_spec = importlib.util.spec_from_file_location("admission_runtime_run", _run_path)
if _run_spec is None or _run_spec.loader is None:
    raise RuntimeError("admission runtime runner could not be loaded")
_run = importlib.util.module_from_spec(_run_spec)
_run_spec.loader.exec_module(_run)


@pytest.fixture(autouse=True)
def _repo_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # make runs pytest with its temp directory inside the checkout.
    monkeypatch.setattr(_run, "ROOT", tmp_path / "repo")


def test_direct_python_symlink_mounts_resolved_interpreter_root(tmp_path: Path) -> None:
    python_root = tmp_path / "py-3.12.13"
    python_bin = python_root / "bin" / "python3.12"
    python_bin.parent.mkdir(parents=True)
    python_bin.touch()
    entrypoint = tmp_path / "venv" / "bin" / "python"
    entrypoint.parent.mkdir(parents=True)
    entrypoint.symlink_to(python_bin)

    assert _run._python_mounts(entrypoint) == [
        "--mount",
        f"type=bind,src={python_root},dst={python_root},readonly",
    ]


def test_python_symlink_mounts_intermediate_and_resolved_roots(tmp_path: Path) -> None:
    version_root = tmp_path / "py-3.12.13"
    version_bin = version_root / "bin" / "python3.12"
    version_bin.parent.mkdir(parents=True)
    version_bin.touch()
    minor_root = tmp_path / "py-3.12"
    minor_root.symlink_to(version_root, target_is_directory=True)
    entrypoint = tmp_path / "venv" / "bin" / "python"
    entrypoint.parent.mkdir(parents=True)
    entrypoint.symlink_to(minor_root / "bin" / "python3.12")

    assert _run._python_mounts(entrypoint) == [
        "--mount",
        f"type=bind,src={minor_root},dst={minor_root},readonly",
        "--mount",
        f"type=bind,src={version_root},dst={version_root},readonly",
    ]


def test_python_symlink_loop_fails_instead_of_hanging(tmp_path: Path) -> None:
    first = tmp_path / "py" / "bin" / "python"
    second = first.parent / "python-other"
    first.parent.mkdir(parents=True)
    first.symlink_to(second)
    second.symlink_to(first)
    entrypoint = tmp_path / "venv" / "bin" / "python"
    entrypoint.parent.mkdir(parents=True)
    entrypoint.symlink_to(first)

    with pytest.raises((OSError, RuntimeError)):
        _run._python_mounts(entrypoint)


def test_external_alias_into_repo_is_kept(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    vendored_bin = repo / "vendor" / "python" / "bin" / "python3.12"
    vendored_bin.parent.mkdir(parents=True)
    vendored_bin.touch()
    alias = tmp_path / "py"
    alias.symlink_to(repo / "vendor" / "python", target_is_directory=True)
    entrypoint = repo / ".venv" / "bin" / "python"
    entrypoint.parent.mkdir(parents=True)
    entrypoint.symlink_to(alias / "bin" / "python3.12")

    assert _run._python_mounts(entrypoint) == [
        "--mount",
        f"type=bind,src={alias},dst={alias},readonly",
    ]


def test_link_outside_a_bin_directory_does_not_mount_its_grandparent(tmp_path: Path) -> None:
    python_root = tmp_path / "home" / ".local" / "python"
    python_bin = python_root / "bin" / "python3"
    python_bin.parent.mkdir(parents=True)
    python_bin.touch()
    alias = tmp_path / "home" / "python"
    alias.symlink_to(python_bin)
    entrypoint = tmp_path / "venv" / "bin" / "python"
    entrypoint.parent.mkdir(parents=True)
    entrypoint.symlink_to(alias)

    assert _run._python_mounts(entrypoint) == [
        "--mount",
        f"type=bind,src={python_root},dst={python_root},readonly",
    ]


def test_relative_link_from_symlinked_venv_resolves_from_the_real_directory(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    python_bin = repo / "python" / "bin" / "python3.12"
    python_bin.parent.mkdir(parents=True)
    python_bin.touch()
    real_venv_bin = repo / "envs" / "runtime" / "bin"
    real_venv_bin.mkdir(parents=True)
    (real_venv_bin / "python").symlink_to("../../../python/bin/python3.12")
    (repo / ".venv").symlink_to(repo / "envs" / "runtime", target_is_directory=True)
    (tmp_path / "python").mkdir()

    assert _run._python_mounts(repo / ".venv" / "bin" / "python") == []


def test_symlinked_bin_directory_falls_back_to_the_resolved_root(tmp_path: Path) -> None:
    python_root = tmp_path / "python-root"
    python_bin = python_root / "bin" / "python3.12"
    python_bin.parent.mkdir(parents=True)
    python_bin.touch()
    home = tmp_path / "home"
    home.mkdir()
    (home / "bin").symlink_to(python_root / "bin", target_is_directory=True)
    entrypoint = tmp_path / "venv" / "bin" / "python"
    entrypoint.parent.mkdir(parents=True)
    entrypoint.symlink_to(home / "bin" / "python3.12")

    assert _run._python_mounts(entrypoint) == [
        "--mount",
        f"type=bind,src={python_root},dst={python_root},readonly",
    ]
