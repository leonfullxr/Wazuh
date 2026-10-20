from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


def test_service_root_resolves_plain_snapshot_without_git_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = tmp_path / "snapshot"
    seed_dir = snapshot / "examples/content-seed"
    seed_dir.mkdir(parents=True)
    (snapshot / "pyproject.toml").touch()
    (snapshot / "src/ai_soc/content").mkdir(parents=True)

    script = Path(__file__).parents[3] / "examples/content-seed/run_fixture_demo.py"
    spec = importlib.util.spec_from_file_location("seed_fixture_runner", script)
    assert spec is not None and spec.loader is not None
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)

    monkeypatch.setenv("GIT_DIR", str(tmp_path / "unavailable-supervisor-git-dir"))
    assert runner._service_root(seed_dir) == snapshot
    assert not (snapshot / ".git").exists()
