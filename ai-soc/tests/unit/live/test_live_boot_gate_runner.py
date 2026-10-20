from __future__ import annotations

import subprocess

import pytest

from scripts import live_boot_check


def _run_runtime_gate_with_output(
    monkeypatch: pytest.MonkeyPatch, positive_output: str
) -> list[str]:
    monkeypatch.setattr(
        live_boot_check.subprocess,
        "run",
        lambda args, **kwargs: subprocess.CompletedProcess(args, 1, stdout="1 failed", stderr=""),
    )
    captured_args: list[str] = []

    def fake_run(args: list[str], *, env: dict[str, str], timeout: int) -> str:
        captured_args.extend(args)
        assert env["LIVE_BOOT_CHECK"] == "1"
        assert env["DYNAMODB_LOCAL_ENDPOINT"] == "http://127.0.0.1:8000"
        return positive_output

    monkeypatch.setattr(live_boot_check, "_run", fake_run)
    live_boot_check._pytest_runtime_gate(8000, {})
    return captured_args


def test_runtime_gate_explicitly_executes_positive_live_sentinel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = _run_runtime_gate_with_output(monkeypatch, "1 passed in 0.01s")

    assert args[-3:] == ["-m", "live", "tests/unit/live/test_live_boot_gate.py"]


def test_runtime_gate_rejects_deselected_positive_sentinel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(RuntimeError, match="positive sentinel must execute and pass"):
        _run_runtime_gate_with_output(monkeypatch, "1 deselected in 0.01s")
