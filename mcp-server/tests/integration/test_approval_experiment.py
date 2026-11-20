"""The offline human-approval experiment is never registered as an MCP tool."""

from dataclasses import replace
from pathlib import Path
from runpy import run_path

import pytest

SPIKE = run_path(str(Path(__file__).resolve().parents[2] / "evals" / "approval_experiment.py"))


def test_bound_single_use_approval_survives_process_loss(tmp_path):
    preview = SPIKE["Preview"]("fixture-cluster", "007", 30)
    path = tmp_path / "experiment.sqlite"
    first = SPIKE["ApprovalExperiment"](path)
    token = first.approve(preview, "trusted-host/alice", 100)
    for changed, actor, now in [
        (replace(preview, agent="008"), "trusted-host/alice", 101),
        (preview, "another-user", 101),
        (preview, "trusted-host/alice", 160),
    ]:
        with pytest.raises(ValueError, match="unavailable"):
            first.simulate(token, changed, actor, now)
    assert first.simulate(token, preview, "trusted-host/alice", 101, interrupt=True) == "outcome_unknown"
    first.db.close()
    second = SPIKE["ApprovalExperiment"](path)
    try:
        assert second.status(token) == "outcome_unknown"
        with pytest.raises(ValueError):
            second.simulate(token, preview, "trusted-host/alice", 102)
        second.reconcile(token, fixture_marker_present=True)
        assert second.status(token) == "verified"
        fresh = second.approve(preview, "trusted-host/alice", 103)
        assert second.simulate(fresh, preview, "trusted-host/alice", 104) == "dispatched"
        assert second.status("unknown") == "not_dispatched"
    finally:
        second.db.close()
