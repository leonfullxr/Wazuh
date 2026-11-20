"""Prove the offline compatibility gate detects drift and identifies the affected tool."""

import json
from pathlib import Path
from runpy import run_path

import pytest

ROOT = Path(__file__).resolve().parents[2] / "compatibility"
checker = run_path(str(ROOT / "check.py"))


@pytest.mark.parametrize("change", ["missing_operation", "required_parameter", "rbac", "mapping"])
def test_contract_drift(change):
    snapshot = json.loads((ROOT / "snapshots/4.8.0.json").read_text())
    if change == "missing_operation":
        del snapshot["manager"]["/agents"]
    elif change == "required_parameter":
        snapshot["manager"]["/agents"]["required"].append(["query", "zone"])
    elif change == "rbac":
        snapshot["manager"]["/agents"]["actions"].append("group:read")
    else:
        del snapshot["fields"]["vulnerability.id"]
    errors, warnings = checker["compare"](snapshot)
    expected = "get_wazuh_vulnerabilities" if change == "mapping" else "get_wazuh_agents"
    assert len(errors) == 1 and expected in errors[0]
    assert any("get_wazuh_remoted_stats" in item for item in warnings)


def test_pinned_snapshots_match():
    assert checker["verify"]()


@pytest.mark.parametrize("parameter", ["agents_list", "select"])
def test_timeline_manager_query_drift(parameter):
    snapshot = json.loads((ROOT / "snapshots/4.14.7.json").read_text())
    snapshot["manager"]["/agents"]["timeline_query_params"].remove(parameter)
    errors, _ = checker["compare"](snapshot)
    assert errors == [f"GET /agents lacks {parameter} for investigate_agent_timeline"]
