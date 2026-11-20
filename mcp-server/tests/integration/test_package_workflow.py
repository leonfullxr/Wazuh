"""Check that the repository workflow and the package verification entry point stay connected."""

from pathlib import Path

import yaml


def test_ci_targets_package_and_uses_verified_runner():
    package = Path(__file__).resolve().parents[2]
    workflow = package.parent / ".github/workflows/mcp-server-ci.yml"
    config = yaml.safe_load(workflow.read_text())
    assert config["permissions"] == {"contents": "read"}
    assert set(config["on"]) == {"pull_request", "push", "workflow_dispatch"}
    for event in ("pull_request", "push"):
        assert set(config["on"][event]["paths"]) == {"mcp-server/**", ".github/workflows/mcp-server-ci.yml"}
    job = config["jobs"]["package"]
    assert job["defaults"]["run"]["working-directory"] == "mcp-server"
    assert set(job["strategy"]["matrix"]["python"]) == {"3.11", "3.13"}
    assert all(len(step["uses"].split("@")[1]) == 40 for step in job["steps"] if "uses" in step)
    assert any(step.get("run") == "scripts/verify.sh" for step in job["steps"])
    assert "--cov" in (package / "scripts/verify.sh").read_text()
