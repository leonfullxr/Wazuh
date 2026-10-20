from __future__ import annotations

import subprocess

import pytest

from scripts import live_boot_check


def test_cleanup_removes_only_containers_owned_by_its_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    containers = {
        "run-a-s3": "project-a",
        "run-a-partial": "project-a",
        "run-b-s3": "project-b",
    }
    removed: list[str] = []
    commands: list[list[str]] = []

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(args)
        if args[:3] == ["docker", "ps", "-aq"]:
            label = args[args.index("--filter") + 1]
            owner = label.removeprefix(f"label={live_boot_check.RUN_OWNERSHIP_LABEL}=")
            matching = [name for name, run_id in containers.items() if run_id == owner]
            return subprocess.CompletedProcess(args, 0, "\n".join(matching), "")
        if args[:3] == ["docker", "rm", "-f"]:
            name = args[-1]
            removed.append(name)
            containers.pop(name, None)
            return subprocess.CompletedProcess(args, 0, "", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(live_boot_check.subprocess, "run", fake_run)

    live_boot_check._cleanup("project-a", {}, ["run-a-s3"])

    discovery = next(args for args in commands if args[:3] == ["docker", "ps", "-aq"])
    assert discovery[-2:] == [
        "--filter",
        f"label={live_boot_check.RUN_OWNERSHIP_LABEL}=project-a",
    ]
    assert set(removed) == {"run-a-s3", "run-a-partial"}
    assert containers == {"run-b-s3": "project-b"}
    compose_down = next(
        args for args in commands if args[-3:] == ["down", "--remove-orphans", "-v"]
    )
    assert compose_down[compose_down.index("--project-name") + 1] == "project-a"
