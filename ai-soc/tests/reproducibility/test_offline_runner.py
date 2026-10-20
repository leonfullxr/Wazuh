from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.reproducible_image import (  # noqa: E402
    create_tmpfs_scratch,
    remove_tmpfs_scratch,
)

GN04_CASES = json.loads(
    (Path(__file__).parent / "data" / "gn04_offline_runner_cases.json").read_text()
)


def _runner_environment(*, sentinel: str) -> dict[str, str | None]:
    uv = shutil.which("uv")
    assert uv is not None, "the pinned uv executable must be on PATH"
    developer_home = Path.home()
    assert ROOT.is_relative_to(developer_home), "offline runner requires checkout below HOME"
    probe = (
        "import json, os; "
        "keys = ('HOME', 'TMPDIR', 'AWS_CONFIG_FILE', 'AWS_SHARED_CREDENTIALS_FILE', "
        "'AWS_DEFAULT_REGION', 'AWS_REGION', 'AWS_EC2_METADATA_DISABLED', 'TZ', 'LC_ALL', "
        "'PYTHONHASHSEED', 'SOC_MODE', 'SOC_ANCHOR', 'AWS_PROFILE', 'AWS_WEB_IDENTITY_TOKEN_FILE', "
        "'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN'); "
        "print(json.dumps({key: os.environ.get(key) for key in keys}, sort_keys=True))"
    )
    env = {
        **os.environ,
        "HOME": str(developer_home),
        "AWS_PROFILE": f"profile-{sentinel}",
        "AWS_WEB_IDENTITY_TOKEN_FILE": "/tmp/sentinel-token",
        "AWS_ACCESS_KEY_ID": f"access-key-{sentinel}",
        "AWS_SECRET_ACCESS_KEY": "sentinel-secret-key",
        "AWS_SESSION_TOKEN": "sentinel-session-token",
        "TZ": "Pacific/Honolulu",
        "LC_ALL": "C",
        "PYTHONHASHSEED": "random",
    }
    result = subprocess.run(
        [
            str(ROOT / "scripts/run-offline.sh"),
            uv,
            "run",
            "--locked",
            "--offline",
            "python",
            "-c",
            probe,
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_offline_runner_replaces_ambient_credentials_and_clock() -> None:
    observed = _runner_environment(sentinel="/unavailable/developer/home")

    assert observed == {
        "HOME": str(ROOT / "build/private/home"),
        "TMPDIR": str(ROOT / "build/private/tmp"),
        "AWS_CONFIG_FILE": "/dev/null",
        "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
        "AWS_DEFAULT_REGION": "us-east-1",
        "AWS_REGION": "us-east-1",
        "AWS_EC2_METADATA_DISABLED": "true",
        "TZ": "UTC",
        "LC_ALL": "C.UTF-8",
        "PYTHONHASHSEED": "0",
        "SOC_MODE": "fixture",
        "SOC_ANCHOR": "2026-09-30T12:00:00Z",
        "AWS_PROFILE": None,
        "AWS_WEB_IDENTITY_TOKEN_FILE": None,
        "AWS_ACCESS_KEY_ID": None,
        "AWS_SECRET_ACCESS_KEY": None,
        "AWS_SESSION_TOKEN": None,
    }


def test_offline_runner_outputs_are_independent_of_caller_environment() -> None:
    first = _runner_environment(sentinel="/first/developer/home")
    second = _runner_environment(sentinel="/second/developer/home")

    assert first == second


def test_offline_runner_exposes_only_the_exact_task_tmpfs_namespace() -> None:
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    scratch, _ = create_tmpfs_scratch(Path("/dev/shm"), run_id)
    sentinel = scratch / "visible.txt"
    sentinel.write_text("task-owned tmpfs sentinel\n")
    environment = {
        **os.environ,
        "SOC_B6_TMPFS_SCRATCH_ROOT": str(scratch),
    }
    try:
        result = subprocess.run(
            [
                str(ROOT / "scripts/run-offline.sh"),
                sys.executable,
                "-c",
                "from pathlib import Path; import sys; print(Path(sys.argv[1]).read_text())",
                str(sentinel),
            ],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.rstrip().endswith("task-owned tmpfs sentinel")
    finally:
        remove_tmpfs_scratch(scratch)


@pytest.mark.parametrize("variant", ("positive", "negative", "boundary", "failure"))
def test_gn04_offline_runner_variants_match_independent_environment_fixture(
    variant: str, record_property: Callable[[str, str], None]
) -> None:
    record_property("acceptance_ids", "GN04")
    record_property("case_id", "B6-GN04.offline-runner.private")
    record_property("variant", variant)
    record_property(
        "fixture_sha256",
        "196e7457ff7aea7424a272ac1ae6e7177eb852d2de075977fc9953f92ab3b55b",
    )
    variants = cast(dict[str, object], GN04_CASES["variants"])
    case = cast(dict[str, object], variants[variant])
    ambient = cast(dict[str, str], case.get("ambient", {}))
    environment = {**os.environ, **ambient}
    argv = cast(list[str], case.get("argv", []))
    if not argv:
        probe = (
            "import json, os; keys = ('HOME', 'TMPDIR', 'AWS_CONFIG_FILE', "
            "'AWS_SHARED_CREDENTIALS_FILE', 'AWS_REGION', 'AWS_EC2_METADATA_DISABLED', "
            "'TZ', 'LC_ALL', 'PYTHONHASHSEED', 'SOC_MODE', 'SOC_ANCHOR', "
            "'AWS_PROFILE', 'AWS_WEB_IDENTITY_TOKEN_FILE', 'AWS_ACCESS_KEY_ID', "
            "'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN'); "
            "print(json.dumps({key: os.environ.get(key) for key in keys}, sort_keys=True))"
        )
        argv = [sys.executable, "-c", probe]

    result = subprocess.run(
        [str(ROOT / "scripts/run-offline.sh"), *argv],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    if "expected_returncode" in case:
        expected_returncode = case["expected_returncode"]
        assert result.returncode == expected_returncode
        return

    assert result.returncode == 0, result.stderr
    observed = cast(dict[str, str | None], json.loads(result.stdout.strip().splitlines()[-1]))
    assert observed["HOME"] == str(ROOT / "build/private/home")
    assert observed["TMPDIR"] == str(ROOT / "build/private/tmp")
    assert observed["AWS_CONFIG_FILE"] == "/dev/null"
    assert observed["AWS_SHARED_CREDENTIALS_FILE"] == "/dev/null"
    assert observed["AWS_REGION"] == "us-east-1"
    assert observed["AWS_EC2_METADATA_DISABLED"] == "true"
    assert observed["SOC_MODE"] == "fixture"
    assert observed["SOC_ANCHOR"] == "2026-09-30T12:00:00Z"
    expected_cleared = cast(list[str], case.get("expected_cleared", []))
    assert all(observed[key] is None for key in expected_cleared)
    expected_fixed = cast(dict[str, str], case.get("expected_fixed", {}))
    assert all(observed[key] == value for key, value in expected_fixed.items())
