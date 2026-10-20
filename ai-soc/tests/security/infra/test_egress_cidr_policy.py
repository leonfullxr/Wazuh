from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE = Path(__file__).parent / "data/egress_cidr_validation"
TERRAFORM = REPO_ROOT / "build/tool-cache/terraform/terraform"


@pytest.fixture(scope="module")
def terraform_init() -> Path:
    if not TERRAFORM.is_file():
        pytest.skip("terraform binary not prepared; run make bootstrap")
    subprocess.run(
        [str(TERRAFORM), "init", "-backend=false", "-input=false"],
        cwd=MODULE,
        check=True,
        capture_output=True,
        text=True,
    )
    return MODULE


def _plan(module: Path, cidrs: list[str]) -> subprocess.CompletedProcess[str]:
    payload = json.dumps(cidrs)
    return subprocess.run(
        [
            str(TERRAFORM),
            "plan",
            "-input=false",
            f"-var=cidrs={payload}",
        ],
        cwd=module,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize(
    ("cidrs",),
    [
        (["203.0.113.10/32"],),
        (["198.51.100.0/24"],),
        (["2001:db8::/48"],),
    ],
)
def test_egress_cidr_validation_accepts_reviewed_prefixes(
    terraform_init: Path, cidrs: list[str]
) -> None:
    result = _plan(terraform_init, cidrs)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("cidrs",),
    [
        (["10.0.0.0/23"],),
        (["0.0.0.0/0"],),
        (["2001:db8::/47"],),
        (["::/0"],),
    ],
)
def test_egress_cidr_validation_rejects_broad_or_default_routes(
    terraform_init: Path, cidrs: list[str]
) -> None:
    result = _plan(terraform_init, cidrs)
    assert result.returncode != 0, result.stdout
