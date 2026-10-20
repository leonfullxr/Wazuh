from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURE = Path(__file__).parent / "data/root_variables_validation"
VALID_TFVARS = FIXTURE / "valid.tfvars.json"
TERRAFORM = REPO_ROOT / "build/tool-cache/terraform/terraform"
INFRA_VARIABLES = REPO_ROOT / "infra/variables.tf"


@pytest.fixture(scope="module")
def terraform_init(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if not TERRAFORM.is_file():
        pytest.skip("terraform binary not prepared; run make bootstrap")
    module = tmp_path_factory.mktemp("root-variables-validation")
    (module / "variables.tf").symlink_to(INFRA_VARIABLES)
    (module / "main.tf").symlink_to(FIXTURE / "main.tf")
    subprocess.run(
        [str(TERRAFORM), "init", "-backend=false", "-input=false"],
        cwd=module,
        check=True,
        capture_output=True,
        text=True,
    )
    return module


def _plan(
    module: Path,
    *,
    idp_in_vpc: bool,
    identity_egress_cidrs: list[str],
) -> subprocess.CompletedProcess[str]:
    cidrs_json = json.dumps(identity_egress_cidrs)
    return subprocess.run(
        [
            str(TERRAFORM),
            "plan",
            "-input=false",
            f"-var-file={VALID_TFVARS}",
            f"-var=idp_in_vpc={str(idp_in_vpc).lower()}",
            f"-var=identity_egress_cidrs={cidrs_json}",
        ],
        cwd=module,
        capture_output=True,
        text=True,
    )


def test_root_identity_egress_allows_empty_list_when_idp_in_vpc(terraform_init: Path) -> None:
    result = _plan(terraform_init, idp_in_vpc=True, identity_egress_cidrs=[])
    assert result.returncode == 0, result.stderr + result.stdout


def test_root_identity_egress_rejects_default_route_even_when_idp_in_vpc(
    terraform_init: Path,
) -> None:
    result = _plan(terraform_init, idp_in_vpc=True, identity_egress_cidrs=["0.0.0.0/0"])
    assert result.returncode != 0, result.stdout


def test_root_identity_egress_accepts_reviewed_cidr_when_idp_not_in_vpc(
    terraform_init: Path,
) -> None:
    result = _plan(terraform_init, idp_in_vpc=False, identity_egress_cidrs=["203.0.113.20/32"])
    assert result.returncode == 0, result.stderr + result.stdout


def test_root_identity_egress_rejects_empty_list_when_idp_not_in_vpc(
    terraform_init: Path,
) -> None:
    result = _plan(terraform_init, idp_in_vpc=False, identity_egress_cidrs=[])
    assert result.returncode != 0, result.stdout


def test_root_alb_key_egress_rejects_broad_cloudfront_range(
    terraform_init: Path,
) -> None:
    result = subprocess.run(
        [
            str(TERRAFORM),
            "plan",
            "-input=false",
            f"-var-file={VALID_TFVARS}",
            '-var=alb_public_key_egress_cidrs=["203.0.113.0/24"]',
        ],
        cwd=terraform_init,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "host routes (/32 or /128)" in result.stderr + result.stdout
