from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
TERRAFORM = REPO_ROOT / "build/tool-cache/terraform/terraform"


def prepare_root_module(directory: Path) -> Path:
    """Expose the production root configuration without its remote backend."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "main.tf").symlink_to(REPO_ROOT / "infra/main.tf")
    (directory / "outputs.tf").symlink_to(REPO_ROOT / "infra/outputs.tf")
    (directory / "variables.tf").symlink_to(REPO_ROOT / "infra/variables.tf")
    (directory / "moved.tf").symlink_to(REPO_ROOT / "infra/moved.tf")
    for configuration in (REPO_ROOT / "infra").glob("qualification_*.tf"):
        (directory / configuration.name).symlink_to(configuration)
    (directory / ".terraform.lock.hcl").symlink_to(REPO_ROOT / "infra/.terraform.lock.hcl")
    (directory / "versions.tf").write_text(
        'terraform {\n  required_version = "= 1.16.5"\n'
        "  required_providers {\n    aws = {\n"
        '      source = "hashicorp/aws"\n      version = "= 6.67.0"\n'
        "    }\n  }\n}\n"
        'provider "aws" {\n'
        "  region                      = var.aws_region\n"
        '  access_key                  = "test"\n'
        '  secret_key                  = "test"\n'
        "  skip_credentials_validation = true\n"
        "  skip_metadata_api_check     = true\n"
        "  skip_requesting_account_id  = true\n"
        "}\n",
        encoding="utf-8",
    )
    subprocess.run(
        [str(TERRAFORM), "init", "-backend=false", "-input=false", "-lockfile=readonly"],
        cwd=directory,
        check=True,
        capture_output=True,
        text=True,
    )
    return directory
