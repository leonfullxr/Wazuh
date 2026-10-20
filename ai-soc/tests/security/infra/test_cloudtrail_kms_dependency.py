from __future__ import annotations

import subprocess
from pathlib import Path

from terraform_root import TERRAFORM, prepare_root_module


def test_cloudtrail_terraform_graph_waits_for_kms_policy_and_bucket_encryption(
    tmp_path: Path,
) -> None:
    module = prepare_root_module(tmp_path / "root")
    result = subprocess.run(
        [str(TERRAFORM), "graph"],
        cwd=module,
        check=True,
        capture_output=True,
        text=True,
    )
    graph = result.stdout
    for dependency in (
        "aws_kms_key_policy.storage",
        "aws_s3_bucket_server_side_encryption_configuration.cloudtrail",
        "aws_s3_bucket_policy.cloudtrail",
        "aws_s3_bucket_ownership_controls.cloudtrail",
    ):
        assert f'"aws_cloudtrail.service" -> "{dependency}"' in graph
