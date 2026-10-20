from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.staging_golden import main


def _inline_manifest(tmp_path: Path) -> Path:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "3",
                "gate_id": "LV-NIGHTLY",
                "acceptance_ids": ["GP3"],
                "owners": ["staging provisioner"],
                "artifacts": {
                    "service_sha": "a" * 40,
                    "content_sha": "b" * 40,
                    "artifact_digest": "c" * 64,
                },
                "expected_deployment": {
                    "account_id": "123456789012",
                    "region": "eu-central-1",
                    "cluster_arn": "arn:aws:ecs:eu-central-1:123456789012:cluster/qualification",
                    "service_arn": (
                        "arn:aws:ecs:eu-central-1:123456789012:service/qualification/"
                        "synthetic-staging"
                    ),
                    "task_definition_arn": (
                        "arn:aws:ecs:eu-central-1:123456789012:task-definition/ai-soc:7"
                    ),
                    "deployment_name": "synthetic-staging",
                    "image_digest": "c" * 64,
                    "service_sha": "a" * 40,
                    "content_sha": "b" * 40,
                    "configuration_sha256": "d" * 64,
                },
                "commands": ["make staging-golden"],
                "evidence_refs": ["synthetic/nightly"],
                "inputs": {
                    "nightly": {
                        "required_case_ids": ["G001"],
                        "baseline": {
                            "sha256": "d" * 64,
                            "en_cases": 20,
                            "es_cases": 20,
                            "drop_rate": 0.0,
                            "independently_reviewed": True,
                        },
                        "results": [
                            {
                                "case_id": "G001",
                                "language": "en",
                                "outcome": "completed",
                                "route_matches": True,
                            }
                        ],
                    }
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest


def test_inline_nightly_without_flag_reports_not_run(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("SOC_STAGING_ALLOW_INLINE_NIGHTLY", raising=False)
    evidence = tmp_path / "evidence.json"
    assert main(["--manifest", str(_inline_manifest(tmp_path)), "--evidence", str(evidence)]) == 2
    result = json.loads(evidence.read_text(encoding="utf-8"))["result"]
    assert result["status"] == "NOT_RUN"
    assert result["data_source"] == "inline_manifest"


def test_inline_nightly_perfect_inline_scores_never_live_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOC_STAGING_ALLOW_INLINE_NIGHTLY", "1")
    evidence = tmp_path / "evidence.json"
    assert main(["--manifest", str(_inline_manifest(tmp_path)), "--evidence", str(evidence)]) == 2
    result = json.loads(evidence.read_text(encoding="utf-8"))["result"]
    assert result["status"] == "NOT_RUN"
    assert result["status"] != "PASS"
    assert "inline manifest" in result["results"]["reason"]
