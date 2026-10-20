from __future__ import annotations

import hashlib
import shutil
import sys
from pathlib import Path
from typing import cast
from uuid import uuid4

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from scripts.coverage import collect, resolve_results_dir  # noqa: E402


def test_accepted_registry_and_fixture_bytes_match_current_checkpoint() -> None:
    accepted_sha256 = {
        "contracts/v1/freeze.json": (
            "5e8cb7c06ae4793dd133de55642c81a3f1fb46e4a60616ce93cd9df1a8549f1e"
        ),
        "docs/case_catalog.json": (
            "6ae199eafdb414266eaaea34e267b9286cfa0042bf44610343580a027597c1f4"
        ),
        "docs/traceability.json": (
            "26d32fb1788473b1bbdba81c2aea71695dc4e894563184d7bda9aa4dd3c3b5b9"
        ),
        "tests/fixtures/v1/contract_cases.json": (
            "4b4487601141c3551a119933f4136de3ebce4596d40f5665d7d8e6ecc6b65ce5"
        ),
        "tests/fixtures/v1/config_profile_inputs.json": (
            "373c73607ca0ae194fe0567d0741af9d08de0dc469103a137232ebeba3201cc9"
        ),
        "tests/fixtures/v1/g006_table_before_judgment.json": (
            "2b0c300b7bc5ebbcbaaea4c7305f353ff3b4d2f5bd6476d1ff914c6f6f79447a"
        ),
        "tests/fixtures/v1/b3_private_route_cases.json": (
            "a480b9f8dd937ebbfe3d384f0aa19f40de62bbd64bfea9f50d38d8afd00ebaf6"
        ),
        "tests/fixtures/v1/g040_coverage_inputs.json": (
            "68946f3f1d7d0650d789f25eaf22cca929b92b2cf564e5fab9d53eacd3e897bc"
        ),
        "tests/reproducibility/data/gn04_offline_runner_cases.json": (
            "196e7457ff7aea7424a272ac1ae6e7177eb852d2de075977fc9953f92ab3b55b"
        ),
        "tests/security/infra/data/g043_private_inference_cases.json": (
            "a363fe4af19cd0212339451c4874efb06a504397fcfbf0249fbd543a03dae070"
        ),
        "tests/security/infra/data/g045_private_bedrock_cases.json": (
            "e99f3cda37397d17697dd650e44fa349bd8a708d8e2007531bbfbc2af856d6d7"
        ),
        "tests/integration/data/fm003_audit_ack_cases.json": (
            "b9f92e8b82a4e95edc03720673ae18cd7a72c2fb2ae7e608db3d5d25cc97ca5b"
        ),
        "tests/integration/data/qa014_nightly_gate_cases.json": (
            "a2db7f3cbef12249e3ffd65ffb4048b1016ace11f6c379b61fe7ff9c17500ce3"
        ),
        "tests/integration/admission_runtime/data/query_no_reuse_cases.json": (
            "21718df15af9bad38c8a6c3fa555c423a02d8c134a61370490403a4cd30f4527"
        ),
    }
    actual = {
        path: hashlib.sha256((REPO_ROOT / path).read_bytes()).hexdigest()
        for path in accepted_sha256
    }
    assert actual == accepted_sha256


def _junit_case(name: str, *, variant: str, result: str = "") -> str:
    suffix = f"<{result}/>" if result else ""
    fixture_hash = "e6d52fe71a2af38a1ec7b6ff8365237e5ae1e9e0761c42fb0822afeaca661977"
    return (
        f'<testcase classname="fixture" name="{name}">'
        "<properties>"
        '<property name="acceptance_ids" value="G031"/>'
        '<property name="case_id" value="G031.en.mixed"/>'
        f'<property name="variant" value="{variant}"/>'
        f'<property name="fixture_sha256" value="{fixture_hash}"/>'
        "</properties>"
        f"{suffix}</testcase>"
    )


def test_coverage_joins_actual_passed_nodes_and_excludes_skip_and_failure() -> None:
    evidence = REPO_ROOT / "build/evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    folder = evidence / f"coverage-harness-{uuid4().hex}"
    folder.mkdir()
    try:
        (folder / "results.xml").write_text(
            "<testsuite>"
            + _junit_case("passed", variant="positive")
            + _junit_case("skipped", variant="negative", result='skipped message="xfail"')
            + _junit_case("failed", variant="boundary", result='failure message="assert"')
            + "</testsuite>"
        )

        report = collect(folder)

        assert report["collected_node_count"] == 3
        assert report["passed_node_count"] == 1
        assert report["skipped_node_count"] == 1
        assert report["failed_node_count"] == 1
        rows = cast(list[dict[str, object]], report["requirements"])
        row = next(row for row in rows if row["acceptance_id"] == "G031")
        assert row["passed_variants"] == ["positive"]
        assert row["coverage_percent"] == 25.0
        assert row["complete"] is False
        assert any("skipped test node" in item for item in cast(list[str], report["failures"]))
        assert any("failed test node" in item for item in cast(list[str], report["failures"]))
    finally:
        shutil.rmtree(folder)


def test_coverage_rejects_zero_collection_unknown_case_and_invalid_fixture_hash() -> None:
    evidence = REPO_ROOT / "build/evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    folder = evidence / f"coverage-harness-{uuid4().hex}"
    folder.mkdir()
    try:
        (folder / "empty.xml").write_text('<testsuite tests="0"/>')
        (folder / "bad.xml").write_text(
            '<testsuite><testcase classname="fixture" name="bad">'
            "<properties>"
            '<property name="acceptance_ids" value="G031"/>'
            '<property name="case_id" value="NOT-REGISTERED"/>'
            '<property name="variant" value="positive"/>'
            '<property name="fixture_sha256" value="0"/>'
            "</properties></testcase></testsuite>"
        )

        report = collect(folder)

        failures = cast(list[str], report["failures"])
        assert any("zero tests collected" in failure for failure in failures)
        assert any("unregistered case ID" in failure for failure in failures)
        assert any("invalid fixture SHA-256" in failure for failure in failures)
    finally:
        shutil.rmtree(folder)


def test_coverage_rejects_duplicate_case_variant_and_collected_node() -> None:
    evidence = REPO_ROOT / "build/evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    folder = evidence / f"coverage-harness-{uuid4().hex}"
    folder.mkdir()
    try:
        duplicate_variant = _junit_case("first", variant="positive") + _junit_case(
            "second", variant="positive"
        )
        duplicate_node = _junit_case("same-node", variant="negative") + _junit_case(
            "same-node", variant="boundary"
        )
        (folder / "duplicate-variant.xml").write_text(f"<testsuite>{duplicate_variant}</testsuite>")
        (folder / "duplicate-node.xml").write_text(f"<testsuite>{duplicate_node}</testsuite>")

        report = collect(folder)

        failures = cast(list[str], report["failures"])
        assert any("duplicate case/variant result" in item for item in failures)
        assert any("duplicate collected node ID" in item for item in failures)
    finally:
        shutil.rmtree(folder)


def test_coverage_cli_resolves_repository_relative_make_results_path() -> None:
    assert resolve_results_dir(Path("build/evidence")) == REPO_ROOT / "build/evidence"


def test_coverage_rejects_results_outside_the_repository() -> None:
    try:
        resolve_results_dir(Path("/tmp/ai-soc-coverage-outside-test"))
    except ValueError as error:
        assert "inside the repository" in str(error)
    else:
        raise AssertionError("outside-repository results path was accepted")


def test_ci_coverage_uses_required_fresh_result_names_and_reports_missing_files() -> None:
    evidence = REPO_ROOT / "build/evidence"
    folder = evidence / f"coverage-harness-{uuid4().hex}"
    folder.mkdir(parents=True)
    try:
        content = "<testsuite>" + _junit_case("same", variant="positive") + "</testsuite>"
        (folder / "contract.xml").write_text(content)
        (folder / "stale.xml").write_text(content)

        report = collect(folder, expected_files=("contract.xml", "unit.xml"))

        assert report["collected_node_count"] == 1
        assert report["result_files"] == [str((folder / "contract.xml").relative_to(REPO_ROOT))]
        failures = cast(list[str], report["failures"])
        assert "missing expected JUnit result file: unit.xml" in failures
        assert not any("duplicate collected node" in item for item in failures)
    finally:
        shutil.rmtree(folder)


def _metadata_case(
    name: str, *, case_id: str, variant: str, fixture_sha256: str, acceptance_ids: str = ""
) -> str:
    props: list[str] = []
    if acceptance_ids:
        props.append(f'<property name="acceptance_ids" value="{acceptance_ids}"/>')
    props.extend(
        [
            f'<property name="case_id" value="{case_id}"/>',
            f'<property name="variant" value="{variant}"/>',
            f'<property name="fixture_sha256" value="{fixture_sha256}"/>',
        ]
    )
    return (
        f'<testcase classname="fixture" name="{name}"><properties>'
        + "".join(props)
        + "</properties></testcase>"
    )


def test_coverage_enforces_empty_component_scope_and_exact_fixture_hash() -> None:
    evidence = REPO_ROOT / "build/evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    folder = evidence / f"coverage-harness-{uuid4().hex}"
    folder.mkdir()
    route_hash = hashlib.sha256(
        (REPO_ROOT / "tests/unit/api/data/route_security_cases.json").read_bytes()
    ).hexdigest()
    try:
        valid_component = _metadata_case(
            "valid-component",
            case_id="B5-API.ingress-component",
            variant="positive",
            fixture_sha256=route_hash,
        )
        leaked_requirement = _metadata_case(
            "leaked-requirement",
            case_id="B5-API.ingress-component",
            variant="negative",
            fixture_sha256=route_hash,
            acceptance_ids="G057",
        )
        wrong_fixture = _metadata_case(
            "wrong-fixture",
            case_id="G031.en.mixed",
            variant="positive",
            fixture_sha256="0" * 64,
            acceptance_ids="G031",
        )
        unregistered_hash = _metadata_case(
            "unregistered-hash",
            case_id="QA-014.resolution",
            variant="positive",
            fixture_sha256="a" * 64,
            acceptance_ids="GP3",
        )
        (folder / "scope.xml").write_text(
            "<testsuite>"
            f"{valid_component}{leaked_requirement}{wrong_fixture}{unregistered_hash}"
            "</testsuite>"
        )

        report = collect(folder)

        failures = cast(list[str], report["failures"])
        assert not any("valid-component" in item for item in failures)
        assert any("out-of-scope acceptance IDs" in item for item in failures)
        assert any("fixture SHA-256 outside registered scope" in item for item in failures)
        assert any("no authoritative fixture SHA-256" in item for item in failures)
    finally:
        shutil.rmtree(folder)
