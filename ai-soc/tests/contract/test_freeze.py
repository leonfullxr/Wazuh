from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest
from jsonschema import Draft202012Validator
from pydantic import TypeAdapter

from ai_soc.contracts import freeze
from ai_soc.contracts.coverage import (
    case_fixture_bindings,
    case_fixture_bindings_sha256,
    validate_case_fixture_bindings,
    validate_traceability,
)
from ai_soc.contracts.models import GoldenCase

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "v1"


def known_task_ids() -> set[str]:
    registry = json.loads((ROOT / "docs/task_ids.json").read_text("utf-8"))
    task_ids = registry["task_ids"]
    assert registry["schema_version"] == "1"
    assert task_ids == sorted(set(task_ids))
    return set(task_ids)


def test_generated_json_openapi_and_typescript_are_in_sync() -> None:
    freeze.generate(check=True)
    schemas = json.loads((ROOT / "contracts/v1/models.schema.json").read_text("utf-8"))
    openapi = json.loads((ROOT / "contracts/v1/openapi.json").read_text("utf-8"))
    typescript = (ROOT / "contracts/v1/generated/types.ts").read_text("utf-8")
    definitions = schemas["$defs"]
    Draft202012Validator.check_schema(schemas)
    assert "python_executable" not in definitions["RunnerManifest"]["properties"]
    refs = set(re.findall(r"#/\$defs/([^\" ]+)", json.dumps(schemas)))
    assert refs <= set(definitions)
    assert set(definitions) == set(openapi["components"]["schemas"])
    assert {"/v1/questions", "/v1/fetches/page", "/v1/feedback", "/mcp"} <= set(openapi["paths"])
    for type_name in (
        "Answer",
        "AuditAck",
        "AuditEvent",
        "AuditFetchRecord",
        "CompletionCommand",
        "RecoveryPage",
        "AdmissionGrant",
        "EmbeddingGrant",
        "ModelCountGrant",
        "ReadOperationGrant",
        "StageCapacityRejection",
        "TopicPromptPack",
        "FindingTemplate",
        "FeedbackReceiptPayload",
        "CursorPayload",
        "GoldenCase",
        "SemanticSuggestion",
        "TopicDefinition",
    ):
        assert type_name in definitions
        assert f" {type_name} " in typescript or f"interface {type_name} " in typescript
    manifest = json.loads((ROOT / "contracts/v1/freeze.json").read_text("utf-8"))
    runner = json.loads((ROOT / "contracts/v1/runner-manifest.json").read_text("utf-8"))
    assert manifest["contract_version"] == "1"
    assert manifest["freeze_revision"] == "1.15"
    assert manifest["fixture_mode_required"] is True
    assert len(manifest["acceptance_ids"]) >= 70
    assert len(manifest["case_ids"]) >= 30
    assert runner["node"] == "22.23.3"
    assert runner["npm"] == "10.9.9"
    assert runner["typescript"] == "5.9.3"
    assert runner["playwright"] == "@playwright/test 1.63.0; @axe-core/playwright 4.13.0"
    assert runner["browser_version"] == "153.0.8010.12"
    assert runner["terraform"] == "1.16.5"
    assert runner["tflint"] == "0.64.0"
    assert runner["trivy"] == "0.74.0"
    assert runner["python_implementation"] == "CPython"
    assert runner["python"] == "CPython 3.12.13"
    assert "python_executable" not in runner
    assert runner["docker_compose"] == "v5.5.1"
    assert runner["docker_buildx"] == "v0.37.1"
    assert runner["buildkit"].startswith("v0.33.1 pinned from the immutable toolchain lock")
    assert runner["b6_toolchain_lock_source_commit"] == "4ae876df59ef15157ad5df850ddea6a8b3b8a4ab"
    assert (
        runner["b6_toolchain_lock_sha256"]
        == "9d9fecbf48e4f5de84b3e944aa457aba45e7dbe7259a0ea09be4d2055c9f91f8"
    )
    buildkit = next(image for image in runner["images"] if image["name"] == "buildkit")
    assert buildkit["version"] == "v0.33.1"
    assert buildkit["commit"] == "8c91502"
    assert (
        buildkit["index_digest"]
        == "sha256:cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea"
    )
    assert (
        buildkit["platform_manifest_sha256"]
        == "98cc6a3fc46220d00f8224ae483f3274fc874e9be8d7dd1e2e2c5481209228b5"
    )
    assert buildkit["prepared"] is False
    assert runner["scan_database_prepared"] is True
    assert re.fullmatch(r"[0-9a-f]{64}", runner["scan_database_content_sha256"])
    assert all(image["prepared"] is False for image in runner["images"])
    assert re.fullmatch(r"[0-9a-f]{64}", runner["node_archive_sha256"])
    assert re.fullmatch(r"[0-9a-f]{64}", runner["typescript_package_lock_sha256"])


def test_openapi_references_resolve_to_emitted_component_schemas() -> None:
    openapi = json.loads((ROOT / "contracts/v1/openapi.json").read_text("utf-8"))
    components = openapi["components"]["schemas"]
    refs = set(re.findall(r"#/components/schemas/([^\" ]+)", json.dumps(openapi)))
    assert refs <= set(components)


def test_formal_golden_examples_validate_as_typed_cases() -> None:
    document = json.loads((FIXTURES / "golden_examples.json").read_text("utf-8"))
    cases = [TypeAdapter(GoldenCase).validate_json(json.dumps(row)) for row in document["cases"]]
    assert len(cases) == 10
    assert len({case.case_id for case in cases}) == len(cases)
    assert all(case.evidence_class != "live" for case in cases)


def test_fixture_tree_has_no_private_key_or_customer_artifact() -> None:
    for path in FIXTURES.rglob("*"):
        if path.is_file():
            content = path.read_bytes()
            assert b"BEGIN PRIVATE KEY" not in content
            assert b"BEGIN RSA PRIVATE KEY" not in content
            assert b"customer-prod" not in content
    manifest = json.loads((FIXTURES / "synthetic_manifest.json").read_text("utf-8"))
    assert manifest["mode"] == "fixture" and manifest["synthetic"] is True


def test_namespace_imports_have_no_network_home_or_key_access() -> None:
    script = """
import os
import pathlib
import sys

home = os.environ['HOME']

def audit(event, args):
    if event.startswith('socket.'):
        raise AssertionError('network access during import')
    if event == 'open' and args and isinstance(args[0], (str, bytes, os.PathLike)):
        path = os.path.abspath(os.fsdecode(args[0]))
        if path.startswith(home + os.sep):
            raise AssertionError('home access during import')

sys.addaudithook(audit)
pathlib.Path.home = lambda self: (_ for _ in ()).throw(
    AssertionError('home lookup during import')
)
import ai_soc
import ai_soc.config
import ai_soc.contracts.models
import ai_soc.contracts.ports
import ai_soc.content
import ai_soc.planning
import ai_soc.identity
import ai_soc.query
import ai_soc.state
import ai_soc.judgment
import ai_soc.application
import ai_soc.api
import ai_soc.mcp
import ai_soc.telemetry
import ai_soc.feedback
import ai_soc.validation
""".strip()
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": str(ROOT / "src"),
        "HOME": str(ROOT / "build/private-home"),
        "PYTHONNOUSERSITE": "1",
    }
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=ROOT, env=environment, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr


def test_direct_socket_attempt_is_denied_by_local_contract_sentinel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def denied(*args: object, **kwargs: object) -> None:
        raise AssertionError("external network is forbidden in CF-1 contract tests")

    monkeypatch.setattr(socket.socket, "connect", denied)
    with pytest.raises(AssertionError, match="external network is forbidden"):
        socket.socket().connect(("203.0.113.1", 443))


def test_case_catalog_and_traceability_are_frozen_without_false_results() -> None:
    catalog = json.loads((ROOT / "docs/case_catalog.json").read_text("utf-8"))
    manifest = json.loads((ROOT / "contracts/v1/freeze.json").read_text("utf-8"))
    catalog_ids = {row["case_id"] for row in catalog["cases"]}
    contract_cases = json.loads((FIXTURES / "contract_cases.json").read_text("utf-8"))
    contract_case_ids = {row["case_id"] for row in contract_cases["cases"]}
    assert catalog_ids | contract_case_ids == set(manifest["case_ids"])
    traceability = json.loads((ROOT / "docs/traceability.json").read_text("utf-8"))
    required = {row["acceptance_id"] for row in traceability["entries"]}
    assert required == set(manifest["acceptance_ids"])
    assert all(
        row["test_node_ids"] == [] and row["results_status"] == "PENDING_IMPLEMENTATION"
        for row in traceability["entries"]
    )
    validate_case_fixture_bindings(catalog, manifest["case_fixture_bindings_sha256"])


def test_case_fixture_bindings_are_canonical_and_match_the_frozen_manifest() -> None:
    catalog = json.loads((ROOT / "docs/case_catalog.json").read_text("utf-8"))
    manifest = json.loads((ROOT / "contracts/v1/freeze.json").read_text("utf-8"))
    bindings = case_fixture_bindings(catalog)
    assert case_fixture_bindings_sha256(catalog) == manifest["case_fixture_bindings_sha256"]
    assert bindings["B2-G008.content"]["positive"] == [
        "af3fc7f9bc6b98199640548d0039b84f9592987a3235c9566ff83e490e6d1ea8"
    ]
    assert "G013" not in next(
        row["requirements"] for row in catalog["cases"] if row["case_id"] == "QA-001.resolution"
    )
    rows = {row["case_id"]: row for row in catalog["cases"]}
    assert rows["B2-G012.parser"]["requirements"] == ["G012"]
    assert rows["B2-G013.parser"]["requirements"] == ["G013"]
    assert rows["B5-G035.ui-route-component"]["requirements"] == []
    assert rows["B5-G042.composition.private"]["requirements"] == ["G042"]


def test_case_fixture_bindings_boundary_accepts_multiple_independent_inputs() -> None:
    catalog = json.loads((ROOT / "docs/case_catalog.json").read_text("utf-8"))
    failure_hashes = case_fixture_bindings(catalog)["QA-006.resolution"]["failure"]
    assert len(failure_hashes) == 2
    assert failure_hashes == sorted(failure_hashes)


def test_case_fixture_bindings_reject_malformed_or_unapproved_hashes() -> None:
    malformed = {
        "cases": [
            {
                "case_id": "case",
                "variants": ["positive", "negative", "boundary", "failure"],
                "fixture_sha256_by_variant": {"positive": ["A" * 64]},
            }
        ]
    }
    with pytest.raises(AssertionError, match="lower-case SHA-256"):
        case_fixture_bindings(malformed)
    unapproved_variant = {
        "cases": [
            {
                "case_id": "case",
                "variants": ["positive", "negative", "boundary", "failure"],
                "fixture_sha256_by_variant": {"other": ["a" * 64]},
            }
        ]
    }
    with pytest.raises(AssertionError, match="unknown variant"):
        case_fixture_bindings(unapproved_variant)
    outside_case = {
        "cases": [
            {
                "case_id": "case",
                "variants": ["positive"],
                "fixture_sha256_by_variant": {"failure": ["a" * 64]},
            }
        ]
    }
    with pytest.raises(AssertionError, match="outside the case"):
        case_fixture_bindings(outside_case)
    empty_hashes: dict[str, object] = {
        "cases": [
            {
                "case_id": "case",
                "variants": ["positive"],
                "fixture_sha256_by_variant": {"positive": []},
            }
        ]
    }
    with pytest.raises(AssertionError, match="non-empty arrays"):
        case_fixture_bindings(empty_hashes)
    unordered_hashes = {
        "cases": [
            {
                "case_id": "case",
                "variants": ["positive"],
                "fixture_sha256_by_variant": {"positive": ["b" * 64, "a" * 64]},
            }
        ]
    }
    with pytest.raises(AssertionError, match="sorted and unique"):
        case_fixture_bindings(unordered_hashes)


def test_case_fixture_bindings_failure_detects_drift_from_frozen_digest() -> None:
    catalog = json.loads((ROOT / "docs/case_catalog.json").read_text("utf-8"))
    with pytest.raises(AssertionError, match="differ from frozen digest"):
        validate_case_fixture_bindings(catalog, "0" * 64)


G040_COVERAGE_SHA256 = "68946f3f1d7d0650d789f25eaf22cca929b92b2cf564e5fab9d53eacd3e897bc"


def g040_coverage_inputs() -> dict[str, object]:
    value: object = json.loads((FIXTURES / "g040_coverage_inputs.json").read_text("utf-8"))
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def g040_string(oracle: dict[str, object], key: str) -> str:
    value = oracle[key]
    assert isinstance(value, str)
    return value


def g040_string_list(oracle: dict[str, object], key: str) -> list[str]:
    value = oracle[key]
    assert isinstance(value, list)
    items = cast(list[object], value)
    assert all(isinstance(item, str) for item in items)
    return cast(list[str], items)


def record_g040_properties(request: pytest.FixtureRequest, variant: str) -> None:
    request.node.user_properties.extend(
        [
            ("acceptance_ids", "G040"),
            ("case_id", "B1-G040.coverage"),
            ("variant", variant),
            ("fixture_sha256", G040_COVERAGE_SHA256),
        ]
    )


@pytest.mark.case_id("B1-G040.coverage")
@pytest.mark.variant("positive")
@pytest.mark.fixture_sha256(G040_COVERAGE_SHA256)
def test_g040_coverage_positive_joins_frozen_inventory_to_catalog(
    request: pytest.FixtureRequest,
) -> None:
    record_g040_properties(request, "positive")
    oracle = g040_coverage_inputs()
    trace = json.loads((ROOT / "docs/traceability.json").read_text("utf-8"))
    catalog = json.loads((ROOT / "docs/case_catalog.json").read_text("utf-8"))
    actual = {row["acceptance_id"] for row in trace["entries"]}
    expected = set(g040_string_list(oracle, "expected_acceptance_ids"))
    catalog_ids = {row["case_id"] for row in catalog["cases"]}
    g040 = next(row for row in trace["entries"] if row["acceptance_id"] == "G040")
    validate_traceability(trace, expected, catalog_ids, known_task_ids())
    assert actual == expected
    assert "B1-G040.coverage" in catalog_ids
    assert "B1-G040.coverage" in g040["review_cases"]


@pytest.mark.case_id("B1-G040.coverage")
@pytest.mark.variant("negative")
@pytest.mark.fixture_sha256(G040_COVERAGE_SHA256)
def test_g040_coverage_negative_detects_missing_acceptance_mapping(
    request: pytest.FixtureRequest,
) -> None:
    record_g040_properties(request, "negative")
    oracle = g040_coverage_inputs()
    expected = set(g040_string_list(oracle, "expected_acceptance_ids"))
    trace = json.loads((ROOT / "docs/traceability.json").read_text("utf-8"))
    mutated = json.loads(json.dumps(trace))
    mutated["entries"] = [row for row in mutated["entries"] if row["acceptance_id"] != "G040"]
    catalog = json.loads((ROOT / "docs/case_catalog.json").read_text("utf-8"))
    with pytest.raises(AssertionError, match="acceptance inventory"):
        validate_traceability(
            mutated,
            expected,
            {row["case_id"] for row in catalog["cases"]},
            known_task_ids(),
        )


@pytest.mark.case_id("B1-G040.coverage")
@pytest.mark.variant("boundary")
@pytest.mark.fixture_sha256(G040_COVERAGE_SHA256)
def test_g040_coverage_boundary_is_exactly_71_acceptances(
    request: pytest.FixtureRequest,
) -> None:
    record_g040_properties(request, "boundary")
    oracle = g040_coverage_inputs()
    trace = json.loads((ROOT / "docs/traceability.json").read_text("utf-8"))
    expected_ids = set(g040_string_list(oracle, "expected_acceptance_ids"))
    assert len(expected_ids) == 71
    assert {row["acceptance_id"] for row in trace["entries"]} == expected_ids
    assert set(g040_string_list(oracle, "expected_proposal_ids")) == {"P1", "P2", "P3", "P4"}
    assert g040_string(oracle, "ui_acceptance_id") == "GUI"
    assert g040_string(oracle, "mcp_acceptance_id") == "GMCP"


@pytest.mark.case_id("B1-G040.coverage")
@pytest.mark.variant("failure")
@pytest.mark.fixture_sha256(G040_COVERAGE_SHA256)
def test_g040_coverage_failure_detects_dangling_case_reference(
    request: pytest.FixtureRequest,
) -> None:
    record_g040_properties(request, "failure")
    trace = json.loads((ROOT / "docs/traceability.json").read_text("utf-8"))
    catalog = json.loads((ROOT / "docs/case_catalog.json").read_text("utf-8"))
    known_cases = {row["case_id"] for row in catalog["cases"]}
    task_registry = known_task_ids()
    requirement = next(row for row in trace["entries"] if row["acceptance_id"] == "G040")
    requirement["review_cases"].append("B1-G040.unregistered")
    with pytest.raises(AssertionError, match="unknown review case"):
        validate_traceability(
            trace,
            set(g040_string_list(g040_coverage_inputs(), "expected_acceptance_ids")),
            known_cases,
            task_registry,
        )
    mutated = json.loads(json.dumps(trace))
    next(row for row in mutated["entries"] if row["acceptance_id"] == "G040")["tasks"].append(
        "B1-T999"
    )
    with pytest.raises(AssertionError, match="unknown task"):
        validate_traceability(
            mutated,
            set(g040_string_list(g040_coverage_inputs(), "expected_acceptance_ids")),
            known_cases,
            task_registry,
        )
