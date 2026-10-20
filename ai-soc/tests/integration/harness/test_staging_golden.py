from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Literal, TypedDict

import pytest
from pydantic import TypeAdapter

from scripts.staging.clients import (
    NetworkProbeReport,
    NightlyResultsReport,
    StagingClients,
)
from scripts.staging.manifest import NetworkGateInput, NightlyCaseInput, manifest_sha256
from scripts.staging.models import (
    DeploymentBinding,
    EvidenceKind,
    EvidenceReference,
    GateId,
    ObligationResult,
    ObligationStatus,
)
from scripts.staging.registry import GATE_REGISTRY
from scripts.staging_golden import (
    CaseOutcome,
    CaseResult,
    ReviewedBaseline,
    evaluate_nightly,
    main,
)

QA014_FIXTURE = Path(__file__).parents[1] / "data/qa014_nightly_gate_cases.json"


def _binding(**overrides: str) -> DeploymentBinding:
    values = {
        "account_id": "123456789012",
        "region": "eu-central-1",
        "cluster_arn": "arn:aws:ecs:eu-central-1:123456789012:cluster/qualification",
        "service_arn": (
            "arn:aws:ecs:eu-central-1:123456789012:service/qualification/synthetic-staging"
        ),
        "task_definition_arn": "arn:aws:ecs:eu-central-1:123456789012:task-definition/ai-soc:7",
        "deployment_name": "synthetic-staging",
        "deployment_id": "ecs-svc/1234567890123456789",
        "image_digest": "c" * 64,
        "service_sha": "a" * 40,
        "content_sha": "b" * 40,
        "configuration_sha256": "d" * 64,
    }
    values.update(overrides)
    return DeploymentBinding(**values)


class _Observer:
    def __init__(self, binding: DeploymentBinding | None = None):
        self.binding = binding or _binding()

    def observe_deployment(self) -> DeploymentBinding | None:
        return self.binding


def _clients(*, nightly=None, network=None, binding=None) -> StagingClients:
    return StagingClients(observer=_Observer(binding), nightly=nightly, network=network)


def _network_report(
    *,
    status: ObligationStatus = ObligationStatus.PASS,
    evidence_ref: str = "evidence/network",
    site_id: str = "alpha",
) -> NetworkProbeReport:
    return NetworkProbeReport(
        binding=_binding(),
        site_id=site_id,
        obligations=tuple(
            ObligationResult(
                item.obligation_id,
                status,
                "observed",
                (
                    EvidenceReference(
                        EvidenceKind.FILE_SHA256, f"{evidence_ref}/{item.obligation_id}", "e" * 64
                    ),
                ),
            )
            for item in GATE_REGISTRY[GateId.LV_NETWORK].obligations
        ),
    )


def _nightly_report(cases: tuple[NightlyCaseInput, ...]) -> NightlyResultsReport:
    return NightlyResultsReport(
        binding=_binding(),
        cases=cases,
        obligations=(
            *(
                ObligationResult(
                    obligation_id,
                    ObligationStatus.PASS,
                    "nightly metric observed",
                    (
                        EvidenceReference(
                            EvidenceKind.FILE_SHA256, f"nightly/{obligation_id}", "1" * 64
                        ),
                    ),
                )
                for obligation_id in (
                    "nightly_usage_cost",
                    "nightly_usage_latency",
                    "nightly_cache_behavior",
                    "nightly_missing_run_behavior",
                )
            ),
            ObligationResult(
                "gp3_stage_evidence",
                ObligationStatus.PASS,
                "nightly stage archived",
                (EvidenceReference(EvidenceKind.FILE_SHA256, "nightly/stage", "2" * 64),),
            ),
            ObligationResult(
                "gp3_trace_evidence",
                ObligationStatus.PASS,
                "nightly trace archived",
                (EvidenceReference(EvidenceKind.FILE_SHA256, "nightly/trace", "3" * 64),),
            ),
        ),
    )


class QA014InputResult(TypedDict):
    case_id: str
    language: Literal["en", "es"]
    route_matches: bool
    outcome: Literal["completed", "no_findings", "invalid_json", "provider_failure"]
    valid_candidates: int
    dropped_candidates: int


class QA014Expected(TypedDict):
    status: Literal["PASS", "FAIL"]
    routed_correctly: int
    empty_cohort: bool
    drop_alarm: bool
    missing_cases: list[str]


class QA014Case(TypedDict):
    variant: Literal["positive", "negative", "boundary", "failure"]
    required_case_ids: list[str]
    baseline_rate: float
    results: list[QA014InputResult]
    expected: QA014Expected


class QA014Fixture(TypedDict):
    schema_version: Literal["1"]
    case_id: Literal["QA-014.resolution"]
    requirements: list[Literal["G058", "GP2", "GP3"]]
    variants: list[QA014Case]


def _qa014_cases() -> list[QA014Case]:
    fixture: object = json.loads(QA014_FIXTURE.read_text(encoding="utf-8"))
    adapter: TypeAdapter[QA014Fixture] = TypeAdapter(QA014Fixture)
    return adapter.validate_python(fixture)["variants"]


def _baseline(rate: float) -> ReviewedBaseline:
    return ReviewedBaseline(
        sha256="a" * 64,
        en_cases=20,
        es_cases=20,
        drop_rate=rate,
        independently_reviewed=True,
    )


def _case(
    case_id: str,
    *,
    route_matches: bool | None = True,
    outcome: CaseOutcome = CaseOutcome.completed,
    valid_candidates: int = 0,
    dropped_candidates: int = 0,
) -> CaseResult:
    return CaseResult(
        case_id=case_id,
        language="en",
        outcome=outcome,
        route_matches=route_matches,
        valid_candidates=valid_candidates,
        dropped_candidates=dropped_candidates,
    )


@pytest.mark.parametrize("case", _qa014_cases(), ids=lambda case: case["variant"])
def test_gp3_nightly_evaluator_uses_exact_bilingual_denominators_and_alarm_rules(
    case: QA014Case, record_property: Callable[[str, str], None]
) -> None:
    record_property("acceptance_ids", "GP3")
    record_property("case_id", "B6-QA014.nightly-evaluator")
    record_property("variant", case["variant"])
    record_property("fixture_sha256", hashlib.sha256(QA014_FIXTURE.read_bytes()).hexdigest())
    results = tuple(
        CaseResult(
            case_id=row["case_id"],
            language=row["language"],
            outcome=CaseOutcome(row["outcome"]),
            route_matches=row["route_matches"],
            valid_candidates=row["valid_candidates"],
            dropped_candidates=row["dropped_candidates"],
        )
        for row in case["results"]
    )
    result = evaluate_nightly(
        required_case_ids=tuple(case["required_case_ids"]),
        results=results,
        baseline=_baseline(case["baseline_rate"]),
    )

    assert result.status == case["expected"]["status"]
    assert result.required_cases == len(case["required_case_ids"])
    assert result.routed_correctly == case["expected"]["routed_correctly"]
    assert result.empty_cohort is case["expected"]["empty_cohort"]
    assert result.drop_alarm is case["expected"]["drop_alarm"]
    assert list(result.missing_cases) == case["expected"]["missing_cases"]


def test_missing_router_cases_count_against_full_required_denominator() -> None:
    result = evaluate_nightly(
        required_case_ids=("G001", "G002", "G003"),
        results=(_case("G001"), _case("G002", route_matches=False)),
        baseline=_baseline(0.10),
    )

    assert result.status == "FAIL"
    assert result.required_cases == 3
    assert result.routed_correctly == 1
    assert result.router_accuracy == pytest.approx(1 / 3)
    assert result.missing_cases == ("G003",)
    assert result.outcome_counts["missing"] == 1


def test_zero_candidate_cohort_has_no_rate_and_keeps_no_findings_distinct() -> None:
    result = evaluate_nightly(
        required_case_ids=("G001", "G002"),
        results=(
            _case("G001", outcome=CaseOutcome.no_findings),
            _case("G002", outcome=CaseOutcome.completed),
        ),
        baseline=_baseline(0.0),
    )

    assert result.status == "PASS"
    assert result.candidate_count == 0
    assert result.empty_cohort is True
    assert result.drop_rate is None
    assert result.outcome_counts["no_findings"] == 1
    assert result.outcome_counts["invalid_json"] == 0
    assert result.outcome_counts["provider_failure"] == 0


def test_drop_alarm_requires_twenty_candidates_and_strictly_exceeds_threshold() -> None:
    equality = evaluate_nightly(
        required_case_ids=("G001",),
        results=(_case("G001", valid_candidates=20, dropped_candidates=1),),
        baseline=_baseline(0.0),
    )
    above = evaluate_nightly(
        required_case_ids=("G001",),
        results=(_case("G001", valid_candidates=20, dropped_candidates=2),),
        baseline=_baseline(0.0),
    )
    under_denominator = evaluate_nightly(
        required_case_ids=("G001",),
        results=(_case("G001", valid_candidates=19, dropped_candidates=2),),
        baseline=_baseline(0.0),
    )

    assert equality.drop_alarm is False
    assert above.drop_alarm is True
    assert above.status == "FAIL"
    assert under_denominator.drop_alarm is False


@pytest.mark.parametrize("outcome", [CaseOutcome.invalid_json, CaseOutcome.provider_failure])
def test_invalid_json_and_provider_failure_are_not_zero_drop_or_green(
    outcome: CaseOutcome,
) -> None:
    result = evaluate_nightly(
        required_case_ids=("G001",),
        results=(_case("G001", outcome=outcome),),
        baseline=_baseline(0.0),
    )

    assert result.status == "FAIL"
    assert result.candidate_count == 0
    assert result.drop_rate is None
    assert result.outcome_counts[outcome.value] == 1


def test_duplicate_unexpected_and_impossible_candidate_counts_are_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate case"):
        evaluate_nightly(
            required_case_ids=("G001",),
            results=(_case("G001"), _case("G001")),
            baseline=_baseline(0.0),
        )
    with pytest.raises(ValueError, match="unexpected case"):
        evaluate_nightly(
            required_case_ids=("G001",),
            results=(_case("G002"),),
            baseline=_baseline(0.0),
        )
    with pytest.raises(ValueError, match="cannot exceed"):
        evaluate_nightly(
            required_case_ids=("G001",),
            results=(_case("G001", valid_candidates=1, dropped_candidates=2),),
            baseline=_baseline(0.0),
        )


def test_unreviewed_or_undersized_baseline_cannot_produce_a_gate_result() -> None:
    with pytest.raises(ValueError, match="20 reviewed cases per language"):
        evaluate_nightly(
            required_case_ids=("G001",),
            results=(_case("G001"),),
            baseline=ReviewedBaseline(
                sha256="a" * 64,
                en_cases=19,
                es_cases=20,
                drop_rate=0.0,
                independently_reviewed=True,
            ),
        )
    with pytest.raises(ValueError, match="independently reviewed"):
        evaluate_nightly(
            required_case_ids=("G001",),
            results=(_case("G001"),),
            baseline=ReviewedBaseline(
                sha256="a" * 64,
                en_cases=20,
                es_cases=20,
                drop_rate=0.0,
                independently_reviewed=False,
            ),
        )


def test_absent_manifest_writes_not_configured_evidence_without_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = tmp_path / "evidence.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "staging_golden.py",
            "--manifest",
            str(tmp_path / "missing.json"),
            "--evidence",
            str(evidence),
        ],
    )

    assert main() == 2
    artifact = json.loads(evidence.read_text(encoding="utf-8"))
    assert artifact["status"] == "NOT_CONFIGURED"
    assert artifact["result"] is None


def test_present_manifest_stays_not_run_when_authorized_adapter_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"schema_version":"1"}\n', encoding="utf-8")
    evidence = tmp_path / "evidence.json"
    monkeypatch.setattr(
        "sys.argv",
        ["staging_golden.py", "--manifest", str(manifest), "--evidence", str(evidence)],
    )

    assert main() == 2
    artifact = json.loads(evidence.read_text(encoding="utf-8"))
    assert artifact["status"] == "NOT_RUN"
    assert artifact["result"] is None
    assert "schema 1 is legacy" in artifact["reason"]


def test_unsupported_manifest_schema_fails_without_claiming_live_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"schema_version":"9"}\n', encoding="utf-8")
    evidence = tmp_path / "evidence.json"
    monkeypatch.setattr(
        "sys.argv",
        ["staging_golden.py", "--manifest", str(manifest), "--evidence", str(evidence)],
    )

    assert main() == 1
    artifact = json.loads(evidence.read_text(encoding="utf-8"))
    assert artifact["status"] == "FAIL"
    assert artifact["result"] is None
    assert artifact["reason"] == "unsupported staging manifest schema"


def _example_artifacts() -> dict[str, str]:
    return {
        "service_sha": "a" * 40,
        "content_sha": "b" * 40,
        "artifact_digest": "c" * 64,
    }


def _expected_deployment() -> dict[str, str]:
    return {
        "account_id": "123456789012",
        "region": "eu-central-1",
        "cluster_arn": "arn:aws:ecs:eu-central-1:123456789012:cluster/qualification",
        "service_arn": (
            "arn:aws:ecs:eu-central-1:123456789012:service/qualification/synthetic-staging"
        ),
        "task_definition_arn": "arn:aws:ecs:eu-central-1:123456789012:task-definition/ai-soc:7",
        "deployment_name": "synthetic-staging",
        "deployment_id": "ecs-svc/1234567890123456789",
        "image_digest": "c" * 64,
        "service_sha": "a" * 40,
        "content_sha": "b" * 40,
        "configuration_sha256": "d" * 64,
    }


def _nightly_manifest(*, results: list[dict[str, object]] | None = None) -> dict[str, object]:
    nightly: dict[str, object] = {
        "required_case_ids": ["G001"],
        "baseline": {
            "sha256": "d" * 64,
            "en_cases": 20,
            "es_cases": 20,
            "drop_rate": 0.0,
            "independently_reviewed": True,
        },
    }
    if results is not None:
        nightly["results"] = results
    return {
        "schema_version": "3",
        "gate_id": "LV-NIGHTLY",
        "acceptance_ids": ["GP3"],
        "owners": ["staging provisioner"],
        "artifacts": _example_artifacts(),
        "expected_deployment": _expected_deployment(),
        "commands": ["make staging-golden"],
        "evidence_refs": ["synthetic/nightly"],
        "inputs": {"nightly": nightly},
    }


def test_lv_nightly_manifest_emits_live_gate_result_and_passes(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            _nightly_manifest(
                results=[
                    {
                        "case_id": "G001",
                        "language": "en",
                        "outcome": "completed",
                        "route_matches": True,
                    }
                ]
            )
        )
        + "\n",
        encoding="utf-8",
    )
    evidence = tmp_path / "evidence.json"

    class _Client:
        def collect_case_results(self) -> NightlyResultsReport:
            return _nightly_report(
                (
                    NightlyCaseInput(
                        case_id="G001",
                        language="en",
                        outcome="completed",
                        route_matches=True,
                        evidence_refs=(
                            EvidenceReference(EvidenceKind.FILE_SHA256, "nightly/G001", "f" * 64),
                        ),
                    ),
                )
            )

    assert (
        main(
            ["--manifest", str(manifest), "--evidence", str(evidence)],
            clients=_clients(nightly=_Client()),
        )
        == 2
    )
    artifact = json.loads(evidence.read_text(encoding="utf-8"))
    result = artifact["result"]
    assert artifact["status"] == "NOT_RUN"
    assert result["gate_id"] == "LV-NIGHTLY"
    assert result["status"] == "NOT_RUN"
    assert result["data_source"] == "nightly_client"
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    assert result["inputs_manifest_sha256"] == manifest_sha256(raw)
    assert result["service_sha"] == "a" * 40
    assert result["results"]["nightly"]["status"] == "NOT_RUN"
    assert "checked_at" in result
    assert result["commands"]


def test_cli_uses_nightly_collector_constructed_from_client_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import scripts.staging_golden as staging_cli

    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(_nightly_manifest()) + "\n", encoding="utf-8")
    evidence = tmp_path / "evidence.json"
    client_config = tmp_path / "clients.json"
    client_config.write_text(
        json.dumps(
            {
                "source_profile": "qualification-source",
                "role_arn": "arn:aws:iam::123456789012:role/qualification",
                "account_id": "123456789012",
                "region": "eu-central-1",
                "cluster": "qualification",
                "service_name": "synthetic-staging",
                "app_container_name": "ai-soc",
                "nightly": {
                    "factory": "qualification.collectors:build_nightly_client",
                    "options": {"dataset": "nightly"},
                },
            }
        ),
        encoding="utf-8",
    )

    class _Client:
        def collect_case_results(self) -> NightlyResultsReport:
            return _nightly_report(
                (
                    NightlyCaseInput(
                        case_id="G001",
                        language="en",
                        outcome="completed",
                        route_matches=True,
                        evidence_refs=(
                            EvidenceReference(EvidenceKind.FILE_SHA256, "nightly/G001", "f" * 64),
                        ),
                    ),
                )
            )

    def _build(config):
        assert config.nightly is not None
        assert config.nightly.factory == "qualification.collectors:build_nightly_client"
        return SimpleNamespace(
            observer=_Observer(), clients=object(), nightly=_Client(), network=None
        )

    monkeypatch.setattr(staging_cli, "build_explicit_staging_aws", _build)
    assert (
        main(
            [
                "--manifest",
                str(manifest),
                "--evidence",
                str(evidence),
                "--clients-config",
                str(client_config),
            ]
        )
        == 2
    )
    assert json.loads(evidence.read_text(encoding="utf-8"))["result"]["status"] == "NOT_RUN"


def test_nightly_passing_observation_without_evidence_cannot_pass(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(_nightly_manifest()) + "\n", encoding="utf-8")
    evidence = tmp_path / "evidence.json"
    valid = _nightly_report(
        (
            NightlyCaseInput(
                case_id="G001",
                language="en",
                outcome="completed",
                route_matches=True,
                evidence_refs=(EvidenceReference(EvidenceKind.FILE_SHA256, "case/G001", "f" * 64),),
            ),
        )
    )
    rows = tuple(
        replace(row, evidence_refs=()) if row.obligation_id == "nightly_usage_cost" else row
        for row in valid.obligations
    )

    class _Client:
        def collect_case_results(self) -> NightlyResultsReport:
            return replace(valid, obligations=rows)

    assert (
        main(
            ["--manifest", str(manifest), "--evidence", str(evidence)],
            clients=_clients(nightly=_Client()),
        )
        == 2
    )
    result = json.loads(evidence.read_text(encoding="utf-8"))["result"]
    row = next(
        item for item in result["obligations"] if item["obligation_id"] == "nightly_usage_cost"
    )
    assert result["status"] == "NOT_RUN"
    assert row["status"] == "NOT_RUN"


def test_nightly_reported_failure_is_not_overwritten_by_derived_pass(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(_nightly_manifest()) + "\n", encoding="utf-8")
    evidence = tmp_path / "evidence.json"
    valid = _nightly_report(
        (
            NightlyCaseInput(
                case_id="G001",
                language="en",
                outcome="completed",
                route_matches=True,
                evidence_refs=(EvidenceReference(EvidenceKind.FILE_SHA256, "case/G001", "f" * 64),),
            ),
        )
    )
    rows = (
        *valid.obligations,
        ObligationResult(
            "nightly_drop_alarm",
            ObligationStatus.FAIL,
            "observed alarm",
            (EvidenceReference(EvidenceKind.FILE_SHA256, "nightly/alarm", "4" * 64),),
        ),
    )

    class _Client:
        def collect_case_results(self) -> NightlyResultsReport:
            return replace(valid, obligations=rows)

    assert (
        main(
            ["--manifest", str(manifest), "--evidence", str(evidence)],
            clients=_clients(nightly=_Client()),
        )
        == 1
    )
    result = json.loads(evidence.read_text(encoding="utf-8"))["result"]
    row = next(
        item for item in result["obligations"] if item["obligation_id"] == "nightly_drop_alarm"
    )
    assert result["status"] == "FAIL"
    assert row["status"] == "FAIL"
    assert row["detail"] == "observed alarm"


@pytest.mark.parametrize("malformation", ("duplicate", "unknown"))
def test_nightly_duplicate_or_unknown_obligation_records_fail(
    tmp_path: Path, malformation: str
) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(_nightly_manifest()) + "\n", encoding="utf-8")
    evidence = tmp_path / "evidence.json"
    valid = _nightly_report(
        (
            NightlyCaseInput(
                case_id="G001",
                language="en",
                outcome="completed",
                route_matches=True,
                evidence_refs=(EvidenceReference(EvidenceKind.FILE_SHA256, "case/G001", "f" * 64),),
            ),
        )
    )
    extra = (
        valid.obligations[0]
        if malformation == "duplicate"
        else ObligationResult(
            "unregistered_metric",
            ObligationStatus.PASS,
            "unexpected",
            valid.obligations[0].evidence_refs,
        )
    )

    class _Client:
        def collect_case_results(self) -> NightlyResultsReport:
            return replace(valid, obligations=(*valid.obligations, extra))

    assert (
        main(
            ["--manifest", str(manifest), "--evidence", str(evidence)],
            clients=_clients(nightly=_Client()),
        )
        == 1
    )
    result = json.loads(evidence.read_text(encoding="utf-8"))["result"]
    assert result["status"] == "FAIL"
    key = "duplicate_obligations" if malformation == "duplicate" else "unknown_obligations"
    assert result["results"]["nightly"][key]


def test_nightly_missing_metric_rows_and_gp3_trace_keep_acceptances_not_run(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(_nightly_manifest()) + "\n", encoding="utf-8")
    evidence = tmp_path / "evidence.json"

    class _Client:
        def collect_case_results(self) -> NightlyResultsReport:
            return NightlyResultsReport(
                binding=_binding(),
                cases=(
                    NightlyCaseInput(
                        case_id="G001",
                        language="en",
                        outcome="completed",
                        route_matches=True,
                        evidence_refs=(
                            EvidenceReference(EvidenceKind.FILE_SHA256, "case/G001", "f" * 64),
                        ),
                    ),
                ),
                obligations=(
                    ObligationResult(
                        "gp3_stage_evidence",
                        ObligationStatus.PASS,
                        "stage evidence exists but trace is missing",
                        (EvidenceReference(EvidenceKind.FILE_SHA256, "nightly/stage", "1" * 64),),
                    ),
                ),
            )

    assert (
        main(
            ["--manifest", str(manifest), "--evidence", str(evidence)],
            clients=_clients(nightly=_Client()),
        )
        == 2
    )
    result = json.loads(evidence.read_text(encoding="utf-8"))["result"]
    assert result["status"] == "NOT_RUN"
    assert all(
        row["status"] == "NOT_RUN"
        for row in result["obligations"]
        if row["obligation_id"]
        in {
            "nightly_usage_cost",
            "nightly_usage_latency",
            "nightly_cache_behavior",
            "nightly_missing_run_behavior",
        }
    )
    assert result["acceptance_results"][0]["status"] == "NOT_RUN"


def test_lv_nightly_without_results_stays_not_run(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(_nightly_manifest()) + "\n", encoding="utf-8")
    evidence = tmp_path / "evidence.json"

    assert main(["--manifest", str(manifest), "--evidence", str(evidence)], clients=_clients()) == 2
    artifact = json.loads(evidence.read_text(encoding="utf-8"))
    assert artifact["status"] == "NOT_RUN"
    assert artifact["result"]["gate_id"] == "LV-NIGHTLY"
    assert "no configured nightly results client" in artifact["result"]["results"]["reason"]


def test_default_runner_evidence_path_is_unique_per_invocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts import staging_golden

    monkeypatch.setattr(staging_golden, "ROOT", tmp_path)
    config = tmp_path / "config"
    config.mkdir()
    manifest = config / "staging-validation.json"
    manifest.write_text(json.dumps(_nightly_manifest()) + "\n", encoding="utf-8")

    assert staging_golden.main(["--manifest", "config/staging-validation.json"]) == 2
    assert staging_golden.main(["--manifest", "config/staging-validation.json"]) == 2
    evidence = sorted((tmp_path / "build/evidence/live").glob("*/LV-NIGHTLY.json"))
    assert len(evidence) == 2
    assert evidence[0] != evidence[1]


def test_unregistered_gate_never_passes_without_adapter(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    document = {
        "schema_version": "3",
        "gate_id": "LV-PLATFORM",
        "acceptance_ids": [],
        "owners": ["platform provisioner"],
        "artifacts": _example_artifacts(),
        "expected_deployment": _expected_deployment(),
        "commands": ["make staging-golden"],
        "inputs": {},
    }
    manifest.write_text(json.dumps(document) + "\n", encoding="utf-8")
    evidence = tmp_path / "evidence.json"

    assert main(["--manifest", str(manifest), "--evidence", str(evidence)]) == 2
    artifact = json.loads(evidence.read_text(encoding="utf-8"))
    assert artifact["status"] == "NOT_RUN"
    assert artifact["result"]["status"] == "NOT_RUN"
    assert artifact["result"]["status"] != "PASS"


def test_lv_network_uses_injected_probe_client(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    document = {
        "schema_version": "3",
        "gate_id": "LV-NETWORK",
        "acceptance_ids": ["GP4"],
        "owners": ["network owner"],
        "artifacts": _example_artifacts(),
        "expected_deployment": _expected_deployment(),
        "commands": ["make staging-golden"],
        "inputs": {
            "network": {
                "environment_id": "alpha",
                "hostname": "alpha.private.example.test",
                "secret_id": "arn:aws:secretsmanager:us-east-1:123456789012:secret:alpha",
                "secret_version": "version-alpha",
                "ca_sha256": "e" * 64,
                "indexer_origin": "https://alpha.private.example.test:9200",
            }
        },
    }
    manifest.write_text(json.dumps(document) + "\n", encoding="utf-8")
    evidence = tmp_path / "evidence.json"

    class _Client:
        def probe_network(self, spec: NetworkGateInput):
            assert spec.environment_id == "alpha"
            return _network_report(evidence_ref="evidence/network-alpha")

    assert (
        main(
            ["--manifest", str(manifest), "--evidence", str(evidence)],
            clients=_clients(network=_Client()),
        )
        == 2
    )
    artifact = json.loads(evidence.read_text(encoding="utf-8"))
    assert artifact["status"] == "NOT_RUN"
    obligations = artifact["result"]["results"]["network"]["obligations"]
    assert len(obligations) == 7
    assert all(row["status"] == "NOT_RUN" for row in obligations)
    assert all(not row["evidence_refs"] for row in obligations)


def test_lv_network_requires_every_configured_site_and_gp4_evidence(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    document = {
        "schema_version": "3",
        "gate_id": "LV-NETWORK",
        "acceptance_ids": ["GP4"],
        "owners": ["network owner"],
        "artifacts": _example_artifacts(),
        "expected_deployment": _expected_deployment(),
        "commands": ["make staging-golden"],
        "inputs": {
            "network": [
                {
                    "environment_id": site,
                    "hostname": f"{site}.private.example.test",
                    "secret_id": f"arn:aws:secretsmanager:eu-central-1:123456789012:secret:{site}",
                    "secret_version": f"version-{site}",
                    "ca_sha256": "e" * 64,
                    "indexer_origin": f"https://{site}.private.example.test:9200",
                }
                for site in ("alpha", "beta")
            ]
        },
    }
    manifest.write_text(json.dumps(document) + "\n", encoding="utf-8")
    evidence = tmp_path / "evidence.json"

    class _Client:
        def probe_network(self, spec: NetworkGateInput) -> NetworkProbeReport:
            return _network_report(
                site_id=spec.environment_id,
                evidence_ref=f"evidence/{spec.environment_id}",
            )

    assert (
        main(
            ["--manifest", str(manifest), "--evidence", str(evidence)],
            clients=_clients(network=_Client()),
        )
        == 2
    )
    artifact = json.loads(evidence.read_text(encoding="utf-8"))
    assert artifact["result"]["results"]["network"]["observed_site_ids"] == ["alpha", "beta"]
    gp4 = artifact["result"]["acceptance_results"][0]
    assert gp4["status"] == "NOT_RUN"
    assert gp4["obligation"]["obligation_id"] == "GP4"
    assert len(gp4["evidence_refs"]) == 0

    missing_site_evidence = tmp_path / "missing-site.json"

    class _MissingSiteClient:
        def probe_network(self, spec: NetworkGateInput) -> NetworkProbeReport:
            return _network_report(site_id="alpha", evidence_ref=f"evidence/{spec.environment_id}")

    assert (
        main(
            ["--manifest", str(manifest), "--evidence", str(missing_site_evidence)],
            clients=_clients(network=_MissingSiteClient()),
        )
        == 1
    )
    missing_site = json.loads(missing_site_evidence.read_text(encoding="utf-8"))["result"]
    assert missing_site["results"]["network"]["observed_site_ids"] == ["alpha", "alpha"]
    assert missing_site["acceptance_results"][0]["status"] == "FAIL"

    wrong_pin_evidence = tmp_path / "wrong-pin.json"

    class _WrongPinClient:
        def probe_network(self, spec: NetworkGateInput) -> NetworkProbeReport:
            report = _network_report(site_id=spec.environment_id)
            rows = tuple(
                replace(row, status=ObligationStatus.FAIL)
                if row.obligation_id == "gp4_wrong_pin_denied"
                else row
                for row in report.obligations
            )
            return replace(report, obligations=rows)

    assert (
        main(
            ["--manifest", str(manifest), "--evidence", str(wrong_pin_evidence)],
            clients=_clients(network=_WrongPinClient()),
        )
        == 1
    )
    wrong_pin = json.loads(wrong_pin_evidence.read_text(encoding="utf-8"))["result"]
    assert wrong_pin["acceptance_results"][0]["status"] == "FAIL"


def test_lv_network_missing_obligation_remains_not_run(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    document = {
        "schema_version": "3",
        "gate_id": "LV-NETWORK",
        "acceptance_ids": ["GP4"],
        "owners": ["network owner"],
        "artifacts": _example_artifacts(),
        "expected_deployment": _expected_deployment(),
        "commands": ["make staging-golden"],
        "inputs": {
            "network": {
                "environment_id": "alpha",
                "hostname": "alpha.private.example.test",
                "secret_id": "arn:aws:secretsmanager:us-east-1:123456789012:secret:alpha",
                "secret_version": "version-alpha",
                "ca_sha256": "e" * 64,
                "indexer_origin": "https://alpha.private.example.test:9200",
            }
        },
    }
    manifest.write_text(json.dumps(document) + "\n", encoding="utf-8")
    evidence = tmp_path / "evidence.json"

    class _Client:
        def probe_network(self, spec: NetworkGateInput):
            assert spec.environment_id == "alpha"
            report = _network_report(evidence_ref="evidence/network-alpha")
            return type(report)(
                binding=report.binding, site_id=report.site_id, obligations=report.obligations[:2]
            )

    assert (
        main(
            ["--manifest", str(manifest), "--evidence", str(evidence)],
            clients=_clients(network=_Client()),
        )
        == 2
    )
    artifact = json.loads(evidence.read_text(encoding="utf-8"))
    assert artifact["status"] == "NOT_RUN"
    assert artifact["result"]["status"] == "NOT_RUN"
    assert "bedrock_invoke_via_vpce_allowed" in artifact["result"]["results"]["reason"]
    obligations = artifact["result"]["results"]["network"]["obligations"]
    assert [row["status"] for row in obligations] == [
        "NOT_RUN",
        "NOT_RUN",
        "NOT_RUN",
        "NOT_RUN",
        "NOT_RUN",
        "NOT_RUN",
        "NOT_RUN",
    ]


def test_lv_network_duplicate_observations_keep_fail_and_every_evidence_ref(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "manifest.json"
    document = {
        "schema_version": "3",
        "gate_id": "LV-NETWORK",
        "acceptance_ids": ["GP4"],
        "owners": ["network owner"],
        "artifacts": _example_artifacts(),
        "expected_deployment": _expected_deployment(),
        "commands": ["make staging-golden"],
        "inputs": {
            "network": {
                "environment_id": "alpha",
                "hostname": "alpha.private.example.test",
                "secret_id": "arn:aws:secretsmanager:us-east-1:123456789012:secret:alpha",
                "secret_version": "version-alpha",
                "ca_sha256": "e" * 64,
                "indexer_origin": "https://alpha.private.example.test:9200",
            }
        },
    }
    manifest.write_text(json.dumps(document) + "\n", encoding="utf-8")
    evidence = tmp_path / "evidence.json"

    class _Client:
        def probe_network(self, spec: NetworkGateInput) -> NetworkProbeReport:
            assert spec.environment_id == "alpha"
            report = _network_report(evidence_ref="evidence/network-alpha")
            duplicate_fail = ObligationResult(
                obligation_id=report.obligations[0].obligation_id,
                status=ObligationStatus.FAIL,
                detail="first probe failed",
                evidence_refs=(
                    EvidenceReference(EvidenceKind.FILE_SHA256, "network-alpha-failed", "1" * 64),
                ),
            )
            duplicate_pass = ObligationResult(
                obligation_id=report.obligations[0].obligation_id,
                status=ObligationStatus.PASS,
                detail="later probe passed",
                evidence_refs=(
                    EvidenceReference(EvidenceKind.FILE_SHA256, "network-alpha-retried", "2" * 64),
                ),
            )
            return NetworkProbeReport(
                binding=_binding(),
                site_id="alpha",
                obligations=(
                    duplicate_fail,
                    duplicate_pass,
                    *report.obligations[1:],
                ),
            )

    assert (
        main(
            ["--manifest", str(manifest), "--evidence", str(evidence)],
            clients=_clients(network=_Client()),
        )
        == 1
    )
    artifact = json.loads(evidence.read_text(encoding="utf-8"))
    assert artifact["status"] == "FAIL"
    obligations = artifact["result"]["results"]["network"]["obligations"]
    assert [row["status"] for row in obligations] == [
        "FAIL",
        "NOT_RUN",
        "NOT_RUN",
        "NOT_RUN",
        "NOT_RUN",
        "NOT_RUN",
        "NOT_RUN",
    ]
    assert obligations[0]["evidence_refs"][0]["identifier"] == "network-alpha-failed"
    assert obligations[0]["evidence_refs"][1]["identifier"] == "network-alpha-retried"


def test_lv_nightly_client_wires_evaluate_nightly(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(_nightly_manifest()) + "\n", encoding="utf-8")
    evidence = tmp_path / "evidence.json"

    class _Client:
        def collect_case_results(self) -> NightlyResultsReport:
            return _nightly_report(
                (
                    NightlyCaseInput(
                        case_id="G001",
                        language="en",
                        outcome="completed",
                        route_matches=True,
                        evidence_refs=(
                            EvidenceReference(EvidenceKind.FILE_SHA256, "nightly/G001", "f" * 64),
                        ),
                    ),
                )
            )

    assert (
        main(
            ["--manifest", str(manifest), "--evidence", str(evidence)],
            clients=_clients(nightly=_Client()),
        )
        == 2
    )
    artifact = json.loads(evidence.read_text(encoding="utf-8"))
    assert artifact["result"]["results"]["nightly"]["routed_correctly"] == 1


def test_manifest_secret_fields_fail_closed(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    document = _nightly_manifest(
        results=[
            {
                "case_id": "G001",
                "language": "en",
                "outcome": "completed",
                "route_matches": True,
            }
        ]
    )
    document["client_secret"] = "not-allowed"
    manifest.write_text(json.dumps(document) + "\n", encoding="utf-8")
    evidence = tmp_path / "evidence.json"

    assert main(["--manifest", str(manifest), "--evidence", str(evidence)]) == 1
    artifact = json.loads(evidence.read_text(encoding="utf-8"))
    assert artifact["status"] == "FAIL"
    assert "forbidden key" in artifact["reason"]


def test_lv_platform_guard_rejects_pass_without_adapter(tmp_path: Path) -> None:
    """Regression guard: unregistered gates must not report PASS."""
    manifest = tmp_path / "manifest.json"
    document = {
        "schema_version": "3",
        "gate_id": "LV-PLATFORM",
        "acceptance_ids": [],
        "owners": ["platform provisioner"],
        "artifacts": _example_artifacts(),
        "expected_deployment": _expected_deployment(),
        "commands": ["make staging-golden"],
        "inputs": {},
    }
    manifest.write_text(json.dumps(document) + "\n", encoding="utf-8")
    evidence = tmp_path / "evidence.json"
    assert main(["--manifest", str(manifest), "--evidence", str(evidence)]) == 2
    assert json.loads(evidence.read_text(encoding="utf-8"))["result"]["status"] == "NOT_RUN"
