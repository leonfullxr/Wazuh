from __future__ import annotations

import asyncio
import copy
import dataclasses
import hashlib
import json
import shutil
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import pytest

from ai_soc.contracts.models import CheckOutcome, CheckResult
from ai_soc.query.compiler import default_profile
from scripts.evaluation import replay_eval as runner

ROOT = Path(__file__).resolve().parents[3]
CORPUS = ROOT / "tests" / "fixtures" / "evaluation" / "v3"
EXPECTED = cast(dict[str, Any], json.loads((CORPUS / "expected_metrics.json").read_text("utf-8")))
CODE_SHA = "a" * 40


def _assert_expected(expected: object, actual: object, path: str) -> None:
    if isinstance(expected, dict):
        assert isinstance(actual, dict), path
        expected_map = cast(dict[str, object], expected)
        actual_map = cast(dict[str, object], actual)
        for key, value in expected_map.items():
            assert key in actual_map, f"{path}.{key} is missing"
            _assert_expected(value, actual_map[key], f"{path}.{key}")
        extra = set(actual_map) - set(expected_map)
        assert not extra, f"{path} has unexpected keys {sorted(extra)}"
        return
    assert actual == expected, f"{path}: expected {expected!r}, got {actual!r}"


def _assert_pack_disclosures(
    corpus: runner.Corpus,
    results: Mapping[str, Mapping[str, runner.ComparatorResult]],
    *,
    expected_overrides: Mapping[str, Mapping[str, list[str]]] | None = None,
) -> None:
    disclosure_ids = runner._disclosure_template_ids(corpus)
    for case in corpus.pack_cases():
        label = corpus.labels[case.case_id]
        expected_by_comparator = (
            expected_overrides[case.case_id]
            if expected_overrides is not None and case.case_id in expected_overrides
            else label.expected_disclosures or {}
        )
        expected_eligible = label.expected_eligible_disclosures or {}
        for comparator in runner.COMPARATORS:
            expected = expected_by_comparator.get(comparator, [])
            rendered = sorted(
                template_id
                for template_id, _binding in results[case.case_id][comparator].rendered
                if template_id in disclosure_ids
            )
            eligible = sorted(runner._eligible_disclosures(corpus, case, comparator))
            assert rendered == expected, (
                f"{case.case_id}.{comparator}.rendered: expected {expected!r}, got {rendered!r}"
            )
            expected_eligible_ids = expected_eligible.get(comparator, [])
            assert eligible == expected_eligible_ids, (
                f"{case.case_id}.{comparator}.eligible: "
                f"expected {expected_eligible_ids!r}, got {eligible!r}"
            )


@pytest.fixture(scope="module")
def v3_corpus() -> runner.Corpus:
    return runner.load_corpus(CORPUS / "manifest.json", code_sha=CODE_SHA)


@pytest.fixture(scope="module")
def v3_pack_results(
    v3_corpus: runner.Corpus,
) -> dict[str, dict[str, runner.ComparatorResult]]:
    return asyncio.run(
        runner.run_pack_stage(
            v3_corpus,
            v3_corpus.manifest.identities,
            default_profile(runner.MAPPING_PROFILE_ID),
            runner.STANDING_RULES,
        )
    )


@pytest.fixture(scope="module")
def v3_run_report(tmp_path_factory: pytest.TempPathFactory) -> runner.RunOutput:
    output_dir = tmp_path_factory.mktemp("v3-report") / "report"
    return runner.run_replay(CORPUS / "manifest.json", output_dir, code_sha=CODE_SHA)


def test_v3_corpus_reproduces_hand_computed_pack_classes(
    v3_pack_results: dict[str, dict[str, runner.ComparatorResult]],
) -> None:
    actual = {
        case_id: {comparator: result.status() for comparator, result in results.items()}
        for case_id, results in v3_pack_results.items()
    }
    _assert_expected(EXPECTED["pack"]["per_case"], actual, "pack.per_case")


def test_v3_corpus_reproduces_hand_computed_pack_aggregates(
    v3_run_report: runner.RunOutput,
) -> None:
    expected = dict(EXPECTED["pack"])
    actual = dict(cast(dict[str, Any], v3_run_report.report["pack"]))
    actual.pop("model_calls")
    _assert_expected(expected, actual, "pack")


def test_v3_pack_aggregate_comparison_rejects_numerator_mutation(
    v3_run_report: runner.RunOutput,
) -> None:
    expected = dict(EXPECTED["pack"])
    actual_pack = copy.deepcopy(cast(dict[str, Any], v3_run_report.report["pack"]))
    actual_pack.pop("model_calls")
    original_numerator = actual_pack["all"]["counts"]["D"]["tp"]
    actual_pack["all"]["counts"]["D"]["tp"] -= 1
    with pytest.raises(AssertionError, match="pack.all.counts.D.tp"):
        _assert_expected(expected, actual_pack, "pack")
    assert v3_run_report.report["pack"]["all"]["counts"]["D"]["tp"] == original_numerator


def test_v3_corpus_reproduces_disclosures_and_metrics(
    v3_corpus: runner.Corpus,
    v3_pack_results: dict[str, dict[str, runner.ComparatorResult]],
) -> None:
    _disclosure_case, disclosures, disclosure_cohorts = runner._disclosure_report(
        v3_corpus, v3_pack_results
    )
    _assert_expected(EXPECTED["disclosures"], disclosures, "disclosures")
    _assert_expected(
        EXPECTED["disclosure_cohorts"],
        disclosure_cohorts,
        "disclosure_cohorts",
    )
    _assert_pack_disclosures(v3_corpus, v3_pack_results)


def test_v3_disclosure_comparisons_reject_the_two_review_mutations(
    v3_corpus: runner.Corpus,
    v3_pack_results: dict[str, dict[str, runner.ComparatorResult]],
) -> None:
    case_id = "pack_recency_denied"
    expected = {
        case.case_id: dict(v3_corpus.labels[case.case_id].expected_disclosures or {})
        for case in v3_corpus.pack_cases()
    }
    expected[case_id]["M"] = []
    with pytest.raises(AssertionError, match="pack_recency_denied.M.rendered"):
        _assert_pack_disclosures(v3_corpus, v3_pack_results, expected_overrides=expected)

    moved_results = {key: dict(value) for key, value in v3_pack_results.items()}
    source_case = next(
        case.case_id
        for case in v3_corpus.pack_cases()
        if v3_corpus.labels[case.case_id].expected_disclosures
        and v3_corpus.labels[case.case_id].expected_disclosures.get("M")
    )
    target_case = next(
        case.case_id
        for case in v3_corpus.pack_cases()
        if case.case_id != source_case
        and not (v3_corpus.labels[case.case_id].expected_disclosures or {}).get("M")
    )
    source = moved_results[source_case]["M"]
    moved = next(
        finding
        for finding in source.rendered
        if finding[0] in runner._disclosure_template_ids(v3_corpus)
    )
    moved_results[source_case]["M"] = dataclasses.replace(
        source, rendered=tuple(finding for finding in source.rendered if finding != moved)
    )
    target = moved_results[target_case]["M"]
    moved_results[target_case]["M"] = dataclasses.replace(
        target, rendered=(*target.rendered, moved)
    )
    with pytest.raises(AssertionError):
        _assert_pack_disclosures(v3_corpus, moved_results)
    _assert_pack_disclosures(v3_corpus, v3_pack_results)


def test_v3_corpus_reproduces_source_metrics(v3_run_report: runner.RunOutput) -> None:
    output = v3_run_report
    source = dict(cast(dict[str, Any], output.report["source"]))
    expected = dict(EXPECTED["source"])
    expected_cases = expected.pop("per_case")
    actual_cases = source.pop("per_case")
    additions = source.pop("v3_additions")
    corpus = runner.load_corpus(CORPUS / "manifest.json", code_sha=CODE_SHA)
    _assert_expected(
        {case_id: {"outcome": value["outcome"]} for case_id, value in expected_cases.items()},
        {case_id: {"outcome": corpus.labels[case_id].outcome} for case_id in actual_cases},
        "source.per_case",
    )
    assert set(actual_cases) == {case.case_id for case in corpus.source_cases()}
    for case_id, observations in actual_cases.items():
        assert observations, case_id
        assert all(item["matched"] for item in observations), case_id
        assert any(item["field"] == "check_explanations" for item in observations) == bool(
            corpus.labels[case_id].expected_observations.check_explanations
        )
        for check_id, facts in corpus.labels[
            case_id
        ].expected_observations.check_explanations.items():
            for fact in facts:
                assert any(
                    item["field"] == "check_explanations" and item["key"] == f"{check_id}.{fact}"
                    for item in observations
                )
        for check_id in corpus.labels[case_id].expected_observations.no_check_ids:
            assert any(
                item["field"] == "no_check_ids" and item["key"] == check_id for item in observations
            )
    _assert_expected(EXPECTED["v3_additions"]["source"], additions, "source.v3_additions")
    _assert_expected(expected, source, "source")


def test_v3_source_comparisons_detect_recency_and_explanation_mutations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    corpus = runner.load_corpus(CORPUS / "manifest.json", code_sha=CODE_SHA)
    case = next(item for item in corpus.source_cases() if item.case_id == "source_age_3601")
    original = runner._score_source
    checked: set[str] = set()

    def inspect(expected: runner.Observations, answer: runner.Answer, topic_id: str):
        changed = answer.model_copy(deep=True)
        recency = next(
            check
            for block in changed.blocks
            for check in block.checks
            if str(check.check_id) == "auth_recency"
        )
        recency_index = next(
            index
            for index, check in enumerate(changed.blocks[0].checks)
            if str(check.check_id) == "auth_recency"
        )
        changed.blocks[0].checks[recency_index] = recency.model_copy(update={"outcome": "passed"})
        assert any(
            item.field == "record_age_outcomes" and not item.matched
            for item in original(expected, changed, topic_id)
        )
        checked.add("recency")

        changed = answer.model_copy(deep=True)
        recency_index = next(
            index
            for index, check in enumerate(changed.blocks[0].checks)
            if str(check.check_id) == "auth_recency"
        )
        check = changed.blocks[0].checks[recency_index]
        changed.blocks[0].checks[recency_index] = check.model_copy(
            update={"message": check.message.replace("Based on returned rows only; ", "")}
        )
        assert any(
            item.field == "check_explanations"
            and item.key == "auth_recency.returned_rows_only"
            and not item.matched
            for item in original(expected, changed, topic_id)
        )
        checked.add("explanation")
        return original(expected, answer, topic_id)

    monkeypatch.setattr(runner, "_score_source", inspect)
    result = asyncio.run(
        runner.run_source_case(
            corpus, case, default_profile(runner.MAPPING_PROFILE_ID), runner.STANDING_RULES
        )
    )
    assert checked == {"recency", "explanation"}
    assert any(item.field == "checks" and not item.matched for item in result.observations) is False


def test_every_explanation_comparison_counts_in_source_accuracy() -> None:
    corpus = runner.load_corpus(CORPUS / "manifest.json", code_sha=CODE_SHA)
    case = next(item for item in corpus.source_cases() if item.case_id == "source_age_3601")
    result = asyncio.run(
        runner.run_source_case(
            corpus, case, default_profile(runner.MAPPING_PROFILE_ID), runner.STANDING_RULES
        )
    )
    explanation_indexes = [
        index
        for index, observation in enumerate(result.observations)
        if observation.field == "check_explanations"
    ]
    assert explanation_indexes
    baseline = runner._source_block([result])["observation_accuracy"]
    for index in explanation_indexes:
        observations = list(result.observations)
        observations[index] = dataclasses.replace(observations[index], matched=False)
        changed = dataclasses.replace(result, observations=tuple(observations))
        accuracy = runner._source_block([changed])["observation_accuracy"]
        assert accuracy["denominator"] == baseline["denominator"]
        assert accuracy["numerator"] == baseline["numerator"] - 1


def test_v3_absent_checks_extra_rows_and_cardinality_are_scored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    corpus = runner.load_corpus(CORPUS / "manifest.json", code_sha=CODE_SHA)
    case = next(item for item in corpus.source_cases() if item.case_id == "source_age_3599")
    original = runner._score_source

    def add_unexpected_observations(
        expected: runner.Observations, answer: runner.Answer, topic: str
    ):
        changed = answer.model_copy(deep=True)
        table = changed.blocks[0].tables[0]
        table.rows.append(table.rows[0].model_copy(deep=True))
        changed.blocks[0].checks.append(
            CheckResult(
                check_id="unexpected_check",
                topic_id=changed.blocks[0].topic_id,
                label="synthetic",
                outcome=CheckOutcome.unknown,
                evidence_ids=[],
                message="unexpected",
            )
        )
        return original(expected, changed, topic)

    monkeypatch.setattr(runner, "_score_source", add_unexpected_observations)
    result = asyncio.run(
        runner.run_source_case(
            corpus, case, default_profile(runner.MAPPING_PROFILE_ID), runner.STANDING_RULES
        )
    )
    changed_observations = result.observations
    assert any(
        item.field == "checks" and item.expected == "absent" and not item.matched
        for item in changed_observations
    )
    assert any(
        item.field == "rows" and item.expected == "absent" and not item.matched
        for item in changed_observations
    )
    assert any(
        item.field == "rows" and item.key.endswith(".cardinality") and not item.matched
        for item in changed_observations
    )
    scored_failures = [
        item
        for item in changed_observations
        if not item.matched
        and (
            item.expected == "absent"
            or (item.field == "rows" and item.key.endswith(".cardinality"))
        )
    ]
    assert len(scored_failures) >= 3
    for observation in scored_failures:
        isolated = dataclasses.replace(
            result,
            baseline=False,
            has_v3_expectations=True,
            observations=(observation,),
        )
        isolated_accuracy = runner._source_block([isolated])["observation_accuracy"]
        assert isolated_accuracy["numerator"] == 0
        assert isolated_accuracy["denominator"] == 1
    changed = dataclasses.replace(result, observations=changed_observations)
    accuracy = runner._source_block([changed])["observation_accuracy"]
    assert accuracy["numerator"] < accuracy["denominator"]


def test_v3_absent_check_expectation_detects_present_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    corpus = runner.load_corpus(CORPUS / "manifest.json", code_sha=CODE_SHA)
    case = next(
        item for item in corpus.source_cases() if item.case_id == "source_vuln_detected_fresh"
    )
    original = runner._score_source
    checked = False

    def inspect(expected: runner.Observations, answer: runner.Answer, topic_id: str):
        changed = answer.model_copy(deep=True)
        changed.blocks[0].checks.append(
            CheckResult(
                check_id="auth_recency",
                topic_id="vuln_review",
                label="synthetic",
                outcome=CheckOutcome.unknown,
                evidence_ids=[],
                message="unexpected",
            )
        )
        mismatches = [item for item in original(expected, changed, topic_id) if not item.matched]
        assert any(
            item.field == "no_check_ids" and item.key == "auth_recency" for item in mismatches
        )
        nonlocal checked
        checked = True
        return original(expected, answer, topic_id)

    monkeypatch.setattr(runner, "_score_source", inspect)
    asyncio.run(
        runner.run_source_case(
            corpus,
            case,
            default_profile(runner.MAPPING_PROFILE_ID),
            runner.STANDING_RULES,
        )
    )
    assert checked


def test_v3_invalid_timestamp_neighbor_rows_match_the_hand_computed_oracle(
    v3_corpus: runner.Corpus,
) -> None:
    case = next(
        item for item in v3_corpus.source_cases() if item.case_id == "source_invalid_neighbors"
    )
    result = asyncio.run(
        runner.run_source_case(
            v3_corpus,
            case,
            default_profile(runner.MAPPING_PROFILE_ID),
            runner.STANDING_RULES,
        )
    )
    mismatches = [item for item in result.observations if not item.matched]
    assert mismatches == []


def test_v3_future_at_timestamp_is_fatal_even_with_malformed_rows(tmp_path: Path) -> None:
    root = tmp_path / "v3"
    shutil.copytree(CORPUS, root)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text("utf-8"))
    case = next(item for item in manifest["cases"] if item["case_id"] == "source_invalid_neighbors")
    source_path = root / case["input_path"]
    source = json.loads(source_path.read_text("utf-8"))
    search_response = next(
        item["response"] for item in source["responses"] if "hits" in item["response"]
    )
    hits = search_response["hits"]["hits"]
    assert any(
        isinstance(hit["_source"].get("@timestamp"), str)
        and hit["_source"]["@timestamp"] == "bad-time"
        for hit in hits
    )
    hits[0]["_source"]["@timestamp"] = "2026-10-18T13:00:00.000000Z"
    source_path.write_text(json.dumps(source, indent=2, sort_keys=True) + "\n", encoding="ascii")
    case["input_sha256"] = hashlib.sha256(source_path.read_bytes()).hexdigest()
    case["responses"] = source["responses"]
    lock_path = root / "holdout.lock"
    lock_entries = {
        relative: digest
        for line in lock_path.read_text("ascii").splitlines()
        for digest, _, relative in [line.partition("  ")]
    }
    lock_entries[case["input_path"]] = case["input_sha256"]
    lock_path.write_text(
        "".join(f"{digest}  {relative}\n" for relative, digest in sorted(lock_entries.items())),
        encoding="ascii",
    )
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    with pytest.raises(
        runner.CorpusError, match="data timestamp after as_of: source_invalid_neighbors"
    ):
        runner.load_corpus(manifest_path, code_sha=CODE_SHA)


def test_v3_naive_timestamp_is_skipped_by_as_of_guard(tmp_path: Path) -> None:
    root = tmp_path / "v3"
    shutil.copytree(CORPUS, root)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text("utf-8"))
    case = next(item for item in manifest["cases"] if item["case_id"] == "source_invalid_neighbors")
    source_path = root / case["input_path"]
    source = json.loads(source_path.read_text("utf-8"))
    search_response = next(
        item["response"] for item in source["responses"] if "hits" in item["response"]
    )
    search_response["hits"]["hits"][0]["_source"]["@timestamp"] = "2026-10-18T13:00:00"
    source_path.write_text(json.dumps(source, indent=2, sort_keys=True) + "\n", encoding="ascii")
    case["input_sha256"] = hashlib.sha256(source_path.read_bytes()).hexdigest()
    case["responses"] = source["responses"]
    lock_path = root / "holdout.lock"
    lock_entries = {
        relative: digest
        for line in lock_path.read_text("ascii").splitlines()
        for digest, _, relative in [line.partition("  ")]
    }
    lock_entries[case["input_path"]] = case["input_sha256"]
    lock_path.write_text(
        "".join(f"{digest}  {relative}\n" for relative, digest in sorted(lock_entries.items())),
        encoding="ascii",
    )
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    runner.load_corpus(manifest_path, code_sha=CODE_SHA)


def test_v3_manifest_source_payload_fields_are_required(tmp_path: Path) -> None:
    root = tmp_path / "v3"
    shutil.copytree(CORPUS, root)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text("utf-8"))
    case = next(item for item in manifest["cases"] if item["case_id"] == "source_age_3599")
    del case["responses"]
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    with pytest.raises(
        runner.CorpusError, match="source manifest entry differs from its file: source_age_3599"
    ):
        runner.load_corpus(manifest_path, code_sha=CODE_SHA)


def test_v3_manifest_source_payload_must_match_source_file(tmp_path: Path) -> None:
    root = tmp_path / "v3"
    shutil.copytree(CORPUS, root)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text("utf-8"))
    case = next(item for item in manifest["cases"] if item["case_id"] == "source_age_3599")
    case["responses"][0]["status"] = 201
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    with pytest.raises(
        runner.CorpusError, match="source manifest entry differs from its file: source_age_3599"
    ):
        runner.load_corpus(manifest_path, code_sha=CODE_SHA)


def test_v3_manifest_as_of_must_match_source_file(tmp_path: Path) -> None:
    root = tmp_path / "v3"
    shutil.copytree(CORPUS, root)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text("utf-8"))
    case = next(item for item in manifest["cases"] if item["case_id"] == "source_age_3599")
    case["as_of"] = "2026-10-19T12:00:00Z"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    with pytest.raises(
        runner.CorpusError, match="source manifest entry differs from its file: source_age_3599"
    ):
        runner.load_corpus(manifest_path, code_sha=CODE_SHA)


@pytest.mark.parametrize("field", ["incident_id", "entity_keys", "dedup_key"])
def test_v3_partition_overlap_is_rejected_for_every_partition_key(
    tmp_path: Path, field: str
) -> None:
    root = tmp_path / "v3"
    shutil.copytree(CORPUS, root)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text("utf-8"))
    dev = next(item for item in manifest["cases"] if item["partition"] == "dev")
    holdout = next(
        item
        for item in manifest["cases"]
        if item["partition"] == "holdout" and item.get("topic_id") is not None
    )
    holdout[field] = dev[field]
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    partition_name = {"incident_id": "incident", "entity_keys": "entity", "dedup_key": "dedup"}[
        field
    ]
    with pytest.raises(runner.CorpusError, match=f"{partition_name} shared across partitions"):
        runner.load_corpus(manifest_path, code_sha=CODE_SHA)


def test_explanation_facts_are_false_when_the_message_does_not_state_them() -> None:
    assert runner._check_explanation_facts("") == {
        "invalid_timestamp_rows": 0,
        "returned_rows_only": False,
        "approximate_total_noted": False,
        "first_page_only": False,
        "denied": False,
        "no_valid_timestamp_rows": 0,
        "no_rows_returned": False,
        "read_unavailable": False,
    }
    assert runner._check_explanation_facts("The check was denied by site authorization.")["denied"]
    assert runner._check_explanation_facts(
        "Check could not be confirmed: the source read was unavailable."
    )["read_unavailable"]
    assert (
        runner._check_explanation_facts("The total count is approximate and was not used")[
            "approximate_total_noted"
        ]
        is True
    )


def test_v3_vulnerability_topic_does_not_emit_authentication_recency_check(
    v3_corpus: runner.Corpus,
) -> None:
    case = next(item for item in v3_corpus.source_cases() if item.case_id == "source_spanish")
    result = asyncio.run(
        runner.run_source_case(
            v3_corpus,
            case,
            default_profile(runner.MAPPING_PROFILE_ID),
            runner.STANDING_RULES,
        )
    )
    mismatches = [
        item
        for item in result.observations
        if item.field == "record_age_outcomes" and not item.matched
    ]
    assert mismatches == []


@pytest.mark.parametrize(
    ("case_id", "comparator", "missing"),
    [
        ("pack_guess_stale", "M", True),
        ("pack_guess_fresh", "D+M", False),
    ],
)
def test_v3_disclosure_comparison_detects_expected_and_unexpected_rendering(
    v3_corpus: runner.Corpus,
    v3_pack_results: dict[str, dict[str, runner.ComparatorResult]],
    case_id: str,
    comparator: str,
    missing: bool,
) -> None:
    changed_results = dict(v3_pack_results)
    case_results = dict(changed_results[case_id])
    result = case_results[comparator]
    if missing:
        rendered = tuple(key for key in result.rendered if key[0] != "auth_recency_gap")
    else:
        source = v3_pack_results[case_id]["M"]
        disclosure = next(key for key in source.rendered if key[0] == "auth_recency_gap")
        rendered = (*result.rendered, disclosure)
    case_results[comparator] = dataclasses.replace(result, rendered=rendered)
    changed_results[case_id] = case_results
    disclosure_case, _metrics, _cohorts = runner._disclosure_report(v3_corpus, changed_results)
    assert not disclosure_case["per_case"][case_id][comparator]["matched"]


def test_v3_missed_expected_disclosure_is_reported(
    v3_corpus: runner.Corpus,
    v3_pack_results: dict[str, dict[str, runner.ComparatorResult]],
) -> None:
    results = dict(v3_pack_results)
    case_id = "pack_guess_stale"
    result = results[case_id]["M"]
    results[case_id]["M"] = dataclasses.replace(
        result,
        rendered=tuple(key for key in result.rendered if key[0] != "auth_recency_gap"),
    )
    per_case, metrics, _cohorts = runner._disclosure_report(v3_corpus, results)
    assert not per_case["per_case"][case_id]["M"]["matched"]
    assert metrics["M"]["missed_when_expected_and_scripted"]["numerator"] > 0


def test_disclosure_eligibility_survives_model_unavailable_result(
    v3_corpus: runner.Corpus,
    v3_pack_results: dict[str, dict[str, runner.ComparatorResult]],
) -> None:
    case_id = "pack_guess_stale"
    result = v3_pack_results[case_id]["D+M"]
    unavailable = dataclasses.replace(
        result,
        klass="failed",
        detail="model_unavailable",
        rendered=(),
        scripted_findings=(),
    )
    changed = dict(v3_pack_results)
    changed[case_id] = {**changed[case_id], "D+M": unavailable}
    per_case, metrics, _cohorts = runner._disclosure_report(v3_corpus, changed)
    assert per_case["per_case"][case_id]["D+M"]["eligible"] == ["auth_recency_gap"]
    assert metrics["D+M"]["missed_when_expected_and_scripted"]["denominator"] > 0
