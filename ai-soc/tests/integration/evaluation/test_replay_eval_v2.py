from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any, cast

import pytest

from ai_soc.query.compiler import default_profile
from scripts.evaluation import replay_eval as runner

ROOT = Path(__file__).resolve().parents[3]
CORPUS = ROOT / "tests" / "fixtures" / "evaluation" / "v2"
EXPECTED = cast(dict[str, Any], json.loads((CORPUS / "expected_metrics.json").read_text("utf-8")))
CODE_SHA = "a" * 40


def _assert_expected(expected: object, actual: object, path: str) -> None:
    if isinstance(expected, dict):
        assert isinstance(actual, dict), path
        observed = cast(dict[str, object], actual)
        for key, value in cast(dict[str, object], expected).items():
            assert key in observed, f"{path}.{key} is missing"
            _assert_expected(value, observed[key], f"{path}.{key}")
        extra = set(observed) - set(cast(dict[str, object], expected))
        assert not extra, f"{path} has unexpected keys {sorted(extra)}"
        return
    assert actual == expected, f"{path}: expected {expected!r}, got {actual!r}"


def _read(path: Path) -> Any:
    return json.loads(path.read_text("utf-8"))


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii")


def _copied_manifest(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    root = tmp_path / "v2"
    shutil.copytree(CORPUS, root)
    return root / "manifest.json", _read(root / "manifest.json")


def _case(manifest: dict[str, Any], case_id: str) -> dict[str, Any]:
    return next(case for case in manifest["cases"] if case["case_id"] == case_id)


def _refresh_case_hash(root: Path, manifest: dict[str, Any], case_id: str) -> None:
    case = _case(manifest, case_id)
    input_path = root / case["input_path"]
    case["input_sha256"] = hashlib.sha256(input_path.read_bytes()).hexdigest()
    if case["stage"] == "source":
        case["responses"] = _read(input_path)["responses"]
    if case["partition"] == "holdout":
        lock_path = root / "holdout.lock"
        entries = {}
        for line in lock_path.read_text("ascii").splitlines():
            digest, _, relative = line.partition("  ")
            entries[relative] = digest
        entries[case["input_path"]] = case["input_sha256"]
        lock_path.write_text(
            "".join(f"{digest}  {path}\n" for path, digest in sorted(entries.items())),
            encoding="ascii",
        )


@pytest.fixture(scope="module")
def v2_run_report(tmp_path_factory: pytest.TempPathFactory) -> runner.RunOutput:
    out = tmp_path_factory.mktemp("v2-report") / "report"
    return runner.run_replay(CORPUS / "manifest.json", out, code_sha=CODE_SHA)


def test_v2_corpus_reproduces_hand_computed_pack_classes(v2_run_report: runner.RunOutput) -> None:
    pack = cast(dict[str, Any], v2_run_report.report["pack"])
    _assert_expected(EXPECTED["pack"]["per_case"], pack["per_case"], "pack.per_case")


def test_v2_corpus_reproduces_hand_computed_pack_metrics(
    v2_run_report: runner.RunOutput,
) -> None:
    expected = dict(EXPECTED["pack"])
    expected.pop("per_case")
    actual = dict(cast(dict[str, Any], v2_run_report.report["pack"]))
    actual.pop("per_case")
    actual.pop("model_calls")
    _assert_expected(expected, actual, "pack")


def test_v2_source_metrics_match_expected(v2_run_report: runner.RunOutput) -> None:
    actual = cast(dict[str, Any], v2_run_report.report["source"])
    expected = dict(EXPECTED["source"])
    expected_cases = expected.pop("per_case")
    actual_metrics = dict(actual)
    actual_cases = cast(dict[str, list[dict[str, Any]]], actual_metrics.pop("per_case"))
    _assert_expected(expected, actual_metrics, "source")
    corpus = runner.load_corpus(CORPUS / "manifest.json", code_sha=CODE_SHA)
    case_summary = {
        case_id: {
            "observation_fields": list(
                dict.fromkeys(observation["field"] for observation in observations)
            ),
            "outcome": corpus.labels[case_id].outcome,
        }
        for case_id, observations in actual_cases.items()
    }
    _assert_expected(expected_cases, case_summary, "source.per_case")


def test_v2_topic_sections_include_pack_rates_with_counts(v2_run_report: runner.RunOutput) -> None:
    report = cast(dict[str, Any], v2_run_report.report["pack"])
    assert report["all"]["cases"]["attack"] == 7
    assert report["auth_review"]["cases"]["attack"] == 4
    assert report["vuln_review"]["cases"]["attack"] == 3
    for topic_id in ("auth_review", "vuln_review"):
        assert topic_id in report
        topic = report[topic_id]
        for comparator in topic["metrics"].values():
            for metric in comparator.values():
                if isinstance(metric, dict) and "rate" in metric:
                    assert "numerator" in metric and "denominator" in metric


def test_v2_empty_cohort_rate_is_null() -> None:
    assert runner._rate(0, 0) == {
        "numerator": 0,
        "denominator": 0,
        "rate": None,
        "status": "empty_cohort",
    }


def test_v2_source_check_outcome_missing_and_extra_are_mismatches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    corpus = runner.load_corpus(CORPUS / "manifest.json", code_sha=CODE_SHA)
    case = next(item for item in corpus.source_cases() if item.case_id == "source_auth_10")
    original = runner._score_source
    profile = default_profile(runner.MAPPING_PROFILE_ID)
    checked = {"outcome": False, "missing": False, "extra": False}

    def inspect(expected: runner.Observations, answer: runner.Answer, topic_id: str):
        changed = answer.model_copy(deep=True)
        topic = changed.blocks[0]
        if not checked["outcome"]:
            topic.checks[0] = topic.checks[0].model_copy(update={"outcome": "failed"})
            mismatch = [item for item in original(expected, changed, topic_id) if not item.matched]
            assert any(item.field == "checks" for item in mismatch)
            checked["outcome"] = True
        changed = answer.model_copy(deep=True)
        changed.blocks[0].checks.pop()
        mismatch = [item for item in original(expected, changed, topic_id) if not item.matched]
        assert any(item.field == "checks" and item.observed == "absent" for item in mismatch)
        checked["missing"] = True
        changed = answer.model_copy(deep=True)
        check = changed.blocks[0].checks[0].model_copy(update={"check_id": "extra_check"})
        changed.blocks[0].checks.append(check)
        mismatch = [item for item in original(expected, changed, topic_id) if not item.matched]
        assert any(item.field == "checks" and item.expected == "absent" for item in mismatch)
        checked["extra"] = True
        return original(expected, answer, topic_id)

    monkeypatch.setattr(runner, "_score_source", inspect)
    asyncio.run(runner.run_source_case(corpus, case, profile, runner.STANDING_RULES))
    assert all(checked.values())


def test_v2_duplicate_source_check_is_an_extra_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    corpus = runner.load_corpus(CORPUS / "manifest.json", code_sha=CODE_SHA)
    case = next(item for item in corpus.source_cases() if item.case_id == "source_auth_10")
    original = runner._score_source
    checked = False

    def inspect(expected: runner.Observations, answer: runner.Answer, topic_id: str):
        changed = answer.model_copy(deep=True)
        check = changed.blocks[0].checks[0]
        changed.blocks[0].checks[0] = check.model_copy(update={"outcome": "failed"})
        changed.blocks[0].checks.append(check)
        mismatches = [item for item in original(expected, changed, topic_id) if not item.matched]
        assert any(item.field == "checks" and item.expected == "absent" for item in mismatches)
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


def test_v2_wrong_source_topic_is_a_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    corpus = runner.load_corpus(CORPUS / "manifest.json", code_sha=CODE_SHA)
    case = next(item for item in corpus.source_cases() if item.case_id == "source_auth_10")
    original = runner._score_source
    checked = False

    def inspect(expected: runner.Observations, answer: runner.Answer, topic_id: str):
        changed = answer.model_copy(deep=True)
        original_block = changed.blocks[0]
        block = original_block.model_copy(
            update={
                "topic_id": "vuln_review",
                "tables": [
                    table.model_copy(update={"topic_id": "vuln_review"})
                    for table in original_block.tables
                ],
                "checks": [
                    check.model_copy(update={"topic_id": "vuln_review"})
                    for check in original_block.checks
                ],
            }
        )
        changed.blocks[0] = block
        assert topic_id == "auth_review"
        mismatches = [item for item in original(expected, changed, topic_id) if not item.matched]
        assert any(item.field == "topic" for item in mismatches)
        nonlocal checked
        checked = True
        return original(expected, answer, topic_id)

    monkeypatch.setattr(runner, "_score_source", inspect)
    result = asyncio.run(
        runner.run_source_case(
            corpus,
            case,
            default_profile(runner.MAPPING_PROFILE_ID),
            runner.STANDING_RULES,
        )
    )
    assert checked
    assert result.topic_id == "auth_review"


def test_v2_missing_source_field_does_not_match_explicit_null(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    corpus = runner.load_corpus(CORPUS / "manifest.json", code_sha=CODE_SHA)
    case = next(item for item in corpus.source_cases() if item.case_id == "source_missing_field")
    original = runner._score_source
    checked = False

    def inspect(expected: runner.Observations, answer: runner.Answer, topic_id: str):
        row = next(
            row for values in expected.rows.values() for row in values if None in row.values()
        )
        field_name = next(name for name, value in row.items() if value is None)
        changed = answer.model_copy(deep=True)
        found = False
        for block in changed.blocks:
            for table in block.tables:
                for index, actual_row in enumerate(table.rows):
                    field_key = next(
                        (key for key in actual_row.values if str(key) == field_name), None
                    )
                    if field_key is not None and actual_row.values[field_key] is None:
                        values = dict(actual_row.values)
                        values.pop(field_key)
                        table.rows[index] = actual_row.model_copy(update={"values": values})
                        found = True
                        break
                if found:
                    break
            if found:
                break
        assert found
        mismatches = [item for item in original(expected, changed, topic_id) if not item.matched]
        assert any(item.key.endswith(f".{field_name}") for item in mismatches)
        literal_rows = {key: [dict(row) for row in value] for key, value in expected.rows.items()}
        next(row for value in literal_rows.values() for row in value if field_name in row)[
            field_name
        ] = "missing"
        literal = expected.model_copy(update={"rows": literal_rows})
        mismatches = [item for item in original(literal, changed, topic_id) if not item.matched]
        assert any(item.key.endswith(f".{field_name}") for item in mismatches)
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


def test_v2_declared_row_cardinality_must_match_complete_label_rows(tmp_path: Path) -> None:
    manifest_path, manifest = _copied_manifest(tmp_path)
    root = manifest_path.parent
    labels = _read(root / "labels.json")
    label = next(
        item for item in labels["labels"] if item["expected_observations"].get("row_cardinality")
    )
    case_id = label["case_id"]
    fetch_id = next(iter(label["expected_observations"]["row_cardinality"]))
    label["expected_observations"]["row_cardinality"][fetch_id] += 1
    _write(root / "labels.json", labels)
    with pytest.raises(runner.CorpusError, match=case_id):
        runner.load_corpus(manifest_path, code_sha=CODE_SHA)


def test_v2_source_extra_row_and_wrong_typed_values_are_mismatches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    corpus = runner.load_corpus(CORPUS / "manifest.json", code_sha=CODE_SHA)
    case = next(item for item in corpus.source_cases() if item.case_id == "source_auth_10")
    original = runner._score_source
    profile = default_profile(runner.MAPPING_PROFILE_ID)
    checked: set[str] = set()

    def inspect(expected: runner.Observations, answer: runner.Answer, topic_id: str):
        nullable_rows = {key: [dict(row) for row in value] for key, value in expected.rows.items()}
        nullable_field = next(
            (
                field
                for row in nullable_rows.get("auth_rows", [])
                for field, value in row.items()
                if value is None
            ),
            None,
        )
        if nullable_field is not None:
            nullable_rows["auth_rows"][0][nullable_field] = "present"
            altered = expected.model_copy(update={"rows": nullable_rows})
            mismatch = [item for item in original(altered, answer, topic_id) if not item.matched]
            assert any(
                item.key.endswith(f".{nullable_field}")
                and item.expected == "present"
                and item.observed is None
                for item in mismatch
            )
            checked.add("null")
            return original(expected, answer, topic_id)

        changed = answer.model_copy(deep=True)
        table = next(table for block in changed.blocks for table in block.tables if table.rows)
        table.rows.append(table.rows[0].model_copy(deep=True))
        mismatch = [item for item in original(expected, changed, topic_id) if not item.matched]
        assert any(item.field == "rows" and item.key.endswith(".cardinality") for item in mismatch)
        checked.add("extra_row")

        rows = {key: [dict(row) for row in value] for key, value in expected.rows.items()}
        row = rows["auth_rows"][0]
        assert type(row["rule.level"]) is int
        row["rule.level"] = 9
        altered = expected.model_copy(update={"rows": rows})
        level_table = next(table for block in answer.blocks for table in block.tables if table.rows)
        actual_values = dict(level_table.rows[0].values)
        level_key = next(key for key in actual_values if str(key) == "rule.level")
        actual_values[level_key] = 10
        changed_answer = answer.model_copy(deep=True)
        changed_table = next(
            table for block in changed_answer.blocks for table in block.tables if table.rows
        )
        changed_table.rows[0] = changed_table.rows[0].model_copy(update={"values": actual_values})
        mismatch = [
            item for item in original(altered, changed_answer, topic_id) if not item.matched
        ]
        assert any(item.key.endswith(".rule.level") for item in mismatch)
        checked.add("integer")

        string_rows = {key: [dict(row) for row in value] for key, value in expected.rows.items()}
        string_rows["auth_rows"][0]["rule.level"] = str(string_rows["auth_rows"][0]["rule.level"])
        string_typed_expected = expected.model_copy(update={"rows": string_rows})
        mismatch = [
            item for item in original(string_typed_expected, answer, topic_id) if not item.matched
        ]
        assert any(item.key.endswith(".rule.level") for item in mismatch)
        checked.add("type")

        return original(expected, answer, topic_id)

    monkeypatch.setattr(runner, "_score_source", inspect)
    asyncio.run(runner.run_source_case(corpus, case, profile, runner.STANDING_RULES))
    missing_case = next(
        item for item in corpus.source_cases() if item.case_id == "source_missing_field"
    )
    asyncio.run(runner.run_source_case(corpus, missing_case, profile, runner.STANDING_RULES))
    assert checked == {"extra_row", "integer", "type", "null"}


@pytest.mark.parametrize(
    ("case_id", "field_name"),
    [
        ("vuln_critical_exploited", "vulnerability.detected_at"),
        ("source_vuln_critical", "detected_at"),
    ],
)
def test_v2_future_vulnerability_detection_is_fatal(
    tmp_path: Path, case_id: str, field_name: str
) -> None:
    manifest_path, manifest = _copied_manifest(tmp_path)
    root = manifest_path.parent
    case = _case(manifest, case_id)
    input_path = root / case["input_path"]
    data = _read(input_path)

    def update_timestamp(value: object) -> bool:
        if isinstance(value, dict):
            for key, child in list(value.items()):
                if key == field_name:
                    value[key] = "2026-10-18T13:00:00.000000Z"
                    return True
                if update_timestamp(child):
                    return True
        elif isinstance(value, list):
            for child in value:
                if update_timestamp(child):
                    return True
        return False

    assert update_timestamp(data)
    _write(input_path, data)
    _refresh_case_hash(root, manifest, case_id)
    _write(manifest_path, manifest)
    with pytest.raises(runner.CorpusError, match="data timestamp after as_of"):
        runner.load_corpus(manifest_path, code_sha=CODE_SHA)
