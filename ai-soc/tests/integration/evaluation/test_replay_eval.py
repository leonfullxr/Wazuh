from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest

from ai_soc.query.compiler import default_profile
from scripts.evaluation import replay_eval as runner

ROOT = Path(__file__).resolve().parents[3]
CORPUS = ROOT / "tests" / "fixtures" / "evaluation" / "v1"
EXPECTED = cast(dict[str, Any], json.loads((CORPUS / "expected_metrics.json").read_text("utf-8")))
CODE_SHA = "a" * 40


@pytest.fixture(scope="module")
def committed_run(tmp_path_factory: pytest.TempPathFactory) -> runner.RunOutput:
    out = tmp_path_factory.mktemp("committed")
    return runner.run_replay(CORPUS / "manifest.json", out, code_sha=CODE_SHA)


def _assert_expected(expected: object, actual: object, path: str) -> None:
    if isinstance(expected, dict):
        mapping = cast(dict[str, object], expected)
        assert isinstance(actual, dict), path
        observed = cast(dict[str, object], actual)
        for key, value in mapping.items():
            assert key in observed, f"{path}.{key} is missing"
            if key == "by_reason":
                reasons = cast(dict[str, object], observed[key])
                for reason, count in cast(dict[str, object], value).items():
                    assert reasons[reason] == count, f"{path}.by_reason.{reason}"
                continue
            _assert_expected(value, observed[key], f"{path}.{key}")
        return
    assert actual == expected, f"{path}: expected {expected!r}, got {actual!r}"


def _rate_blocks(node: object) -> list[dict[str, object]]:
    found: list[dict[str, object]] = []
    if isinstance(node, dict):
        mapping = cast(dict[str, object], node)
        if "rate" in mapping:
            found.append(mapping)
        for child in mapping.values():
            found.extend(_rate_blocks(child))
    elif isinstance(node, list):
        for child in cast(list[object], node):
            found.extend(_rate_blocks(child))
    return found


def _copy_corpus(tmp_path: Path) -> Path:
    target = tmp_path / "v1"
    shutil.copytree(CORPUS, target)
    return target


def _read(path: Path) -> Any:
    return json.loads(path.read_text("utf-8"))


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii")


def _case(manifest: dict[str, Any], case_id: str) -> dict[str, Any]:
    return next(case for case in manifest["cases"] if case["case_id"] == case_id)


def _refresh_input_hash(root: Path, manifest: dict[str, Any], case_id: str) -> None:
    case = _case(manifest, case_id)
    case["input_sha256"] = hashlib.sha256((root / case["input_path"]).read_bytes()).hexdigest()


def _load_error(manifest_path: Path) -> str:
    with pytest.raises(runner.CorpusError) as info:
        runner.load_corpus(manifest_path, code_sha=CODE_SHA)
    return str(info.value)


def _mutate(tmp_path: Path, edit: Callable[[Path, dict[str, Any]], None]) -> Path:
    root = _copy_corpus(tmp_path)
    manifest = _read(root / "manifest.json")
    edit(root, manifest)
    _write(root / "manifest.json", manifest)
    return root / "manifest.json"


def test_committed_corpus_loads_without_fatal_problems() -> None:
    corpus = runner.load_corpus(CORPUS / "manifest.json", code_sha=CODE_SHA)
    assert len(corpus.pack_cases()) == 16
    assert len(corpus.source_cases()) == 5
    assert set(corpus.labels) == {case.case_id for case in corpus.manifest.cases}


def test_committed_pack_stage_reproduces_expected_cases_and_metrics(
    committed_run: runner.RunOutput,
) -> None:
    pack = cast(dict[str, Any], committed_run.report["pack"])
    _assert_expected(EXPECTED["pack"]["per_case"], pack["per_case"], "pack.per_case")
    for language in ("en", "es"):
        expected = EXPECTED["pack"][language]
        actual = pack[language]
        _assert_expected(expected["cases"], actual["cases"], f"pack.{language}.cases")
        _assert_expected(expected["counts"], actual["counts"], f"pack.{language}.counts")
        _assert_expected(expected["metrics"], actual["metrics"], f"pack.{language}.metrics")


def test_deterministic_comparator_makes_no_model_call(committed_run: runner.RunOutput) -> None:
    pack = cast(dict[str, Any], committed_run.report["pack"])
    calls = cast(dict[str, int], pack["model_calls"])
    assert calls["D"] == 0
    assert calls["M"] > 0
    assert calls["D+M"] > 0


def test_every_rate_is_reported_with_its_counts(committed_run: runner.RunOutput) -> None:
    blocks = _rate_blocks(committed_run.report)
    assert blocks
    for block in blocks:
        assert "numerator" in block and "denominator" in block


def test_every_source_observation_matches(
    committed_run: runner.RunOutput,
) -> None:
    source = cast(dict[str, Any], committed_run.report["source"])
    mismatches = {
        (case_id, observation["field"])
        for case_id, observations in source["per_case"].items()
        for observation in observations
        if not observation["matched"]
    }
    assert mismatches == set()


def test_source_metrics_match_expected(committed_run: runner.RunOutput) -> None:
    for language in ("en", "es"):
        expected = EXPECTED["source"][language]
        actual = cast(dict[str, Any], committed_run.report["source"][language])
        _assert_expected(
            expected["observation_accuracy"],
            actual["observation_accuracy"],
            f"source.{language}.observation_accuracy",
        )
        if "per_field" in expected:
            _assert_expected(expected["per_field"], actual["per_field"], "source.en.per_field")
            assert actual["unknown_cohort"]["count"] == expected["unknown_cohort"]["count"]


def test_report_identities_and_labels_digest(committed_run: runner.RunOutput) -> None:
    report = committed_run.report
    labels_sha = hashlib.sha256((CORPUS / "labels.json").read_bytes()).hexdigest()
    assert report["labels_sha256"] == labels_sha
    identities = cast(dict[str, Any], report["identities"])
    assert identities["code_sha"] == CODE_SHA
    for name in (
        "content_pack_sha256",
        "policy_hash",
        "mapping_sha256",
        "query_sha256",
        "model_capability_sha256",
        "prompt_sha256",
    ):
        assert len(identities[name]) == 64, name
    assert committed_run.summary.splitlines()[0] == runner.LABEL


def test_reports_include_wilson_independence_caveat(tmp_path: Path) -> None:
    caveat = (
        "Wilson intervals assume independent cases; language and injection variants of one "
        "incident are correlated, so intervals for pooled cohorts are optimistic."
    )
    out = tmp_path / "report"
    runner.run_replay(CORPUS / "manifest.json", out, code_sha=CODE_SHA)
    report = _read(out / "report.json")
    summary = (out / "summary.txt").read_text("ascii")
    assert report["statistical_caveat"] == caveat
    assert caveat in summary


def test_m_comparator_keeps_duplicate_candidate_ids() -> None:
    corpus = runner.load_corpus(CORPUS / "manifest.json", code_sha=CODE_SHA)
    scripts = dict(corpus.scripts.scripts)
    attack = cast(runner.FindingsScript, scripts["correct_attack"])
    benign = cast(runner.FindingsScript, scripts["correct_benign"])
    duplicate_benign = benign.findings[0].model_copy(
        update={"finding_id": attack.findings[0].finding_id}
    )
    scripts["duplicate_candidate_ids"] = attack.model_copy(
        update={"findings": [attack.findings[0], duplicate_benign]}
    )
    case_scripts = dict(corpus.scripts.cases)
    case_scripts["pack_attack_en"] = "duplicate_candidate_ids"
    changed_scripts = corpus.scripts.model_copy(update={"scripts": scripts, "cases": case_scripts})
    corpus = dataclasses.replace(corpus, scripts=changed_scripts)

    case = next(item for item in corpus.pack_cases() if item.case_id == "pack_attack_en")
    pack = corpus.packs[case.case_id]
    profile = default_profile(runner.MAPPING_PROFILE_ID)
    context = runner._validation_context(corpus.catalog, case, pack, corpus.manifest.identities)
    plan = runner._pack_plan(corpus.catalog, pack, runner._parse_time(case.as_of))
    result = asyncio.run(
        runner._run_comparator(
            "M",
            case,
            corpus,
            profile,
            runner.STANDING_RULES,
            runner._first_site(corpus),
            plan,
            pack,
            context,
        )
    )
    assert result.escalate
    assert len(result.rendered) == 2
    label = corpus.labels["pack_attack_en"]
    _, metrics = runner._comparator_metrics("M", [(label, result)])
    unsupported = cast(dict[str, object], metrics["unsupported_claims"])
    assert unsupported["denominator"] == 2


def test_source_case_runs_through_compose_soc_and_ask() -> None:
    corpus = runner.load_corpus(CORPUS / "manifest.json", code_sha=CODE_SHA)
    case = next(item for item in corpus.source_cases() if item.case_id == "source_reused_id")
    profile = default_profile(runner.MAPPING_PROFILE_ID)
    result = asyncio.run(runner.run_source_case(corpus, case, profile, runner.STANDING_RULES))
    assert [key[0] for key in result.served] == ["POST", "POST", "POST", "DELETE"]
    assert result.answer_language == "en"


def test_source_scorer_rejects_an_extra_row(monkeypatch: pytest.MonkeyPatch) -> None:
    corpus = runner.load_corpus(CORPUS / "manifest.json", code_sha=CODE_SHA)
    case = next(item for item in corpus.source_cases() if item.case_id == "source_reused_id")
    profile = default_profile(runner.MAPPING_PROFILE_ID)
    score_source = runner._score_source

    def score_with_extra_row(expected: runner.Observations, answer: runner.Answer, topic_id: str):
        table = next(table for block in answer.blocks for table in block.tables if table.rows)
        table.rows.append(table.rows[0].model_copy(deep=True))
        empty_expected = expected.model_copy(update={"rows": {table.fetch_id: []}})
        empty_mismatches = [
            item for item in score_source(empty_expected, answer, topic_id) if not item.matched
        ]
        assert any(
            item.field == "rows" and item.expected == 0 and item.observed == len(table.rows)
            for item in empty_mismatches
        )
        absent_expected = expected.model_copy(update={"rows": {"absent_fetch": []}})
        assert any(
            item.key == "absent_fetch.cardinality" and item.observed == "missing"
            for item in score_source(absent_expected, answer, topic_id)
            if not item.matched
        )
        return score_source(expected, answer, topic_id)

    monkeypatch.setattr(runner, "_score_source", score_with_extra_row)
    result = asyncio.run(runner.run_source_case(corpus, case, profile, runner.STANDING_RULES))
    mismatches = [item for item in result.observations if not item.matched]
    assert any(item.field == "rows" and item.key.endswith(".cardinality") for item in mismatches)


def test_unmatched_indexer_request_fails_the_source_case(tmp_path: Path) -> None:
    manifest_path = _copy_corpus(tmp_path) / "manifest.json"
    root = manifest_path.parent
    source_path = root / "cases" / "source_reused_id.json"
    source = _read(source_path)
    source["responses"] = source["responses"][:2]
    _write(source_path, source)
    manifest = _read(manifest_path)
    _case(manifest, "source_reused_id")["responses"] = source["responses"]
    _refresh_input_hash(root, manifest, "source_reused_id")
    _write(manifest_path, manifest)
    corpus = runner.load_corpus(manifest_path, code_sha=CODE_SHA)
    case = next(item for item in corpus.source_cases() if item.case_id == "source_reused_id")
    profile = default_profile(runner.MAPPING_PROFILE_ID)
    with pytest.raises(runner.HarnessError, match="unmatched indexer"):
        asyncio.run(runner.run_source_case(corpus, case, profile, runner.STANDING_RULES))


def test_standing_rules_change_prompt_sha256() -> None:
    corpus = runner.load_corpus(CORPUS / "manifest.json", code_sha=CODE_SHA)
    profile = default_profile(runner.MAPPING_PROFILE_ID)
    identities = corpus.manifest.identities
    base = asyncio.run(runner.run_pack_stage(corpus, identities, profile, runner.STANDING_RULES))
    changed = asyncio.run(
        runner.run_pack_stage(corpus, identities, profile, runner.STANDING_RULES + " Changed.")
    )
    assert runner.prompt_sha256(base, corpus) != runner.prompt_sha256(changed, corpus)


def test_mapping_profile_change_changes_mapping_sha256() -> None:
    profile = default_profile(runner.MAPPING_PROFILE_ID)
    same = default_profile(runner.MAPPING_PROFILE_ID)
    changed = dataclasses.replace(profile, tie_break_field=None)
    assert runner.mapping_sha256(profile) == runner.mapping_sha256(same)
    assert runner.mapping_sha256(profile) != runner.mapping_sha256(changed)


def test_unknown_field_is_fatal(tmp_path: Path) -> None:
    def edit(root: Path, manifest: dict[str, Any]) -> None:
        _case(manifest, "pack_attack_en")["bogus"] = True

    message = _load_error(_mutate(tmp_path, edit))
    assert "unknown field" in message
    assert "pack_attack_en" in message


def test_input_hash_mismatch_is_fatal(tmp_path: Path) -> None:
    def edit(root: Path, manifest: dict[str, Any]) -> None:
        _case(manifest, "pack_attack_en")["input_sha256"] = "0" * 64

    message = _load_error(_mutate(tmp_path, edit))
    assert "input_sha256 mismatch: pack_attack_en" in message


def test_duplicate_case_id_is_fatal(tmp_path: Path) -> None:
    def edit(root: Path, manifest: dict[str, Any]) -> None:
        manifest["cases"].append(dict(_case(manifest, "pack_attack_en")))

    message = _load_error(_mutate(tmp_path, edit))
    assert "duplicate case_id: pack_attack_en" in message


def test_data_timestamp_after_as_of_is_fatal(tmp_path: Path) -> None:
    def edit(root: Path, manifest: dict[str, Any]) -> None:
        _case(manifest, "pack_attack_en")["as_of"] = "2026-10-17T08:00:00.000000Z"

    message = _load_error(_mutate(tmp_path, edit))
    assert "data timestamp after as_of: pack_attack_en" in message


def test_identifier_shared_across_partitions_is_fatal(tmp_path: Path) -> None:
    def edit(root: Path, manifest: dict[str, Any]) -> None:
        _case(manifest, "pack_benign_en")["entity_keys"] = ["101", "198.51.100.20"]

    message = _load_error(_mutate(tmp_path, edit))
    assert "entity shared across partitions: 101" in message


def test_holdout_bytes_differing_from_lock_are_fatal(tmp_path: Path) -> None:
    manifest_path = _copy_corpus(tmp_path) / "manifest.json"
    lock = manifest_path.parent / "holdout.lock"
    lines = [
        f"{'0' * 64}  {line.split('  ', 1)[1]}"
        if line.endswith("cases/pack_benign_en.json")
        else line
        for line in lock.read_text("ascii").splitlines()
    ]
    lock.write_text("\n".join(lines) + "\n", encoding="ascii")
    message = _load_error(manifest_path)
    assert "holdout bytes differ from holdout.lock: pack_benign_en" in message


def test_label_for_unknown_case_is_fatal(tmp_path: Path) -> None:
    root = _copy_corpus(tmp_path)
    labels_path = root / "labels.json"
    labels = _read(labels_path)
    ghost = dict(labels["labels"][0])
    ghost["case_id"] = "pack_ghost"
    labels["labels"].append(ghost)
    _write(labels_path, labels)
    message = _load_error(root / "manifest.json")
    assert "label for unknown case: pack_ghost" in message


def test_case_without_label_is_fatal(tmp_path: Path) -> None:
    root = _copy_corpus(tmp_path)
    labels_path = root / "labels.json"
    labels = _read(labels_path)
    labels["labels"] = [
        item for item in labels["labels"] if item["case_id"] != "pack_stale_context"
    ]
    _write(labels_path, labels)
    message = _load_error(root / "manifest.json")
    assert "case without label: pack_stale_context" in message


def test_pack_policy_hash_differing_from_manifest_is_fatal(tmp_path: Path) -> None:
    def edit(root: Path, manifest: dict[str, Any]) -> None:
        manifest["identities"]["policy_hash"] = "0" * 64

    message = _load_error(_mutate(tmp_path, edit))
    assert "pack policy hash differs from manifest" in message
    assert "pack_attack_en" in message


def test_pack_sha256_mismatch_is_fatal(tmp_path: Path) -> None:
    def edit(root: Path, manifest: dict[str, Any]) -> None:
        pack_path = root / "cases" / "pack_attack_en.json"
        pack = _read(pack_path)
        aggregate = next(item for item in pack["items"] if item["kind"] == "aggregate")
        aggregate["values"]["count"] = 15
        _write(pack_path, pack)
        _refresh_input_hash(root, manifest, "pack_attack_en")

    message = _load_error(_mutate(tmp_path, edit))
    assert "pack sha256 mismatch: pack_attack_en" in message


def test_pack_hash_includes_model_defaults(tmp_path: Path) -> None:
    def edit(root: Path, manifest: dict[str, Any]) -> None:
        pack_path = root / "cases" / "pack_attack_en.json"
        pack = _read(pack_path)
        del pack["fetches"][0]["message"]
        payload = {key: value for key, value in pack.items() if key != "sha256"}
        pack["sha256"] = runner.sha256_hex(payload)
        _write(pack_path, pack)
        _refresh_input_hash(root, manifest, "pack_attack_en")

    message = _load_error(_mutate(tmp_path, edit))
    assert "pack sha256 mismatch: pack_attack_en" in message


def test_catalog_digest_mismatch_is_fatal(tmp_path: Path) -> None:
    root = _copy_corpus(tmp_path)
    topic = root / "catalog" / "topics" / "ssh_auth.json"
    topic.write_text(topic.read_text("utf-8") + "\n", encoding="utf-8")
    message = _load_error(root / "manifest.json")
    assert "catalog digest differs from manifest identities" in message
