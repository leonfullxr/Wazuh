import hashlib
import json
from dataclasses import replace
from pathlib import Path

from ai_soc.contracts.models import EmbeddingManifest
from ai_soc.planning.semantic import (
    EvaluationReport,
    LanguageConfusion,
    SemanticExample,
    evaluate_model,
    select_model,
)


def test_bilingual_family_split_is_disjoint_and_selection_uses_dev_metrics() -> None:
    corpus_sha = "1" * 64
    vectors_sha = "2" * 64
    manifest = EmbeddingManifest(
        model_id="fixture-a",
        region="us-east-1",
        dimensions=2,
        purpose="topic_cards",
        normalization="l2",
        corpus_sha256=corpus_sha,
        vector_sha256=vectors_sha,
        golden_sha256="3" * 64,
        threshold=0.8,
        minimum_margin=0.1,
        selection_report_path="reports/selection.json",
    )
    examples = tuple(
        SemanticExample(
            case_id=f"{family}-{language}",
            family_id=f"family-{family_number}",
            language=language,
            query_vector=(1.0, 0.0),
            card_vectors={"ldap": (1.0, 0.0)},
            expected_topic="ldap",
        )
        for family_number in range(500)
        for language in ("en", "es")
        for family in (f"family-{family_number}",)
    )
    report_a = evaluate_model(
        examples,
        model_id="fixture-a",
        manifest=manifest,
        query_mode="query",
        document_mode="document",
        corpus_sha256=corpus_sha,
        vector_sha256=vectors_sha,
        manifest_sha256="4" * 64,
        thresholds=(0.8,),
        margins=(0.1,),
    )
    assert report_a.en.sample_count >= 20 and report_a.es.sample_count >= 20
    assert report_a.en.precision == report_a.es.precision == 1.0
    assert report_a.held_out_cases == report_a.en.sample_count + report_a.es.sample_count
    assert len(report_a.split_sha256) == 64

    report_b = replace(report_a, model_id="fixture-b")
    selected = select_model(
        (report_b, report_a), embedding_calls_by_model={"fixture-a": 2, "fixture-b": 1}
    )
    assert selected.selected_model_id == "fixture-b"
    assert [report.model_id for report in selected.candidate_reports] == [
        "fixture-a",
        "fixture-b",
    ]
    assert len(selected.selection_sha256) == 64


def test_select_model_prefers_higher_macro_precision_at_precision_floor() -> None:
    corpus_sha = "1" * 64
    high = LanguageConfusion("en", 10, 0, 0, 0, 0, 1.0, 0.5, 10)
    low_recall = LanguageConfusion("en", 19, 1, 0, 0, 0, 0.95, 0.95, 20)
    report_high = EvaluationReport(
        "4" * 64,
        corpus_sha,
        "2" * 64,
        "fixture-high",
        "5" * 64,
        "search_query",
        "search_document",
        2,
        "l2",
        0.8,
        0.1,
        high,
        high,
        1.0,
        0.5,
        high,
        high,
        1.0,
        20,
    )
    report_low = replace(
        report_high,
        model_id="fixture-low",
        dev_en=low_recall,
        dev_es=low_recall,
        dev_macro_precision=0.95,
        dev_macro_recall=0.95,
    )
    selected = select_model(
        (report_low, report_high),
        embedding_calls_by_model={"fixture-high": 1, "fixture-low": 1},
    )
    assert selected.selected_model_id == "fixture-high"


def test_independent_bilingual_heldout_goldens_pin_threshold_metrics_and_hashes() -> None:
    fixture = json.loads(
        (Path(__file__).parent / "data/semantic_goldens.json").read_text(encoding="utf-8")
    )

    def digest(value: object) -> str:
        encoded = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    topics = fixture["topics"]
    vectors = {topic_id: tuple(vector) for topic_id, vector in topics.items()}
    cases = fixture["cases"]
    assert digest(topics) == fixture["vector_sha256"]
    assert digest(fixture["corpus_texts"]) == fixture["corpus_sha256"]
    assert digest(cases) == fixture["golden_sha256"]

    family_splits: dict[str, str] = {}
    examples: list[SemanticExample] = []
    for case in cases:
        family_id = case["family_id"]
        bucket = int(hashlib.sha256(family_id.encode("utf-8")).hexdigest()[:8], 16) % 100
        split = "train" if bucket < 60 else "dev" if bucket < 80 else "test"
        assert case["expected_split"] == split
        assert family_splits.setdefault(family_id, split) == split
        examples.append(
            SemanticExample(
                case_id=case["case_id"],
                family_id=family_id,
                language=case["language"],
                query_vector=tuple(case["query_vector"]),
                card_vectors=vectors,
                expected_topic=case["expected_topic"],
            )
        )
    assert digest(family_splits) == fixture["split_sha256"]

    manifest = EmbeddingManifest(
        model_id="fixture-multilingual-v2",
        region="us-east-1",
        dimensions=3,
        purpose="topic_cards",
        normalization="l2",
        corpus_sha256=fixture["corpus_sha256"],
        vector_sha256=fixture["vector_sha256"],
        golden_sha256=fixture["golden_sha256"],
        threshold=0.8,
        minimum_margin=0.1,
        selection_report_path="reports/selection.json",
    )
    manifest_sha = digest(manifest.model_dump(mode="json"))
    report = evaluate_model(
        tuple(examples),
        model_id=manifest.model_id,
        manifest=manifest,
        query_mode="search_query",
        document_mode="search_document",
        corpus_sha256=fixture["corpus_sha256"],
        vector_sha256=fixture["vector_sha256"],
        manifest_sha256=manifest_sha,
    )
    assert report.threshold == fixture["expected_threshold"]
    assert report.minimum_margin == fixture["expected_minimum_margin"]
    assert report.split_sha256 == fixture["split_sha256"]
    assert report.corpus_sha256 == fixture["corpus_sha256"]
    assert report.vector_sha256 == fixture["vector_sha256"]
    assert report.manifest_sha256 == manifest_sha
    assert report.dev_en.sample_count == report.dev_es.sample_count == 30
    assert report.dev_en.precision == report.dev_es.precision == 1.0
    assert report.dev_en.recall == report.dev_es.recall == 15 / 21
    assert report.en.sample_count == report.es.sample_count == 33
    assert report.held_out_cases == 66
    assert (
        report.en.true_positive,
        report.en.false_positive,
        report.en.true_negative,
        report.en.false_negative,
    ) == (11, 1, 14, 7)
    assert (
        report.es.true_positive,
        report.es.false_positive,
        report.es.true_negative,
        report.es.false_negative,
    ) == (11, 1, 14, 7)
    assert report.en.false_positive == report.es.false_positive == 1
    assert report.en.precision == report.es.precision
    assert report.en.recall == report.es.recall

    selected = select_model((report,), embedding_calls_by_model={manifest.model_id: 150})
    assert selected.selected_model_id == manifest.model_id
    assert selected.candidate_reports[0].corpus_sha256 == fixture["corpus_sha256"]
    assert selected.candidate_reports[0].manifest_sha256 == manifest_sha
    assert len(selected.selection_sha256) == 64
