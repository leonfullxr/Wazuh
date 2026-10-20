"""Pure topic-card ranking and bounded asynchronous embedding suggestions."""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

from ai_soc.contracts.canonical import canonical_bytes
from ai_soc.contracts.models import EmbeddingManifest, ExecutionContext, SemanticSuggestion
from ai_soc.contracts.ports import ContentCatalog, EmbeddingProvider, SemanticSuggester
from ai_soc.planning.parser import has_deterministic_route


@dataclass(frozen=True, slots=True)
class RankedTopic:
    topic_id: str
    score: float


@dataclass(frozen=True, slots=True)
class LanguageConfusion:
    language: str
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    abstained: int
    precision: float
    recall: float
    sample_count: int


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    split_sha256: str
    corpus_sha256: str
    vector_sha256: str
    model_id: str
    manifest_sha256: str
    query_mode: str
    document_mode: str
    dimensions: int
    normalization: str
    threshold: float
    minimum_margin: float
    dev_en: LanguageConfusion
    dev_es: LanguageConfusion
    dev_macro_precision: float
    dev_macro_recall: float
    en: LanguageConfusion
    es: LanguageConfusion
    macro_precision: float
    held_out_cases: int


@dataclass(frozen=True, slots=True)
class ModelSelectionReport:
    selected_model_id: str | None
    candidate_reports: tuple[EvaluationReport, ...]
    selection_sha256: str


@dataclass(frozen=True, slots=True)
class SemanticExample:
    case_id: str
    family_id: str
    language: str
    query_vector: tuple[float, ...]
    card_vectors: Mapping[str, tuple[float, ...]]
    expected_topic: str | None


@dataclass(frozen=True, slots=True)
class SemanticIndex:
    manifest: EmbeddingManifest
    card_vectors: Mapping[str, tuple[float, ...]]
    query_mode: str
    document_mode: str
    enabled: bool = True
    manifest_sha256: str = ""

    def __post_init__(self) -> None:
        frozen_vectors = {topic_id: tuple(vector) for topic_id, vector in self.card_vectors.items()}
        vector_sha256 = hashlib.sha256(
            canonical_bytes(
                {topic_id: list(frozen_vectors[topic_id]) for topic_id in sorted(frozen_vectors)}
            )
        ).hexdigest()
        if vector_sha256 != self.manifest.vector_sha256:
            raise ValueError("topic-card vector hash does not match the embedding manifest")
        manifest_sha256 = hashlib.sha256(canonical_bytes(self.manifest)).hexdigest()
        if self.manifest_sha256 and self.manifest_sha256 != manifest_sha256:
            raise ValueError("embedding manifest hash does not match the supplied manifest")
        object.__setattr__(self, "card_vectors", MappingProxyType(frozen_vectors))
        object.__setattr__(self, "manifest_sha256", manifest_sha256)


@dataclass(frozen=True, slots=True)
class SemanticProviderBinding:
    """Metadata copied from an already validated embedding capability at composition."""

    model_id: str
    dimensions: int
    purpose: Literal["topic_cards"]
    normalization: Literal["l2"]
    query_mode: Literal["single_text", "search_query"]
    document_mode: Literal["single_text", "search_document"]


def _validate_vector(vector: tuple[float, ...], dimensions: int, *, label: str) -> None:
    if len(vector) != dimensions:
        raise ValueError(f"{label} vector has the wrong dimension")
    if not vector or any(not math.isfinite(value) for value in vector):
        raise ValueError(f"{label} vector must be finite and nonempty")
    norm = math.sqrt(sum(value * value for value in vector))
    if norm == 0.0:
        raise ValueError(f"{label} vector has zero norm")
    if not math.isclose(norm, 1.0, rel_tol=1e-5, abs_tol=1e-5):
        raise ValueError(f"{label} vector is not L2 normalized")


def rank_topics(
    query_vector: tuple[float, ...],
    card_vectors: Mapping[str, tuple[float, ...]],
    *,
    dimensions: int,
) -> tuple[RankedTopic, ...]:
    """Rank immutable normalized cards by cosine similarity with stable ID ordering."""
    _validate_vector(query_vector, dimensions, label="query")
    if not card_vectors:
        return ()
    ranked: list[RankedTopic] = []
    for topic_id, vector in card_vectors.items():
        _validate_vector(vector, dimensions, label=f"topic {topic_id}")
        score = math.fsum(left * right for left, right in zip(query_vector, vector, strict=True))
        ranked.append(RankedTopic(topic_id=topic_id, score=score))
    return tuple(sorted(ranked, key=lambda item: (-item.score, item.topic_id)))


def evaluate_threshold(
    ranked: tuple[RankedTopic, ...],
    *,
    threshold: float,
    minimum_margin: float,
) -> tuple[bool, float, bool]:
    """Return qualifies, top-one margin, and near-threshold flag."""
    if not math.isfinite(threshold) or not math.isfinite(minimum_margin) or minimum_margin < 0:
        raise ValueError("threshold and margin must be finite; margin cannot be negative")
    if not ranked:
        return False, 0.0, False
    best = ranked[0].score
    second = ranked[1].score if len(ranked) > 1 else -1.0
    margin = best - second
    margin_satisfies = margin + 1e-12 >= minimum_margin
    qualifies = best >= threshold and margin_satisfies and (len(ranked) == 1 or best > second)
    near = not qualifies and (abs(best - threshold) <= 0.02 or abs(margin - minimum_margin) <= 0.02)
    return qualifies, margin, near


class EmbeddingSemanticSuggester(SemanticSuggester):
    """Optional semantic fallback; it can suggest a topic but never creates a plan."""

    def __init__(
        self,
        index: SemanticIndex,
        provider: EmbeddingProvider,
        *,
        provider_binding: SemanticProviderBinding,
    ) -> None:
        if (
            provider_binding.model_id != index.manifest.model_id
            or provider_binding.dimensions != index.manifest.dimensions
            or provider_binding.purpose != index.manifest.purpose
            or provider_binding.normalization != index.manifest.normalization
            or (provider_binding.query_mode, provider_binding.document_mode)
            not in {
                ("single_text", "single_text"),
                ("search_query", "search_document"),
            }
        ):
            raise ValueError("embedding provider capability does not match the topic-card manifest")
        self._index = index
        self._provider = provider

    async def suggest(
        self,
        question: str,
        *,
        language: str,
        catalog: ContentCatalog,
        execution: ExecutionContext,
    ) -> SemanticSuggestion | None:
        index = self._index
        if (
            not index.enabled
            or language not in {"en", "es"}
            or not index.card_vectors
            or has_deterministic_route(question, catalog, language)
        ):
            return None
        vectors = await self._provider.embed((question,), purpose="query", execution=execution)
        if len(vectors) != 1:
            return None
        ranked = rank_topics(vectors[0], index.card_vectors, dimensions=index.manifest.dimensions)
        if not ranked:
            return None
        qualifies, margin, near = evaluate_threshold(
            ranked,
            threshold=index.manifest.threshold,
            minimum_margin=index.manifest.minimum_margin,
        )
        return SemanticSuggestion(
            topic_id=ranked[0].topic_id,
            score=ranked[0].score,
            margin=margin,
            model_id=index.manifest.model_id,
            qualifies=qualifies,
            near_threshold=near,
        )


def _confusion(
    examples: list[SemanticExample],
    threshold: float,
    minimum_margin: float,
    dims: int,
    language: str,
) -> LanguageConfusion:
    tp = fp = tn = fn = abstained = 0
    for example in examples:
        ranked = rank_topics(example.query_vector, example.card_vectors, dimensions=dims)
        qualifies, _, _ = evaluate_threshold(
            ranked, threshold=threshold, minimum_margin=minimum_margin
        )
        suggestion = ranked[0].topic_id if qualifies and ranked else None
        positive = example.expected_topic is not None
        if suggestion is None:
            abstained += 1
            if positive:
                fn += 1
            else:
                tn += 1
        elif positive and suggestion == example.expected_topic:
            tp += 1
        else:
            fp += 1
            if positive:
                fn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    return LanguageConfusion(language, tp, fp, tn, fn, abstained, precision, recall, len(examples))


def _family_split(family_id: str) -> str:
    value = int(hashlib.sha256(family_id.encode("utf-8")).hexdigest()[:8], 16) % 100
    return "train" if value < 60 else "dev" if value < 80 else "test"


def evaluate_model(
    examples: tuple[SemanticExample, ...],
    *,
    model_id: str,
    manifest: EmbeddingManifest,
    query_mode: str,
    document_mode: str,
    corpus_sha256: str,
    vector_sha256: str,
    manifest_sha256: str,
    thresholds: tuple[float, ...] = tuple(index / 100 for index in range(0, 101)),
    margins: tuple[float, ...] = (0.0, 0.01, 0.025, 0.05, 0.1),
) -> EvaluationReport:
    """Tune thresholds on dev family groups, then report disjoint held-out results."""
    if manifest.normalization != "l2" or manifest.dimensions <= 0:
        raise ValueError("unsupported embedding manifest")
    if (
        not model_id
        or not query_mode
        or not document_mode
        or not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256)
    ):
        raise ValueError("model and embedding provenance fields must be complete")
    if corpus_sha256 != manifest.corpus_sha256 or vector_sha256 != manifest.vector_sha256:
        raise ValueError("evaluation hashes do not match the embedding manifest")
    if not thresholds or not margins:
        raise ValueError("threshold and margin candidate sets cannot be empty")
    if any(not math.isfinite(value) or not -1 <= value <= 1 for value in thresholds):
        raise ValueError("threshold candidates must be finite cosine scores")
    if any(not math.isfinite(value) or not 0 <= value <= 2 for value in margins):
        raise ValueError("margin candidates must be finite cosine differences")
    families: set[str] = set()
    case_ids: set[str] = set()
    card_ids: set[str] | None = None
    for example in examples:
        if example.language not in {"en", "es"}:
            raise ValueError("evaluation language must be en or es")
        if not example.case_id or not example.family_id or example.case_id in case_ids:
            raise ValueError("evaluation case IDs must be unique and nonempty")
        case_ids.add(example.case_id)
        families.add(example.family_id)
        current_card_ids = set(example.card_vectors)
        if card_ids is None:
            card_ids = current_card_ids
        elif current_card_ids != card_ids:
            raise ValueError("evaluation cases must use the same topic card set")
        if _family_split(example.family_id) == "test":
            rank_topics(example.query_vector, example.card_vectors, dimensions=manifest.dimensions)
    dev = [example for example in examples if _family_split(example.family_id) == "dev"]
    test = [example for example in examples if _family_split(example.family_id) == "test"]
    if (
        sum(item.language == "en" for item in test) < 20
        or sum(item.language == "es" for item in test) < 20
    ):
        raise ValueError("held-out test needs at least 20 examples in each language")
    candidates: list[tuple[float, float, float, float]] = []
    for threshold in thresholds:
        for margin in margins:
            en = _confusion(
                [item for item in dev if item.language == "en"],
                threshold,
                margin,
                manifest.dimensions,
                "en",
            )
            es = _confusion(
                [item for item in dev if item.language == "es"],
                threshold,
                margin,
                manifest.dimensions,
                "es",
            )
            if en.precision >= 0.95 and es.precision >= 0.95:
                recall = (en.recall + es.recall) / 2
                precision = (en.precision + es.precision) / 2
                candidates.append((precision, recall, threshold, margin))
    if candidates:
        _, _, threshold, margin = max(
            candidates, key=lambda item: (item[0], item[1], -item[2], -item[3])
        )
    else:
        threshold, margin = 1.0, 1.0
    dev_en_result = _confusion(
        [item for item in dev if item.language == "en"],
        threshold,
        margin,
        manifest.dimensions,
        "en",
    )
    dev_es_result = _confusion(
        [item for item in dev if item.language == "es"],
        threshold,
        margin,
        manifest.dimensions,
        "es",
    )
    en_result = _confusion(
        [item for item in test if item.language == "en"],
        threshold,
        margin,
        manifest.dimensions,
        "en",
    )
    es_result = _confusion(
        [item for item in test if item.language == "es"],
        threshold,
        margin,
        manifest.dimensions,
        "es",
    )
    split_hash = hashlib.sha256(
        canonical_bytes({family: _family_split(family) for family in sorted(families)})
    ).hexdigest()
    return EvaluationReport(
        split_hash,
        corpus_sha256,
        vector_sha256,
        model_id,
        manifest_sha256,
        query_mode,
        document_mode,
        manifest.dimensions,
        manifest.normalization,
        threshold,
        margin,
        dev_en_result,
        dev_es_result,
        (dev_en_result.precision + dev_es_result.precision) / 2,
        (dev_en_result.recall + dev_es_result.recall) / 2,
        en_result,
        es_result,
        (en_result.precision + es_result.precision) / 2,
        len(test),
    )


def select_model(
    reports: tuple[EvaluationReport, ...],
    *,
    embedding_calls_by_model: Mapping[str, int],
) -> ModelSelectionReport:
    """Select by bilingual dev macro precision under the precision floor."""
    if len({report.model_id for report in reports}) != len(reports):
        raise ValueError("model evaluation reports must have unique model IDs")
    if reports and (
        len({report.corpus_sha256 for report in reports}) != 1
        or len({report.split_sha256 for report in reports}) != 1
        or len({report.held_out_cases for report in reports}) != 1
    ):
        raise ValueError("model candidates must share one corpus and family-disjoint split")
    if any(count < 0 for count in embedding_calls_by_model.values()):
        raise ValueError("embedding call counts cannot be negative")
    eligible = [
        report
        for report in reports
        if report.dev_en.precision >= 0.95 and report.dev_es.precision >= 0.95
    ]
    selected = min(
        eligible,
        key=lambda report: (
            -report.dev_macro_precision,
            embedding_calls_by_model.get(report.model_id, 0),
            report.model_id,
        ),
        default=None,
    )
    ordered = tuple(sorted(reports, key=lambda report: report.model_id))
    payload = {
        "selected_model_id": selected.model_id if selected else None,
        "candidates": [
            {
                "model_id": report.model_id,
                "corpus_sha256": report.corpus_sha256,
                "vector_sha256": report.vector_sha256,
                "manifest_sha256": report.manifest_sha256,
                "dev_macro_precision": report.dev_macro_precision,
                "dev_macro_recall": report.dev_macro_recall,
                "heldout_en_precision": report.en.precision,
                "heldout_es_precision": report.es.precision,
                "heldout_en_recall": report.en.recall,
                "heldout_es_recall": report.es.recall,
                "embedding_calls": embedding_calls_by_model.get(report.model_id, 0),
            }
            for report in ordered
        ],
    }
    selection_sha = hashlib.sha256(canonical_bytes(payload)).hexdigest()
    return ModelSelectionReport(
        selected.model_id if selected else None,
        ordered,
        selection_sha,
    )
