import pytest
from pytest import approx

from ai_soc.planning.semantic import RankedTopic, evaluate_threshold, rank_topics


def test_ranking_is_pure_deterministic_and_ties_sort_only_for_reporting() -> None:
    ranked = rank_topics(
        (1.0, 0.0),
        {"zeta": (1.0, 0.0), "alpha": (1.0, 0.0), "beta": (0.0, 1.0)},
        dimensions=2,
    )
    assert [topic.topic_id for topic in ranked] == ["alpha", "zeta", "beta"]
    qualifies, margin, _ = evaluate_threshold(ranked, threshold=0.8, minimum_margin=0.0)
    assert not qualifies
    assert margin == 0.0


@pytest.mark.parametrize(
    "vector",
    [(0.0, 0.0), (float("nan"), 1.0), (1.0,), (2.0, 0.0)],
)
def test_invalid_query_vectors_fail_closed(vector: tuple[float, ...]) -> None:
    with pytest.raises(ValueError):
        rank_topics(vector, {"ldap": (1.0, 0.0)}, dimensions=2)


def test_threshold_equality_qualifies_only_when_margin_is_positive() -> None:
    ranked = (RankedTopic("ldap", 0.9), RankedTopic("dns", 0.8))
    qualifies, margin, near = evaluate_threshold(ranked, threshold=0.9, minimum_margin=0.1)
    assert qualifies and margin == approx(0.1) and not near
    assert evaluate_threshold(ranked, threshold=0.91, minimum_margin=0.1)[2]
