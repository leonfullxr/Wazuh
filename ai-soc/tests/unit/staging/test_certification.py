from __future__ import annotations

from dataclasses import replace

from scripts.staging.certification import normalize_live_result
from scripts.staging.models import (
    KnownResultView,
    ObligationStatus,
)
from tests.unit.staging.session_test_support import _binding, _result


def test_plain_pass_and_serialized_replay_are_noncertifying() -> None:
    result = normalize_live_result(_result())

    assert result.status == "NOT_RUN"
    assert all(row.status == ObligationStatus.NOT_RUN for row in result.obligations)
    assert result.to_dict()["status"] == "NOT_RUN"


def test_unverified_pass_is_demoted_and_failures_are_preserved() -> None:
    result = _result()
    normalized = normalize_live_result(result)
    assert normalized.status == "NOT_RUN"
    assert "verified_observations" not in normalized.to_dict()

    failed = replace(
        result,
        obligations=(
            replace(result.obligations[0], status=ObligationStatus.FAIL),
            *result.obligations[1:],
        ),
        verified_observations=(),
    )
    assert normalize_live_result(failed).status == "FAIL"

    integrity_failure = replace(result, status="FAIL")
    normalized_failure = normalize_live_result(integrity_failure)
    assert normalized_failure.status == "FAIL"


def test_certification_serializes_registered_views_without_rewriting_diagnostics() -> None:
    result = _result()
    result = replace(
        result,
        results={
            "diagnostic": {"status": "PASS", "detail": "an application-specific observation"},
        },
        result_views=(
            KnownResultView(
                kind="contributor",
                view_id="mcp",
                diagnostics={"status": "PASS", "evidence_refs": ["untrusted"]},
                obligation_ids=tuple(row.obligation_id for row in result.obligations),
            ),
        ),
    )

    normalized = normalize_live_result(result)

    assert normalized.results["diagnostic"]["status"] == "PASS"
    payload = normalized.to_dict()
    assert payload["results"]["contributors"]["mcp"]["status"] == "NOT_RUN"
    assert payload["results"]["contributors"]["mcp"]["evidence_refs"] == []


def test_deployment_id_none_is_not_a_binding_wildcard() -> None:
    observed = _binding()
    expected = _binding(deployment_id=None)

    from scripts.staging.models import matches_expected_binding

    assert not matches_expected_binding(observed, expected)
