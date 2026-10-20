from __future__ import annotations

from scripts.staging.evaluators import _state_candidate_rows


def test_missing_second_contender_keeps_observed_failure_and_marks_pair_not_run() -> None:
    result = _state_candidate_rows(
        {
            "A": {
                "lease_acquired": True,
                "stage_admission": False,
                "ambiguous_settlement_exactly_once": None,
                "stale_fence_rejected": None,
                "recovery_terminalized": None,
            }
        }
    )

    assert result["ddb_replica_transactions"][0] is None
    assert result["stage_admission"][0] is False
    assert result["exactly_once_settlement"][0] is None


def test_authenticated_cancellation_negative_fails_even_when_experiment_is_partial() -> None:
    result = _state_candidate_rows(
        {
            "A": {
                "lease_acquired": True,
                "lease_contended": False,
                "stage_admission": True,
                "ambiguous_settlement_exactly_once": True,
                "stale_fence_rejected": False,
                "recovery_terminalized": True,
            },
            "B": {"lease_acquired": False, "lease_contended": True},
        }
    )

    assert result["cancellation_recovery"][0] is False


def test_absent_stale_fence_fact_cannot_pass_cancellation() -> None:
    result = _state_candidate_rows(
        {
            "A": {
                "lease_acquired": True,
                "lease_contended": False,
                "stage_admission": True,
                "ambiguous_settlement_exactly_once": True,
                "recovery_terminalized": True,
            },
            "B": {"lease_acquired": False, "lease_contended": True},
        }
    )

    assert result["cancellation_recovery"][0] is None


def test_state_probe_partial_negative_fails_recovery_without_certifying_positive() -> None:
    result = _state_candidate_rows(
        {
            "A": {
                "lease_acquired": True,
                "lease_contended": False,
                "stale_fence_rejected": False,
                "recovery_terminalized": True,
                "ambiguous_settlement_exactly_once": True,
            }
        }
    )

    assert result["ddb_replica_transactions"][0] is None
    assert result["cancellation_recovery"][0] is False
    assert result["exactly_once_settlement"][0] is None
