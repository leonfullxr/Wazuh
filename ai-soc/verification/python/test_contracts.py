"""Synthetic checks for public request and evidence contracts."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from pydantic import ValidationError

from ai_soc.contracts.canonical import canonical_bytes, evidence_id, owner_key
from ai_soc.contracts.models import AskRequest, ResolvedWindow


def test_followup_requires_both_identity_and_revision() -> None:
    request = {"question": "Review authentication", "environment_id": "synthetic"}
    assert AskRequest.model_validate(request).followup_id is None
    with pytest.raises(ValidationError):
        AskRequest.model_validate({**request, "followup_id": UUID(int=1)})
    with pytest.raises(ValidationError):
        AskRequest.model_validate({**request, "followup_revision": 1})
    assert (
        AskRequest.model_validate(
            {**request, "followup_id": UUID(int=1), "followup_revision": 1}
        ).followup_revision
        == 1
    )


def test_window_cannot_extend_past_anchor() -> None:
    anchor = datetime(2026, 1, 2, tzinfo=UTC)
    window = {
        "start": anchor - timedelta(days=1),
        "end": anchor,
        "anchor_at": anchor,
        "semantics": "absolute",
        "source_text": "yesterday",
        "timezone": "UTC",
    }
    assert ResolvedWindow.model_validate(window).end == anchor
    with pytest.raises(ValidationError):
        ResolvedWindow.model_validate({**window, "end": anchor + timedelta(seconds=1)})


def test_canonical_identity_is_stable_and_bound_to_source() -> None:
    assert canonical_bytes({"b": 2, "a": 1}) == canonical_bytes({"a": 1, "b": 2})
    assert owner_key("issuer", "subject") != owner_key("issuer2", "subject")
    evidence = {
        "question_id": "question",
        "environment_id": "synthetic",
        "topic_id": "auth",
        "fetch_id": "fetch",
        "check_id": None,
        "kind": "count",
        "source": {"index": "alerts"},
        "snapshot_key": "snapshot",
        "values": {"count": 1},
    }
    assert evidence_id(**evidence) != evidence_id(**{**evidence, "values": {"count": 2}})
    with pytest.raises(ValueError):
        evidence_id(**{**evidence, "check_id": "check"})
