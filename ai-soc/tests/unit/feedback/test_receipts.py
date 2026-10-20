from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import pytest

from ai_soc.application.errors import ServiceFailure
from ai_soc.contracts.models import AnswerStatus
from ai_soc.feedback.receipts import FeedbackReceiptCodec
from ai_soc.feedback.redaction import redact_note

_FEEDBACK_CASE_FIXTURE = Path(__file__).parent / "data" / "feedback_receipt_cases.json"
_FEEDBACK_CASE_SHA256 = hashlib.sha256(_FEEDBACK_CASE_FIXTURE.read_bytes()).hexdigest()


def feedback_cases() -> dict[str, object]:
    return cast(
        dict[str, object],
        json.loads(_FEEDBACK_CASE_FIXTURE.read_text(encoding="utf-8")),
    )


@pytest.fixture
def codec() -> FeedbackReceiptCodec:
    return FeedbackReceiptCodec({"key-1": b"a" * 32, "key-0": b"b" * 32}, "key-1")


def issue(
    codec: FeedbackReceiptCodec,
    now: datetime,
    outcome_code: AnswerStatus = AnswerStatus.answered,
    *,
    lifetime_seconds: int = 1800,
) -> tuple[str, UUID]:
    question_id = uuid4()
    token = codec.issue(
        question_id=question_id,
        owner_key="a" * 64,
        environment_id="alpha",
        content_sha="b" * 40,
        cue_ids=["fetch"],
        topic_ids=["ldap"],
        outcome_code=outcome_code,
        now=now,
        lifetime_seconds=lifetime_seconds,
    )
    return token, question_id


@pytest.mark.acceptance()
@pytest.mark.case_id("B5-feedback.receipt-component")
@pytest.mark.variant("positive")
@pytest.mark.fixture_sha256(_FEEDBACK_CASE_SHA256)
def test_receipt_is_encrypted_and_opens_on_a_replica() -> None:
    fixture = feedback_cases()
    expected = cast(dict[str, object], fixture["positive"])
    now = datetime(2026, 9, 30, tzinfo=UTC)
    codec = FeedbackReceiptCodec({"key-1": b"a" * 32}, "key-1")
    assert expected["replica_opens"] is True
    assert expected["followup_field_present"] is False
    for status in cast(list[str], expected["outcomes"]):
        token, question_id = issue(codec, now, AnswerStatus(status))
        assert "a" * 64 not in token
        payload = FeedbackReceiptCodec({"key-1": b"a" * 32}, "key-1").open(
            token,
            question_id=question_id,
            owner_key="a" * 64,
            environment_id="alpha",
            now=now + timedelta(minutes=1),
        )
        assert payload.topic_ids == ["ldap"]
        assert payload.outcome_code == status
        assert "followup_id" not in payload.model_dump()


def test_note_redaction_rejects_secrets_and_redacts_identifiers() -> None:
    with pytest.raises(ValueError):
        redact_note("password=not-for-review")
    safe = redact_note("Please check alice@example.test at 203.0.113.30")
    assert safe == "Please check [redacted email] at [redacted address]"


@pytest.mark.parametrize("binding", ["owner", "site", "question", "expired", "tampered"])
def test_receipt_rejects_invalid_bindings_uniformly(
    codec: FeedbackReceiptCodec, binding: str
) -> None:
    now = datetime(2026, 9, 30, tzinfo=UTC)
    token, question_id = issue(codec, now)
    owner = "a" * 64
    site = "alpha"
    timestamp = now
    if binding == "owner":
        owner = "c" * 64
    elif binding == "site":
        site = "beta"
    elif binding == "question":
        question_id = uuid4()
    elif binding == "expired":
        timestamp = now + timedelta(minutes=31)
    else:
        token = token[:-1] + ("A" if token[-1] != "A" else "B")
    with pytest.raises(ServiceFailure) as error:
        codec.open(
            token, question_id=question_id, owner_key=owner, environment_id=site, now=timestamp
        )
    assert error.value.error.code == "FEEDBACK_INVALID"


@pytest.mark.acceptance()
@pytest.mark.case_id("B5-feedback.receipt-component")
@pytest.mark.variant("negative")
@pytest.mark.fixture_sha256(_FEEDBACK_CASE_SHA256)
def test_registered_foreign_and_tampered_receipts_share_the_finite_error(
    codec: FeedbackReceiptCodec,
) -> None:
    fixture = feedback_cases()
    expected = cast(dict[str, object], fixture["negative"])
    now = datetime(2026, 9, 30, tzinfo=UTC)
    errors: list[str] = []
    for binding in cast(list[str], expected["bindings"]):
        token, question_id = issue(codec, now)
        owner, site, timestamp = "a" * 64, "alpha", now
        if binding == "owner":
            owner = "c" * 64
        elif binding == "site":
            site = "beta"
        elif binding == "question":
            question_id = uuid4()
        elif binding == "expired":
            timestamp = now + timedelta(minutes=31)
        else:
            token = token[:-1] + ("A" if token[-1] != "A" else "B")
        with pytest.raises(ServiceFailure) as failure:
            codec.open(
                token,
                question_id=question_id,
                owner_key=owner,
                environment_id=site,
                now=timestamp,
            )
        errors.append(failure.value.error.code)

    assert errors == [expected["public_error"]] * len(expected["bindings"])


@pytest.mark.acceptance()
@pytest.mark.case_id("B5-feedback.receipt-component")
@pytest.mark.variant("boundary")
@pytest.mark.fixture_sha256(_FEEDBACK_CASE_SHA256)
def test_receipt_lifetime_accepts_last_instant_and_rejects_exact_expiry(
    codec: FeedbackReceiptCodec,
) -> None:
    fixture = feedback_cases()
    expected = cast(dict[str, object], fixture["boundary"])
    now = datetime(2026, 9, 30, tzinfo=UTC)
    token, question_id = issue(
        codec,
        now,
        lifetime_seconds=int(expected["lifetime_seconds"]),
    )
    last_valid = codec.open(
        token,
        question_id=question_id,
        owner_key="a" * 64,
        environment_id="alpha",
        now=now + timedelta(seconds=int(expected["last_valid_offset_seconds"])),
    )
    assert last_valid.question_id == question_id
    with pytest.raises(ServiceFailure) as expired:
        codec.open(
            token,
            question_id=question_id,
            owner_key="a" * 64,
            environment_id="alpha",
            now=now + timedelta(seconds=int(expected["expiry_offset_seconds"])),
        )
    assert expired.value.error.code == "FEEDBACK_INVALID"
