import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from support import FixedClock, make_catalog, make_principal, record_case

from ai_soc.content.catalog import ContentCatalog
from ai_soc.contracts.models import (
    AskRequest,
    Clarified,
    FollowupRecord,
    LeftOut,
    LeftOutReason,
    Planned,
    Refused,
    VerifiedPrincipal,
)
from ai_soc.planning.followups import InvalidContinuation, transform_followup
from ai_soc.planning.parser import DeterministicPlanner

POLICY_HASH = "a" * 64
QA006_FIXTURE = Path(__file__).parent / "data/qa006_variants.json"


def _qa006_fixture() -> dict[str, object]:
    return json.loads(QA006_FIXTURE.read_text(encoding="utf-8"))


def test_continuation_refreshes_only_selected_left_out_topic_and_keeps_parent_immutable(
    record_property: Callable[[str, str], None],
) -> None:
    fixture = _qa006_fixture()["positive"]
    assert fixture == {
        "selected": ["dns"],
        "expected_topics": ["dns"],
        "expected_origin": "leftout_followup",
    }
    record_case(
        record_property,
        requirements=("G004", "G019", "G028"),
        case_id="QA-006.resolution",
        variant="positive",
        fixture=QA006_FIXTURE,
    )
    principal = make_principal()
    catalog = make_catalog()
    original = DeterministicPlanner(catalog).plan(
        AskRequest(
            question="LDAP is failing; DNS is failing; TLS is failing; recommend fixes",
            environment_id="alpha",
            timezone="UTC",
        ),
        principal,
        None,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )
    assert isinstance(original, Planned)
    parent = original.plan
    old_dns = parent.topics[1]
    record = FollowupRecord(
        followup_id=uuid4(),
        owner_key=principal.owner_key,
        environment_id="alpha",
        revision=1,
        plan=parent,
        answered_topic_ids=["ldap"],
        leftout_topic_ids=["dns", "tls"],
        leftout_stages=[
            LeftOut(
                topic_id="dns",
                stage="judgment",
                reason=LeftOutReason.capacity_limited,
                retryable=True,
            ),
            LeftOut(
                topic_id="tls",
                stage="judgment",
                reason=LeftOutReason.deadline_exceeded,
                retryable=True,
            ),
        ],
        created_at=datetime(2026, 9, 30, 12, tzinfo=UTC),
        expires_at=datetime(2026, 10, 1, 12, tzinfo=UTC),
    )
    result = transform_followup(
        AskRequest(
            question="continue the left-out judgments",
            environment_id="alpha",
            followup_id=record.followup_id,
            followup_revision=record.revision,
            continue_topic_ids=["dns"],
            timezone="UTC",
        ),
        principal,
        record,
        catalog=catalog,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )
    assert isinstance(result, Planned)
    assert [topic.topic_id for topic in result.plan.topics] == ["dns"]
    assert result.plan.topics[0].ordinal == 1
    assert result.plan.topics[0].judgment
    assert result.plan.provenance.origin == "leftout_followup"
    assert parent.topics[1] == old_dns
    assert len(parent.topics) == 3

    fetch_plan = DeterministicPlanner(make_catalog(("ldap",))).plan(
        AskRequest(
            question="Show LDAP alerts for the last 24 hours",
            environment_id="alpha",
            timezone="UTC",
        ),
        principal,
        None,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )
    assert isinstance(fetch_plan, Planned)
    keep_record = FollowupRecord(
        followup_id=uuid4(),
        owner_key=principal.owner_key,
        environment_id="alpha",
        revision=1,
        plan=fetch_plan.plan,
        answered_topic_ids=["ldap"],
        leftout_topic_ids=[],
        leftout_stages=[],
        created_at=datetime(2026, 9, 30, 12, tzinfo=UTC),
        expires_at=datetime(2026, 10, 1, 12, tzinfo=UTC),
    )
    kept = transform_followup(
        AskRequest(
            question="LDAP, keep those alerts",
            environment_id="alpha",
            followup_id=keep_record.followup_id,
            followup_revision=keep_record.revision,
            timezone="UTC",
        ),
        principal,
        keep_record,
        catalog=make_catalog(("ldap",)),
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )
    assert isinstance(kept, Planned)
    assert kept.plan.provenance.origin == "explicit_keep"
    assert kept.plan.topics[0].fetches[0].window == fetch_plan.plan.topics[0].fetches[0].window


def test_continuation_rejects_topic_outside_left_out_set(
    record_property: Callable[[str, str], None],
) -> None:
    fixture = _qa006_fixture()["negative"]
    assert fixture == {
        "left_out": ["ldap"],
        "requested": ["dns"],
        "prior_fetch_topic": "ldap",
        "cross_topic_keep": "DNS, keep those alerts",
        "expected_cross_topic": "clarified",
    }
    record_case(
        record_property,
        requirements=("G004", "G019", "G028"),
        case_id="QA-006.resolution",
        variant="negative",
        fixture=QA006_FIXTURE,
    )
    principal = make_principal()
    catalog = make_catalog(("ldap", "dns"))
    original = DeterministicPlanner(catalog).plan(
        AskRequest(question="LDAP is failing", environment_id="alpha", timezone="UTC"),
        principal,
        None,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )
    assert isinstance(original, Planned)
    parent = original.plan
    record = FollowupRecord(
        followup_id=uuid4(),
        owner_key=principal.owner_key,
        environment_id="alpha",
        revision=1,
        plan=parent,
        answered_topic_ids=[],
        leftout_topic_ids=["ldap"],
        leftout_stages=[
            LeftOut(
                topic_id="ldap",
                stage="judgment",
                reason=LeftOutReason.capacity_limited,
                retryable=True,
            ),
        ],
        created_at=datetime(2026, 9, 30, 12, tzinfo=UTC),
        expires_at=datetime(2026, 10, 1, 12, tzinfo=UTC),
    )
    with pytest.raises(InvalidContinuation):
        transform_followup(
            AskRequest(
                question="continue the left-out judgments",
                environment_id="alpha",
                followup_id=record.followup_id,
                followup_revision=record.revision,
                continue_topic_ids=["dns"],
                timezone="UTC",
            ),
            principal,
            record,
            catalog=catalog,
            policy_hash=POLICY_HASH,
            clock=FixedClock(),
        )

    fetch_plan = DeterministicPlanner(catalog).plan(
        AskRequest(
            question="Show LDAP alerts for the last 24 hours",
            environment_id="alpha",
            timezone="UTC",
        ),
        principal,
        None,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )
    assert isinstance(fetch_plan, Planned)
    keep_record = FollowupRecord(
        followup_id=uuid4(),
        owner_key=principal.owner_key,
        environment_id="alpha",
        revision=1,
        plan=fetch_plan.plan,
        answered_topic_ids=["ldap"],
        leftout_topic_ids=[],
        leftout_stages=[],
        created_at=datetime(2026, 9, 30, 12, tzinfo=UTC),
        expires_at=datetime(2026, 10, 1, 12, tzinfo=UTC),
    )
    cross_topic_keep = transform_followup(
        AskRequest(
            question=fixture["cross_topic_keep"],
            environment_id="alpha",
            followup_id=keep_record.followup_id,
            followup_revision=keep_record.revision,
            timezone="UTC",
        ),
        principal,
        keep_record,
        catalog=catalog,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )
    assert fixture["expected_cross_topic"] == "clarified"
    assert isinstance(cross_topic_keep, Clarified)


def test_window_followup_refreshes_every_fetch_without_mutating_previous_plan(
    record_property: Callable[[str, str], None],
) -> None:
    fixture = _qa006_fixture()["boundary"]
    assert fixture == {
        "prior_window_hours": 24,
        "requested_window_days": 7,
        "expected_start": "2026-09-23T12:00:00+00:00",
        "new_topic_question": "DNS is failing",
        "expected_new_topics": ["dns"],
    }
    record_case(
        record_property,
        requirements=("G004", "G019", "G028"),
        case_id="QA-006.resolution",
        variant="boundary",
        fixture=QA006_FIXTURE,
    )
    principal = make_principal()
    catalog = make_catalog(("ldap", "dns"))
    original = DeterministicPlanner(catalog).plan(
        AskRequest(
            question="Show LDAP alerts for the last 24 hours",
            environment_id="alpha",
            timezone="UTC",
        ),
        principal,
        None,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )
    assert isinstance(original, Planned)
    parent = original.plan
    parent_window = parent.topics[0].fetches[0].window
    record = FollowupRecord(
        followup_id=uuid4(),
        owner_key=principal.owner_key,
        environment_id="alpha",
        revision=1,
        plan=parent,
        answered_topic_ids=["ldap"],
        leftout_topic_ids=[],
        leftout_stages=[],
        created_at=datetime(2026, 9, 30, 12, tzinfo=UTC),
        expires_at=datetime(2026, 10, 1, 12, tzinfo=UTC),
    )
    result = transform_followup(
        AskRequest(
            question="and for the last 7 days?",
            environment_id="alpha",
            followup_id=record.followup_id,
            followup_revision=record.revision,
            timezone="UTC",
        ),
        principal,
        record,
        catalog=catalog,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )
    assert isinstance(result, Planned)
    refreshed = result.plan.topics[0].fetches[0].window
    assert refreshed.start.isoformat() == "2026-09-23T12:00:00+00:00"
    assert refreshed != parent_window
    assert parent.topics[0].fetches[0].window == parent_window
    assert result.plan.provenance.origin == "window_followup"
    new_topic = DeterministicPlanner(catalog).plan(
        AskRequest(
            question=fixture["new_topic_question"],
            environment_id="alpha",
            followup_id=record.followup_id,
            followup_revision=record.revision,
            timezone="UTC",
        ),
        principal,
        record,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )
    assert fixture["expected_new_topics"] == ["dns"]
    assert isinstance(new_topic, Planned)
    assert [topic.topic_id for topic in new_topic.plan.topics] == ["dns"]
    assert new_topic.plan.provenance.previous_question_id is None


def test_window_followup_adds_playbook_window_override_for_failure_topics() -> None:
    principal = make_principal()
    catalog = make_catalog(("ldap",))
    original = DeterministicPlanner(catalog).plan(
        AskRequest(question="LDAP is failing", environment_id="alpha", timezone="UTC"),
        principal,
        None,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )
    assert isinstance(original, Planned)
    assert original.plan.topics[0].playbook_id == "ldap_checks"
    assert original.plan.topics[0].fetches == []
    record = FollowupRecord(
        followup_id=uuid4(),
        owner_key=principal.owner_key,
        environment_id="alpha",
        revision=1,
        plan=original.plan,
        answered_topic_ids=["ldap"],
        leftout_topic_ids=[],
        leftout_stages=[],
        created_at=datetime(2026, 9, 30, 12, tzinfo=UTC),
        expires_at=datetime(2026, 10, 1, 12, tzinfo=UTC),
    )
    result = transform_followup(
        AskRequest(
            question="and for the last 7 days?",
            environment_id="alpha",
            followup_id=record.followup_id,
            followup_revision=record.revision,
            timezone="UTC",
        ),
        principal,
        record,
        catalog=catalog,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )
    assert isinstance(result, Planned)
    topic = result.plan.topics[0]
    assert topic.fetches == []
    assert topic.playbook_window is not None
    assert topic.playbook_window.start.isoformat() == "2026-09-23T12:00:00+00:00"


def test_quoted_and_for_does_not_apply_window_followup_transform() -> None:
    principal = make_principal()
    catalog = make_catalog(("ldap",))
    original = DeterministicPlanner(catalog).plan(
        AskRequest(question="LDAP is failing", environment_id="alpha", timezone="UTC"),
        principal,
        None,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )
    assert isinstance(original, Planned)
    record = FollowupRecord(
        followup_id=uuid4(),
        owner_key=principal.owner_key,
        environment_id="alpha",
        revision=1,
        plan=original.plan,
        answered_topic_ids=["ldap"],
        leftout_topic_ids=[],
        leftout_stages=[],
        created_at=datetime(2026, 9, 30, 12, tzinfo=UTC),
        expires_at=datetime(2026, 10, 1, 12, tzinfo=UTC),
    )
    result = transform_followup(
        AskRequest(
            question='"and for the last 7 days?"',
            environment_id="alpha",
            followup_id=record.followup_id,
            followup_revision=record.revision,
            timezone="UTC",
        ),
        principal,
        record,
        catalog=catalog,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )
    assert result is None


def test_spanish_window_followup_with_leading_punctuation() -> None:
    principal = make_principal()
    catalog = make_catalog(("ldap",))
    original = DeterministicPlanner(catalog).plan(
        AskRequest(question="LDAP is failing", environment_id="alpha", timezone="UTC"),
        principal,
        None,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )
    assert isinstance(original, Planned)
    record = FollowupRecord(
        followup_id=uuid4(),
        owner_key=principal.owner_key,
        environment_id="alpha",
        revision=1,
        plan=original.plan,
        answered_topic_ids=["ldap"],
        leftout_topic_ids=[],
        leftout_stages=[],
        created_at=datetime(2026, 9, 30, 12, tzinfo=UTC),
        expires_at=datetime(2026, 10, 1, 12, tzinfo=UTC),
    )
    result = transform_followup(
        AskRequest(
            question="¿y para los ultimos 7 dias?",
            environment_id="alpha",
            followup_id=record.followup_id,
            followup_revision=record.revision,
            timezone="UTC",
        ),
        principal,
        record,
        catalog=catalog,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )
    assert isinstance(result, Planned)
    assert result.plan.provenance.origin == "window_followup"


def test_window_followup_refreshes_playbook_window_when_topic_has_fetches() -> None:
    principal = make_principal()
    catalog = make_catalog(("ldap",))
    original = DeterministicPlanner(catalog).plan(
        AskRequest(
            question="LDAP is failing; show LDAP alerts for the last 7 days",
            environment_id="alpha",
            timezone="UTC",
        ),
        principal,
        None,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )
    assert isinstance(original, Planned)
    topic = original.plan.topics[0]
    assert topic.playbook_id is not None
    assert topic.fetches
    record = FollowupRecord(
        followup_id=uuid4(),
        owner_key=principal.owner_key,
        environment_id="alpha",
        revision=1,
        plan=original.plan,
        answered_topic_ids=["ldap"],
        leftout_topic_ids=[],
        leftout_stages=[],
        created_at=datetime(2026, 9, 30, 12, tzinfo=UTC),
        expires_at=datetime(2026, 10, 1, 12, tzinfo=UTC),
    )
    result = transform_followup(
        AskRequest(
            question="and for the last 3 days?",
            environment_id="alpha",
            followup_id=record.followup_id,
            followup_revision=record.revision,
            timezone="UTC",
        ),
        principal,
        record,
        catalog=catalog,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )
    assert isinstance(result, Planned)
    refreshed = result.plan.topics[0]
    assert refreshed.playbook_window is not None
    assert refreshed.playbook_window.start.isoformat() == "2026-09-27T12:00:00+00:00"
    assert refreshed.fetches[0].window == refreshed.playbook_window


def test_explicit_keep_requires_same_topic_and_reuses_only_the_window() -> None:
    principal = make_principal()
    catalog = make_catalog(("ldap", "dns"))
    original = DeterministicPlanner(catalog).plan(
        AskRequest(
            question="Show LDAP alerts for the last 24 hours",
            environment_id="alpha",
            timezone="UTC",
        ),
        principal,
        None,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )
    assert isinstance(original, Planned)
    record = FollowupRecord(
        followup_id=uuid4(),
        owner_key=principal.owner_key,
        environment_id="alpha",
        revision=1,
        plan=original.plan,
        answered_topic_ids=["ldap"],
        leftout_topic_ids=[],
        leftout_stages=[],
        created_at=datetime(2026, 9, 30, 12, tzinfo=UTC),
        expires_at=datetime(2026, 10, 1, 12, tzinfo=UTC),
    )
    common = {
        "environment_id": "alpha",
        "followup_id": record.followup_id,
        "followup_revision": record.revision,
        "timezone": "UTC",
    }
    kept = transform_followup(
        AskRequest(question="LDAP, keep those alerts", **common),
        principal,
        record,
        catalog=catalog,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )
    assert isinstance(kept, Planned)
    assert kept.plan.provenance.origin == "explicit_keep"
    assert kept.plan.topics[0].fetches[0].window == original.plan.topics[0].fetches[0].window
    wrong_topic = transform_followup(
        AskRequest(question="DNS, keep those alerts", **common),
        principal,
        record,
        catalog=catalog,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )
    assert wrong_topic is not None and not isinstance(wrong_topic, Planned)


def test_planner_policy_binding_matches_independent_oracles_and_rejects_stale_followups(
    record_property: Callable[[str, str], None],
) -> None:
    fixture = _qa006_fixture()["failure"]
    assert fixture == {"prior_policy_hash": "b" * 64, "current_policy_hash": "a" * 64}
    record_case(
        record_property,
        requirements=("G004", "G019", "G028"),
        case_id="QA-006.resolution",
        variant="failure",
        fixture=QA006_FIXTURE,
    )
    oracle_path = Path(__file__).resolve().parents[2] / "fixtures/v1/policy_binding_oracles.json"
    oracle = json.loads(oracle_path.read_text())
    principal = make_principal()
    catalog = make_catalog(("ldap",))
    planner = DeterministicPlanner(catalog)
    for case in oracle["cases"]:
        current_hash = case["current_policy_hash"]
        prior_hash = case["prior_plan_policy_hash"]
        original = planner.plan(
            AskRequest(question="LDAP is failing", environment_id="alpha", timezone="UTC"),
            principal,
            None,
            policy_hash=current_hash,
            clock=FixedClock(),
        )
        assert isinstance(original, Planned)
        assert original.plan.policy_hash == current_hash
        if case["expected"] == "reject-before-planning":
            prior_plan = original.plan.model_copy(update={"policy_hash": prior_hash})
            record = FollowupRecord(
                followup_id=uuid4(),
                owner_key=principal.owner_key,
                environment_id="alpha",
                revision=1,
                plan=prior_plan,
                answered_topic_ids=["ldap"],
                leftout_topic_ids=[],
                leftout_stages=[],
                created_at=datetime(2026, 9, 30, 12, tzinfo=UTC),
                expires_at=datetime(2026, 10, 1, 12, tzinfo=UTC),
            )
            rejected = planner.plan(
                AskRequest(
                    question="and for the last 7 days",
                    environment_id="alpha",
                    followup_id=record.followup_id,
                    followup_revision=record.revision,
                    timezone="UTC",
                ),
                principal,
                record,
                policy_hash=current_hash,
                clock=FixedClock(),
            )
            assert isinstance(rejected, Refused)
        else:
            assert case["expected"] == "plan-uses-current-authorized-policy"


def test_planner_rejects_followups_from_foreign_owner_site_or_content() -> None:
    principal = make_principal()
    catalog = make_catalog(("ldap",))
    planner = DeterministicPlanner(catalog)
    original = planner.plan(
        AskRequest(question="LDAP is failing", environment_id="alpha", timezone="UTC"),
        principal,
        None,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )
    assert isinstance(original, Planned)
    fixtures = (
        {"owner_key": "8" * 64},
        {"environment_id": "beta"},
        {"plan": original.plan.model_copy(update={"content_sha": "9" * 40})},
    )
    for updates in fixtures:
        record = FollowupRecord(
            followup_id=uuid4(),
            owner_key=principal.owner_key,
            environment_id="alpha",
            revision=1,
            plan=original.plan,
            answered_topic_ids=["ldap"],
            leftout_topic_ids=[],
            leftout_stages=[],
            created_at=datetime(2026, 9, 30, 12, tzinfo=UTC),
            expires_at=datetime(2026, 10, 1, 12, tzinfo=UTC),
        ).model_copy(update=updates)
        result = planner.plan(
            AskRequest(
                question="and for the last 7 days",
                environment_id="alpha",
                followup_id=record.followup_id,
                followup_revision=record.revision,
                timezone="UTC",
            ),
            principal,
            record,
            policy_hash=POLICY_HASH,
            clock=FixedClock(),
        )
        assert isinstance(result, Refused)


def _record_without_retryable_left_outs() -> tuple[
    FollowupRecord, VerifiedPrincipal, ContentCatalog
]:
    principal = make_principal()
    catalog = make_catalog(("ldap", "dns"))
    original = DeterministicPlanner(catalog).plan(
        AskRequest(question="LDAP is failing", environment_id="alpha", timezone="UTC"),
        principal,
        None,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )
    assert isinstance(original, Planned)
    record = FollowupRecord(
        followup_id=uuid4(),
        owner_key=principal.owner_key,
        environment_id="alpha",
        revision=1,
        plan=original.plan,
        answered_topic_ids=[],
        leftout_topic_ids=[],
        leftout_stages=[],
        created_at=datetime(2026, 9, 30, 12, tzinfo=UTC),
        expires_at=datetime(2026, 10, 1, 12, tzinfo=UTC),
    )
    return record, principal, catalog


def _continue(
    record: FollowupRecord,
    principal: VerifiedPrincipal,
    catalog: ContentCatalog,
    topics: list[str] | None,
) -> Planned | Clarified | Refused | None:
    return transform_followup(
        AskRequest(
            question="continue the left-out judgments",
            environment_id="alpha",
            followup_id=record.followup_id,
            followup_revision=record.revision,
            continue_topic_ids=topics,
            timezone="UTC",
        ),
        principal,
        record,
        catalog=catalog,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )


def test_explicit_continuation_of_a_non_retryable_left_out_is_invalid() -> None:
    record, principal, catalog = _record_without_retryable_left_outs()

    with pytest.raises(InvalidContinuation):
        _continue(record, principal, catalog, ["ldap"])


def test_bare_continuation_without_retryable_left_outs_is_refused() -> None:
    record, principal, catalog = _record_without_retryable_left_outs()

    assert isinstance(_continue(record, principal, catalog, None), Refused)
