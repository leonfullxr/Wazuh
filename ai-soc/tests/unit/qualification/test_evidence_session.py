from __future__ import annotations

import hashlib
import io
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from botocore.config import Config
from botocore.exceptions import ParamValidationError
from botocore.session import Session
from botocore.stub import Stubber

from ai_soc.qualification.evidence import CanaryEnvelope, EvidencePaths
from scripts.qualification.canary_delivery import VerifiedCanaryDelivery
from scripts.qualification.evidence_session import (
    SettingsJournal,
    install_cloudtrail_write_selectors,
    install_xray_sampling_rule,
    measured_delivery_budget_seconds,
    read_canary_object_version,
    restore_cloudtrail_selectors,
    restore_xray_sampling_rule,
    verify_canary_delivery,
)
from scripts.qualification.settings_journal import UncertainMutation
from scripts.qualification.settings_session import SettingConflict


class CloudTrail:
    def __init__(self) -> None:
        self.meta = SimpleNamespace(
            config=Config(retries={"total_max_attempts": 1, "mode": "standard"})
        )
        self.current: dict[str, Any] = {"EventSelectors": [{"IncludeManagementEvents": True}]}
        self.installed: dict[str, Any] | None = None

    def get_event_selectors(self, **_kwargs: Any) -> dict[str, Any]:
        return self.current

    def put_event_selectors(self, **kwargs: Any) -> None:
        self.installed = kwargs
        self.current = {"EventSelectors": kwargs["EventSelectors"]}


def xray_client() -> Any:
    return Session().create_client(
        "xray",
        region_name="eu-west-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"total_max_attempts": 1, "mode": "standard"}),
    )


def sampling_rule(name: str, *, version: int = 1) -> dict[str, Any]:
    return {
        "RuleName": name,
        "ResourceARN": "*",
        "Priority": 1000,
        "FixedRate": 1.0,
        "ReservoirSize": 1,
        "ServiceName": "ai-soc",
        "ServiceType": "*",
        "Host": "*",
        "HTTPMethod": "*",
        "URLPath": "*",
        "Version": version,
    }


def sampling_rule_record(rule: dict[str, Any]) -> dict[str, Any]:
    installed = {
        **rule,
        "RuleARN": f"arn:aws:xray:eu-west-1:123456789012:rule/{rule['RuleName']}",
        "Attributes": rule.get("Attributes", {}),
    }
    created = datetime(2026, 10, 8, 10, 0, tzinfo=UTC)
    return {"SamplingRule": installed, "CreatedAt": created, "ModifiedAt": created}


class S3ObjectReader:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.request: dict[str, Any] | None = None

    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        self.request = kwargs
        return {
            "VersionId": kwargs["VersionId"],
            "Body": io.BytesIO(self.body),
            "Metadata": {"sha256": hashlib.sha256(self.body).hexdigest()},
        }


def test_cloudtrail_selectors_are_run_scoped_preserve_management_and_restore(
    tmp_path: Path,
) -> None:
    client = CloudTrail()
    journal = SettingsJournal(tmp_path / "journal.json")
    install_cloudtrail_write_selectors(
        client,
        journal,
        trail_name="bound-trail",
        bucket="evidence",
        evidence_paths=EvidencePaths(
            app_prefix="qualification/",
            consumer_prefix="events/qualification/",
            map_key="qualification-maps/resource-map.json",
            input_prefix="qualification-inputs/",
        ),
        session_id="session-7",
        run_id="run-123",
    )

    assert client.installed is not None
    selectors = client.installed["EventSelectors"]
    assert selectors[0] == {"IncludeManagementEvents": True}
    assert selectors[1] == {
        "ReadWriteType": "WriteOnly",
        "IncludeManagementEvents": False,
        "DataResources": [
            {
                "Type": "AWS::S3::Object",
                "Values": [
                    "arn:aws:s3:::evidence/qualification/session-7/",
                    "arn:aws:s3:::evidence/events/qualification/run-123/",
                ],
            }
        ],
    }
    persisted = json.loads((tmp_path / "journal.json").read_text())
    assert persisted["entries"]["cloudtrail:bound-trail"]["before"] == {
        "EventSelectors": [{"IncludeManagementEvents": True}]
    }
    assert os.stat(tmp_path / "journal.json").st_mode & 0o777 == 0o600

    restore_cloudtrail_selectors(journal, client, "bound-trail")
    assert client.current == {"EventSelectors": [{"IncludeManagementEvents": True}]}
    assert not journal.pending


def test_cloudtrail_selector_install_refuses_intervening_selector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = CloudTrail()
    journal = SettingsJournal(tmp_path / "journal.json")
    original_read = client.get_event_selectors
    read_calls = 0
    intervening = {"IncludeManagementEvents": False, "ReadWriteType": "All"}

    def add_selector_before_write(**kwargs: Any) -> dict[str, Any]:
        nonlocal read_calls
        read_calls += 1
        if read_calls == 2:
            client.current = {"EventSelectors": [*client.current["EventSelectors"], intervening]}
        return original_read(**kwargs)

    monkeypatch.setattr(client, "get_event_selectors", add_selector_before_write)

    with pytest.raises(SettingConflict, match="changed after observation"):
        install_cloudtrail_write_selectors(
            client,
            journal,
            trail_name="bound-trail",
            bucket="evidence",
            evidence_paths=EvidencePaths(
                app_prefix="qualification/",
                consumer_prefix="events/qualification/",
                map_key="qualification-maps/resource-map.json",
                input_prefix="qualification-inputs/",
            ),
            session_id="session-7",
            run_id="run-123",
        )

    assert read_calls == 2
    assert client.installed is None
    assert client.current["EventSelectors"][-1] == intervening
    assert not journal.pending


def test_sampling_rule_is_journaled_and_removed_on_restore(tmp_path: Path) -> None:
    client = xray_client()
    rule = sampling_rule("qualification-run")
    journal = SettingsJournal(tmp_path / "journal.json")
    with Stubber(client) as stubber:
        stubber.add_response("get_sampling_rules", {"SamplingRuleRecords": []}, {})
        record = sampling_rule_record(rule)
        stubber.add_response(
            "create_sampling_rule", {"SamplingRuleRecord": record}, {"SamplingRule": rule}
        )
        stubber.add_response("get_sampling_rules", {"SamplingRuleRecords": [record]}, {})
        stubber.add_response("delete_sampling_rule", {}, {"RuleName": "qualification-run"})
        stubber.add_response("get_sampling_rules", {"SamplingRuleRecords": []}, {})
        install_xray_sampling_rule(client, journal, rule)
        assert journal.pending["xray:qualification-run"].before is None
        assert journal.pending["xray:qualification-run"].after == record["SamplingRule"]
        restore_xray_sampling_rule(journal, client, "qualification-run")
        stubber.assert_no_pending_responses()
    assert not journal.pending


def test_sampling_create_interruption_keeps_obligation_after_reconciliation_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = xray_client()
    rule = sampling_rule("qualification-run")
    record = sampling_rule_record(rule)
    journal_path = tmp_path / "journal.json"
    journal = SettingsJournal(journal_path)
    stubber = Stubber(client)
    stubber.add_response("get_sampling_rules", {"SamplingRuleRecords": []}, {})
    stubber.add_response(
        "create_sampling_rule", {"SamplingRuleRecord": record}, {"SamplingRule": rule}
    )
    stubber.add_response("get_sampling_rules", {"SamplingRuleRecords": []}, {})
    stubber.add_response("get_sampling_rules", {"SamplingRuleRecords": [record]}, {})
    create = client.create_sampling_rule

    def interrupt_after_send(**kwargs: Any) -> dict[str, Any]:
        in_flight = json.loads(journal_path.read_text())
        assert in_flight["entries"]["xray:qualification-run"]["uncertain_until"]
        create(**kwargs)
        raise KeyboardInterrupt

    monkeypatch.setattr(client, "create_sampling_rule", interrupt_after_send)
    with stubber:
        with pytest.raises(KeyboardInterrupt):
            install_xray_sampling_rule(client, journal, rule)

        journal.mark_uncertain(
            "xray:qualification-run",
            until=datetime(2020, 1, 1, tzinfo=UTC),
            target=rule,
        )
        restarted_journal = SettingsJournal(journal_path)
        assert isinstance(restarted_journal.pending["xray:qualification-run"], UncertainMutation)
        with pytest.raises(RuntimeError, match="outcome is still uncertain"):
            restore_xray_sampling_rule(restarted_journal, client, "qualification-run")
        assert "xray:qualification-run" in restarted_journal.pending
        with pytest.raises(RuntimeError, match="outcome is still uncertain"):
            restore_xray_sampling_rule(restarted_journal, client, "qualification-run")
        stubber.assert_no_pending_responses()
    assert "xray:qualification-run" in restarted_journal.pending


def test_unsent_sampling_validation_failure_clears_journal_and_allows_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = xray_client()
    rule = sampling_rule("qualification-run")
    record = sampling_rule_record(rule)
    journal = SettingsJournal(tmp_path / "journal.json")
    stubber = Stubber(client)
    stubber.add_response("get_sampling_rules", {"SamplingRuleRecords": []}, {})
    stubber.add_response("get_sampling_rules", {"SamplingRuleRecords": []}, {})
    stubber.add_response(
        "create_sampling_rule", {"SamplingRuleRecord": record}, {"SamplingRule": rule}
    )
    stubber.add_response("get_sampling_rules", {"SamplingRuleRecords": [record]}, {})
    stubber.add_response("delete_sampling_rule", {}, {"RuleName": "qualification-run"})
    stubber.add_response("get_sampling_rules", {"SamplingRuleRecords": []}, {})
    create = client.create_sampling_rule

    def reject_before_send(**_kwargs: Any) -> dict[str, Any]:
        raise ParamValidationError(report="Invalid local X-Ray request parameters")

    with stubber:
        monkeypatch.setattr(client, "create_sampling_rule", reject_before_send)
        with pytest.raises(ParamValidationError):
            install_xray_sampling_rule(client, journal, rule)
        assert not journal.pending

        monkeypatch.setattr(client, "create_sampling_rule", create)
        install_xray_sampling_rule(client, journal, rule)
        assert journal.pending["xray:qualification-run"].after == record["SamplingRule"]
        restore_xray_sampling_rule(journal, client, "qualification-run")
        stubber.assert_no_pending_responses()
    assert not journal.pending


def test_sampling_rule_paginates_and_uses_update_shape_for_install_and_restore(
    tmp_path: Path,
) -> None:
    client = xray_client()
    old = sampling_rule("qualification-run", version=3)
    old["RuleARN"] = "arn:aws:xray:eu-west-1:123456789012:rule/qualification-run"
    old["Attributes"] = {"owner": "previous"}
    desired = {**sampling_rule("qualification-run", version=99), "Attributes": {"owner": "test"}}
    journal = SettingsJournal(tmp_path / "journal.json")
    stubber = Stubber(client)
    stubber.add_response(
        "get_sampling_rules",
        {
            "SamplingRuleRecords": [sampling_rule_record(sampling_rule("other"))],
            "NextToken": "page-2",
        },
        {},
    )
    stubber.add_response(
        "get_sampling_rules",
        {"SamplingRuleRecords": [sampling_rule_record(old)]},
        {"NextToken": "page-2"},
    )
    update_expected = {key: value for key, value in desired.items() if key != "Version"}
    stubber.add_response("update_sampling_rule", {}, {"SamplingRuleUpdate": update_expected})
    stubber.add_response(
        "get_sampling_rules", {"SamplingRuleRecords": [sampling_rule_record(desired)]}, {}
    )
    stubber.add_response(
        "update_sampling_rule",
        {},
        {
            "SamplingRuleUpdate": {
                key: value for key, value in old.items() if key not in {"Version", "RuleARN"}
            }
        },
    )
    stubber.add_response(
        "get_sampling_rules", {"SamplingRuleRecords": [sampling_rule_record(old)]}, {}
    )
    with stubber:
        install_xray_sampling_rule(client, journal, desired)
        assert journal.pending["xray:qualification-run"].before == old
        restore_xray_sampling_rule(journal, client, "qualification-run")
        stubber.assert_no_pending_responses()


def test_interrupted_sampling_update_stays_unresolved_after_late_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = sampling_rule("qualification-run", version=1)
    desired = {**sampling_rule("qualification-run", version=2), "FixedRate": 0.25}

    class StatefulXRay:
        meta = SimpleNamespace(config=Config(retries={"total_max_attempts": 1, "mode": "standard"}))
        current = sampling_rule_record(old)["SamplingRule"]
        updates: list[dict[str, Any]] = []

        def get_sampling_rules(self, **_kwargs: Any) -> dict[str, Any]:
            return {"SamplingRuleRecords": [{"SamplingRule": self.current}]}

        def update_sampling_rule(self, **kwargs: Any) -> dict[str, Any]:
            update = kwargs["SamplingRuleUpdate"]
            self.updates.append(update)
            self.current = {**self.current, **update}
            return {}

    client = StatefulXRay()
    journal_path = tmp_path / "journal.json"
    journal = SettingsJournal(journal_path)
    pending: dict[str, Any] = {}

    def interrupt_after_send(**kwargs: Any) -> dict[str, Any]:
        state = json.loads(journal_path.read_text())
        pending.update(kwargs["SamplingRuleUpdate"])
        assert state["entries"]["xray:qualification-run"]["in_flight_target"] == desired
        raise KeyboardInterrupt

    monkeypatch.setattr("scripts.qualification.settings_session.time.sleep", lambda _delay: None)
    monkeypatch.setattr(client, "update_sampling_rule", interrupt_after_send)
    with pytest.raises(KeyboardInterrupt):
        install_xray_sampling_rule(client, journal, desired)

    restarted = SettingsJournal(journal_path)
    with pytest.raises(RuntimeError, match="outcome is still uncertain"):
        restore_xray_sampling_rule(restarted, client, "qualification-run")
    assert len(client.updates) == 0
    assert "xray:qualification-run" in restarted.pending

    client.current = {**client.current, **pending}
    with pytest.raises(RuntimeError, match="outcome is still uncertain"):
        restore_xray_sampling_rule(restarted, client, "qualification-run")
    assert client.current["FixedRate"] == desired["FixedRate"]
    assert len(client.updates) == 0
    assert "xray:qualification-run" in restarted.pending


def test_interrupted_cloudtrail_selector_put_stays_unresolved_after_late_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = CloudTrail()
    journal_path = tmp_path / "journal.json"
    journal = SettingsJournal(journal_path)
    pending: dict[str, Any] = {}
    put_calls = 0

    def interrupt_after_send(**kwargs: Any) -> None:
        nonlocal put_calls
        put_calls += 1
        state = json.loads(journal_path.read_text())
        pending.update({"EventSelectors": kwargs["EventSelectors"]})
        assert state["entries"]["cloudtrail:bound-trail"]["in_flight_target"] == pending
        raise KeyboardInterrupt

    monkeypatch.setattr("scripts.qualification.settings_session.time.sleep", lambda _delay: None)
    monkeypatch.setattr(client, "put_event_selectors", interrupt_after_send)
    with pytest.raises(KeyboardInterrupt):
        install_cloudtrail_write_selectors(
            client,
            journal,
            trail_name="bound-trail",
            bucket="evidence",
            evidence_paths=EvidencePaths(
                app_prefix="qualification/",
                consumer_prefix="events/qualification/",
                map_key="qualification-maps/resource-map.json",
                input_prefix="qualification-inputs/",
            ),
            session_id="session-7",
            run_id="run-123",
        )

    restarted = SettingsJournal(journal_path)
    with pytest.raises(RuntimeError, match="outcome is still uncertain"):
        restore_cloudtrail_selectors(restarted, client, "bound-trail")
    assert put_calls == 1
    assert "cloudtrail:bound-trail" in restarted.pending

    client.current = pending
    with pytest.raises(RuntimeError, match="outcome is still uncertain"):
        restore_cloudtrail_selectors(restarted, client, "bound-trail")
    assert client.current == pending
    assert put_calls == 1
    assert "cloudtrail:bound-trail" in restarted.pending


def test_interrupted_sampling_restore_stays_unresolved_when_read_matches_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = sampling_rule("qualification-run", version=1)
    after = {**sampling_rule("qualification-run", version=2), "FixedRate": 0.25}

    class StatefulXRay:
        meta = SimpleNamespace(config=Config(retries={"total_max_attempts": 1, "mode": "standard"}))
        current = sampling_rule_record(after)["SamplingRule"]
        update_calls = 0

        def get_sampling_rules(self, **_kwargs: Any) -> dict[str, Any]:
            return {"SamplingRuleRecords": [{"SamplingRule": self.current}]}

        def update_sampling_rule(self, **kwargs: Any) -> dict[str, Any]:
            self.update_calls += 1
            assert kwargs["SamplingRuleUpdate"]["FixedRate"] == before["FixedRate"]
            raise KeyboardInterrupt

    client = StatefulXRay()
    journal_path = tmp_path / "journal.json"
    journal = SettingsJournal(journal_path)
    journal.record("xray:qualification-run", before, after)
    monkeypatch.setattr("scripts.qualification.settings_session.time.sleep", lambda _delay: None)

    with pytest.raises(KeyboardInterrupt):
        restore_xray_sampling_rule(journal, client, "qualification-run")

    restarted = SettingsJournal(journal_path)
    for _ in range(2):
        with pytest.raises(RuntimeError, match="outcome is still uncertain"):
            restore_xray_sampling_rule(restarted, client, "qualification-run")
        assert client.update_calls == 1
        assert "xray:qualification-run" in restarted.pending

    client.current = sampling_rule_record(before)["SamplingRule"]
    with pytest.raises(RuntimeError, match="outcome is still uncertain"):
        restore_xray_sampling_rule(restarted, client, "qualification-run")
    assert client.update_calls == 1
    assert "xray:qualification-run" in restarted.pending


def test_interrupted_cloudtrail_restore_stays_unresolved_when_read_matches_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = CloudTrail()
    before = {"EventSelectors": [{"IncludeManagementEvents": True}]}
    after = {
        "EventSelectors": [
            {"IncludeManagementEvents": True},
            {
                "ReadWriteType": "WriteOnly",
                "IncludeManagementEvents": False,
                "DataResources": [
                    {"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::evidence/events/"]}
                ],
            },
        ]
    }
    client.current = after
    journal_path = tmp_path / "journal.json"
    journal = SettingsJournal(journal_path)
    journal.record("cloudtrail:bound-trail", before, after)
    put_calls = 0

    def interrupt_restore(**kwargs: Any) -> None:
        nonlocal put_calls
        put_calls += 1
        assert kwargs["EventSelectors"] == before["EventSelectors"]
        raise KeyboardInterrupt

    monkeypatch.setattr("scripts.qualification.settings_session.time.sleep", lambda _delay: None)
    monkeypatch.setattr(client, "put_event_selectors", interrupt_restore)
    with pytest.raises(KeyboardInterrupt):
        restore_cloudtrail_selectors(journal, client, "bound-trail")

    restarted = SettingsJournal(journal_path)
    for _ in range(2):
        with pytest.raises(RuntimeError, match="outcome is still uncertain"):
            restore_cloudtrail_selectors(restarted, client, "bound-trail")
        assert put_calls == 1
        assert "cloudtrail:bound-trail" in restarted.pending

    client.current = before
    with pytest.raises(RuntimeError, match="outcome is still uncertain"):
        restore_cloudtrail_selectors(restarted, client, "bound-trail")
    assert put_calls == 1
    assert "cloudtrail:bound-trail" in restarted.pending


def test_ambiguous_sampling_create_keeps_journal_when_late_completion_matches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = xray_client()
    rule = sampling_rule("qualification-run")
    record = sampling_rule_record(rule)
    journal = SettingsJournal(tmp_path / "journal.json")
    stubber = Stubber(client)
    stubber.add_response("get_sampling_rules", {"SamplingRuleRecords": []}, {})
    stubber.add_response(
        "create_sampling_rule", {"SamplingRuleRecord": record}, {"SamplingRule": rule}
    )
    stubber.add_response("get_sampling_rules", {"SamplingRuleRecords": [record]}, {})
    create = client.create_sampling_rule

    def create_then_timeout(**kwargs: Any) -> dict[str, Any]:
        create(**kwargs)
        raise TimeoutError("simulated response loss after remote creation")

    monkeypatch.setattr("scripts.qualification.settings_session.time.sleep", lambda _delay: None)
    monkeypatch.setattr(client, "create_sampling_rule", create_then_timeout)
    with stubber:
        with pytest.raises(TimeoutError, match="response loss"):
            install_xray_sampling_rule(client, journal, rule)
        assert isinstance(journal.pending["xray:qualification-run"], UncertainMutation)
        assert journal.pending["xray:qualification-run"].after == rule
        with pytest.raises(RuntimeError, match="outcome is still uncertain"):
            restore_xray_sampling_rule(journal, client, "qualification-run")
    stubber.assert_no_pending_responses()
    assert "xray:qualification-run" in journal.pending


def test_sampling_create_absence_during_reconciliation_retains_cleanup_obligation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = xray_client()
    rule = sampling_rule("qualification-run")
    journal = SettingsJournal(tmp_path / "journal.json")
    stubber = Stubber(client)
    stubber.add_response("get_sampling_rules", {"SamplingRuleRecords": []}, {})
    stubber.add_response(
        "create_sampling_rule",
        {"SamplingRuleRecord": sampling_rule_record(rule)},
        {"SamplingRule": rule},
    )
    for _ in range(8):
        stubber.add_response("get_sampling_rules", {"SamplingRuleRecords": []}, {})
    create = client.create_sampling_rule

    def create_then_timeout(**kwargs: Any) -> dict[str, Any]:
        create(**kwargs)
        raise TimeoutError("simulated response loss")

    monkeypatch.setattr("scripts.qualification.settings_session.time.sleep", lambda _delay: None)
    monkeypatch.setattr(client, "create_sampling_rule", create_then_timeout)
    with stubber:
        with pytest.raises(TimeoutError):
            install_xray_sampling_rule(client, journal, rule)
        assert isinstance(journal.pending["xray:qualification-run"], UncertainMutation)
        with pytest.raises(RuntimeError, match="outcome is still uncertain"):
            restore_xray_sampling_rule(journal, client, "qualification-run")
        assert "xray:qualification-run" in journal.pending
        with pytest.raises(RuntimeError, match="outcome is still uncertain"):
            restore_xray_sampling_rule(journal, client, "qualification-run")
        stubber.assert_no_pending_responses()
    assert "xray:qualification-run" in journal.pending


def test_unchanged_sampling_rule_skips_update_and_does_not_create_obligation(
    tmp_path: Path,
) -> None:
    client = xray_client()
    rule = sampling_rule("qualification-run")
    record = sampling_rule_record(rule)
    journal = SettingsJournal(tmp_path / "journal.json")
    stubber = Stubber(client)
    stubber.add_response("get_sampling_rules", {"SamplingRuleRecords": [record]}, {})

    with stubber:
        install_xray_sampling_rule(client, journal, rule)
        stubber.assert_no_pending_responses()

    assert not journal.pending


def test_matching_state_does_not_resolve_an_already_sent_equal_sampling_update(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rule = sampling_rule("qualification-run")
    record = sampling_rule_record(rule)["SamplingRule"]

    class DelayedXRay:
        meta = SimpleNamespace(config=Config(retries={"total_max_attempts": 1, "mode": "standard"}))
        outstanding_attempts = 1
        update_calls = 0

        def get_sampling_rules(self, **_kwargs: Any) -> dict[str, Any]:
            return {"SamplingRuleRecords": [{"SamplingRule": record}]}

        def update_sampling_rule(self, **_kwargs: Any) -> dict[str, Any]:
            self.update_calls += 1
            return {}

    client = DelayedXRay()
    journal = SettingsJournal(tmp_path / "journal.json")
    journal.record("xray:qualification-run", record, record)
    journal.mark_uncertain(
        "xray:qualification-run",
        until=datetime.now(UTC) + timedelta(seconds=30),
        target=record,
    )
    monkeypatch.setattr("scripts.qualification.settings_session.time.sleep", lambda _delay: None)

    with pytest.raises(RuntimeError, match="outcome is still uncertain"):
        restore_xray_sampling_rule(journal, client, "qualification-run")
    assert client.outstanding_attempts == 1
    assert client.update_calls == 0
    assert "xray:qualification-run" in journal.pending

    # The original request applies after recovery observed the same state.
    client.outstanding_attempts = 0
    with pytest.raises(RuntimeError, match="outcome is still uncertain"):
        restore_xray_sampling_rule(journal, client, "qualification-run")
    assert client.update_calls == 0
    assert "xray:qualification-run" in journal.pending


def test_sampling_restore_refuses_to_delete_a_rule_changed_after_install(tmp_path: Path) -> None:
    client = xray_client()
    installed = sampling_rule("qualification-run")
    replacement = sampling_rule("qualification-run", version=2)
    replacement["FixedRate"] = 0.25
    journal = SettingsJournal(tmp_path / "journal.json")
    journal.record("xray:qualification-run", None, installed)
    stubber = Stubber(client)
    stubber.add_response(
        "get_sampling_rules", {"SamplingRuleRecords": [{"SamplingRule": replacement}]}, {}
    )
    with stubber, pytest.raises(RuntimeError, match="refusing restore"):
        restore_xray_sampling_rule(journal, client, "qualification-run")
    assert "xray:qualification-run" in journal.pending


def test_canary_receipt_requires_writer_task_version_and_validated_digest() -> None:
    event = {
        "eventSource": "s3.amazonaws.com",
        "eventName": "PutObject",
        "eventID": "event-1",
        "recipientAccountId": "123456789012",
        "awsRegion": "eu-west-1",
        "eventTime": "2026-10-08T09:59:00Z",
        "requestParameters": {
            "bucketName": "evidence",
            "key": "qualification/s/canary/service/r/task.json",
        },
        "responseElements": {"x-amz-version-id": "version-2"},
        "userIdentity": {
            "sessionContext": {
                "sessionIssuer": {"arn": "arn:aws:iam::123456789012:role/app"},
            },
            "inScopeOf": {
                "issuerType": "AWS::ECS::Task",
                "credentialsIssuedTo": "arn:aws:ecs:eu-west-1:123456789012:task/cluster/task",
            },
        },
    }
    digest = {
        "digest_validated": True,
        "event_id": "event-1",
        "digest_validated_at": "2026-10-08T11:03:00Z",
        "digest_file_sha256": "b" * 64,
    }
    object_receipt = {
        "bucket": "evidence",
        "key": event["requestParameters"]["key"],
        "version_id": "version-2",
        "sha256": "a" * 64,
        "body": CanaryEnvelope(
            wire_schema="ai-soc.qualification-canary.v1",
            task_arn="arn:aws:ecs:eu-west-1:123456789012:task/cluster/task",
            session_id="session-7",
            run_id="run-123",
            placement="service",
            nonce="n" * 32,
            started_at=datetime(2026, 10, 8, 9, 58, tzinfo=UTC),
            written_at=datetime(2026, 10, 8, 9, 59, tzinfo=UTC),
        ),
    }
    receipt = verify_canary_delivery(
        event=event,
        digest_receipt=digest,
        object_receipt=object_receipt,
        expected_bucket="evidence",
        expected_key=event["requestParameters"]["key"],
        expected_account_id="123456789012",
        expected_region="eu-west-1",
        expected_role_arn="arn:aws:iam::123456789012:role/app",
        expected_task_arn="arn:aws:ecs:eu-west-1:123456789012:task/cluster/task",
        expected_session_id="session-7",
        expected_run_id="run-123",
        expected_body_sha256="a" * 64,
        task_started_at="2026-10-08T09:58:00Z",
        task_finished_at="2026-10-08T10:00:00Z",
    )
    assert receipt.version_id == "version-2"
    with pytest.raises(ValueError, match="NOT_RUN"):
        verify_canary_delivery(
            event=event,
            digest_receipt={**digest, "digest_validated": False},
            object_receipt=object_receipt,
            expected_bucket="evidence",
            expected_key=event["requestParameters"]["key"],
            expected_account_id="123456789012",
            expected_region="eu-west-1",
            expected_role_arn="arn:aws:iam::123456789012:role/app",
            expected_task_arn="arn:aws:ecs:eu-west-1:123456789012:task/cluster/task",
            expected_session_id="session-7",
            expected_run_id="run-123",
            expected_body_sha256="a" * 64,
            task_started_at="2026-10-08T09:58:00Z",
            task_finished_at="2026-10-08T10:00:00Z",
        )


def test_canary_reader_fetches_only_event_version_and_hashes_bytes() -> None:
    body = json.dumps(
        {
            "schema": "ai-soc.qualification-canary.v1",
            "task_arn": "task-1",
            "session_id": "s",
            "run_id": "r",
            "placement": "service",
            "nonce": "n" * 32,
            "started_at": "2026-10-08T09:58:00Z",
            "written_at": "2026-10-08T09:59:00Z",
        }
    ).encode()
    s3 = S3ObjectReader(body)
    receipt = read_canary_object_version(
        s3,
        bucket="evidence",
        key="qualification/s/canary/service/r/task.json",
        version_id="version-2",
        expected_owner="123456789012",
    )
    assert s3.request == {
        "Bucket": "evidence",
        "Key": "qualification/s/canary/service/r/task.json",
        "VersionId": "version-2",
        "ExpectedBucketOwner": "123456789012",
    }
    assert receipt["sha256"] == hashlib.sha256(body).hexdigest()


def test_delivery_budget_requires_both_placements_and_fits_session() -> None:
    receipts = [
        VerifiedCanaryDelivery(
            placement=placement,
            session_id="session-7",
            run_id="run-123",
            event_id="event-1",
            version_id="version-2",
            task_arn="task-1",
            object_sha256="a" * 64,
            task_started_at=datetime(2026, 10, 8, 9, 58, tzinfo=UTC),
            task_finished_at=datetime(2026, 10, 8, 10, 0, tzinfo=UTC),
            event_time=datetime(2026, 10, 8, 9, 59, tzinfo=UTC),
            digest_validated_at=datetime(2026, 10, 8, 11, 3, tzinfo=UTC),
            digest_file_sha256="b" * 64,
        )
        for placement in ("service", "public-isolated")
    ]
    assert measured_delivery_budget_seconds(receipts, session_remaining_seconds=5000) == 4680
    assert measured_delivery_budget_seconds(receipts[:1], session_remaining_seconds=5000) is None
    assert measured_delivery_budget_seconds(receipts, session_remaining_seconds=4000) is None
