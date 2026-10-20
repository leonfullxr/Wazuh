"""Shared, journal-first lifecycle for narrowly scoped AWS setting mutations."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from botocore.exceptions import (
    CredentialRetrievalError,
    NoCredentialsError,
    ParamValidationError,
    PartialCredentialsError,
    TokenRetrievalError,
    UnknownEndpointError,
    UnknownServiceError,
)

from scripts.qualification.settings_journal import SettingsJournal, UncertainMutation

RECONCILIATION_DELAYS = (0.25, 0.5, 1.0)
RECONCILIATION_WINDOW = timedelta(seconds=30)
UNSENT_ERRORS = (
    CredentialRetrievalError,
    NoCredentialsError,
    ParamValidationError,
    PartialCredentialsError,
    TokenRetrievalError,
    UnknownEndpointError,
    UnknownServiceError,
)


class SettingAdapter[Snapshot](Protocol):
    name: str

    def read(self) -> Snapshot: ...
    def target(self, change: Any, observed: Snapshot) -> Snapshot: ...
    def write(self, target: Snapshot, observed: Snapshot) -> Snapshot: ...
    def matches(self, actual: Snapshot, expected: Snapshot) -> bool: ...


class SettingConflict(RuntimeError):
    """A setting changed after the lifecycle captured its mutation snapshot."""


def apply_change(adapter: SettingAdapter, journal: SettingsJournal, desired: Any) -> None:
    """Persist before one physical mutation; leave ambiguous outcomes unresolved."""
    _require_single_attempt_mutations(adapter.client)
    if adapter.name in journal.pending:
        raise RuntimeError(f"settings mutation is unresolved for {adapter.name}")
    observed = adapter.read()
    target = adapter.target(desired, observed)
    if adapter.matches(observed, target):
        return
    journal.record(adapter.name, observed, target)
    journal.mark_uncertain(
        adapter.name,
        until=datetime.now(UTC) + RECONCILIATION_WINDOW,
        target=target,
    )
    try:
        actual = adapter.write(target, observed)
    except SettingConflict:
        journal.restored(adapter.name)
        raise
    except UNSENT_ERRORS:
        journal.restored(adapter.name)
        raise
    journal.update_after(adapter.name, actual)
    journal.mutation_succeeded(adapter.name)


def restore_change(adapter: SettingAdapter, journal: SettingsJournal) -> None:
    entry = journal.pending.get(adapter.name)
    if entry is None:
        return
    _require_single_attempt_mutations(adapter.client)
    before, after = entry.before, entry.after
    if isinstance(entry, UncertainMutation):
        confirm_state(adapter, entry.target, bounded=entry.deadline > datetime.now(UTC))
        raise RuntimeError(f"{adapter.name} mutation outcome is still uncertain; journal retained")
    current = adapter.read()
    if adapter.matches(current, before):
        journal.restored(adapter.name)
        return
    if not adapter.matches(current, after):
        raise SettingConflict(f"{adapter.name} changed after installation; refusing restore")
    journal.mark_uncertain(
        adapter.name,
        until=datetime.now(UTC) + RECONCILIATION_WINDOW,
        target=before,
    )
    try:
        adapter.write(before, current)
    except SettingConflict:
        journal.mutation_succeeded(adapter.name)
        raise
    except UNSENT_ERRORS:
        journal.mutation_succeeded(adapter.name)
        raise
    except Exception as exc:
        raise RuntimeError(
            f"{adapter.name} restoration attempt is unresolved; journal retained"
        ) from exc
    journal.mutation_succeeded(adapter.name)
    if confirm_state(adapter, before, bounded=True):
        journal.restored(adapter.name)
        return
    raise RuntimeError(f"{adapter.name} restoration is unconfirmed; journal retained")


def confirm_state(adapter: SettingAdapter, expected: Any, *, bounded: bool) -> bool:
    """Poll a setting after a known attempt; callers retain uncertain journal state."""
    attempts = len(RECONCILIATION_DELAYS) + 1 if bounded else 1
    for attempt in range(attempts):
        if adapter.matches(adapter.read(), expected):
            return True
        if attempt < attempts - 1:
            time.sleep(RECONCILIATION_DELAYS[attempt])
    return False


class CloudTrailSelectors:
    def __init__(self, client: Any, trail_name: str) -> None:
        self.client, self.trail_name = client, trail_name
        self.name = f"cloudtrail:{trail_name}"

    def read(self) -> dict[str, Any]:
        value = self.client.get_event_selectors(TrailName=self.trail_name)
        return {
            key: value[key] for key in ("EventSelectors", "AdvancedEventSelectors") if key in value
        }

    def target(self, values: list[str], observed: dict[str, Any]) -> dict[str, Any]:
        if observed.get("AdvancedEventSelectors"):
            raise ValueError("NOT_RUN: advanced selectors require an explicitly reviewed merge")
        selectors = list(observed.get("EventSelectors", []))
        if len(selectors) >= 5:
            raise ValueError(
                "NOT_RUN: CloudTrail event selector limit leaves no scoped selector slot"
            )
        return {
            "EventSelectors": [
                *selectors,
                {
                    "ReadWriteType": "WriteOnly",
                    "IncludeManagementEvents": False,
                    "DataResources": [{"Type": "AWS::S3::Object", "Values": values}],
                },
            ]
        }

    def write(self, value: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
        if not self.matches(self.read(), observed):
            raise SettingConflict(f"{self.name} changed after observation; refusing mutation")
        self.client.put_event_selectors(TrailName=self.trail_name, **value)
        return value

    def matches(self, actual: Any, expected: Any) -> bool:
        return actual == expected


class XRaySamplingRule:
    def __init__(self, client: Any, rule_name: str) -> None:
        self.client, self.rule_name = client, rule_name
        self.name = f"xray:{rule_name}"

    def read(self) -> dict[str, Any] | None:
        token = None
        seen: set[str] = set()
        for _ in range(100):
            response = self.client.get_sampling_rules(**({"NextToken": token} if token else {}))
            for record in response.get("SamplingRuleRecords", []):
                rule = record.get("SamplingRule")
                if isinstance(rule, dict) and rule.get("RuleName") == self.rule_name:
                    return rule
            token = response.get("NextToken")
            if token is None:
                return None
            if not isinstance(token, str) or not token or token in seen:
                raise ValueError("X-Ray sampling-rule pagination returned an invalid token")
            seen.add(token)
        raise ValueError("X-Ray sampling-rule pagination exceeded the 100-page safety bound")

    def target(
        self, desired: dict[str, Any] | None, _observed: dict[str, Any] | None
    ) -> dict[str, Any] | None:
        return desired

    def write(
        self, value: dict[str, Any] | None, observed: dict[str, Any] | None
    ) -> dict[str, Any] | None:
        if value is None:
            if observed is not None:
                self.client.delete_sampling_rule(RuleName=self.rule_name)
            return None
        update = _sampling_rule_update(value)
        if observed is None:
            response = self.client.create_sampling_rule(SamplingRule=value)
            record = response.get("SamplingRuleRecord") if isinstance(response, dict) else None
            rule = record.get("SamplingRule") if isinstance(record, dict) else None
            return rule if isinstance(rule, dict) else value
        self.client.update_sampling_rule(SamplingRuleUpdate=update)
        return value

    def matches(self, actual: Any, expected: Any) -> bool:
        if actual is None or expected is None:
            return actual is expected
        return _sampling_rule_update(actual) == _sampling_rule_update(expected)


def _sampling_rule_update(rule: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "RuleName",
        "RuleARN",
        "ResourceARN",
        "Priority",
        "FixedRate",
        "ReservoirSize",
        "Host",
        "ServiceName",
        "ServiceType",
        "HTTPMethod",
        "URLPath",
        "Attributes",
        "SamplingRateBoost",
    }
    update = {key: value for key, value in rule.items() if key in allowed}
    if not update.get("RuleName") and not update.get("RuleARN"):
        raise ValueError("sampling-rule update requires RuleName or RuleARN")
    if update.get("RuleName") and update.get("RuleARN"):
        update.pop("RuleARN")
    if update.get("Attributes") == {}:
        update.pop("Attributes")
    return update


def _require_single_attempt_mutations(client: Any) -> None:
    config = getattr(getattr(client, "meta", None), "config", None)
    retries = getattr(config, "retries", None)
    if not isinstance(retries, dict) or retries.get("total_max_attempts") != 1:
        raise ValueError("journaled qualification mutations require botocore total_max_attempts=1")
