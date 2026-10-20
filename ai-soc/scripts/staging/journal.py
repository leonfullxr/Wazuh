"""Typed qualification journal records and wire parsing models."""

from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai_soc.qualification.models import ProbeInvocationConfig
from scripts.staging.models import DeploymentBinding, GateId
from scripts.staging.registry import probe_registrations


class DeliveryReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    verified: Literal["true"]
    placement: Literal["service", "public-isolated"]
    session_id: str
    run_id: str
    event_id: str = Field(min_length=1)
    version_id: str = Field(min_length=1)
    task_arn: str = Field(min_length=1)
    object_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    task_finished_at: datetime
    task_started_at: datetime
    event_time: datetime
    digest_file_uri: str = Field(pattern=r"^s3://")
    digest_version_id: str = Field(min_length=1)
    digest_validated_at: datetime
    digest_availability_seconds: str = Field(min_length=1)
    digest_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("task_started_at", "task_finished_at", "event_time", "digest_validated_at")
    @classmethod
    def _aware_times(cls, value: str | datetime) -> str | datetime:
        _parse_time(value)
        return value

    @field_validator("version_id", "digest_version_id")
    @classmethod
    def _immutable_version(cls, value: str) -> str:
        if value == "null":
            raise ValueError("delivery receipts require immutable object versions")
        return value


class DeliveryMeasurement(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_name: Literal["ai-soc.qualification-delivery-measurement.v1"] = Field(alias="schema")
    session_id: str
    run_id: str
    receipts: tuple[DeliveryReceipt, ...]
    budget_seconds: int = Field(ge=1, le=86_400)
    margin_seconds: int = Field(ge=0)
    session_remaining_seconds: int = Field(ge=1, le=86_400)
    recorded_at: datetime

    @field_validator("recorded_at")
    @classmethod
    def _aware_recorded_at(cls, value: datetime) -> datetime:
        _parse_time(value)
        return value

    def to_wire(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)


@dataclass(frozen=True, slots=True)
class RunIntent:
    invocation_id: str
    run_id: str
    started_by: str
    client_tokens: tuple[str, ...]
    gate_id: str
    contributor_id: str
    task_slots: tuple[str, ...]
    task_arns: tuple[str, ...]
    probe_spec: ProbeInvocationConfig | None
    launch_requests: tuple[dict[str, Any], ...]
    deadline_utc: str
    state: Literal["intent", "launched", "stopping", "stopped", "ambiguous"]
    discovered_arns: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        UUID(self.invocation_id)
        UUID(self.run_id)
        if self.started_by != self.run_id:
            raise ValueError("ECS startedBy must match the random run ID")
        try:
            gate_id = GateId(self.gate_id)
        except ValueError as exc:
            raise ValueError("qualification run names an unregistered gate") from exc
        registrations = probe_registrations(gate_id, self.contributor_id)
        if not registrations:
            raise ValueError("qualification contributor is not registered for its gate")
        if not 1 <= len(self.task_slots) <= 2 or len(set(self.task_slots)) != len(self.task_slots):
            raise ValueError("qualification task slots must be unique and bounded")
        matching = tuple(
            registration
            for registration in registrations
            if self.probe_spec is None or registration.entrypoint == self.probe_spec.entrypoint
        )
        if not any(registration.slots == self.task_slots for registration in matching):
            raise ValueError("qualification task slots do not match a registered probe")
        if len(self.client_tokens) != len(self.task_slots):
            raise ValueError("every task slot requires its own RunTask client token")
        for token in self.client_tokens:
            UUID(token)
        if any(not arn.startswith("arn:") for arn in (*self.task_arns, *self.discovered_arns)):
            raise ValueError("qualification task ARNs must be fully qualified")
        if len(self.launch_requests) not in {0, len(self.task_slots)} or any(
            not isinstance(item, dict) for item in self.launch_requests
        ):
            raise ValueError("qualification launch requests do not match the registered slots")
        if self.probe_spec is not None and not isinstance(self.probe_spec, ProbeInvocationConfig):
            raise ValueError("qualification ProbeSpec must use the strict invocation model")
        datetime.fromisoformat(self.deadline_utc.replace("Z", "+00:00"))


@dataclass(frozen=True, slots=True)
class QualificationJournal:
    schema_version: int
    account_id: str
    region: str
    cluster_arn: str
    session_id: str
    binding: DeploymentBinding
    runs: tuple[RunIntent, ...]
    session_fault: str | None = None
    delivery_measurement: DeliveryMeasurement | None = None
    session_expires_at: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.binding, DeploymentBinding):
            raise ValueError("qualification journal binding must be a parsed deployment model")
        if any(not isinstance(run, RunIntent) for run in self.runs):
            raise ValueError("qualification journal runs must be typed records")

    @property
    def barrier_reason(self) -> str | None:
        from scripts.staging.run_recovery import derive_launch_barrier

        return derive_launch_barrier(self.runs, self.session_fault)


_JOURNAL_SCHEMA = 7
_JOURNAL_ROOT_ENV = "AI_SOC_QUALIFICATION_JOURNAL_ROOT"
_DELIVERY_RECEIPT_IDENTITY_FIELDS = (
    "verified",
    "placement",
    "session_id",
    "run_id",
    "event_id",
    "version_id",
    "task_arn",
    "object_sha256",
    "task_finished_at",
    "task_started_at",
    "event_time",
    "digest_file_uri",
    "digest_version_id",
    "digest_file_sha256",
)


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate journal key")
        result[key] = value
    return result


def _binding_dict(binding: DeploymentBinding) -> dict[str, Any]:
    return {
        "account_id": binding.account_id,
        "region": binding.region,
        "cluster_arn": binding.cluster_arn,
        "service_arn": binding.service_arn,
        "task_definition_arn": binding.task_definition_arn,
        "deployment_name": binding.deployment_name,
        "deployment_id": binding.deployment_id,
        "image_digest": binding.image_digest,
        "service_sha": binding.service_sha,
        "content_sha": binding.content_sha,
        "configuration_sha256": binding.configuration_sha256,
    }


def _delivery_budget_seconds(
    receipts: tuple[DeliveryReceipt, ...],
    *,
    session_id: str,
    session_remaining_seconds: int,
    margin_seconds: int,
) -> int | None:
    required = {"service", "public-isolated"}
    if (
        type(session_remaining_seconds) is not int
        or not 1 <= session_remaining_seconds <= 86_400
        or type(margin_seconds) is not int
        or margin_seconds < 0
        or len(receipts) != 2
    ):
        return None
    observed: dict[str, float] = {}
    run_ids: set[str] = set()
    for receipt in receipts:
        try:
            placement = receipt.placement
            if placement not in required or placement in observed:
                return None
            if receipt.session_id != session_id:
                return None
            UUID(receipt.run_id)
            run_ids.add(receipt.run_id)
            if not receipt.event_id or not receipt.task_arn.startswith("arn:"):
                return None
            started = _parse_time(receipt.task_started_at)
            finished = _parse_time(receipt.task_finished_at)
            event_time = _parse_time(receipt.event_time)
            digest_time = _parse_time(receipt.digest_validated_at)
            availability = (digest_time - event_time).total_seconds()
            delay = (digest_time - finished).total_seconds()
            if (
                started > finished
                or not started <= event_time <= finished
                or digest_time < finished
                or delay < 0
                or receipt.digest_availability_seconds != str(availability)
            ):
                return None
            observed[placement] = delay
        except (KeyError, TypeError, ValueError, AttributeError):
            return None
    if set(observed) != required or len(run_ids) != 1:
        return None
    budget = math.ceil(max(observed.values())) + margin_seconds
    if budget <= 0 or budget > min(session_remaining_seconds, 86_400):
        return None
    return budget


def _parse_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise ValueError("time value has an unsupported type")
    if parsed.tzinfo is None:
        raise ValueError("time value must include a UTC offset")
    return parsed.astimezone(UTC)


def _configured_journal_root() -> Path:
    configured = os.environ.get(_JOURNAL_ROOT_ENV)
    if not configured:
        raise RuntimeError(f"{_JOURNAL_ROOT_ENV} must name the shared absolute coordinator root")
    root = Path(configured).expanduser()
    if not root.is_absolute():
        raise RuntimeError(f"{_JOURNAL_ROOT_ENV} must be an absolute path")
    return root.resolve()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _validate_delivery_measurement(
    measurement: DeliveryMeasurement, *, session_id: str, now: datetime
) -> int | None:
    if (
        measurement.schema_name != "ai-soc.qualification-delivery-measurement.v1"
        or measurement.session_id != session_id
    ):
        return None
    try:
        recorded_at = _parse_time(measurement.recorded_at)
        if recorded_at > now or (now - recorded_at).total_seconds() > 86_400:
            return None
        receipts = measurement.receipts
        if {item.run_id for item in receipts} != {measurement.run_id}:
            return None
        if any(
            (now - _parse_time(item.digest_validated_at)).total_seconds() > 86_400
            or _parse_time(item.digest_validated_at) > now
            for item in receipts
        ):
            return None
        budget = _delivery_budget_seconds(
            receipts,
            session_id=session_id,
            session_remaining_seconds=measurement.session_remaining_seconds,
            margin_seconds=measurement.margin_seconds,
        )
    except (TypeError, ValueError):
        return None
    if budget != measurement.budget_seconds:
        return None
    return budget


def _same_delivery_receipt_identities(
    authenticated: tuple[DeliveryReceipt, ...], recorded: tuple[DeliveryReceipt, ...]
) -> bool:
    """Match immutable proof identities while retaining the original timing measurement."""
    if len(authenticated) != 2 or len(recorded) != 2:
        return False

    def by_placement(receipts: tuple[DeliveryReceipt, ...]) -> dict[str, tuple[Any, ...]] | None:
        identities: dict[str, tuple[Any, ...]] = {}
        for receipt in receipts:
            placement = receipt.placement
            if placement not in {"service", "public-isolated"} or placement in identities:
                return None
            identities[placement] = tuple(
                getattr(receipt, field) for field in _DELIVERY_RECEIPT_IDENTITY_FIELDS
            )
        return identities

    recorded_identities = by_placement(recorded)
    authenticated_identities = by_placement(authenticated)
    return (
        recorded_identities is not None
        and authenticated_identities is not None
        and recorded_identities == authenticated_identities
    )


def _journal_dict(journal: QualificationJournal) -> dict[str, Any]:
    return {
        "schema_version": journal.schema_version,
        "account_id": journal.account_id,
        "region": journal.region,
        "cluster_arn": journal.cluster_arn,
        "session_id": journal.session_id,
        "binding": _binding_dict(journal.binding),
        "runs": [
            {
                "invocation_id": run.invocation_id,
                "run_id": run.run_id,
                "started_by": run.started_by,
                "client_tokens": list(run.client_tokens),
                "gate_id": run.gate_id,
                "contributor_id": run.contributor_id,
                "task_slots": list(run.task_slots),
                "task_arns": list(run.task_arns),
                "discovered_arns": list(run.discovered_arns),
                "probe_spec": (
                    run.probe_spec.model_dump(mode="json") if run.probe_spec is not None else {}
                ),
                "launch_requests": list(run.launch_requests),
                "deadline_utc": run.deadline_utc,
                "state": run.state,
            }
            for run in journal.runs
        ],
        "session_fault": journal.session_fault,
        "delivery_measurement": (
            journal.delivery_measurement.to_wire()
            if journal.delivery_measurement is not None
            else None
        ),
        "session_expires_at": journal.session_expires_at,
    }


def _parse_journal(raw: object) -> QualificationJournal:
    upgraded, _source_schema = upgrade_legacy_journal(raw)
    return parse_current_journal(upgraded)


def upgrade_legacy_journal(raw: object) -> tuple[dict[str, Any], int]:
    """Convert supported historical journal layouts to the current wire shape."""
    if not isinstance(raw, dict):
        raise ValueError("unsupported qualification journal")
    source_schema = raw.get("schema_version")
    if type(source_schema) is not int or source_schema not in {2, 3, 4, 6, _JOURNAL_SCHEMA}:
        raise ValueError("unsupported qualification journal")
    upgraded = dict(raw)
    if source_schema < _JOURNAL_SCHEMA:
        upgraded.setdefault("delivery_measurement", None)
        upgraded.setdefault("session_expires_at", None)
        run_rows = upgraded.get("runs")
        if isinstance(run_rows, list):
            upgraded["runs"] = [
                {
                    **row,
                    "discovered_arns": row.get("discovered_arns", row.get("task_arns", [])),
                    "task_arns": [] if source_schema == 2 else row.get("task_arns", []),
                }
                if isinstance(row, dict)
                else row
                for row in run_rows
            ]
        if source_schema < 7:
            old_fault = upgraded.pop("barrier_reason", None)
            runs = upgraded.get("runs", [])
            has_run_barrier = False
            if not isinstance(runs, list):
                has_run_barrier = True
            else:
                for row in runs:
                    if not isinstance(row, dict):
                        has_run_barrier = True
                        break
                    task_arns = row.get("task_arns", [])
                    task_slots = row.get("task_slots", [])
                    discovered_arns = row.get("discovered_arns", [])
                    if not all(
                        isinstance(value, list) and all(isinstance(item, str) for item in value)
                        for value in (task_arns, task_slots, discovered_arns)
                    ):
                        has_run_barrier = True
                        break
                    if (
                        row.get("state") in {"intent", "stopping", "ambiguous"}
                        or len(task_arns) != len(task_slots)
                        or len(set(task_arns)) != len(task_arns)
                        or not set(discovered_arns).issubset(task_arns)
                    ):
                        has_run_barrier = True
                        break
            upgraded["session_fault"] = old_fault if old_fault and not has_run_barrier else None
    upgraded["schema_version"] = _JOURNAL_SCHEMA
    return upgraded, source_schema


def parse_current_journal(raw: dict[str, Any]) -> QualificationJournal:
    journal_keys = {
        "schema_version",
        "account_id",
        "region",
        "cluster_arn",
        "session_id",
        "binding",
        "runs",
        "session_fault",
        "delivery_measurement",
        "session_expires_at",
    }
    run_keys = {
        "invocation_id",
        "run_id",
        "started_by",
        "client_tokens",
        "gate_id",
        "contributor_id",
        "task_slots",
        "task_arns",
        "probe_spec",
        "launch_requests",
        "deadline_utc",
        "state",
        "discovered_arns",
    }
    if frozenset(raw) != frozenset(journal_keys) or raw.get("schema_version") != _JOURNAL_SCHEMA:
        raise ValueError("unsupported qualification journal")
    runs_raw = raw.get("runs")
    if not isinstance(runs_raw, list) or len(runs_raw) > 1024:
        raise ValueError("qualification journal runs must be a list")
    runs_list: list[RunIntent] = []
    for row in runs_raw:
        if not isinstance(row, dict) or frozenset(row) != frozenset(run_keys):
            raise ValueError("qualification run has unknown or missing fields")
        scalar_fields = (
            "invocation_id",
            "run_id",
            "started_by",
            "gate_id",
            "contributor_id",
            "deadline_utc",
            "state",
        )
        if not all(isinstance(row.get(name), str) and row[name] for name in scalar_fields):
            raise ValueError("qualification run has invalid identity fields")
        UUID(row["invocation_id"])
        UUID(row["run_id"])
        if row["started_by"] != row["run_id"]:
            raise ValueError("ECS startedBy must match the random run ID")
        if row["state"] not in {"intent", "launched", "stopping", "stopped", "ambiguous"}:
            raise ValueError("qualification run state is invalid")
        slots, arns, tokens = row["task_slots"], row["task_arns"], row["client_tokens"]
        discovered_arns = row["discovered_arns"]
        probe_spec, launch_requests = row["probe_spec"], row["launch_requests"]
        if not isinstance(probe_spec, dict) or not isinstance(launch_requests, list):
            raise ValueError("qualification run request journal is invalid")
        if len(launch_requests) not in {0, len(slots)} or any(
            not isinstance(item, dict) for item in launch_requests
        ):
            raise ValueError("qualification launch requests are invalid")
        if not isinstance(slots, list) or not 1 <= len(slots) <= 2:
            raise ValueError("qualification task slots are invalid")
        if not all(isinstance(item, str) and item for item in slots):
            raise ValueError("qualification task slots are invalid")
        if len(set(slots)) != len(slots):
            raise ValueError("qualification task slots are duplicated")
        parsed_probe_spec = (
            None if not probe_spec else ProbeInvocationConfig.model_validate(probe_spec)
        )
        if not isinstance(tokens, list) or len(tokens) != len(slots):
            raise ValueError("every task slot requires its own RunTask client token")
        if not all(isinstance(item, str) and item for item in tokens):
            raise ValueError("qualification client tokens are invalid")
        for token in tokens:
            UUID(token)
        if not isinstance(arns, list) or not all(
            isinstance(item, str) and item.startswith("arn:") for item in arns
        ):
            raise ValueError("qualification task ARN set is invalid")
        if not isinstance(discovered_arns, list) or not all(
            isinstance(item, str) and item.startswith("arn:") for item in discovered_arns
        ):
            raise ValueError("discovered qualification task ARN set is invalid")
        datetime.fromisoformat(row["deadline_utc"].replace("Z", "+00:00"))
        runs_list.append(
            RunIntent(
                invocation_id=row["invocation_id"],
                run_id=row["run_id"],
                started_by=row["started_by"],
                client_tokens=tuple(tokens),
                gate_id=row["gate_id"],
                contributor_id=row["contributor_id"],
                task_slots=tuple(slots),
                task_arns=tuple(arns),
                probe_spec=parsed_probe_spec,
                launch_requests=tuple(launch_requests),
                deadline_utc=row["deadline_utc"],
                state=row["state"],
                discovered_arns=tuple(discovered_arns),
            )
        )
    runs = tuple(runs_list)
    if not isinstance(raw.get("binding"), dict):
        raise ValueError("qualification journal binding is invalid")
    if raw.get("session_fault") is not None and not isinstance(raw["session_fault"], str):
        raise ValueError("qualification journal session fault is invalid")
    expiry = raw.get("session_expires_at")
    if expiry is not None:
        if not isinstance(expiry, str):
            raise ValueError("qualification journal absolute expiry is invalid")
        _parse_time(expiry)
    measurement_raw = raw.get("delivery_measurement")
    measurement = (
        DeliveryMeasurement.model_validate(measurement_raw) if measurement_raw is not None else None
    )
    return QualificationJournal(
        schema_version=_JOURNAL_SCHEMA,
        account_id=raw["account_id"],
        region=raw["region"],
        cluster_arn=raw["cluster_arn"],
        session_id=raw["session_id"],
        binding=DeploymentBinding(**raw["binding"]),
        runs=runs,
        session_fault=raw.get("session_fault"),
        delivery_measurement=measurement,
        session_expires_at=raw.get("session_expires_at"),
    )
