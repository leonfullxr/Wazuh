"""Typed host-side qualification delivery proof and budget calculation."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from ai_soc.qualification.evidence import CanaryEnvelope


@dataclass(frozen=True)
class VerifiedCanaryDelivery:
    placement: Literal["service", "public-isolated"]
    session_id: str
    run_id: str
    event_id: str
    version_id: str
    task_arn: str
    object_sha256: str
    task_started_at: datetime
    task_finished_at: datetime
    event_time: datetime
    digest_validated_at: datetime
    digest_file_sha256: str

    @property
    def digest_availability_seconds(self) -> float:
        return (self.digest_validated_at - self.event_time).total_seconds()

    @property
    def delivery_seconds(self) -> float:
        return (self.digest_validated_at - self.task_finished_at).total_seconds()


def parse_time(value: str | datetime) -> datetime:
    parsed = (
        value
        if isinstance(value, datetime)
        else datetime.fromisoformat(value.replace("Z", "+00:00"))
    )
    if parsed.tzinfo is None:
        raise ValueError("timestamps must include a UTC offset")
    return parsed.astimezone(UTC)


def verify_canary_delivery(
    *,
    event: dict[str, Any],
    digest_receipt: dict[str, Any],
    object_receipt: dict[str, Any],
    expected_bucket: str,
    expected_key: str,
    expected_account_id: str,
    expected_region: str,
    expected_role_arn: str,
    expected_task_arn: str,
    expected_session_id: str,
    expected_run_id: str,
    expected_body_sha256: str,
    task_started_at: str | datetime,
    task_finished_at: str | datetime,
) -> VerifiedCanaryDelivery:
    """Validate service identity, exact S3 version, trail digest and task window."""
    if event.get("eventSource") != "s3.amazonaws.com" or event.get("eventName") != "PutObject":
        raise ValueError("NOT_RUN: expected a delivered S3 PutObject data event")
    if (
        event.get("recipientAccountId") != expected_account_id
        or event.get("awsRegion") != expected_region
    ):
        raise ValueError("NOT_RUN: event account or Region differs from the bound canary")
    request, identity = event.get("requestParameters"), event.get("userIdentity")
    if not isinstance(request, dict) or not isinstance(identity, dict):
        raise ValueError("NOT_RUN: event omitted request or writer identity")
    if request.get("bucketName") != expected_bucket or request.get("key") != expected_key:
        raise ValueError("NOT_RUN: event does not identify the canary object")
    session = identity.get("sessionContext")
    issuer = session.get("sessionIssuer") if isinstance(session, dict) else None
    scope = identity.get("inScopeOf")
    if not isinstance(issuer, dict) or issuer.get("arn") != expected_role_arn:
        raise ValueError("NOT_RUN: event writer is not the bound application role")
    if (
        not isinstance(scope, dict)
        or scope.get("issuerType") != "AWS::ECS::Task"
        or scope.get("credentialsIssuedTo") != expected_task_arn
    ):
        raise ValueError("NOT_RUN: event does not prove the writing ECS task")
    response = event.get("responseElements")
    version_id = response.get("x-amz-version-id") if isinstance(response, dict) else None
    if not isinstance(version_id, str) or not version_id or version_id == "null":
        raise ValueError("NOT_RUN: event omitted the object version")
    if digest_receipt.get("digest_validated") is not True or digest_receipt.get(
        "event_id"
    ) != event.get("eventID"):
        raise ValueError("NOT_RUN: CloudTrail digest has not been validated for this event")
    body = object_receipt.get("body")
    try:
        envelope = CanaryEnvelope.model_validate(body)
        started, finished = parse_time(task_started_at), parse_time(task_finished_at)
        event_time = parse_time(event["eventTime"])
        digest_time = parse_time(digest_receipt["digest_validated_at"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("NOT_RUN: canary task, event, and digest times are required") from exc
    if started > finished or not started <= event_time <= finished:
        raise ValueError("NOT_RUN: canary PutObject event is outside the task execution window")
    if digest_time < finished:
        raise ValueError("NOT_RUN: digest was validated before task completion")
    identity = envelope.identity
    if (
        object_receipt.get("bucket") != expected_bucket
        or object_receipt.get("key") != expected_key
        or object_receipt.get("version_id") != version_id
        or object_receipt.get("sha256") != expected_body_sha256
        or identity.task_arn != expected_task_arn
        or identity.session_id != expected_session_id
        or identity.run_id != expected_run_id
    ):
        raise ValueError("NOT_RUN: exact version body receipt does not match the canary")
    return VerifiedCanaryDelivery(
        placement=identity.placement,
        session_id=expected_session_id,
        run_id=expected_run_id,
        event_id=str(event["eventID"]),
        version_id=version_id,
        task_arn=expected_task_arn,
        object_sha256=expected_body_sha256,
        task_started_at=started,
        task_finished_at=finished,
        event_time=event_time,
        digest_validated_at=digest_time,
        digest_file_sha256=str(digest_receipt.get("digest_file_sha256", "")),
    )


def measured_delivery_budget_seconds(
    receipts: list[VerifiedCanaryDelivery],
    *,
    session_remaining_seconds: int,
    margin_seconds: int = 900,
) -> int | None:
    """Use both placement proofs to bound delivery plus digest collection."""
    required = {"service", "public-isolated"}
    observed: dict[str, float] = {}
    bindings: set[tuple[str, str]] = set()
    for receipt in receipts:
        if not isinstance(receipt, VerifiedCanaryDelivery):
            return None
        if receipt.placement in required:
            if (
                receipt.task_started_at > receipt.task_finished_at
                or not receipt.task_started_at <= receipt.event_time <= receipt.task_finished_at
            ):
                return None
            if (
                receipt.digest_validated_at < receipt.task_finished_at
                or receipt.delivery_seconds < 0
            ):
                return None
            bindings.add((receipt.session_id, receipt.run_id))
            observed[receipt.placement] = max(
                receipt.delivery_seconds, observed.get(receipt.placement, 0.0)
            )
    if set(observed) != required or len(bindings) != 1 or margin_seconds < 0:
        return None
    budget = math.ceil(max(observed.values())) + margin_seconds
    if budget <= 0 or budget > min(session_remaining_seconds, 24 * 60 * 60):
        return None
    return budget
