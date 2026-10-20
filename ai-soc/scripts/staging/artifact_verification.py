"""Authenticated ECS launch and immutable output object verification."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from scripts.staging.fact_verification import _verify_fact_chain
from scripts.staging.registry import FACT_SELECTOR_REGISTRY
from scripts.staging.s3_evidence import (
    read_version_bytes,
    require_exact_current_version,
)
from scripts.staging.verifier import (
    _SEAL,
    DigestValidatedLogs,
    EvidenceContradiction,
    EvidenceIncomplete,
    FactRequirement,
    LaunchExpectation,
    VerifiedArtifact,
    VerifiedCanaryReceipt,
    VerifiedFactChain,
    VerifiedInvocationLog,
    VerifiedLaunch,
    _binding_wire,
    _event_time,
    _parse_utc,
    _tag_map,
    _task_identity_matches,
    _utc_z,
    canonical_event_digest,
    canonical_request_digest,
    is_verified_artifact,
    strict_json,
)


def _verify_launch_event(
    expectation: LaunchExpectation,
    event: dict[str, Any],
) -> VerifiedLaunch:
    """Authenticate one RunTask request and the exact returned task identity."""
    digest = canonical_event_digest(event)
    if event.get("eventSource") != "ecs.amazonaws.com" or event.get("eventName") != "RunTask":
        raise EvidenceContradiction("launch evidence is not an ECS RunTask event")
    if event.get("recipientAccountId") != expectation.account_id:
        raise EvidenceContradiction("RunTask event is for a different account")
    if event.get("awsRegion") != expectation.region:
        raise EvidenceContradiction("RunTask event is for a different Region")
    if event.get("errorCode") or event.get("errorMessage"):
        raise EvidenceIncomplete("RunTask event records a rejected or failed request")
    user = event.get("userIdentity")
    issuer = (
        user.get("sessionContext", {}).get("sessionIssuer", {}) if isinstance(user, dict) else {}
    )
    if (
        not isinstance(user, dict)
        or user.get("type") != "AssumedRole"
        or issuer.get("arn") != expectation.launcher_role_arn
    ):
        raise EvidenceContradiction("RunTask event was not issued by the approved launcher role")
    request = event.get("requestParameters")
    if not isinstance(request, dict):
        raise EvidenceIncomplete("RunTask event omits request parameters")
    if any(field not in request for field in expectation.required_request_fields):
        raise EvidenceIncomplete("RunTask event omits a field required by its launch intent")
    if not re.fullmatch(r"[0-9a-f]{64}", expectation.launch_request_digest):
        raise EvidenceContradiction("durable launch intent has a malformed request digest")
    if canonical_request_digest(request) != expectation.launch_request_digest:
        raise EvidenceContradiction("RunTask request differs from its durable canonical request")
    if (
        request.get("cluster") != expectation.cluster_arn
        or request.get("taskDefinition") != expectation.task_definition_arn
        or request.get("startedBy") != expectation.started_by
        or request.get("clientToken") != expectation.client_token
    ):
        raise EvidenceContradiction("RunTask request differs from the durable launch intent")
    tags = _tag_map(request.get("tags"))
    expected_tags = {
        "qualification-session": expectation.session_id,
        "qualification-invocation": expectation.invocation_id,
        "qualification-run": expectation.run_id,
        "qualification-gate": expectation.gate_id.value,
        "qualification-contributor": expectation.contributor_id,
        "qualification-slot": expectation.slot,
    }
    if any(tags.get(key) != value for key, value in expected_tags.items()):
        raise EvidenceContradiction("RunTask tags do not bind the durable session and slot")
    response = event.get("responseElements")
    tasks = response.get("tasks") if isinstance(response, dict) else None
    if not isinstance(tasks, list) or len(tasks) != 1 or not isinstance(tasks[0], dict):
        raise EvidenceIncomplete("RunTask event lacks one exact returned task")
    task = tasks[0]
    task_arn = task.get("taskArn")
    if (
        not isinstance(task_arn, str)
        or not task_arn.startswith(
            f"arn:aws:ecs:{expectation.region}:{expectation.account_id}:task/"
        )
        or task.get("clusterArn") != expectation.cluster_arn
        or task.get("taskDefinitionArn") != expectation.task_definition_arn
        or task.get("startedBy") != expectation.started_by
    ):
        raise EvidenceContradiction("RunTask response identity differs from the launch intent")
    request_id, event_id = event.get("requestID"), event.get("eventID")
    if not isinstance(request_id, str) or not request_id or not isinstance(event_id, str):
        raise EvidenceIncomplete("RunTask event omits request or event identity")
    return VerifiedLaunch(
        _seal=_SEAL,
        expectation=expectation,
        task_arn=task_arn,
        request_id=request_id,
        event_id=event_id,
        event_digest=digest,
        started_at=_utc_z(_event_time(event)),
    )


def _verify_task_output_event(
    launch: VerifiedLaunch,
    event: dict[str, Any],
    *,
    bucket: str,
    key: str,
    role_arn: str,
) -> tuple[str, str, str]:
    """Return an event-proven S3 version only for the authenticated task writer."""
    if launch._seal is not _SEAL:
        raise EvidenceContradiction("unverified launch capability")
    digest = canonical_event_digest(event)
    if event.get("eventSource") != "s3.amazonaws.com" or event.get("eventName") != "PutObject":
        raise EvidenceContradiction("output writer evidence is not an S3 PutObject event")
    if event.get("recipientAccountId") != launch.expectation.account_id:
        raise EvidenceContradiction("output event recipient account differs")
    event_time = _event_time(event)
    if event.get("awsRegion") != launch.expectation.region:
        raise EvidenceContradiction("output event is for a different Region")
    if event.get("errorCode") or event.get("errorMessage"):
        raise EvidenceIncomplete("output PutObject event records a failed request")
    if event_time < _event_time({"eventTime": launch.started_at}):
        raise EvidenceContradiction("output was written before the authenticated launch")
    if event_time > _parse_utc(launch.expectation.deadline_utc):
        raise EvidenceIncomplete("output was written after the original run deadline")
    request = event.get("requestParameters")
    response = event.get("responseElements")
    if not isinstance(request, dict) or not isinstance(response, dict):
        raise EvidenceIncomplete("PutObject event omits request or response elements")
    if request.get("bucketName") != bucket or request.get("key") != key:
        raise EvidenceContradiction("PutObject event targets a different output key")
    key_parts = key.split("/")
    if (
        launch.expectation.session_id not in key_parts
        or launch.expectation.run_id not in key_parts
        or launch.task_arn.rsplit("/", 1)[-1] not in key_parts[-1]
    ):
        raise EvidenceContradiction("PutObject key does not bind session, run and task")
    user = event.get("userIdentity")
    arn = user.get("arn") if isinstance(user, dict) else None
    principal = user.get("principalId") if isinstance(user, dict) else None
    task_suffix = launch.task_arn.rsplit("/", 1)[-1]
    if not isinstance(arn, str) or not arn.startswith(
        f"arn:aws:sts::{launch.expectation.account_id}:assumed-role/"
    ):
        raise EvidenceIncomplete("PutObject writer has no task-role session identity")
    if (
        not arn.endswith("/" + task_suffix)
        or not isinstance(principal, str)
        or not principal.endswith(":" + task_suffix)
    ):
        raise EvidenceIncomplete("PutObject writer cannot be joined to the launched task")
    session_issuer = user.get("sessionContext", {}).get("sessionIssuer", {})
    if not isinstance(session_issuer, dict) or session_issuer.get("arn") != role_arn:
        raise EvidenceContradiction("PutObject writer role differs from the bound task role")
    version_id = response.get("x-amz-version-id") or response.get("xAmzVersionId")
    request_id = event.get("requestID")
    event_id = event.get("eventID")
    if not isinstance(version_id, str) or not version_id or version_id == "null":
        raise EvidenceIncomplete("PutObject event omits a non-null event-provided version ID")
    if not isinstance(request_id, str) or not request_id or not isinstance(event_id, str):
        raise EvidenceIncomplete("PutObject event omits request or event identity")
    return version_id, event_id, digest


def verify_output_mutations(
    launch: VerifiedLaunch,
    events: tuple[dict[str, Any], ...],
    *,
    bucket: str,
    key: str,
    role_arn: str,
) -> tuple[str, str, str]:
    """Require one unique successful PutObject and no successful deletion."""
    mutations: dict[str, dict[str, Any]] = {}
    for event in events:
        if event.get("eventSource") != "s3.amazonaws.com":
            continue
        if event.get("eventName") not in {
            "PutObject",
            "DeleteObject",
            "DeleteObjects",
            "DeleteObjectVersion",
        }:
            continue
        request = event.get("requestParameters")
        if not isinstance(request, dict) or request.get("bucketName") != bucket:
            continue
        keys = {request.get("key")}
        objects = request.get("objects")
        if isinstance(objects, list):
            keys.update(item.get("key") for item in objects if isinstance(item, dict))
        if key not in keys:
            continue
        event_id = event.get("eventID")
        if not isinstance(event_id, str) or not event_id:
            raise EvidenceIncomplete("S3 mutation event omits eventID")
        mutations[event_id] = event
    successful = [event for event in mutations.values() if not event.get("errorCode")]
    puts = [event for event in successful if event.get("eventName") == "PutObject"]
    deletes = [event for event in successful if event.get("eventName") != "PutObject"]
    if deletes:
        raise EvidenceIncomplete("output key has a successful delete or delete-version event")
    if len(puts) != 1:
        raise EvidenceIncomplete("output key does not have exactly one successful PutObject event")
    return _verify_task_output_event(launch, puts[0], bucket=bucket, key=key, role_arn=role_arn)


def _verify_output_object(
    launch: VerifiedLaunch,
    *,
    put_event: dict[str, Any],
    bucket: str,
    key: str,
    role_arn: str,
    expected_kms_key_arn: str,
    expected_bucket_owner: str,
    s3_client: Any,
) -> VerifiedArtifact:
    """Read only the writer-event version and validate envelope, tags and bytes."""
    from ai_soc.qualification.evidence import parse_probe_envelope

    version_id, event_id, event_digest = _verify_task_output_event(
        launch, put_event, bucket=bucket, key=key, role_arn=role_arn
    )
    require_exact_current_version(
        s3_client,
        bucket=bucket,
        key=key,
        version_id=version_id,
        expected_bucket_owner=expected_bucket_owner,
    )
    response, raw = read_version_bytes(
        s3_client,
        bucket=bucket,
        key=key,
        version_id=version_id,
        expected_bucket_owner=expected_bucket_owner,
        maximum_bytes=256 * 1024,
    )
    if response.get("ServerSideEncryption") != "aws:kms":
        raise EvidenceIncomplete("qualification output does not use reviewed SSE-KMS encryption")
    if response.get("SSEKMSKeyId") != expected_kms_key_arn:
        raise EvidenceContradiction("qualification output uses a different KMS key")
    if response.get("ContentLength") != len(raw):
        raise EvidenceContradiction("qualification output ContentLength differs from its bytes")
    digest = hashlib.sha256(raw).hexdigest()
    metadata = response.get("Metadata")
    if not isinstance(metadata, dict) or metadata.get("sha256") != digest:
        raise EvidenceContradiction("qualification output digest metadata does not match bytes")
    if (
        metadata.get("task-arn") != launch.task_arn
        or metadata.get("run-id") != launch.expectation.run_id
    ):
        raise EvidenceContradiction("qualification output metadata does not match launch")
    tagging = s3_client.get_object_tagging(
        Bucket=bucket,
        Key=key,
        VersionId=version_id,
        ExpectedBucketOwner=expected_bucket_owner,
    )
    tag_map = _tag_map(
        [{"key": item.get("Key"), "value": item.get("Value")} for item in tagging.get("TagSet", [])]
    )
    expected_tags = {
        "session": launch.expectation.session_id,
        "invocation": launch.expectation.invocation_id,
        "run": launch.expectation.run_id,
        "gate": launch.expectation.gate_id.value,
        "contributor": launch.expectation.contributor_id,
        "task": launch.task_arn,
    }
    if any(tag_map.get(name) != value for name, value in expected_tags.items()):
        raise EvidenceContradiction("qualification output tags do not match authenticated launch")
    envelope = parse_probe_envelope(raw)
    if (
        envelope.session_id != launch.expectation.session_id
        or envelope.invocation_id != launch.expectation.invocation_id
        or envelope.run_id != launch.expectation.run_id
        or envelope.gate_id != launch.expectation.gate_id.value
        or envelope.contributor_id != launch.expectation.contributor_id
        or envelope.binding.model_dump(mode="python") != _binding_wire(launch.expectation.binding)
    ):
        raise EvidenceContradiction(
            "qualification envelope identity or binding differs from launch"
        )
    execution_deadline = _parse_utc(launch.expectation.deadline_utc)
    if launch.expectation.collection_seconds:
        execution_deadline = min(
            execution_deadline,
            _parse_utc(launch.expectation.deadline_utc)
            - timedelta(seconds=launch.expectation.collection_seconds),
        )
    if launch.expectation.execution_seconds is not None:
        execution_deadline = min(
            execution_deadline,
            _parse_utc(launch.started_at) + timedelta(seconds=launch.expectation.execution_seconds),
        )
    execution_limit = _parse_utc(execution_deadline.isoformat())
    if (
        envelope.started_at < _parse_utc(launch.started_at)
        or envelope.completed_at > execution_limit
    ):
        raise EvidenceContradiction(
            "qualification envelope times differ from the authenticated run"
        )
    if envelope.completed_at >= execution_limit:
        raise EvidenceContradiction("qualification completed at or after its execution deadline")
    require_exact_current_version(
        s3_client,
        bucket=bucket,
        key=key,
        version_id=version_id,
        expected_bucket_owner=expected_bucket_owner,
    )
    return VerifiedArtifact(
        _seal=_SEAL,
        launch=launch,
        bucket=bucket,
        key=key,
        version_id=version_id,
        sha256=digest,
        event_id=event_id,
        event_digest=event_digest,
        envelope=envelope,
    )


def _verify_bucket_policy_history(
    launch: VerifiedLaunch, bucket: str, events: tuple[dict[str, Any], ...]
) -> None:
    """Reject evidence when the bound bucket's write controls changed mid-run."""
    mutation_events = {
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "PutBucketLogging",
        "PutBucketLifecycle",
        "PutEncryptionConfiguration",
        "DeleteBucketEncryption",
    }
    start = _parse_utc(launch.started_at)
    end = _parse_utc(launch.expectation.deadline_utc)
    for event in events:
        if event.get("eventSource") != "s3.amazonaws.com":
            continue
        if event.get("eventName") not in mutation_events:
            continue
        request = event.get("requestParameters")
        if not isinstance(request, dict) or request.get("bucketName") != bucket:
            continue
        if event.get("errorCode") or event.get("errorMessage"):
            continue
        when = _event_time(event)
        if start <= when <= end:
            raise EvidenceIncomplete("evidence bucket controls changed during qualification")


class AuthenticatedEvidenceVerifier:
    """Use only digest-validated events to mint launch, artifact and fact proofs."""

    def __init__(self, logs: DigestValidatedLogs) -> None:
        if not isinstance(logs, DigestValidatedLogs) or logs._seal is not _SEAL:
            raise TypeError("authenticated verifier requires digest-validated CloudTrail logs")
        self.logs = logs

    def authenticate_launch(self, expectation: LaunchExpectation) -> VerifiedLaunch:
        candidates: list[dict[str, Any]] = []
        for event in self.logs.events:
            if (
                event.get("eventSource") != "ecs.amazonaws.com"
                or event.get("eventName") != "RunTask"
            ):
                continue
            request = event.get("requestParameters")
            if (
                isinstance(request, dict)
                and request.get("startedBy") == expectation.started_by
                and request.get("clientToken") == expectation.client_token
            ):
                candidates.append(event)
        if not candidates:
            raise EvidenceIncomplete("digest-validated RunTask event is not available yet")
        if len(candidates) != 1:
            raise EvidenceIncomplete("startedBy resolves to multiple RunTask events")
        return _verify_launch_event(expectation, candidates[0])

    def authenticate_output(
        self,
        launch: VerifiedLaunch,
        *,
        bucket: str,
        key: str,
        role_arn: str,
        expected_kms_key_arn: str,
        expected_bucket_owner: str,
        s3_client: Any,
    ) -> VerifiedArtifact:
        _verify_bucket_policy_history(launch, bucket, self.logs.events)
        _version_id, event_id, _digest = verify_output_mutations(
            launch,
            self.logs.events,
            bucket=bucket,
            key=key,
            role_arn=role_arn,
        )
        event = next(item for item in self.logs.events if item.get("eventID") == event_id)
        return _verify_output_object(
            launch,
            put_event=event,
            bucket=bucket,
            key=key,
            role_arn=role_arn,
            expected_kms_key_arn=expected_kms_key_arn,
            expected_bucket_owner=expected_bucket_owner,
            s3_client=s3_client,
        )

    def verify_facts(
        self,
        launch: VerifiedLaunch,
        requirements: tuple[FactRequirement, ...],
    ) -> VerifiedFactChain:
        # Dynamic requirement objects were previously caller-controlled: a
        # caller could relabel the authenticated output write as every
        # evaluator fact. No fixed selector registry is installed yet, so
        # abstain instead of minting a chain from caller-supplied selectors.
        del launch, requirements
        raise EvidenceIncomplete(
            "registered fact selectors are unavailable; caller-selected facts cannot certify PASS"
        )

    def authenticate_invocation_log(
        self,
        launch: VerifiedLaunch,
        *,
        bucket: str,
        prefix: str,
        request_id: str,
        case_nonce: str,
        expected_bucket_owner: str,
        s3_client: Any,
    ) -> VerifiedInvocationLog:
        """Authenticate exactly one Bedrock-written immutable log for a request."""
        from scripts.staging.cloudtrail import _invocation_prefix_inventory

        if launch._seal is not _SEAL:
            raise EvidenceContradiction("unverified launch capability")
        if not bucket or not prefix.endswith("/") or not request_id or not case_nonce:
            raise EvidenceIncomplete("invocation log selector is incomplete")
        _verify_bucket_policy_history(launch, bucket, self.logs.events)
        start = _parse_utc(launch.started_at)
        deadline = _parse_utc(launch.expectation.deadline_utc)
        matching: list[VerifiedInvocationLog] = []
        inventory = _invocation_prefix_inventory(s3_client, bucket, prefix, expected_bucket_owner)
        events_by_version: dict[tuple[str, str], dict[str, Any]] = {}
        seen_events: dict[str, str] = {}
        for event in self.logs.events:
            if (
                event.get("eventSource") != "s3.amazonaws.com"
                or event.get("eventName") != "PutObject"
            ):
                continue
            request = event.get("requestParameters")
            if (
                not isinstance(request, dict)
                or request.get("bucketName") != bucket
                or not isinstance(request.get("key"), str)
                or not request["key"].startswith(prefix)
                or event.get("recipientAccountId") != launch.expectation.account_id
                or event.get("awsRegion") != launch.expectation.region
            ):
                continue
            event_id = event.get("eventID")
            response = event.get("responseElements")
            version_id = (
                response.get("x-amz-version-id", response.get("versionId"))
                if isinstance(response, dict)
                else None
            )
            if not isinstance(event_id, str) or not event_id:
                raise EvidenceIncomplete("invocation log delivery event has no event identity")
            if not isinstance(version_id, str) or not version_id or version_id == "null":
                raise EvidenceIncomplete("invocation log delivery event has no immutable version")
            digest = canonical_event_digest(event)
            previous = seen_events.get(event_id)
            if previous is not None:
                if previous != digest:
                    raise EvidenceContradiction("conflicting CloudTrail delivery event identity")
                continue
            seen_events[event_id] = digest
            events_by_version[(request["key"], version_id)] = event

        if len(inventory) > 256:
            raise EvidenceIncomplete("invocation log prefix exceeds its bounded inventory")
        total_bytes = 0
        for key, version_id, _is_latest in inventory:
            body_response, body = read_version_bytes(
                s3_client,
                bucket=bucket,
                key=key,
                version_id=version_id,
                expected_bucket_owner=expected_bucket_owner,
                maximum_bytes=16 * 1024 * 1024,
            )
            total_bytes += len(body)
            if total_bytes > 64 * 1024 * 1024:
                raise EvidenceIncomplete("invocation log prefix exceeds its bounded read budget")
            if body_response.get("VersionId") != version_id:
                raise EvidenceIncomplete("invocation log read returned a different version")
            if body_response.get("ServerSideEncryption") not in {"aws:kms", "aws:kms:dsse"}:
                raise EvidenceIncomplete("invocation log is not encrypted with KMS")
            payload = strict_json(body, maximum=16 * 1024 * 1024)
            if not isinstance(payload, dict) or payload.get("requestId") != request_id:
                continue
            event = events_by_version.get((key, version_id))
            if event is None:
                raise EvidenceIncomplete("matching invocation object has no delivered writer proof")
            when = _event_time(event)
            if not start <= when <= deadline or event.get("errorCode") or event.get("errorMessage"):
                raise EvidenceIncomplete(
                    "matching invocation writer event is outside the run window"
                )
            metadata = payload.get("requestMetadata")
            if (
                not isinstance(metadata, dict)
                or metadata.get("qualificationRunId") != launch.expectation.run_id
                or metadata.get("qualificationCaseNonce") != case_nonce
            ):
                raise EvidenceIncomplete("invocation log request metadata does not match the probe")
            identity = event.get("userIdentity")
            if (
                not isinstance(identity, dict)
                or identity.get("type") != "AWSService"
                or identity.get("invokedBy") != "bedrock.amazonaws.com"
            ):
                raise EvidenceIncomplete("invocation log writer is not the Bedrock service")
            event_digest = canonical_event_digest(event)
            matching.append(
                VerifiedInvocationLog(
                    _seal=_SEAL,
                    launch=launch,
                    bucket=bucket,
                    key=key,
                    version_id=version_id,
                    request_id=request_id,
                    case_nonce=case_nonce,
                    sha256=hashlib.sha256(body).hexdigest(),
                    event_id=event["eventID"],
                    event_digest=event_digest,
                    payload=payload,
                )
            )
        if (
            _invocation_prefix_inventory(s3_client, bucket, prefix, expected_bucket_owner)
            != inventory
        ):
            raise EvidenceIncomplete("invocation log prefix changed during request resolution")
        if len(matching) != 1:
            raise EvidenceIncomplete("invocation request has no unique authenticated log object")
        return matching[0]

    def authenticate_canary_delivery(
        self,
        launch: VerifiedLaunch,
        *,
        event_id: str,
        bucket: str,
        key: str,
        placement: str,
        task_finished_at: datetime,
        expected_bucket_owner: str,
        s3_client: Any,
    ) -> VerifiedCanaryReceipt:
        """Authenticate a canary from this launch's digest-backed S3 event/version."""
        if launch._seal is not _SEAL or placement not in {"service", "public-isolated"}:
            raise EvidenceContradiction("canary launch or placement is invalid")
        events = [item for item in self.logs.events if item.get("eventID") == event_id]
        if len(events) != 1:
            raise EvidenceIncomplete("canary PutObject event is not uniquely digest-authenticated")
        event = events[0]
        request = event.get("requestParameters")
        response = event.get("responseElements")
        version_id = (
            response.get("x-amz-version-id", response.get("versionId"))
            if isinstance(response, dict)
            else None
        )
        if (
            event.get("eventSource") != "s3.amazonaws.com"
            or event.get("eventName") != "PutObject"
            or event.get("recipientAccountId") != launch.expectation.account_id
            or event.get("awsRegion") != launch.expectation.region
            or event.get("errorCode")
            or event.get("errorMessage")
            or not isinstance(request, dict)
            or request.get("bucketName") != bucket
            or request.get("key") != key
            or not isinstance(version_id, str)
            or not version_id
            or version_id == "null"
            or not _task_identity_matches(event.get("userIdentity"), launch)
        ):
            raise EvidenceIncomplete("canary event does not bind the launched task and object")
        require_exact_current_version(
            s3_client,
            bucket=bucket,
            key=key,
            version_id=version_id,
            expected_bucket_owner=expected_bucket_owner,
        )
        object_response, body = read_version_bytes(
            s3_client,
            bucket=bucket,
            key=key,
            version_id=version_id,
            expected_bucket_owner=expected_bucket_owner,
            maximum_bytes=16_384,
        )
        if object_response.get("VersionId") != version_id or object_response.get(
            "ServerSideEncryption"
        ) not in {"aws:kms", "aws:kms:dsse"}:
            raise EvidenceIncomplete("canary exact version is unavailable or unencrypted")
        payload = strict_json(body, maximum=16_384)
        if (
            not isinstance(payload, dict)
            or payload.get("schema") != "ai-soc.qualification-canary.v1"
            or payload.get("task_arn") != launch.task_arn
            or payload.get("session_id") != launch.expectation.session_id
            or payload.get("run_id") != launch.expectation.run_id
            or payload.get("placement") != placement
        ):
            raise EvidenceContradiction("canary exact version body differs from launch intent")
        digest = hashlib.sha256(body).hexdigest()
        metadata = object_response.get("Metadata")
        if (
            not isinstance(metadata, dict)
            or metadata.get("sha256") != digest
            or metadata.get("task-arn") != launch.task_arn
        ):
            raise EvidenceContradiction("canary exact version hash differs from its metadata")
        tag_response = s3_client.get_object_tagging(
            Bucket=bucket,
            Key=key,
            VersionId=version_id,
            ExpectedBucketOwner=expected_bucket_owner,
        )
        tags = {row.get("Key"): row.get("Value") for row in tag_response.get("TagSet", [])}
        if tags != {
            "session": launch.expectation.session_id,
            "run": launch.expectation.run_id,
            "placement": placement,
        }:
            raise EvidenceIncomplete("canary exact version tags do not match the journaled launch")
        started = _parse_utc(launch.started_at)
        task_started = _parse_utc(payload.get("started_at", ""))
        written_at = _parse_utc(payload.get("written_at", ""))
        finished = _parse_utc(task_finished_at.isoformat())
        event_time = _event_time(event)
        execution_end = _parse_utc(launch.expectation.deadline_utc)
        if launch.expectation.collection_seconds:
            execution_end = min(
                execution_end,
                execution_end - timedelta(seconds=launch.expectation.collection_seconds),
            )
        if launch.expectation.execution_seconds is not None:
            execution_end = min(
                execution_end,
                started + timedelta(seconds=launch.expectation.execution_seconds),
            )
        # CloudTrail eventTime is rounded to millisecond precision in real
        # responses. The task's own start marker can precede the event by less
        # than one second without implying that the write predates its launch.
        event_window_start = started - timedelta(seconds=1)
        if (
            task_started < event_window_start
            or written_at < task_started
            or finished < written_at
            or finished >= execution_end
            or event_time < event_window_start
            or event_time > execution_end
            or event_time > finished + timedelta(seconds=1)
        ):
            raise EvidenceIncomplete("canary timestamps are outside the authenticated run window")
        require_exact_current_version(
            s3_client,
            bucket=bucket,
            key=key,
            version_id=version_id,
            expected_bucket_owner=expected_bucket_owner,
        )
        validated_at = datetime.now(UTC)
        digest_receipt = next(
            (row[1:] for row in self.logs.event_digest_receipts if row[0] == event_id),
            None,
        )
        if digest_receipt is None:
            raise EvidenceIncomplete("canary has no pinned CloudTrail digest object")
        receipt = {
            "verified": "true",
            "placement": placement,
            "session_id": launch.expectation.session_id,
            "run_id": launch.expectation.run_id,
            "event_id": event_id,
            "version_id": version_id,
            "task_arn": launch.task_arn,
            "object_sha256": digest,
            "task_started_at": task_started.isoformat(),
            "task_finished_at": finished.isoformat(),
            "event_time": event_time.isoformat(),
            "digest_file_uri": digest_receipt[0],
            "digest_version_id": digest_receipt[1],
            "digest_validated_at": validated_at.isoformat(),
            "digest_availability_seconds": str((validated_at - event_time).total_seconds()),
            "digest_file_sha256": digest_receipt[2],
        }
        return VerifiedCanaryReceipt(_seal=_SEAL, launch=launch, receipt=receipt)

    def verify_registered_facts(
        self, launch: VerifiedLaunch, measurements: dict[str, Any]
    ) -> VerifiedFactChain:
        """Resolve only core-registered facts and task-recorded AWS request IDs."""
        selectors = {
            fact_id: selector
            for (gate_id, contributor_id, fact_id), selector in FACT_SELECTOR_REGISTRY.items()
            if gate_id == launch.expectation.gate_id
            and contributor_id == launch.expectation.contributor_id
        }
        claims = measurements.get("fact_requests")
        if not selectors:
            raise EvidenceIncomplete("registered fact selectors are unavailable")
        if not isinstance(claims, list):
            raise EvidenceIncomplete("registered fact request receipts are unavailable")
        claim_map: dict[str, list[dict[str, Any]]] = {}
        for claim in claims:
            if not isinstance(claim, dict):
                raise EvidenceContradiction("task fact request receipt is malformed")
            fact_id = claim.get("fact_id")
            if not isinstance(fact_id, str) or fact_id not in selectors:
                raise EvidenceContradiction("task selected an unregistered fact")
            operation = claim.get("operation")
            request_id = claim.get("request_id")
            selector = selectors[fact_id]
            if (
                operation not in selector.event_names
                or not isinstance(request_id, str)
                or not request_id
            ):
                raise EvidenceContradiction(
                    "task fact request differs from its registered selector"
                )
            claim_map.setdefault(fact_id, []).append(claim)
        resource_arns = dict(launch.expectation.resource_arns)
        requirements: list[FactRequirement] = []
        for fact_id, selected_claims in claim_map.items():
            selector = selectors[fact_id]
            selected_resource = resource_arns.get(selector.resource_key)
            if not selected_resource:
                raise EvidenceIncomplete(
                    f"registered AWS resource is absent: {selector.resource_key}"
                )
            request_ids = [claim["request_id"] for claim in selected_claims]
            if len(request_ids) != len(set(request_ids)):
                raise EvidenceIncomplete(
                    f"registered AWS fact request IDs are ambiguous: {fact_id}"
                )
            requirements.extend(
                FactRequirement(
                    fact_id=fact_id,
                    event_source=selector.event_source,
                    event_names=selector.event_names,
                    resource_arn=selected_resource,
                    request_id_field="$requestID",
                    request_id_value=request_id,
                    outcome=selector.outcome,
                )
                for request_id in request_ids
            )
        return _verify_fact_chain(launch, tuple(requirements), self.logs.events)

    def attach_registered_facts(self, artifact: VerifiedArtifact) -> VerifiedArtifact:
        """Return a sealed artifact with a fact chain derived from its envelope."""
        if not is_verified_artifact(artifact):
            raise TypeError("registered facts require an authenticated output artifact")
        chain = self.verify_registered_facts(artifact.launch, artifact.envelope.measurements)
        return VerifiedArtifact(
            _seal=_SEAL,
            launch=artifact.launch,
            bucket=artifact.bucket,
            key=artifact.key,
            version_id=artifact.version_id,
            sha256=artifact.sha256,
            event_id=artifact.event_id,
            event_digest=artifact.event_digest,
            envelope=artifact.envelope,
            fact_chain=chain,
        )
