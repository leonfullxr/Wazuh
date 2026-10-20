# ruff: noqa: F401
from __future__ import annotations

import gzip
import hashlib
import json
import subprocess
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from io import BytesIO
from types import SimpleNamespace
from typing import Any

import boto3
import pytest
from botocore.config import Config
from botocore.response import StreamingBody
from botocore.stub import Stubber
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ai_soc.qualification.evidence import CanaryEnvelope, ProbeEnvelope
from ai_soc.qualification.mcp_models import LvMcpInputs
from scripts.staging.artifact_verification import AuthenticatedEvidenceVerifier
from scripts.staging.attributed_probe import ProbeSpec, QualificationSession
from scripts.staging.cloudtrail import CloudTrailDigestVerifier
from scripts.staging.journal import RunIntent
from scripts.staging.launch_requests import build_probe_config
from scripts.staging.models import DeploymentBinding, GateId
from scripts.staging.state_adapter import StateGateInputs
from scripts.staging.verifier import (
    EvidenceContradiction,
    EvidenceIncomplete,
    FactRequirement,
    LaunchExpectation,
    canonical_request_digest,
)
from tests.unit.staging.authenticated_evidence_support import (
    ACCOUNT,
    CLUSTER,
    EVIDENCE_BUCKET,
    INVOCATION_ID,
    KMS_KEY,
    LAUNCH_ROLE,
    NOW,
    REGION,
    RUN_ID,
    SESSION_ID,
    TASK_ARN,
    TASK_DEF,
    TASK_ID,
    TASK_ROLE,
    _authenticated_verifier,
    _stub_output_object,
    binding,
    expectation,
    launch_event,
    probe_envelope,
    put_event,
)


def test_authenticated_launch_and_exact_output_version_use_digest_backed_events() -> None:
    s3 = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    artifact_body = json.dumps(
        probe_envelope().model_dump(mode="json"),
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    artifact_digest = hashlib.sha256(artifact_body).hexdigest()
    key = f"qualification/{SESSION_ID}/{RUN_ID}/LV-MCP/mcp/{TASK_ID}.json"
    records = _authenticated_verifier(s3, events=[launch_event(), put_event()])
    with Stubber(s3) as stubber:
        stubber.add_response(
            "list_object_versions",
            {
                "Versions": [
                    {
                        "Key": key,
                        "VersionId": "output-version-1",
                        "IsLatest": True,
                        "LastModified": NOW,
                    }
                ],
                "IsTruncated": False,
            },
            {"Bucket": EVIDENCE_BUCKET, "Prefix": key, "ExpectedBucketOwner": ACCOUNT},
        )
        stubber.add_response(
            "get_object",
            {
                "Body": StreamingBody(BytesIO(artifact_body), len(artifact_body)),
                "VersionId": "output-version-1",
                "ContentLength": len(artifact_body),
                "ServerSideEncryption": "aws:kms",
                "SSEKMSKeyId": KMS_KEY,
                "Metadata": {"sha256": artifact_digest, "task-arn": TASK_ARN, "run-id": RUN_ID},
            },
            {
                "Bucket": EVIDENCE_BUCKET,
                "Key": key,
                "VersionId": "output-version-1",
                "ExpectedBucketOwner": ACCOUNT,
            },
        )
        stubber.add_response(
            "get_object_tagging",
            {
                "TagSet": [
                    {"Key": name, "Value": value}
                    for name, value in {
                        "session": SESSION_ID,
                        "invocation": INVOCATION_ID,
                        "run": RUN_ID,
                        "gate": "LV-MCP",
                        "contributor": "mcp",
                        "task": TASK_ARN,
                    }.items()
                ]
            },
            {
                "Bucket": EVIDENCE_BUCKET,
                "Key": key,
                "VersionId": "output-version-1",
                "ExpectedBucketOwner": ACCOUNT,
            },
        )
        stubber.add_response(
            "list_object_versions",
            {
                "Versions": [
                    {
                        "Key": key,
                        "VersionId": "output-version-1",
                        "IsLatest": True,
                        "LastModified": NOW,
                    }
                ],
                "IsTruncated": False,
            },
            {"Bucket": EVIDENCE_BUCKET, "Prefix": key, "ExpectedBucketOwner": ACCOUNT},
        )
        verifier = AuthenticatedEvidenceVerifier(records)
        launch = verifier.authenticate_launch(expectation())
        artifact = verifier.authenticate_output(
            launch,
            bucket=EVIDENCE_BUCKET,
            key=key,
            role_arn=TASK_ROLE,
            expected_kms_key_arn=KMS_KEY,
            expected_bucket_owner=ACCOUNT,
            s3_client=s3,
        )
        assert artifact.version_id == "output-version-1"
        assert artifact.sha256 == artifact_digest
        assert artifact.envelope.measurements == {"client_flow_complete": True}
        with pytest.raises(TypeError, match="cannot be serialized"):
            artifact.__reduce__()


@pytest.mark.parametrize("case", ("sibling-after-read", "exact-expiry"))
def test_output_rechecks_version_and_rejects_exact_execution_expiry(case: str) -> None:
    s3 = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    completed_at = (
        NOW + timedelta(seconds=46) if case == "exact-expiry" else NOW + timedelta(seconds=45)
    )
    key = f"qualification/{SESSION_ID}/{RUN_ID}/LV-MCP/mcp/{TASK_ID}.json"
    body = json.dumps(
        probe_envelope(completed_at=completed_at).model_dump(mode="json"),
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    launch_expectation = expectation()
    if case == "exact-expiry":
        launch_expectation = replace(
            launch_expectation,
            deadline_utc=completed_at.isoformat().replace("+00:00", "Z"),
        )
    logs = _authenticated_verifier(s3, events=[launch_event(), put_event()])
    verifier = AuthenticatedEvidenceVerifier(logs)
    launch = verifier.authenticate_launch(launch_expectation)
    newer_versions = (
        [
            {"Key": key, "VersionId": "output-version-2", "IsLatest": True},
            {"Key": key, "VersionId": "output-version-1", "IsLatest": False},
        ]
        if case == "sibling-after-read"
        else None
    )
    with Stubber(s3) as stubber:
        _stub_output_object(stubber, key=key, body=body, second_versions=newer_versions)
        error = EvidenceIncomplete if case == "sibling-after-read" else EvidenceContradiction
        message = "ambiguous versions" if case == "sibling-after-read" else "at or after"
        with pytest.raises(error, match=message):
            verifier.authenticate_output(
                launch,
                bucket=EVIDENCE_BUCKET,
                key=key,
                role_arn=TASK_ROLE,
                expected_kms_key_arn=KMS_KEY,
                expected_bucket_owner=ACCOUNT,
                s3_client=s3,
            )


def test_output_rejects_bucket_policy_changes_during_run() -> None:
    s3 = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    policy_event = {
        "eventVersion": "1.08",
        "eventID": "bucket-policy-change",
        "requestID": "policy-request",
        "eventSource": "s3.amazonaws.com",
        "eventName": "PutBucketPolicy",
        "awsRegion": REGION,
        "recipientAccountId": ACCOUNT,
        "eventTime": (NOW + timedelta(seconds=30)).isoformat().replace("+00:00", "Z"),
        "requestParameters": {"bucketName": EVIDENCE_BUCKET},
    }
    verifier = AuthenticatedEvidenceVerifier(
        _authenticated_verifier(s3, events=[launch_event(), put_event(), policy_event])
    )
    launch = verifier.authenticate_launch(expectation())
    with pytest.raises(EvidenceIncomplete, match="controls changed"):
        verifier.authenticate_output(
            launch,
            bucket=EVIDENCE_BUCKET,
            key=f"qualification/{SESSION_ID}/{RUN_ID}/LV-MCP/mcp/{TASK_ID}.json",
            role_arn=TASK_ROLE,
            expected_kms_key_arn=KMS_KEY,
            expected_bucket_owner=ACCOUNT,
            s3_client=s3,
        )


def test_cloudtrail_log_bytes_must_match_authenticated_digest_hash() -> None:
    s3 = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    with pytest.raises(EvidenceIncomplete, match="signed digest hash"):
        _authenticated_verifier(
            s3,
            events=[launch_event()],
            digest_log_hash="0" * 64,
        )


def test_canary_receipt_is_minted_only_from_authenticated_launch_and_exact_object() -> None:
    s3 = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    event_time = NOW + timedelta(seconds=30)
    key = f"canary/{SESSION_ID}/{RUN_ID}/service.json"
    envelope = CanaryEnvelope(
        wire_schema="ai-soc.qualification-canary.v1",
        task_arn=TASK_ARN,
        session_id=SESSION_ID,
        run_id=RUN_ID,
        placement="service",
        nonce="canary-nonce",
        started_at=NOW + timedelta(seconds=5),
        # The envelope is written immediately before the PutObject event.
        written_at=event_time - timedelta(milliseconds=1),
    )
    body = json.dumps(
        envelope.model_dump(mode="json", by_alias=True),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    digest = hashlib.sha256(body).hexdigest()
    event = {
        "eventVersion": "1.08",
        "eventID": "canary-put-1",
        "requestID": "canary-request-1",
        "eventSource": "s3.amazonaws.com",
        "eventName": "PutObject",
        "awsRegion": REGION,
        "recipientAccountId": ACCOUNT,
        "eventTime": event_time.isoformat().replace("+00:00", "Z"),
        "userIdentity": {
            "type": "AssumedRole",
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/application/{TASK_ID}",
            "principalId": f"AROAAPP:{TASK_ID}",
            "sessionContext": {"sessionIssuer": {"arn": TASK_ROLE}},
        },
        "requestParameters": {"bucketName": EVIDENCE_BUCKET, "key": key},
        "responseElements": {"x-amz-version-id": "canary-version-1"},
    }
    logs = _authenticated_verifier(s3, events=[launch_event(), event])
    verifier = AuthenticatedEvidenceVerifier(logs)
    launch = verifier.authenticate_launch(expectation())
    with Stubber(s3) as stubber:
        expected = {
            "Bucket": EVIDENCE_BUCKET,
            "Prefix": key,
            "ExpectedBucketOwner": ACCOUNT,
        }
        for _ in range(2):
            stubber.add_response(
                "list_object_versions",
                {
                    "Versions": [{"Key": key, "VersionId": "canary-version-1", "IsLatest": True}],
                    "IsTruncated": False,
                },
                expected,
            )
            if _ == 0:
                stubber.add_response(
                    "get_object",
                    {
                        "Body": StreamingBody(BytesIO(body), len(body)),
                        "VersionId": "canary-version-1",
                        "ServerSideEncryption": "aws:kms",
                        "Metadata": {"sha256": digest, "task-arn": TASK_ARN},
                    },
                    {
                        "Bucket": EVIDENCE_BUCKET,
                        "Key": key,
                        "VersionId": "canary-version-1",
                        "ExpectedBucketOwner": ACCOUNT,
                    },
                )
                stubber.add_response(
                    "get_object_tagging",
                    {
                        "TagSet": [
                            {"Key": "session", "Value": SESSION_ID},
                            {"Key": "run", "Value": RUN_ID},
                            {"Key": "placement", "Value": "service"},
                        ]
                    },
                    {
                        "Bucket": EVIDENCE_BUCKET,
                        "Key": key,
                        "VersionId": "canary-version-1",
                        "ExpectedBucketOwner": ACCOUNT,
                    },
                )
        proof = verifier.authenticate_canary_delivery(
            launch,
            event_id="canary-put-1",
            bucket=EVIDENCE_BUCKET,
            key=key,
            placement="service",
            task_finished_at=event_time + timedelta(seconds=2),
            expected_bucket_owner=ACCOUNT,
            s3_client=s3,
        )
    assert proof.receipt["digest_file_sha256"] == logs.digest_receipts[0][2]
    assert proof.receipt["task_finished_at"] == (event_time + timedelta(seconds=2)).isoformat()


def test_launch_fails_closed_on_edited_client_token() -> None:
    s3 = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    altered = launch_event()
    request = altered["requestParameters"]
    assert isinstance(request, dict)
    request["clientToken"] = "foreign-token"
    logs = _authenticated_verifier(s3, events=[altered])
    with pytest.raises(EvidenceIncomplete, match="not available"):
        AuthenticatedEvidenceVerifier(logs).authenticate_launch(expectation())


def test_two_recorded_launches_share_run_id_but_resolve_by_client_token() -> None:
    import copy

    s3 = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    first = launch_event()
    second = copy.deepcopy(first)
    second["eventID"] = "launch-event-b"
    second["requestID"] = "launch-request-b"
    second_request = second["requestParameters"]
    assert isinstance(second_request, dict)
    second_request["clientToken"] = "slot-token-b"
    second_tags = second_request["tags"]
    assert isinstance(second_tags, list)
    second_tags[-1] = {"key": "qualification-slot", "value": "B"}
    second_response = second["responseElements"]
    assert isinstance(second_response, dict)
    second_tasks = second_response["tasks"]
    assert isinstance(second_tasks, list)
    second_tasks[0] = {
        **second_tasks[0],
        "taskArn": TASK_ARN.replace(TASK_ID, "abcdef0123456789"),
    }
    logs = _authenticated_verifier(s3, events=[first, second])
    verifier = AuthenticatedEvidenceVerifier(logs)
    launch_a = verifier.authenticate_launch(expectation())
    launch_b = verifier.authenticate_launch(
        replace(
            expectation(),
            client_token="slot-token-b",
            slot="B",
            launch_request_digest=canonical_request_digest(second_request),
        )
    )
    assert launch_a.task_arn != launch_b.task_arn


def test_output_newer_version_inventory_is_ambiguous() -> None:
    s3 = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    logs = _authenticated_verifier(s3, events=[launch_event(), put_event()])
    verifier = AuthenticatedEvidenceVerifier(logs)
    key = f"qualification/{SESSION_ID}/{RUN_ID}/LV-MCP/mcp/{TASK_ID}.json"
    with Stubber(s3) as stubber:
        stubber.add_response(
            "list_object_versions",
            {
                "Versions": [
                    {"Key": key, "VersionId": "output-version-2", "IsLatest": True},
                    {"Key": key, "VersionId": "output-version-1", "IsLatest": False},
                ],
                "IsTruncated": False,
            },
            {"Bucket": EVIDENCE_BUCKET, "Prefix": key, "ExpectedBucketOwner": ACCOUNT},
        )
        with pytest.raises(EvidenceIncomplete, match="ambiguous versions"):
            verifier.authenticate_output(
                verifier.authenticate_launch(expectation()),
                bucket=EVIDENCE_BUCKET,
                key=key,
                role_arn=TASK_ROLE,
                expected_kms_key_arn=KMS_KEY,
                expected_bucket_owner=ACCOUNT,
                s3_client=s3,
            )


def test_output_version_and_duplicate_mutations_are_not_fallbacks() -> None:
    s3 = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    logs = _authenticated_verifier(s3, events=[launch_event(), put_event(version_id=None)])
    verifier = AuthenticatedEvidenceVerifier(logs)
    launch = verifier.authenticate_launch(expectation())
    key = f"qualification/{SESSION_ID}/{RUN_ID}/LV-MCP/mcp/{TASK_ID}.json"
    with pytest.raises(EvidenceIncomplete, match="version ID"):
        verifier.authenticate_output(
            launch,
            bucket=EVIDENCE_BUCKET,
            key=key,
            role_arn=TASK_ROLE,
            expected_kms_key_arn=KMS_KEY,
            expected_bucket_owner=ACCOUNT,
            s3_client=s3,
        )
    duplicate = put_event()
    duplicate["eventID"] = "put-event-2"
    s3_other = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    duplicate_logs = _authenticated_verifier(
        s3_other, events=[launch_event(), put_event(), duplicate]
    )
    with pytest.raises(EvidenceIncomplete, match="exactly one"):
        verify = AuthenticatedEvidenceVerifier(duplicate_logs)
        verify.authenticate_output(
            verify.authenticate_launch(expectation()),
            bucket=EVIDENCE_BUCKET,
            key=key,
            role_arn=TASK_ROLE,
            expected_kms_key_arn=KMS_KEY,
            expected_bucket_owner=ACCOUNT,
            s3_client=s3_other,
        )


@pytest.mark.parametrize("fact_attachment_contradiction", [False, True])
def test_real_authenticate_run_authenticates_launch_and_output_without_substitution(
    monkeypatch, fact_attachment_contradiction: bool
) -> None:
    from scripts.staging import cloudtrail, run_authentication
    from scripts.staging.registry import PROBE_REGISTRY

    now = datetime.now(UTC)
    deadline = (now + timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
    invocation_id = INVOCATION_ID
    client_token = "77777777-8888-4999-8aaa-bbbbbbbbbbbb"
    inputs = LvMcpInputs.model_validate(
        {
            "endpoint": "https://example.test/mcp",
            "rest_endpoint": "https://example.test/v1/questions",
            "token_endpoint": "https://example.test/oauth/token",
            "resource": "https://example.test/resource",
            "issuer": "https://example.test/issuer",
            "client_id": "qualification",
            "synthetic_subject": "soc-probe",
            "access_token_ref": "access-token-ref",
            "id_token_ref": "id-token-ref",
            "browser_cookie_ref": "cookie-ref",
            "csrf_token_ref": "csrf-ref",
            "evidence_bucket": EVIDENCE_BUCKET,
            "evidence_prefix": "qualification/lv-mcp",
            "negative_token_refs": {
                "wrong_resource": "wrong-resource",
                "wrong_issuer": "wrong-issuer",
                "wrong_scope": "wrong-scope",
            },
            "wrong_issuer": {
                "issuer": "https://other.test/issuer",
                "jwks_uri": "https://other.test/jwks",
            },
            "origin": "https://example.test",
            "disallowed_origin": "https://attacker.test",
            "ask_request": {"question": "verify", "environment_id": "alpha"},
            "page_request": {"environment_id": "alpha", "cursor": "cursor"},
        }
    )
    spec = ProbeSpec(
        entrypoint="mcp",
        parameters={"container_name": "ai-soc", "inputs": inputs.model_dump(mode="json")},
        execution_seconds=60,
        collection_seconds=90,
    )
    config = build_probe_config(
        PROBE_REGISTRY[(GateId.LV_MCP, "mcp", "mcp")],
        scenario=spec,
        binding=binding(),
        run_id=RUN_ID,
        session_id=SESSION_ID,
        invocation_id=invocation_id,
        slot="probe",
        deadline_utc=deadline,
        evidence_bucket=EVIDENCE_BUCKET,
        kms_key_arn=KMS_KEY,
        account_id=ACCOUNT,
    )
    request = {
        "cluster": CLUSTER,
        "taskDefinition": TASK_DEF,
        "startedBy": RUN_ID,
        "clientToken": client_token,
        "tags": [
            {"key": key, "value": value}
            for key, value in (
                ("qualification", "true"),
                ("qualification-session", SESSION_ID),
                ("qualification-invocation", invocation_id),
                ("qualification-run", RUN_ID),
                ("qualification-gate", "LV-MCP"),
                ("qualification-contributor", "mcp"),
                ("qualification-slot", "probe"),
            )
        ],
        "overrides": {
            "containerOverrides": [
                {
                    "name": "ai-soc",
                    "command": list(config.command),
                    "environment": list(config.environment),
                }
            ]
        },
    }
    second_task_arn = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task/qualification/{TASK_ID}-second"
    second_client_token = "88888888-9999-4aaa-8bbb-cccccccccccc"
    second_request = json.loads(json.dumps(request))
    second_request["clientToken"] = second_client_token
    for tag in second_request["tags"]:
        if tag["key"] == "qualification-slot":
            tag["value"] = "unregistered-contender"
    launch = launch_event()
    launch["requestParameters"] = request
    output_key = f"qualification/{SESSION_ID}/{RUN_ID}/LV-MCP/mcp/{TASK_ID}.json"
    logs_client = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    logs = _authenticated_verifier(logs_client, events=[launch, put_event()])
    s3 = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    body = json.dumps(
        probe_envelope().model_dump(mode="json"),
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    import scripts.staging.journal as journal

    registration = PROBE_REGISTRY[(GateId.LV_MCP, "mcp", "mcp")]
    monkeypatch.setattr(
        journal,
        "probe_registrations",
        lambda _gate_id, _contributor_id: (
            replace(registration, slots=("probe", "unregistered-contender")),
        ),
    )
    run = RunIntent(
        invocation_id=invocation_id,
        run_id=RUN_ID,
        started_by=RUN_ID,
        client_tokens=(client_token, second_client_token),
        gate_id=GateId.LV_MCP.value,
        contributor_id="mcp",
        task_slots=("probe", "unregistered-contender"),
        task_arns=(TASK_ARN, second_task_arn),
        probe_spec=spec,
        launch_requests=(request, second_request),
        deadline_utc=deadline,
        state="stopped",
    )
    task = {
        "taskArn": TASK_ARN,
        "clusterArn": CLUSTER,
        "taskDefinitionArn": TASK_DEF,
        "startedBy": RUN_ID,
        "lastStatus": "STOPPED",
        "tags": [{"key": item["key"], "value": item["value"]} for item in request["tags"]],
        "containers": [{"name": "ai-soc", "exitCode": 0, "imageDigest": binding().image_digest}],
        "overrides": request["overrides"],
    }
    second_task = {
        **task,
        "taskArn": second_task_arn,
        "tags": [{"key": item["key"], "value": item["value"]} for item in second_request["tags"]],
        "overrides": second_request["overrides"],
    }

    class Ecs:
        def get_paginator(self, operation: str):
            assert operation == "list_tasks"
            return SimpleNamespace(
                paginate=lambda **_kwargs: [{"taskArns": [TASK_ARN, second_task_arn]}]
            )

        def describe_tasks(self, **_kwargs):
            return {"tasks": [task, second_task], "failures": []}

    class Clients:
        session = None

        def client(self, service: str):
            return Ecs() if service == "ecs" else s3

    resource_map = SimpleNamespace(
        certification_enabled=True,
        evidence=SimpleNamespace(
            app_prefix="qualification/", bucket=EVIDENCE_BUCKET, kms_key_arn=KMS_KEY
        ),
        service=SimpleNamespace(application_role_arn=TASK_ROLE),
    )
    session = SimpleNamespace(
        resource_map=resource_map,
        launcher_role_arn=LAUNCH_ROLE,
        _journal=SimpleNamespace(
            runs=(run,), session_expires_at=(now + timedelta(hours=1)).isoformat()
        ),
        binding=binding(),
        clients=Clients(),
        session_id=SESSION_ID,
        _authentication_diagnostics={},
    )
    session._task_identity = lambda task_row, active_run: QualificationSession._task_identity(
        session, task_row, active_run
    )
    session._task_runtime_binding = lambda task_row, active_run: (
        QualificationSession._task_runtime_binding(session, task_row, active_run)
    )
    monkeypatch.setattr(cloudtrail, "validate_session_logs", lambda **_kwargs: logs)
    if fact_attachment_contradiction:

        def reject_fact_attachment(_verifier, _artifact):
            raise EvidenceContradiction("fact evidence contradicts the authenticated envelope")

        monkeypatch.setattr(
            AuthenticatedEvidenceVerifier,
            "attach_registered_facts",
            reject_fact_attachment,
        )
    with Stubber(s3) as stubber:
        _stub_output_object(
            stubber,
            key=output_key,
            body=body,
            second_versions=[
                {"Key": output_key, "VersionId": "output-version-1", "IsLatest": True}
            ],
        )
        artifacts = run_authentication.authenticate_run(session, RUN_ID)

    assert len(artifacts) == 1, session._authentication_diagnostics
    assert artifacts[0].key == output_key
    assert session._authentication_diagnostics[RUN_ID][-1] == (
        "contender authentication failed: ValueError"
    )
    if fact_attachment_contradiction:
        assert any(
            "EvidenceContradiction" in diagnostic
            for diagnostic in session._authentication_diagnostics[RUN_ID]
        ), session._authentication_diagnostics[RUN_ID]
