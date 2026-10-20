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

from ai_soc.qualification.evidence import ProbeEnvelope
from ai_soc.qualification.mcp_models import LvMcpInputs
from scripts.staging.artifact_verification import AuthenticatedEvidenceVerifier
from scripts.staging.attributed_probe import ProbeSpec, QualificationSession, _binding_dict
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
    NOW,
    REGION,
    RUN_ID,
    _authenticated_verifier,
    _stub_invocation_object,
    _stub_invocation_prefix_inventory,
    expectation,
    invocation_put_event,
    launch_event,
)


def test_bedrock_invocation_log_requires_authenticated_service_writer() -> None:
    s3 = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    key = "bedrock-invocations/2026/10/08/planted.json"
    payload = {
        "requestId": "provider-request-1",
        "requestMetadata": {
            "qualificationRunId": RUN_ID,
            "qualificationCaseNonce": "case-nonce-1",
        },
        "output": {"text": "sanitized"},
    }
    logs = _authenticated_verifier(
        s3,
        events=[launch_event(), invocation_put_event(key=key, event_id="planted", writer="runner")],
    )
    verifier = AuthenticatedEvidenceVerifier(logs)
    launch = verifier.authenticate_launch(expectation())
    with Stubber(s3) as stubber:
        _stub_invocation_prefix_inventory(stubber, [(key, "version-planted")])
        _stub_invocation_object(stubber, key=key, event_id="planted", payload=payload)
        _stub_invocation_prefix_inventory(stubber, [(key, "version-planted")])
        with pytest.raises(EvidenceIncomplete, match="writer is not the Bedrock service"):
            verifier.authenticate_invocation_log(
                launch,
                bucket="invocation-bucket",
                prefix="bedrock-invocations/",
                request_id="provider-request-1",
                case_nonce="case-nonce-1",
                expected_bucket_owner=ACCOUNT,
                s3_client=s3,
            )


def test_bedrock_invocation_log_accepts_one_exact_service_written_version() -> None:
    s3 = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    key = "bedrock-invocations/2026/10/08/request-a.json"
    payload = {
        "requestId": "provider-request-1",
        "requestMetadata": {
            "qualificationRunId": RUN_ID,
            "qualificationCaseNonce": "case-nonce-1",
        },
        "usage": {"inputTokens": 12, "outputTokens": 9},
    }
    logs = _authenticated_verifier(
        s3,
        events=[launch_event(), invocation_put_event(key=key, event_id="bedrock-a")],
    )
    verifier = AuthenticatedEvidenceVerifier(logs)
    launch = verifier.authenticate_launch(expectation())
    with Stubber(s3) as stubber:
        _stub_invocation_prefix_inventory(stubber, [(key, "version-bedrock-a")])
        _stub_invocation_object(stubber, key=key, event_id="bedrock-a", payload=payload)
        _stub_invocation_prefix_inventory(stubber, [(key, "version-bedrock-a")])
        authenticated = verifier.authenticate_invocation_log(
            launch,
            bucket="invocation-bucket",
            prefix="bedrock-invocations/",
            request_id="provider-request-1",
            case_nonce="case-nonce-1",
            expected_bucket_owner=ACCOUNT,
            s3_client=s3,
        )
    assert authenticated.version_id == "version-bedrock-a"
    assert authenticated.event_id == "bedrock-a"
    assert authenticated.payload["usage"] == {"inputTokens": 12, "outputTokens": 9}


def test_bedrock_invocation_log_rejects_duplicate_objects_for_request() -> None:
    s3 = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    key_a = "bedrock-invocations/2026/10/08/request-a.json"
    key_b = "bedrock-invocations/2026/10/08/request-b.json"
    payload = {
        "requestId": "provider-request-1",
        "requestMetadata": {
            "qualificationRunId": RUN_ID,
            "qualificationCaseNonce": "case-nonce-1",
        },
        "output": {"text": "same request, duplicate object"},
    }
    logs = _authenticated_verifier(
        s3,
        events=[
            launch_event(),
            invocation_put_event(key=key_a, event_id="bedrock-a"),
            invocation_put_event(key=key_b, event_id="bedrock-b"),
        ],
    )
    verifier = AuthenticatedEvidenceVerifier(logs)
    launch = verifier.authenticate_launch(expectation())
    with Stubber(s3) as stubber:
        _stub_invocation_prefix_inventory(
            stubber,
            [(key_a, "version-bedrock-a"), (key_b, "version-bedrock-b")],
        )
        _stub_invocation_object(stubber, key=key_a, event_id="bedrock-a", payload=payload)
        _stub_invocation_object(stubber, key=key_b, event_id="bedrock-b", payload=payload)
        _stub_invocation_prefix_inventory(
            stubber,
            [(key_a, "version-bedrock-a"), (key_b, "version-bedrock-b")],
        )
        with pytest.raises(EvidenceIncomplete, match="no unique authenticated log object"):
            verifier.authenticate_invocation_log(
                launch,
                bucket="invocation-bucket",
                prefix="bedrock-invocations/",
                request_id="provider-request-1",
                case_nonce="case-nonce-1",
                expected_bucket_owner=ACCOUNT,
                s3_client=s3,
            )


def test_bedrock_invocation_log_rejects_inventory_duplicate_without_delivered_event() -> None:
    s3 = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    key_a = "bedrock-invocations/2026/10/08/request-a.json"
    key_b = "bedrock-invocations/2026/10/08/request-b.json"
    payload = {
        "requestId": "provider-request-1",
        "requestMetadata": {
            "qualificationRunId": RUN_ID,
            "qualificationCaseNonce": "case-nonce-1",
        },
    }
    verifier = AuthenticatedEvidenceVerifier(
        _authenticated_verifier(
            s3,
            events=[
                launch_event(),
                invocation_put_event(key=key_a, event_id="bedrock-a"),
            ],
        )
    )
    launch = verifier.authenticate_launch(expectation())
    with Stubber(s3) as stubber:
        _stub_invocation_prefix_inventory(
            stubber,
            [(key_a, "version-bedrock-a"), (key_b, "version-bedrock-b")],
        )
        _stub_invocation_object(stubber, key=key_a, event_id="bedrock-a", payload=payload)
        _stub_invocation_object(stubber, key=key_b, event_id="bedrock-b", payload=payload)
        with pytest.raises(EvidenceIncomplete, match="no delivered writer proof"):
            verifier.authenticate_invocation_log(
                launch,
                bucket="invocation-bucket",
                prefix="bedrock-invocations/",
                request_id="provider-request-1",
                case_nonce="case-nonce-1",
                expected_bucket_owner=ACCOUNT,
                s3_client=s3,
            )


def test_bedrock_invocation_log_rechecks_prefix_after_body_reads() -> None:
    s3 = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    key = "bedrock-invocations/2026/10/08/request-a.json"
    payload = {
        "requestId": "provider-request-1",
        "requestMetadata": {
            "qualificationRunId": RUN_ID,
            "qualificationCaseNonce": "case-nonce-1",
        },
    }
    verifier = AuthenticatedEvidenceVerifier(
        _authenticated_verifier(
            s3,
            events=[launch_event(), invocation_put_event(key=key, event_id="bedrock-a")],
        )
    )
    launch = verifier.authenticate_launch(expectation())
    with Stubber(s3) as stubber:
        _stub_invocation_prefix_inventory(stubber, [(key, "version-bedrock-a")])
        _stub_invocation_object(stubber, key=key, event_id="bedrock-a", payload=payload)
        _stub_invocation_prefix_inventory(
            stubber,
            [(key, "version-bedrock-a"), (key, "version-late-duplicate")],
        )
        with pytest.raises(EvidenceIncomplete, match="prefix changed"):
            verifier.authenticate_invocation_log(
                launch,
                bucket="invocation-bucket",
                prefix="bedrock-invocations/",
                request_id="provider-request-1",
                case_nonce="case-nonce-1",
                expected_bucket_owner=ACCOUNT,
                s3_client=s3,
            )


def test_bedrock_invocation_log_rejects_bucket_policy_change_during_run() -> None:
    s3 = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    policy_change = {
        "eventVersion": "1.08",
        "eventID": "invocation-policy-change",
        "eventSource": "s3.amazonaws.com",
        "eventName": "PutBucketPolicy",
        "awsRegion": REGION,
        "recipientAccountId": ACCOUNT,
        "eventTime": (NOW + timedelta(seconds=15)).isoformat().replace("+00:00", "Z"),
        "requestParameters": {"bucketName": "invocation-bucket"},
    }
    logs = _authenticated_verifier(s3, events=[launch_event(), policy_change])
    verifier = AuthenticatedEvidenceVerifier(logs)
    launch = verifier.authenticate_launch(expectation())
    with pytest.raises(EvidenceIncomplete, match="controls changed"):
        verifier.authenticate_invocation_log(
            launch,
            bucket="invocation-bucket",
            prefix="bedrock-invocations/",
            request_id="provider-request-1",
            case_nonce="case-nonce-1",
            expected_bucket_owner=ACCOUNT,
            s3_client=s3,
        )
