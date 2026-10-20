from __future__ import annotations

import gzip
import hashlib
import json
import subprocess
from datetime import UTC, datetime, timedelta
from io import BytesIO
from typing import Any

import boto3
from botocore.config import Config
from botocore.response import StreamingBody
from botocore.stub import Stubber
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ai_soc.qualification.evidence import ProbeEnvelope
from ai_soc.qualification.mcp_models import LvMcpInputs
from scripts.staging.artifact_verification import AuthenticatedEvidenceVerifier
from scripts.staging.cloudtrail import CloudTrailDigestVerifier
from scripts.staging.models import DeploymentBinding, GateId
from scripts.staging.verifier import (
    LaunchExpectation,
    canonical_request_digest,
)

REGION = "eu-central-1"
ACCOUNT = "123456789012"
CLUSTER = f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/qualification"
SERVICE = f"arn:aws:ecs:{REGION}:{ACCOUNT}:service/qualification/app"
TASK_DEF = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/ai-soc:7"
TASK_ID = "0123456789abcdef0123456789abcdef"
TASK_ARN = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task/qualification/{TASK_ID}"
TASK_ROLE = f"arn:aws:iam::{ACCOUNT}:role/application"
LAUNCH_ROLE = f"arn:aws:iam::{ACCOUNT}:role/qualification-launcher"
EVIDENCE_BUCKET = "ai-soc-qualification-audit"
TRAIL_BUCKET = "ai-soc-qualification-cloudtrail"
KMS_KEY = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/qualification"
RUN_ID = "11111111-2222-4333-8444-555555555555"
INVOCATION_ID = "66666666-7777-4888-8999-aaaaaaaaaaaa"
SESSION_ID = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
NOW = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)


def binding() -> DeploymentBinding:
    return DeploymentBinding(
        account_id=ACCOUNT,
        region=REGION,
        cluster_arn=CLUSTER,
        service_arn=SERVICE,
        task_definition_arn=TASK_DEF,
        deployment_name="qualification",
        deployment_id="ecs-svc/1234567890123456789",
        image_digest="a" * 64,
        service_sha="b" * 40,
        content_sha="c" * 40,
        configuration_sha256="d" * 64,
    )


def mcp_probe_inputs() -> LvMcpInputs:
    return LvMcpInputs.model_validate(
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


def expectation() -> LaunchExpectation:
    request = launch_event()["requestParameters"]
    assert isinstance(request, dict)
    return LaunchExpectation(
        account_id=ACCOUNT,
        region=REGION,
        launcher_role_arn=LAUNCH_ROLE,
        cluster_arn=CLUSTER,
        task_definition_arn=TASK_DEF,
        started_by=RUN_ID,
        client_token="slot-token-a",
        session_id=SESSION_ID,
        invocation_id=INVOCATION_ID,
        run_id=RUN_ID,
        gate_id=GateId.LV_MCP,
        contributor_id="mcp",
        slot="A",
        task_role_arn=TASK_ROLE,
        binding=binding(),
        deadline_utc=(NOW + timedelta(minutes=5)).isoformat(),
        launch_request_digest=canonical_request_digest(request),
        required_request_fields=tuple(request),
    )


def launch_event() -> dict[str, object]:
    return {
        "eventVersion": "1.08",
        "eventID": "launch-event-1",
        "requestID": "launch-request-1",
        "eventSource": "ecs.amazonaws.com",
        "eventName": "RunTask",
        "awsRegion": REGION,
        "recipientAccountId": ACCOUNT,
        "eventTime": NOW.isoformat().replace("+00:00", "Z"),
        "userIdentity": {
            "type": "AssumedRole",
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/qualification-launcher/test-session",
            "principalId": "AROAEXAMPLE:test-session",
            "sessionContext": {"sessionIssuer": {"arn": LAUNCH_ROLE}},
        },
        "requestParameters": {
            "cluster": CLUSTER,
            "taskDefinition": TASK_DEF,
            "startedBy": RUN_ID,
            "clientToken": "slot-token-a",
            "tags": [
                {"key": "qualification-session", "value": SESSION_ID},
                {"key": "qualification-invocation", "value": INVOCATION_ID},
                {"key": "qualification-run", "value": RUN_ID},
                {"key": "qualification-gate", "value": "LV-MCP"},
                {"key": "qualification-contributor", "value": "mcp"},
                {"key": "qualification-slot", "value": "A"},
            ],
        },
        "responseElements": {
            "tasks": [
                {
                    "taskArn": TASK_ARN,
                    "clusterArn": CLUSTER,
                    "taskDefinitionArn": TASK_DEF,
                    "startedBy": RUN_ID,
                }
            ]
        },
    }


def probe_envelope(*, completed_at: datetime | None = None) -> ProbeEnvelope:
    return ProbeEnvelope(
        schema_version=1,
        session_id=SESSION_ID,
        invocation_id=INVOCATION_ID,
        run_id=RUN_ID,
        gate_id="LV-MCP",
        contributor_id="mcp",
        binding={
            "account_id": ACCOUNT,
            "region": REGION,
            "cluster_arn": CLUSTER,
            "service_arn": SERVICE,
            "task_definition_arn": TASK_DEF,
            "deployment_name": "qualification",
            "deployment_id": "ecs-svc/1234567890123456789",
            "image_digest": "sha256:" + "a" * 64,
            "service_sha": "b" * 40,
            "content_sha": "c" * 40,
            "configuration_sha256": "d" * 64,
        },
        scenario_sha256="e" * 64,
        started_at=NOW,
        completed_at=completed_at or NOW + timedelta(seconds=45),
        measurements={"client_flow_complete": True},
    )


def put_event(*, version_id: str | None = "output-version-1") -> dict[str, object]:
    response: dict[str, str] = {}
    if version_id is not None:
        response["x-amz-version-id"] = version_id
    return {
        "eventVersion": "1.08",
        "eventID": "put-event-1",
        "requestID": "put-request-1",
        "eventSource": "s3.amazonaws.com",
        "eventName": "PutObject",
        "awsRegion": REGION,
        "recipientAccountId": ACCOUNT,
        "eventTime": (NOW + timedelta(seconds=46)).isoformat().replace("+00:00", "Z"),
        "userIdentity": {
            "type": "AssumedRole",
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/application/{TASK_ID}",
            "principalId": f"AROAAPP:{TASK_ID}",
            "sessionContext": {"sessionIssuer": {"arn": TASK_ROLE}},
        },
        "requestParameters": {
            "bucketName": EVIDENCE_BUCKET,
            "key": (f"qualification/{SESSION_ID}/{RUN_ID}/LV-MCP/mcp/{TASK_ID}.json"),
        },
        "responseElements": response,
    }


def invocation_put_event(
    *, key: str, event_id: str, writer: str = "bedrock.amazonaws.com"
) -> dict[str, object]:
    return {
        "eventVersion": "1.08",
        "eventID": event_id,
        "requestID": f"s3-request-{event_id}",
        "eventSource": "s3.amazonaws.com",
        "eventName": "PutObject",
        "awsRegion": REGION,
        "recipientAccountId": ACCOUNT,
        "eventTime": (NOW + timedelta(seconds=10)).isoformat().replace("+00:00", "Z"),
        "userIdentity": {"type": "AWSService", "invokedBy": writer},
        "requestParameters": {"bucketName": "invocation-bucket", "key": key},
        "responseElements": {"x-amz-version-id": f"version-{event_id}"},
    }


def _stub_invocation_object(
    stubber: Stubber, *, key: str, event_id: str, payload: dict[str, Any]
) -> None:
    version_id = f"version-{event_id}"
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    stubber.add_response(
        "get_object",
        {
            "Body": StreamingBody(BytesIO(raw), len(raw)),
            "VersionId": version_id,
            "ServerSideEncryption": "aws:kms",
        },
        {
            "Bucket": "invocation-bucket",
            "Key": key,
            "VersionId": version_id,
            "ExpectedBucketOwner": ACCOUNT,
        },
    )


def _stub_invocation_prefix_inventory(
    stubber: Stubber,
    versions: list[tuple[str, str]],
) -> None:
    stubber.add_response(
        "list_object_versions",
        {
            "Versions": [
                {"Key": key, "VersionId": version_id, "IsLatest": True}
                for key, version_id in versions
            ],
            "IsTruncated": False,
        },
        {
            "Bucket": "invocation-bucket",
            "Prefix": "bedrock-invocations/",
            "ExpectedBucketOwner": ACCOUNT,
        },
    )


def _stub_output_object(
    stubber: Stubber,
    *,
    key: str,
    body: bytes,
    second_versions: list[dict[str, object]] | None = None,
) -> None:
    digest = hashlib.sha256(body).hexdigest()
    expected = {"Bucket": EVIDENCE_BUCKET, "Prefix": key, "ExpectedBucketOwner": ACCOUNT}
    stubber.add_response(
        "list_object_versions",
        {
            "Versions": [{"Key": key, "VersionId": "output-version-1", "IsLatest": True}],
            "IsTruncated": False,
        },
        expected,
    )
    stubber.add_response(
        "get_object",
        {
            "Body": StreamingBody(BytesIO(body), len(body)),
            "VersionId": "output-version-1",
            "ContentLength": len(body),
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": KMS_KEY,
            "Metadata": {"sha256": digest, "task-arn": TASK_ARN, "run-id": RUN_ID},
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
    if second_versions is not None:
        stubber.add_response(
            "list_object_versions",
            {"Versions": second_versions, "IsTruncated": False},
            expected,
        )


class FrozenCredentials:
    access_key = "ASIAEXAMPLE"
    secret_key = "example-secret"
    token = "example-session-token"

    def get_frozen_credentials(self) -> FrozenCredentials:
        return self


def _authenticated_verifier(
    s3: Any,
    *,
    events: list[dict[str, object]],
    digest_log_hash: str | None = None,
    now: datetime | None = None,
) -> AuthenticatedEvidenceVerifier:
    validated_at = now or NOW
    log_bytes = json.dumps({"Records": events}).encode()
    compressed_log = gzip.compress(log_bytes)
    log_key = f"AWSLogs/{ACCOUNT}/CloudTrail/{REGION}/{validated_at:%Y/%m/%d}/log.json.gz"
    digest_key = (
        f"AWSLogs/{ACCOUNT}/CloudTrail-Digest/{REGION}/{validated_at:%Y/%m/%d}/digest.json.gz"
    )
    uri = f"s3://{TRAIL_BUCKET}/{log_key}"
    digest_uri = f"s3://{TRAIL_BUCKET}/{digest_key}"
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    digest_document = {
        "digestS3Bucket": TRAIL_BUCKET,
        "digestS3Object": digest_key,
        "digestEndTime": validated_at.isoformat().replace("+00:00", "Z"),
        "digestSignatureAlgorithm": "SHA256withRSA",
        "digestPublicKeyFingerprint": "fixture-key-fingerprint",
        "previousDigestSignature": "",
        "logFiles": [
            {
                "s3Bucket": TRAIL_BUCKET,
                "s3Object": log_key,
                "hashAlgorithm": "SHA-256",
                "hashValue": digest_log_hash or hashlib.sha256(log_bytes).hexdigest(),
            }
        ],
    }
    digest_bytes = json.dumps(digest_document, separators=(",", ":")).encode()
    signed = "\n".join(
        (
            digest_document["digestEndTime"],
            f"{TRAIL_BUCKET}/{digest_key}",
            hashlib.sha256(digest_bytes).hexdigest(),
            digest_document["previousDigestSignature"],
        )
    ).encode()
    signature = signing_key.sign(signed, padding.PKCS1v15(), hashes.SHA256()).hex()
    compressed_digest = gzip.compress(digest_bytes)
    output = f"Digest file {digest_uri} valid\nLog file {uri} valid\n"

    def run_process(*_args, **_kwargs):
        return subprocess.CompletedProcess(args=["aws"], returncode=0, stdout=output, stderr="")

    verifier = CloudTrailDigestVerifier(
        trail_arn=f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/qualification",
        bucket=TRAIL_BUCKET,
        prefix=f"AWSLogs/{ACCOUNT}",
        region=REGION,
        account_id=ACCOUNT,
        s3_client=s3,
        cloudtrail_client=boto3.client(
            "cloudtrail",
            region_name=REGION,
            aws_access_key_id="test",
            aws_secret_access_key="test",
            config=Config(retries={"max_attempts": 1, "mode": "standard"}),
        ),
        credentials=FrozenCredentials(),
        aws_binary="aws",
        run_process=run_process,
    )
    stubber = Stubber(s3)
    stubber.add_response(
        "list_object_versions",
        {
            "Versions": [
                {
                    "Key": uri.split("/", 3)[-1],
                    "VersionId": "trail-version-1",
                    "IsLatest": True,
                    "LastModified": validated_at,
                }
            ],
            "IsTruncated": False,
        },
        {
            "Bucket": TRAIL_BUCKET,
            "Prefix": uri.split("/", 3)[-1],
            "ExpectedBucketOwner": ACCOUNT,
        },
    )
    stubber.add_response(
        "get_object",
        {
            "Body": StreamingBody(BytesIO(compressed_log), len(compressed_log)),
            "VersionId": "trail-version-1",
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": KMS_KEY,
        },
        {
            "Bucket": TRAIL_BUCKET,
            "Key": uri.split("/", 3)[-1],
            "VersionId": "trail-version-1",
            "ExpectedBucketOwner": ACCOUNT,
        },
    )
    stubber.add_response(
        "list_object_versions",
        {
            "Versions": [
                {
                    "Key": digest_key,
                    "VersionId": "digest-version-1",
                    "IsLatest": True,
                    "LastModified": validated_at,
                }
            ],
            "IsTruncated": False,
        },
        {
            "Bucket": TRAIL_BUCKET,
            "Prefix": digest_key,
            "ExpectedBucketOwner": ACCOUNT,
        },
    )
    stubber.add_response(
        "get_object",
        {
            "Body": StreamingBody(BytesIO(compressed_digest), len(compressed_digest)),
            "VersionId": "digest-version-1",
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": KMS_KEY,
            "Metadata": {"signature": signature, "signature-algorithm": "sha256withrsa"},
        },
        {
            "Bucket": TRAIL_BUCKET,
            "Key": digest_key,
            "VersionId": "digest-version-1",
            "ExpectedBucketOwner": ACCOUNT,
        },
    )
    stubber.add_response(
        "list_object_versions",
        {
            "Versions": [
                {
                    "Key": digest_key,
                    "VersionId": "digest-version-1",
                    "IsLatest": True,
                    "LastModified": validated_at,
                }
            ],
            "IsTruncated": False,
        },
        {
            "Bucket": TRAIL_BUCKET,
            "Prefix": digest_key,
            "ExpectedBucketOwner": ACCOUNT,
        },
    )
    stubber.add_response(
        "list_object_versions",
        {
            "Versions": [
                {
                    "Key": uri.split("/", 3)[-1],
                    "VersionId": "trail-version-1",
                    "IsLatest": True,
                    "LastModified": validated_at,
                }
            ],
            "IsTruncated": False,
        },
        {
            "Bucket": TRAIL_BUCKET,
            "Prefix": uri.split("/", 3)[-1],
            "ExpectedBucketOwner": ACCOUNT,
        },
    )
    stubber.add_response(
        "get_object",
        {
            "Body": StreamingBody(BytesIO(compressed_log), len(compressed_log)),
            "VersionId": "trail-version-1",
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": KMS_KEY,
        },
        {
            "Bucket": TRAIL_BUCKET,
            "Key": uri.split("/", 3)[-1],
            "VersionId": "trail-version-1",
            "ExpectedBucketOwner": ACCOUNT,
        },
    )
    stubber.add_response(
        "list_object_versions",
        {
            "Versions": [
                {
                    "Key": uri.split("/", 3)[-1],
                    "VersionId": "trail-version-1",
                    "IsLatest": True,
                    "LastModified": NOW,
                }
            ],
            "IsTruncated": False,
        },
        {
            "Bucket": TRAIL_BUCKET,
            "Prefix": uri.split("/", 3)[-1],
            "ExpectedBucketOwner": ACCOUNT,
        },
    )
    cloudtrail_stubber = Stubber(verifier.cloudtrail)
    cloudtrail_stubber.add_response(
        "list_public_keys",
        {
            "PublicKeyList": [
                {
                    "Value": signing_key.public_key().public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.PKCS1,
                    ),
                    "ValidityStartTime": validated_at - timedelta(days=1),
                    "ValidityEndTime": validated_at + timedelta(days=1),
                    "Fingerprint": "fixture-key-fingerprint",
                }
            ]
        },
        {
            "StartTime": validated_at - timedelta(minutes=10),
            "EndTime": validated_at + timedelta(minutes=10),
        },
    )
    with stubber, cloudtrail_stubber:
        return verifier.validate_records(
            expected_log_uris=(uri,),
            start_time=validated_at - timedelta(minutes=10),
            end_time=validated_at + timedelta(minutes=10),
        )
