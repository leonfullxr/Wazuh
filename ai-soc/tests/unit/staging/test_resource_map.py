from __future__ import annotations

import hashlib
import json
from io import BytesIO
from typing import Any

import boto3
import pytest
from botocore.config import Config
from botocore.response import StreamingBody
from botocore.stub import Stubber

from ai_soc.live.sealed import QualificationMapPin
from scripts.staging.models import DeploymentBinding
from scripts.staging.resource_map import load_pinned_resource_map

ACCOUNT = "123456789012"
REGION = "eu-central-1"
BUCKET = "ai-soc-qualification-audit"
MAP_KEY = "qualification-maps/resource-map.json"
KMS_KEY = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/qualification"


def _binding() -> DeploymentBinding:
    return DeploymentBinding(
        account_id=ACCOUNT,
        region=REGION,
        cluster_arn=f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/qualification",
        service_arn=f"arn:aws:ecs:{REGION}:{ACCOUNT}:service/qualification/app",
        task_definition_arn=f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/ai-soc:7",
        deployment_name="qualification",
        deployment_id="ecs-svc/1234567890123456789",
        image_digest="a" * 64,
        service_sha="b" * 40,
        content_sha="c" * 40,
        configuration_sha256="d" * 64,
    )


def _document(*, certification_enabled: bool = True) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "account_id": ACCOUNT,
        "region": REGION,
        "evidence": {
            "bucket": BUCKET,
            "app_prefix": "qualification/",
            "consumer_prefix": "events/qualification/",
            "map_key": MAP_KEY,
            "input_prefix": "qualification-inputs/",
            "kms_key_arn": KMS_KEY,
        },
        "cloudtrail": {
            "arn": f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/qualification",
            "bucket": "ai-soc-qualification-cloudtrail",
            "log_validation_enabled": True,
        },
        "invocation_logs": {
            "bucket": "ai-soc-qualification-invocations",
            "prefix": "bedrock-invocations/",
            "writer": "bedrock.amazonaws.com",
        },
        "network": {
            "vpc_id": "vpc-0123456789abcdef0",
            "service_subnet_ids": ["subnet-private"],
            "service_route_table_ids": ["rtb-private"],
            "public_isolated_subnet_ids": ["subnet-isolated"],
            "public_isolated_route_table_ids": ["rtb-isolated"],
            "s3_gateway_endpoint_id": "vpce-s3",
            "storage_kms_key_arn": KMS_KEY,
        },
        "archive_consumer": {
            "task_definition_arn": f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/archive:3",
            "container_name": "audit-archive",
            "image": "123456789012.dkr.ecr.eu-central-1.amazonaws.com/ai-soc@sha256:" + "f" * 64,
            "task_role_arn": f"arn:aws:iam::{ACCOUNT}:role/archive-consumer",
        },
        "service": {
            "cluster_arn": f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/qualification",
            "task_security_group_id": "sg-task",
            "endpoint_security_group_id": "sg-endpoint",
            "application_role_arn": f"arn:aws:iam::{ACCOUNT}:role/application",
        },
        "certification_enabled": certification_enabled,
    }


def _read_map(document: dict[str, Any], *, pin_digest: str | None = None) -> Any:
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    pin = QualificationMapPin(
        bucket=BUCKET,
        key=MAP_KEY,
        version_id="map-version-1",
        sha256=pin_digest or hashlib.sha256(raw).hexdigest(),
    )
    client = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    with Stubber(client) as stubber:
        stubber.add_response(
            "get_object",
            {
                "Body": StreamingBody(BytesIO(raw), len(raw)),
                "VersionId": "map-version-1",
                "ServerSideEncryption": "aws:kms",
                "SSEKMSKeyId": KMS_KEY,
            },
            {
                "Bucket": BUCKET,
                "Key": MAP_KEY,
                "VersionId": "map-version-1",
                "ExpectedBucketOwner": ACCOUNT,
            },
        )
        return load_pinned_resource_map(pin, binding=_binding(), s3_client=client)


def test_resource_map_is_loaded_from_exact_sealed_version_and_digest() -> None:
    resource_map = _read_map(_document())

    assert resource_map.evidence.app_prefix == "qualification/"
    assert resource_map.evidence.consumer_prefix == "events/qualification/"
    assert resource_map.invocation_logs.writer == "bedrock.amazonaws.com"
    assert resource_map.cloudtrail.log_validation_enabled


def test_resource_map_digest_and_certification_gate_fail_closed() -> None:
    with pytest.raises(ValueError, match="SHA-256 pin"):
        _read_map(_document(), pin_digest="0" * 64)
    resource_map = _read_map(_document(certification_enabled=False))
    assert not resource_map.certification_enabled
