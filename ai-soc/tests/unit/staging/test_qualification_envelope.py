from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

import boto3
import pytest
from botocore.config import Config
from botocore.stub import Stubber

from ai_soc.qualification.evidence import (
    ProbeEnvelope,
    emit_probe_envelope,
    parse_probe_envelope,
)


def _envelope(**overrides: Any) -> ProbeEnvelope:
    values: dict[str, Any] = {
        "schema_version": 1,
        "session_id": "session-123",
        "invocation_id": "invocation-123",
        "run_id": "run-123",
        "gate_id": "LV-MCP",
        "contributor_id": "mcp",
        "binding": {
            "account_id": "123456789012",
            "region": "eu-central-1",
            "cluster_arn": "arn:aws:ecs:eu-central-1:123456789012:cluster/qualification",
            "service_arn": "arn:aws:ecs:eu-central-1:123456789012:service/qualification/app",
            "task_definition_arn": "arn:aws:ecs:eu-central-1:123456789012:task-definition/ai-soc:7",
            "deployment_name": "app",
            "deployment_id": "ecs-svc/1234567890123456789",
            "image_digest": "sha256:" + "a" * 64,
            "service_sha": "b" * 40,
            "content_sha": "c" * 40,
            "configuration_sha256": "d" * 64,
        },
        "scenario_sha256": "a" * 64,
        "started_at": datetime(2026, 10, 8, 12, 0, tzinfo=UTC),
        "completed_at": datetime(2026, 10, 8, 12, 1, tzinfo=UTC),
        "measurements": {"initialize_ok": True, "latency_ms": 25},
    }
    values.update(overrides)
    return ProbeEnvelope(**values)


def test_envelope_parser_rejects_duplicate_keys_nonfinite_and_verdict_fields() -> None:
    envelope = _envelope()
    encoded = json.dumps(envelope.model_dump(mode="json")).encode()

    assert parse_probe_envelope(encoded) == envelope
    with pytest.raises(ValueError, match="duplicate"):
        parse_probe_envelope(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(ValueError, match="invalid number"):
        parse_probe_envelope(b'{"measurements":{"latency":NaN}}')
    with pytest.raises(ValueError):
        ProbeEnvelope(**{**envelope.model_dump(), "status": "PASS"})
    with pytest.raises(ValueError, match="private field"):
        _envelope(measurements={"prompt": "private user content"})


def test_emitter_writes_conditionally_with_task_metadata_and_real_s3_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ai_soc.qualification.evidence as evidence

    task_arn = "arn:aws:ecs:eu-central-1:123456789012:task/cluster/0123456789abcdef"
    task_metadata = {
        "TaskARN": task_arn,
        "Cluster": "arn:aws:ecs:eu-central-1:123456789012:cluster/qualification",
        "Family": "ai-soc",
        "Revision": "7",
    }

    class MetadataResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return json.dumps(task_metadata).encode()

    monkeypatch.setattr(evidence, "urlopen", lambda *_args, **_kwargs: MetadataResponse())
    monkeypatch.setenv("ECS_CONTAINER_METADATA_URI_V4", "http://169.254.170.2/v4")
    monkeypatch.setenv("SOC_QUALIFICATION_BUCKET", "qualification-evidence")
    monkeypatch.setenv("SOC_QUALIFICATION_PREFIX", "qualification/session-123/run-123/")
    monkeypatch.setenv(
        "SOC_QUALIFICATION_KMS_KEY_ID", "arn:aws:kms:eu-central-1:123456789012:key/example"
    )
    monkeypatch.setenv("SOC_QUALIFICATION_EXPECTED_OWNER", "123456789012")

    client = boto3.client(
        "s3",
        region_name="eu-central-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(
            connect_timeout=2,
            read_timeout=2,
            retries={"total_max_attempts": 1, "mode": "standard"},
        ),
    )
    envelope = _envelope()
    document = envelope.model_dump(mode="json")
    body = json.dumps(document, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(body).hexdigest()
    key = "qualification/session-123/run-123/LV-MCP/mcp/0123456789abcdef.json"
    tagging = (
        "session=session-123&invocation=invocation-123&run=run-123&gate=LV-MCP&contributor=mcp&"
        "task=arn%3Aaws%3Aecs%3Aeu-central-1%3A123456789012%3Atask%2Fcluster%2F0123456789abcdef"
    )
    with Stubber(client) as stubber:
        expected = {
            "Bucket": "qualification-evidence",
            "Key": key,
            "Body": body,
            "IfNoneMatch": "*",
            "ExpectedBucketOwner": "123456789012",
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": "arn:aws:kms:eu-central-1:123456789012:key/example",
            "ContentType": "application/json",
            "Metadata": {"sha256": digest, "task-arn": task_arn, "run-id": "run-123"},
            "Tagging": tagging,
        }
        stubber.add_response("put_object", {"VersionId": "version-123"}, expected)
        stubber.add_response("put_object", {"VersionId": "version-124"}, expected)
        assert emit_probe_envelope(envelope, s3_client=client) == (key, "version-123")
        original_client = evidence.boto3.client
        client_config = None

        def default_client(service_name: str, *, config: Config):
            nonlocal client_config
            assert service_name == "s3"
            client_config = config
            return client

        monkeypatch.setattr(evidence.boto3, "client", default_client)
        assert emit_probe_envelope(envelope) == (key, "version-124")
        assert client_config is not None
        assert client_config.retries["total_max_attempts"] == 1
        monkeypatch.setattr(evidence.boto3, "client", original_client)
