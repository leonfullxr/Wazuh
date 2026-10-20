"""A bounded same-image S3 write canary for qualification placements."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
import urllib.request
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, cast

from ai_soc.qualification.evidence import CanaryEnvelope, CanaryIdentity, EvidencePaths


class _S3Writer(Protocol):
    def put_object(self, **kwargs: object) -> dict[str, object]: ...


def _task_metadata() -> Mapping[str, object]:
    base = os.environ.get("ECS_CONTAINER_METADATA_URI_V4")
    if not base:
        raise RuntimeError("ECS task metadata URI is required for qualification canaries")
    with urllib.request.urlopen(f"{base}/task", timeout=2) as response:
        parsed: object = json.load(response)
    value: dict[str, object] = cast(dict[str, object], parsed) if isinstance(parsed, dict) else {}
    if not isinstance(value.get("TaskARN"), str):
        raise RuntimeError("ECS task metadata omitted TaskARN")
    return value


def write_canary(
    s3: _S3Writer,
    *,
    bucket: str,
    kms_key_arn: str,
    evidence_paths: EvidencePaths,
    session_id: str,
    run_id: str,
    placement: Literal["service", "public-isolated"],
    task_arn: str,
    account_id: str,
    started_at: datetime | None = None,
    ready_file: Path | None = None,
) -> dict[str, Any]:
    """Write one immutable, task-bound canary object and return its receipt."""
    parsed_identity = CanaryIdentity(
        session_id=session_id, run_id=run_id, placement=placement, task_arn=task_arn
    )
    task_token = hashlib.sha256(task_arn.encode("utf-8")).hexdigest()[:24]
    nonce = secrets.token_hex(16)
    started = started_at or datetime.now(UTC)
    key = (
        f"{evidence_paths.app_prefix}{parsed_identity.session_id}/canary/"
        f"{parsed_identity.placement}/{parsed_identity.run_id}/{task_token}.json"
    )
    envelope = CanaryEnvelope(
        schema="ai-soc.qualification-canary.v1",
        session_id=parsed_identity.session_id,
        run_id=parsed_identity.run_id,
        placement=parsed_identity.placement,
        task_arn=parsed_identity.task_arn,
        nonce=nonce,
        started_at=started,
        written_at=datetime.now(UTC),
    )
    body = envelope.model_dump(mode="json", by_alias=True)
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    if ready_file is not None:
        ready_file.touch()
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=encoded,
        ContentType="application/json",
        IfNoneMatch="*",
        ExpectedBucketOwner=account_id,
        ServerSideEncryption="aws:kms",
        SSEKMSKeyId=kms_key_arn,
        Metadata={"sha256": digest, "task-arn": task_arn},
        Tagging=f"session={session_id}&run={run_id}&placement={placement}",
    )
    return {"bucket": bucket, "key": key, "sha256": digest, **body}


def main() -> int:
    import boto3

    parser = argparse.ArgumentParser()
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--kms-key-arn", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--placement", choices=("service", "public-isolated"), required=True)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--app-prefix", required=True)
    parser.add_argument("--consumer-prefix", required=True)
    parser.add_argument("--map-key", required=True)
    parser.add_argument("--input-prefix", required=True)
    args = parser.parse_args()
    metadata = _task_metadata()
    client_factory = cast(Callable[..., _S3Writer], boto3.client)  # type: ignore[reportUnknownMemberType]
    receipt = write_canary(
        client_factory("s3", region_name=os.environ.get("AWS_REGION")),
        bucket=args.bucket,
        kms_key_arn=args.kms_key_arn,
        evidence_paths=EvidencePaths(
            app_prefix=args.app_prefix,
            consumer_prefix=args.consumer_prefix,
            map_key=args.map_key,
            input_prefix=args.input_prefix,
        ),
        session_id=args.session_id,
        run_id=args.run_id,
        placement=args.placement,
        task_arn=str(metadata["TaskARN"]),
        account_id=args.account_id,
        ready_file=Path(os.environ["AI_SOC_PROBE_READY_FILE"])
        if os.environ.get("AI_SOC_PROBE_READY_FILE")
        else None,
    )
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
