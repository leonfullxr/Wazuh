"""Strict, shared reads for immutable S3 evidence objects."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from scripts.staging.verifier import EvidenceIncomplete


def resolve_sole_current_version(
    client: Any,
    *,
    bucket: str,
    key: str,
    expected_bucket_owner: str,
    deadline_check: Callable[[], None] = lambda: None,
) -> str:
    deadline_check()
    inventory = client.list_object_versions(
        Bucket=bucket,
        Prefix=key,
        ExpectedBucketOwner=expected_bucket_owner,
    )
    deadline_check()
    versions = [row for row in inventory.get("Versions", []) if row.get("Key") == key]
    markers = [row for row in inventory.get("DeleteMarkers", []) if row.get("Key") == key]
    version_id = versions[0].get("VersionId") if len(versions) == 1 else None
    if (
        inventory.get("IsTruncated") is True
        or len(versions) != 1
        or markers
        or versions[0].get("IsLatest") is not True
        or not isinstance(version_id, str)
        or not version_id
        or version_id == "null"
    ):
        raise EvidenceIncomplete("S3 evidence key has ambiguous versions or deletion")
    return version_id


def require_exact_current_version(
    client: Any,
    *,
    bucket: str,
    key: str,
    version_id: str,
    expected_bucket_owner: str,
    deadline_check: Callable[[], None] = lambda: None,
) -> None:
    current = resolve_sole_current_version(
        client,
        bucket=bucket,
        key=key,
        expected_bucket_owner=expected_bucket_owner,
        deadline_check=deadline_check,
    )
    if current != version_id:
        raise EvidenceIncomplete("S3 evidence key version changed or is no longer current")


def read_version_bytes(
    client: Any,
    *,
    bucket: str,
    key: str,
    version_id: str,
    expected_bucket_owner: str,
    maximum_bytes: int,
    deadline_check: Callable[[], None] = lambda: None,
) -> tuple[dict[str, Any], bytes]:
    if maximum_bytes <= 0:
        raise ValueError("maximum_bytes must be positive")
    deadline_check()
    response = client.get_object(
        Bucket=bucket,
        Key=key,
        VersionId=version_id,
        ExpectedBucketOwner=expected_bucket_owner,
    )
    deadline_check()
    if response.get("VersionId") != version_id:
        raise EvidenceIncomplete("S3 evidence response version ID differs from its request")
    body = response.get("Body")
    if body is None:
        raise EvidenceIncomplete("S3 evidence object body is absent")
    try:
        raw = body.read(maximum_bytes + 1)
    finally:
        body.close()
    deadline_check()
    if len(raw) > maximum_bytes:
        raise EvidenceIncomplete("S3 evidence object exceeds its configured size limit")
    return response, raw
