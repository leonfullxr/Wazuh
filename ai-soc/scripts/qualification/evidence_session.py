"""Qualification canary verification and journaled, scoped AWS evidence settings.

This module contains no import-time AWS operations. The caller supplies already
bound clients and invokes one setting at a time inside the approved session.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from ai_soc.qualification.evidence import CanaryEnvelope, EvidencePaths
from scripts.qualification.canary_delivery import (
    measured_delivery_budget_seconds as measured_delivery_budget_seconds,
)
from scripts.qualification.canary_delivery import (
    verify_canary_delivery as verify_canary_delivery,
)
from scripts.qualification.settings_journal import SettingsJournal
from scripts.qualification.settings_session import (
    CloudTrailSelectors,
    XRaySamplingRule,
    apply_change,
    restore_change,
)


def read_canary_object_version(
    s3: Any, *, bucket: str, key: str, version_id: str, expected_owner: str
) -> dict[str, Any]:
    """Read and hash only the event-provided S3 version, never the current key."""
    if not version_id or version_id == "null":
        raise ValueError("NOT_RUN: event did not supply a version ID")
    response = s3.get_object(
        Bucket=bucket,
        Key=key,
        VersionId=version_id,
        ExpectedBucketOwner=expected_owner,
    )
    body = response["Body"].read(16385)
    if len(body) > 16384 or response.get("VersionId", version_id) != version_id:
        raise ValueError("NOT_RUN: version response is oversized or mismatched")
    digest = hashlib.sha256(body).hexdigest()
    if response.get("Metadata", {}).get("sha256") != digest:
        raise ValueError("NOT_RUN: exact version body hash does not match its metadata")
    try:
        envelope = CanaryEnvelope.model_validate_json(body)
    except (TypeError, ValueError) as exc:
        raise ValueError("NOT_RUN: exact version is not a qualification canary") from exc
    return {
        "bucket": bucket,
        "key": key,
        "version_id": version_id,
        "sha256": digest,
        "body": envelope,
    }


def install_cloudtrail_write_selectors(
    client: Any,
    journal: SettingsJournal,
    *,
    trail_name: str,
    bucket: str,
    evidence_paths: EvidencePaths,
    session_id: str,
    run_id: str,
) -> None:
    """Add scoped app and consumer selectors through the shared mutation lifecycle."""
    if not re.fullmatch(r"[A-Za-z0-9-]{1,128}", session_id) or not re.fullmatch(
        r"[A-Za-z0-9-]{1,128}", run_id
    ):
        raise ValueError("NOT_RUN: session and run IDs must be safe path components")
    adapter = CloudTrailSelectors(client, trail_name)
    values = [
        f"arn:aws:s3:::{bucket}/{evidence_paths.app_prefix}{session_id}/",
        f"arn:aws:s3:::{bucket}/{evidence_paths.consumer_prefix}{run_id}/",
    ]
    apply_change(adapter, journal, values)


def install_xray_sampling_rule(client: Any, journal: SettingsJournal, rule: dict[str, Any]) -> None:
    """Install one bounded X-Ray rule through the shared mutation lifecycle."""
    name = rule.get("RuleName")
    if not isinstance(name, str) or not name:
        raise ValueError("sampling rule requires RuleName")
    apply_change(XRaySamplingRule(client, name), journal, rule)


def restore_cloudtrail_selectors(journal: SettingsJournal, client: Any, trail_name: str) -> None:
    restore_change(CloudTrailSelectors(client, trail_name), journal)


def restore_xray_sampling_rule(journal: SettingsJournal, client: Any, rule_name: str) -> None:
    restore_change(XRaySamplingRule(client, rule_name), journal)
