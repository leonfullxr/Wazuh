"""Authentication of launch, immutable output and AWS fact-chain evidence.

Wire receipts and task envelopes are claims.  This module turns those claims
into process-local proof objects only after checking digest-validated CloudTrail
events and exact immutable S3 versions.  Missing proof is represented by
``EvidenceIncomplete``; contradictory or malformed authenticated evidence is a
hard rejection and can never be converted to PASS.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from ai_soc.qualification.evidence import ProbeEnvelope
from scripts.staging.models import DeploymentBinding, GateId

_MAX_LOG_BYTES = 64 * 1024 * 1024
_MAX_LOG_UNCOMPRESSED = 256 * 1024 * 1024
_DIGEST_RESULT = re.compile(r"^(?:\(backfill\)\s+)?(Digest file|Log file)\s+(s3://\S+)\s+(.*)$")
_SEAL = object()


class EvidenceIncomplete(RuntimeError):
    """Required AWS evidence is absent, delayed, unsupported or ambiguous."""


class EvidenceContradiction(RuntimeError):
    """Authenticated evidence contradicts the recorded run or deployment."""


@dataclass(frozen=True, slots=True)
class LaunchExpectation:
    account_id: str
    region: str
    launcher_role_arn: str
    cluster_arn: str
    task_definition_arn: str
    started_by: str
    client_token: str
    session_id: str
    invocation_id: str
    run_id: str
    gate_id: GateId
    contributor_id: str
    slot: str
    task_role_arn: str
    binding: DeploymentBinding
    deadline_utc: str
    launch_request_digest: str
    required_request_fields: tuple[str, ...]
    execution_seconds: int | None = None
    collection_seconds: int = 0
    resource_arns: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True, init=False)
class VerifiedLaunch:
    expectation: LaunchExpectation
    task_arn: str
    request_id: str
    event_id: str
    event_digest: str
    started_at: str
    _seal: object

    def __init__(
        self,
        *,
        _seal: object,
        expectation: LaunchExpectation,
        task_arn: str,
        request_id: str,
        event_id: str,
        event_digest: str,
        started_at: str,
    ) -> None:
        if _seal is not _SEAL:
            raise TypeError("VerifiedLaunch can only be created by the evidence verifier")
        object.__setattr__(self, "expectation", expectation)
        object.__setattr__(self, "task_arn", task_arn)
        object.__setattr__(self, "request_id", request_id)
        object.__setattr__(self, "event_id", event_id)
        object.__setattr__(self, "event_digest", event_digest)
        object.__setattr__(self, "started_at", started_at)
        object.__setattr__(self, "_seal", _seal)

    def __reduce__(self):
        raise TypeError("VerifiedLaunch is process-local and cannot be serialized")


@dataclass(frozen=True, slots=True, init=False)
class VerifiedArtifact:
    _seal: object
    launch: VerifiedLaunch
    bucket: str
    key: str
    version_id: str
    sha256: str
    event_id: str
    event_digest: str
    envelope: ProbeEnvelope
    fact_chain: VerifiedFactChain | None = None

    def __init__(
        self,
        *,
        _seal: object,
        launch: VerifiedLaunch,
        bucket: str,
        key: str,
        version_id: str,
        sha256: str,
        event_id: str,
        event_digest: str,
        envelope: ProbeEnvelope,
        fact_chain: VerifiedFactChain | None = None,
    ) -> None:
        if _seal is not _SEAL:
            raise TypeError("VerifiedArtifact can only be created by the evidence verifier")
        object.__setattr__(self, "launch", launch)
        object.__setattr__(self, "bucket", bucket)
        object.__setattr__(self, "key", key)
        object.__setattr__(self, "version_id", version_id)
        object.__setattr__(self, "sha256", sha256)
        object.__setattr__(self, "event_id", event_id)
        object.__setattr__(self, "event_digest", event_digest)
        object.__setattr__(self, "envelope", envelope)
        object.__setattr__(self, "fact_chain", fact_chain)
        object.__setattr__(self, "_seal", _seal)

    def __reduce__(self):
        raise TypeError("VerifiedArtifact is process-local and cannot be serialized")


@dataclass(frozen=True, slots=True)
class FactRequirement:
    fact_id: str
    event_source: str
    event_names: tuple[str, ...]
    resource_arn: str
    request_id_field: str
    request_id_value: str
    outcome: str = "success"


@dataclass(frozen=True, slots=True)
class VerifiedFact:
    fact_id: str
    request_id: str
    event_id: str
    event_digest: str
    resource_arn: str
    outcome: str


@dataclass(frozen=True, slots=True, init=False)
class VerifiedFactChain:
    _seal: object
    launch: VerifiedLaunch
    facts: tuple[VerifiedFact, ...]
    chain_digest: str

    def __init__(
        self,
        *,
        _seal: object,
        launch: VerifiedLaunch,
        facts: tuple[VerifiedFact, ...],
        chain_digest: str,
    ) -> None:
        if _seal is not _SEAL:
            raise TypeError("VerifiedFactChain can only be created by the evidence verifier")
        object.__setattr__(self, "launch", launch)
        object.__setattr__(self, "facts", facts)
        object.__setattr__(self, "chain_digest", chain_digest)
        object.__setattr__(self, "_seal", _seal)

    def __reduce__(self):
        raise TypeError("VerifiedFactChain is process-local and cannot be serialized")


@dataclass(frozen=True, slots=True, init=False)
class VerifiedInvocationLog:
    """Sealed Bedrock-written request log; payload may contain sensitive data."""

    _seal: object
    launch: VerifiedLaunch
    bucket: str
    key: str
    version_id: str
    request_id: str
    case_nonce: str
    sha256: str
    event_id: str
    event_digest: str
    payload: dict[str, Any] = field(repr=False)

    def __init__(
        self,
        *,
        _seal: object,
        launch: VerifiedLaunch,
        bucket: str,
        key: str,
        version_id: str,
        request_id: str,
        case_nonce: str,
        sha256: str,
        event_id: str,
        event_digest: str,
        payload: dict[str, Any],
    ) -> None:
        if _seal is not _SEAL:
            raise TypeError("VerifiedInvocationLog can only be created by the evidence verifier")
        object.__setattr__(self, "launch", launch)
        object.__setattr__(self, "bucket", bucket)
        object.__setattr__(self, "key", key)
        object.__setattr__(self, "version_id", version_id)
        object.__setattr__(self, "request_id", request_id)
        object.__setattr__(self, "case_nonce", case_nonce)
        object.__setattr__(self, "sha256", sha256)
        object.__setattr__(self, "event_id", event_id)
        object.__setattr__(self, "event_digest", event_digest)
        object.__setattr__(self, "payload", payload)
        object.__setattr__(self, "_seal", _seal)

    def __reduce__(self):
        raise TypeError("VerifiedInvocationLog is process-local and cannot be serialized")


@dataclass(frozen=True, slots=True, init=False)
class VerifiedCanaryReceipt:
    """Sealed proof of one session-owned delivery canary."""

    _seal: object
    launch: VerifiedLaunch
    receipt: dict[str, str]

    def __init__(self, *, _seal: object, launch: VerifiedLaunch, receipt: dict[str, str]) -> None:
        if _seal is not _SEAL:
            raise TypeError("VerifiedCanaryReceipt can only be created by the evidence verifier")
        object.__setattr__(self, "launch", launch)
        object.__setattr__(self, "receipt", receipt)
        object.__setattr__(self, "_seal", _seal)

    def __reduce__(self):
        raise TypeError("VerifiedCanaryReceipt is process-local and cannot be serialized")


@dataclass(frozen=True, slots=True, init=False)
class DigestValidatedLogs:
    """Unforgeable in-process set of events from valid CloudTrail digests."""

    _seal: object
    file_receipts: tuple[tuple[str, str, str], ...]
    digest_receipts: tuple[tuple[str, str, str], ...]
    event_digest_receipts: tuple[tuple[str, str, str, str], ...]
    events: tuple[dict[str, Any], ...]

    def __init__(
        self,
        *,
        _seal: object,
        file_receipts: tuple[tuple[str, str, str], ...],
        digest_receipts: tuple[tuple[str, str, str], ...],
        event_digest_receipts: tuple[tuple[str, str, str, str], ...],
        events: tuple[dict[str, Any], ...],
    ) -> None:
        if _seal is not _SEAL:
            raise TypeError("DigestValidatedLogs can only be created by CloudTrailDigestVerifier")
        object.__setattr__(self, "file_receipts", file_receipts)
        object.__setattr__(self, "digest_receipts", digest_receipts)
        object.__setattr__(self, "event_digest_receipts", event_digest_receipts)
        object.__setattr__(self, "events", events)
        object.__setattr__(self, "_seal", _seal)

    def __reduce__(self):
        raise TypeError("DigestValidatedLogs is process-local and cannot be serialized")


def canonical_event_digest(event: dict[str, Any]) -> str:
    """Stable hash for deduplicating identical CloudTrail deliveries."""
    try:
        encoded = json.dumps(
            event,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise EvidenceContradiction("CloudTrail event is not canonical JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


def canonical_request_digest(request: dict[str, Any]) -> str:
    """Hash the exact normalized RunTask request persisted by the coordinator."""
    return canonical_event_digest(request)


def strict_json(payload: bytes, *, maximum: int) -> Any:
    if len(payload) > maximum:
        raise EvidenceContradiction("authenticated evidence exceeds the size limit")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise EvidenceContradiction("authenticated JSON contains duplicate keys")
            result[key] = value
        return result

    def constant(value: str) -> None:
        raise EvidenceContradiction(f"authenticated JSON contains non-finite value {value}")

    try:
        return json.loads(payload.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except EvidenceContradiction:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceContradiction("authenticated JSON is malformed") from exc


def is_verified_fact_chain(value: object, launch: VerifiedLaunch | None = None) -> bool:
    """Expose a read-only capability check for the fixed evaluator registry."""
    return bool(
        isinstance(value, VerifiedFactChain)
        and value._seal is _SEAL
        and (launch is None or value.launch == launch)
        and re.fullmatch(r"[0-9a-f]{64}", value.chain_digest)
    )


def is_verified_canary_receipt(value: object) -> bool:
    return bool(
        isinstance(value, VerifiedCanaryReceipt)
        and value._seal is _SEAL
        and is_verified_launch(value.launch)
        and value.receipt.get("session_id") == value.launch.expectation.session_id
        and value.receipt.get("run_id") == value.launch.expectation.run_id
        and value.receipt.get("task_arn") == value.launch.task_arn
        and value.receipt.get("verified") == "true"
    )


def is_verified_launch(value: object) -> bool:
    """Expose a read-only capability check for an authenticated ECS launch."""
    return bool(
        isinstance(value, VerifiedLaunch)
        and value._seal is _SEAL
        and isinstance(value.expectation, LaunchExpectation)
        and isinstance(value.task_arn, str)
        and value.task_arn.startswith("arn:")
        and isinstance(value.request_id, str)
        and bool(value.request_id)
        and isinstance(value.event_id, str)
        and bool(value.event_id)
        and re.fullmatch(r"[0-9a-f]{64}", value.event_digest)
    )


def is_verified_artifact(value: object) -> bool:
    """Expose a read-only capability check for an authenticated output version."""
    return bool(
        isinstance(value, VerifiedArtifact)
        and value._seal is _SEAL
        and is_verified_launch(value.launch)
        and isinstance(value.bucket, str)
        and isinstance(value.key, str)
        and isinstance(value.version_id, str)
        and value.version_id.strip()
        and re.fullmatch(r"[0-9a-f]{64}", value.sha256)
        and re.fullmatch(r"[0-9a-f]{64}", value.event_digest)
        and (value.fact_chain is None or is_verified_fact_chain(value.fact_chain, value.launch))
    )


def _parse_validate_logs(output: str) -> tuple[frozenset[str], int]:
    validated: set[str] = set()
    digest_count = 0
    for raw_line in output.splitlines():
        match = _DIGEST_RESULT.match(raw_line.strip())
        if not match:
            if "INVALID:" in raw_line or "unavailable" in raw_line.lower():
                raise EvidenceIncomplete(
                    "CloudTrail digest chain contains an invalid or unavailable file"
                )
            continue
        kind, uri, result = match.groups()
        if result.strip().lower() != "valid":
            raise EvidenceIncomplete("CloudTrail digest validation reported a non-valid file")
        validated.add(uri)
        if kind == "Digest file":
            digest_count += 1
    return frozenset(validated), digest_count


def _credentials_environment(credentials: Any, region: str) -> dict[str, str]:
    if credentials is None:
        raise EvidenceIncomplete("explicit assumed-role credentials are unavailable")
    try:
        frozen = credentials.get_frozen_credentials()
    except (AttributeError, TypeError, ValueError) as exc:
        raise EvidenceIncomplete(
            "AWS credentials could not be frozen for digest validation"
        ) from exc
    if not all((frozen.access_key, frozen.secret_key, frozen.token)):
        raise EvidenceIncomplete("digest validation requires explicit temporary credentials")
    return {
        "AWS_ACCESS_KEY_ID": frozen.access_key,
        "AWS_SECRET_ACCESS_KEY": frozen.secret_key,
        "AWS_SESSION_TOKEN": frozen.token,
        "AWS_DEFAULT_REGION": region,
        "AWS_REGION": region,
        "AWS_PAGER": "",
    }


def _parse_s3_uri(uri: str) -> tuple[str, str]:
    parsed = urlparse(uri)
    if parsed.scheme != "s3" or not parsed.netloc or not parsed.path.startswith("/"):
        raise EvidenceContradiction("CloudTrail locator is not a full S3 URI")
    return parsed.netloc, parsed.path[1:]


def _tag_map(raw: Any) -> dict[str, str]:
    if not isinstance(raw, list):
        return {}
    tags: dict[str, str] = {}
    for item in raw:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("key"), str)
            or not isinstance(item.get("value"), str)
        ):
            continue
        if item["key"] in tags:
            return {}
        tags[item["key"]] = item["value"]
    return tags


def _event_resources(event: dict[str, Any]) -> frozenset[str]:
    resources = event.get("resources")
    if not isinstance(resources, list):
        return frozenset()
    return frozenset(
        value
        for item in resources
        if isinstance(item, dict)
        for value in (item.get("ARN"), item.get("arn"))
        if isinstance(value, str)
    )


def _task_identity_matches(user: Any, launch: VerifiedLaunch) -> bool:
    if not isinstance(user, dict):
        return False
    task_suffix = launch.task_arn.rsplit("/", 1)[-1]
    arn = user.get("arn")
    principal = user.get("principalId")
    issuer = user.get("sessionContext", {}).get("sessionIssuer", {})
    return bool(
        isinstance(arn, str)
        and arn.endswith("/" + task_suffix)
        and isinstance(principal, str)
        and principal.endswith(":" + task_suffix)
        and isinstance(issuer, dict)
        and issuer.get("arn") == launch.expectation.task_role_arn
    )


def _event_time(event: dict[str, Any]) -> datetime:
    raw = event.get("eventTime")
    if not isinstance(raw, str):
        raise EvidenceIncomplete("CloudTrail event omits eventTime")
    try:
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceContradiction("CloudTrail eventTime is malformed") from exc
    if value.tzinfo is None:
        raise EvidenceContradiction("CloudTrail eventTime is not timezone-aware")
    return value.astimezone(UTC)


def _require_supported_event_version(event: dict[str, Any]) -> None:
    raw = event.get("eventVersion")
    if not isinstance(raw, str) or not re.fullmatch(r"[0-9]+\.[0-9]+", raw):
        raise EvidenceIncomplete("CloudTrail event omits a supported eventVersion")
    major_raw, minor_raw = raw.split(".", 1)
    if int(major_raw) != 1 or int(minor_raw) < 8:
        raise EvidenceIncomplete("CloudTrail eventVersion is unsupported by this verifier")


def _parse_utc(raw: str) -> datetime:
    try:
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceContradiction("journal deadline is malformed") from exc
    if value.tzinfo is None:
        raise EvidenceContradiction("journal deadline is not timezone-aware")
    return value.astimezone(UTC)


def _binding_wire(binding: DeploymentBinding) -> dict[str, str | None]:
    return {
        "account_id": binding.account_id,
        "region": binding.region,
        "cluster_arn": binding.cluster_arn,
        "service_arn": binding.service_arn,
        "task_definition_arn": binding.task_definition_arn,
        "deployment_name": binding.deployment_name,
        "deployment_id": binding.deployment_id,
        "image_digest": binding.image_digest,
        "service_sha": binding.service_sha,
        "content_sha": binding.content_sha,
        "configuration_sha256": binding.configuration_sha256,
    }


def _utc_z(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
