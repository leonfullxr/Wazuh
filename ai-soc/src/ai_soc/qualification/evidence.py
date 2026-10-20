"""Strict, task-owned qualification output envelopes.

This module intentionally has no staging imports and is safe to import from a
qualification task without importing the staging runner.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, Protocol, cast
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import boto3
from botocore.config import Config
from pydantic import ConfigDict, Field, StringConstraints, field_validator, model_validator

from ai_soc.contracts.models import StrictModel, UTCDateTime
from ai_soc.qualification.binding import DeploymentBinding

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
_SECRET_TEXT = re.compile(
    r"(?i)(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|"
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|Bearer\s+\S+|"
    r"-----BEGIN [A-Z ]+-----|gh[pousr]_[A-Za-z0-9_]{20,})"
)
_PRIVATE_MEASUREMENT_KEYS = frozenset(
    {"prompt", "raw_prompt", "response_body", "raw_response", "authorization", "cookie", "password"}
)
SafePathComponent = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9-]{1,128}$")]


class _S3Client(Protocol):
    def put_object(self, **kwargs: object) -> dict[str, object]: ...


class EvidencePaths(StrictModel):
    """Validated prefixes shared by task writers and the coordinator."""

    app_prefix: str
    consumer_prefix: str
    map_key: str
    input_prefix: str


class CanaryIdentity(StrictModel):
    session_id: SafePathComponent
    run_id: SafePathComponent
    placement: Literal["service", "public-isolated"]
    task_arn: str


class CanaryEnvelope(StrictModel):
    """Wire envelope written by the calibrated network canary."""

    model_config = ConfigDict(
        strict=True, extra="forbid", frozen=True, use_enum_values=True, populate_by_name=True
    )
    wire_schema: Literal["ai-soc.qualification-canary.v1"] = Field(alias="schema")
    session_id: SafePathComponent
    run_id: SafePathComponent
    placement: Literal["service", "public-isolated"]
    task_arn: str
    nonce: str
    started_at: UTCDateTime
    written_at: UTCDateTime

    @property
    def identity(self) -> CanaryIdentity:
        return CanaryIdentity(
            session_id=self.session_id,
            run_id=self.run_id,
            placement=self.placement,
            task_arn=self.task_arn,
        )


class EvidenceReference(StrictModel):
    """A versioned locator or digest for an immutable dependency."""

    kind: str = Field(min_length=1, max_length=64)
    identifier: str = Field(min_length=1, max_length=2048)
    sha256: str | None = None

    @field_validator("identifier")
    @classmethod
    def safe_locator(cls, value: str) -> str:
        if any(ch in value for ch in "\r\n\x00"):
            raise ValueError("evidence locator must be a single safe line")
        return value

    @field_validator("sha256")
    @classmethod
    def valid_sha256(cls, value: str | None) -> str | None:
        if value is not None and not _SHA256.fullmatch(value):
            raise ValueError("sha256 must be lowercase SHA-256 hex")
        return value


class ProbeEnvelope(StrictModel):
    """Task-owned measurements; status and verdict fields are deliberately absent."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: int = Field(ge=1, le=1)
    session_id: str
    invocation_id: str
    run_id: str
    gate_id: str
    contributor_id: str
    binding: DeploymentBinding
    scenario_sha256: str
    started_at: datetime
    completed_at: datetime
    measurements: dict[str, Any]
    dependencies: tuple[EvidenceReference, ...] = ()
    errors: dict[str, str] = Field(default_factory=dict)

    @field_validator("session_id", "invocation_id", "run_id", "gate_id", "contributor_id")
    @classmethod
    def valid_identity(cls, value: str) -> str:
        if not _ID.fullmatch(value):
            raise ValueError("qualification identity is malformed")
        return value

    @field_validator("scenario_sha256")
    @classmethod
    def valid_scenario_hash(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("scenario_sha256 must be lowercase SHA-256 hex")
        return value

    @model_validator(mode="after")
    def bounded_time_window(self) -> ProbeEnvelope:
        if self.started_at.tzinfo is None or self.completed_at.tzinfo is None:
            raise ValueError("qualification envelope times must be timezone-aware")
        if self.completed_at < self.started_at:
            raise ValueError("qualification completion precedes start")
        if (self.completed_at - self.started_at).total_seconds() > 86_400:
            raise ValueError("qualification envelope time window exceeds one day")
        return self

    @field_validator("measurements")
    @classmethod
    def bounded_measurements(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_safe_measurements(value)
        encoded = json.dumps(value, allow_nan=False, separators=(",", ":")).encode()
        if len(encoded) > 256 * 1024:
            raise ValueError("qualification measurements exceed 256 KiB")
        return value

    @field_validator("errors")
    @classmethod
    def bounded_errors(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 128 or any(
            len(key) > 128 or len(message) > 512 for key, message in value.items()
        ):
            raise ValueError("qualification errors exceed the bounded schema")
        return value

    @property
    def started_utc(self) -> datetime:
        return self.started_at.astimezone(UTC)


def _metadata_document(uri: str, timeout_seconds: float) -> dict[str, object]:
    if not uri.startswith("http://"):
        raise ValueError("ECS task metadata URI must use the task-local HTTP endpoint")
    request = Request(uri, headers={"Accept": "application/json"})
    with urlopen(request, timeout=timeout_seconds) as response:
        raw = response.read(64 * 1024 + 1)
    if len(raw) > 64 * 1024:
        raise ValueError("ECS metadata response exceeds 64 KiB")
    document: object = json.loads(raw)
    if not isinstance(document, dict):
        raise ValueError("ECS metadata response must be an object")
    return cast(dict[str, object], document)


def parse_probe_envelope(payload: bytes) -> ProbeEnvelope:
    """Parse a bounded, duplicate-key-free envelope with no permissive fallback."""

    if len(payload) > 256 * 1024:
        raise ValueError("qualification envelope exceeds 256 KiB")

    def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("qualification envelope contains duplicate JSON keys")
            result[key] = value
        return result

    def reject_nonfinite(value: str) -> None:
        raise ValueError(f"qualification envelope contains invalid number {value}")

    parsed: object = json.loads(
        payload.decode("utf-8"),
        object_pairs_hook=reject_duplicate_pairs,
        parse_constant=reject_nonfinite,
    )
    if not isinstance(parsed, dict):
        raise ValueError("qualification envelope must be a JSON object")
    raw = cast(dict[str, object], parsed)
    for key in ("started_at", "completed_at"):
        value = raw.get(key)
        if not isinstance(value, str):
            raise ValueError(f"qualification envelope {key} must be an ISO timestamp")
        try:
            raw[key] = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"qualification envelope {key} is invalid") from exc
    dependencies = raw.get("dependencies")
    if isinstance(dependencies, list):
        raw["dependencies"] = tuple(cast(list[object], dependencies))
    return ProbeEnvelope.model_validate(raw)


def _validate_safe_measurements(value: object, *, depth: int = 0) -> None:
    if depth > 12:
        raise ValueError("qualification measurements exceed maximum nesting depth")
    if isinstance(value, dict):
        for key, child in cast(dict[object, object], value).items():
            if not isinstance(key, str) or key.lower() in _PRIVATE_MEASUREMENT_KEYS:
                raise ValueError("qualification measurements contain a private field")
            _validate_safe_measurements(child, depth=depth + 1)
    elif isinstance(value, (list, tuple)):
        items = cast(Sequence[object], value)
        if len(items) > 4096:
            raise ValueError("qualification measurement list exceeds its bound")
        for child in items:
            _validate_safe_measurements(child, depth=depth + 1)
    elif isinstance(value, str):
        if len(value) > 4096 or _SECRET_TEXT.search(value):
            raise ValueError("qualification measurements contain unsafe text")
    elif value is None or type(value) in {bool, int, float}:
        return
    else:
        raise ValueError("qualification measurements contain an unsupported value")


def emit_probe_envelope(
    envelope: ProbeEnvelope,
    *,
    s3_client: _S3Client | None = None,
    timeout_seconds: float = 2.0,
) -> tuple[str, str]:
    """Write one conditional, tagged output under the launch-provided run prefix.

    Bucket, KMS key and prefix are supplied only by the verified task launch
    contract. The task metadata endpoint supplies the writer identity; JSON
    fields and S3 metadata are correlation hints, never writer authentication.
    """

    if not 0 < timeout_seconds <= 10:
        raise ValueError("metadata timeout must be between zero and ten seconds")
    metadata_uri = os.environ.get("ECS_CONTAINER_METADATA_URI_V4")
    if not metadata_uri:
        raise RuntimeError("ECS task metadata endpoint is unavailable")
    metadata = _metadata_document(f"{metadata_uri.rstrip('/')}/task", timeout_seconds)
    task_arn = metadata.get("TaskARN")
    cluster = metadata.get("Cluster")
    definition = metadata.get("Family")
    revision = metadata.get("Revision")
    if (
        not isinstance(task_arn, str)
        or not task_arn
        or not isinstance(cluster, str)
        or not cluster
        or not isinstance(definition, str)
        or not definition
        or not isinstance(revision, str)
        or not revision
    ):
        raise RuntimeError("ECS task metadata lacks required task identity fields")
    expected_task_definition = (
        f"{envelope.binding.task_definition_arn.rsplit('/', 1)[0]}/{definition}:{revision}"
    )
    if (
        cluster != envelope.binding.cluster_arn
        or expected_task_definition != envelope.binding.task_definition_arn
    ):
        raise RuntimeError("ECS task metadata differs from the bound deployment")

    bucket = os.environ.get("SOC_QUALIFICATION_BUCKET")
    prefix = os.environ.get("SOC_QUALIFICATION_PREFIX")
    kms_key_id = os.environ.get("SOC_QUALIFICATION_KMS_KEY_ID")
    if not bucket or not prefix or not kms_key_id:
        raise RuntimeError("verified qualification output configuration is unavailable")
    owner = os.environ.get("SOC_QUALIFICATION_EXPECTED_OWNER")
    if not owner or owner != envelope.binding.account_id:
        raise RuntimeError("qualification destination owner does not match the bound account")
    normalized_prefix = prefix.rstrip("/") + "/"
    if not normalized_prefix.startswith(f"qualification/{envelope.session_id}/"):
        raise RuntimeError("qualification output prefix does not match the session")
    if envelope.run_id not in normalized_prefix.split("/"):
        raise RuntimeError("qualification output prefix does not match the run")

    document = envelope.model_dump(mode="json")
    body = json.dumps(document, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()
    if len(body) > 256 * 1024:
        raise ValueError("qualification envelope exceeds 256 KiB")
    digest = hashlib.sha256(body).hexdigest()
    key = (
        f"{normalized_prefix}{envelope.gate_id}/{envelope.contributor_id}/"
        f"{task_arn.rsplit('/', 1)[-1]}.json"
    )
    client_factory = cast(Callable[..., _S3Client], boto3.client)  # type: ignore[reportUnknownMemberType]
    client = s3_client or client_factory(
        "s3",
        config=Config(
            connect_timeout=timeout_seconds,
            read_timeout=timeout_seconds,
            # total_max_attempts includes the initial request.
            retries={"total_max_attempts": 1, "mode": "standard"},
        ),
    )
    client_config = getattr(getattr(client, "meta", None), "config", None)
    if (
        client_config is None
        or client_config.connect_timeout > timeout_seconds
        or client_config.read_timeout > timeout_seconds
        or client_config.retries.get("total_max_attempts") != 1
    ):
        raise ValueError("qualification S3 client does not enforce the output deadline")
    deadline = time.monotonic() + timeout_seconds
    response = client.put_object(
        Bucket=bucket,
        Key=key,
        Body=body,
        IfNoneMatch="*",
        ExpectedBucketOwner=owner,
        ServerSideEncryption="aws:kms",
        SSEKMSKeyId=kms_key_id,
        ContentType="application/json",
        Metadata={"sha256": digest, "task-arn": task_arn, "run-id": envelope.run_id},
        Tagging=urlencode(
            {
                "session": envelope.session_id,
                "invocation": envelope.invocation_id,
                "run": envelope.run_id,
                "gate": envelope.gate_id,
                "contributor": envelope.contributor_id,
                "task": task_arn,
            }
        ),
    )
    if time.monotonic() >= deadline:
        raise TimeoutError("qualification envelope write exceeded its deadline")
    version_id = response.get("VersionId")
    if not isinstance(version_id, str) or not version_id or version_id == "null":
        raise RuntimeError("qualification output did not receive a non-null S3 version")
    return key, version_id
