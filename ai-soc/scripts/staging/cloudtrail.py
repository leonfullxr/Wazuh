"""Bounded discovery of original CloudTrail log files for digest validation."""

from __future__ import annotations

import gzip
import hashlib
import re
import shutil
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from io import BytesIO
from typing import Any

from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from scripts.staging.models import DeploymentBinding
from scripts.staging.resource_map import QualificationResourceMap
from scripts.staging.s3_evidence import (
    read_version_bytes,
    require_exact_current_version,
    resolve_sole_current_version,
)
from scripts.staging.verifier import (
    _SEAL,
    DigestValidatedLogs,
    EvidenceContradiction,
    EvidenceIncomplete,
    _credentials_environment,
    _parse_s3_uri,
    _parse_utc,
    _parse_validate_logs,
    _require_supported_event_version,
    _utc_z,
    canonical_event_digest,
    strict_json,
)

_MAX_LOG_BYTES = 64 * 1024 * 1024
_MAX_LOG_UNCOMPRESSED = 256 * 1024 * 1024


class CloudTrailDigestVerifier:
    """Prove that exact CloudTrail files are referenced by a valid digest chain.

    The AWS CLI's supported validator performs digest-signature and previous-
    digest-chain checks.  This wrapper accepts evidence only for requested log
    locators explicitly printed as valid by ``validate-logs --verbose``.  It
    then reads the sole S3 version of each file, so the validated current object
    cannot be substituted with a different historical version.
    """

    def __init__(
        self,
        *,
        trail_arn: str,
        bucket: str,
        prefix: str,
        region: str,
        account_id: str,
        s3_client: Any,
        cloudtrail_client: Any,
        credentials: Any,
        aws_binary: str | None = None,
        run_process: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        timeout_seconds: int = 120,
        deadline_monotonic: float | None = None,
    ) -> None:
        if not 1 <= timeout_seconds <= 900:
            raise ValueError("digest validation timeout is outside the approved bound")
        self.trail_arn = trail_arn
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.region = region
        self.account_id = account_id
        self.s3 = s3_client
        self.cloudtrail = cloudtrail_client
        self.credentials = credentials
        self.aws_binary = aws_binary or shutil.which("aws") or ""
        self.run_process = run_process
        self.timeout_seconds = timeout_seconds
        self.deadline_monotonic = deadline_monotonic
        self._last_digest_receipts: tuple[tuple[str, str, str], ...] = ()
        self._last_log_digest_receipts: dict[str, tuple[str, str, str]] = {}

    def _check_deadline(self) -> None:
        if self.deadline_monotonic is not None and time.monotonic() >= self.deadline_monotonic:
            raise EvidenceIncomplete("qualification delivery deadline expired during verification")

    def validate_records(
        self,
        *,
        expected_log_uris: tuple[str, ...],
        start_time: datetime,
        end_time: datetime,
    ) -> DigestValidatedLogs:
        files = self.validate_files(
            expected_log_uris=expected_log_uris,
            start_time=start_time,
            end_time=end_time,
        )
        receipts = tuple(
            (uri, version_id, hashlib.sha256(compressed).hexdigest())
            for uri, version_id, compressed in files
        )
        events, event_digest_receipts = parse_cloudtrail_logs(
            files, digest_receipts_by_log=self._last_log_digest_receipts
        )
        return DigestValidatedLogs(
            _seal=_SEAL,
            file_receipts=receipts,
            digest_receipts=self._last_digest_receipts,
            event_digest_receipts=event_digest_receipts,
            events=events,
        )

    def validate_files(
        self,
        *,
        expected_log_uris: tuple[str, ...],
        start_time: datetime,
        end_time: datetime,
    ) -> tuple[tuple[str, str, bytes], ...]:
        if not self.aws_binary:
            raise EvidenceIncomplete("AWS CLI is unavailable for CloudTrail digest validation")
        if not expected_log_uris or len(set(expected_log_uris)) != len(expected_log_uris):
            raise EvidenceIncomplete("CloudTrail proof file set is empty or ambiguous")
        if start_time.tzinfo is None or end_time.tzinfo is None or end_time < start_time:
            raise ValueError("CloudTrail validation window must be ordered and timezone-aware")
        pinned: dict[str, tuple[str, str]] = {}
        for uri in expected_log_uris:
            self._check_deadline()
            bucket, key = _parse_s3_uri(uri)
            if bucket != self.bucket or not key.startswith(self.prefix + "/"):
                raise EvidenceContradiction("CloudTrail log locator is outside the pinned sink")
            version_id = resolve_sole_current_version(
                self.s3,
                bucket=bucket,
                key=key,
                expected_bucket_owner=self.account_id,
                deadline_check=self._check_deadline,
            )
            _response, raw = read_version_bytes(
                self.s3,
                bucket=bucket,
                key=key,
                version_id=version_id,
                expected_bucket_owner=self.account_id,
                maximum_bytes=_MAX_LOG_BYTES,
                deadline_check=self._check_deadline,
            )
            self._check_deadline()
            pinned[uri] = (version_id, hashlib.sha256(raw).hexdigest())
        env = _credentials_environment(self.credentials, self.region)
        command = [
            self.aws_binary,
            "--no-cli-pager",
            "--region",
            self.region,
            "cloudtrail",
            "validate-logs",
            "--trail-arn",
            self.trail_arn,
            "--start-time",
            _utc_z(start_time),
            "--end-time",
            _utc_z(end_time),
            "--s3-bucket",
            self.bucket,
            "--s3-prefix",
            self.prefix,
            "--verbose",
        ]
        try:
            self._check_deadline()
            completed = self.run_process(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                env=env,
            )
            self._check_deadline()
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise EvidenceIncomplete("CloudTrail digest validation did not complete") from exc
        if completed.returncode != 0:
            raise EvidenceIncomplete("CloudTrail digest chain validation failed or is incomplete")
        validated, digest_count = _parse_validate_logs(completed.stdout)
        if digest_count == 0 or any(uri not in validated for uri in expected_log_uris):
            raise EvidenceIncomplete("requested CloudTrail log is not digest-authenticated")
        digest_hashes, digest_receipts, log_digest_receipts = _validated_log_hashes(
            self.s3,
            cloudtrail_client=self.cloudtrail,
            bucket=self.bucket,
            account_id=self.account_id,
            region=self.region,
            start_time=start_time,
            end_time=end_time,
            expected_log_uris=expected_log_uris,
            validated_digest_uris=tuple(uri for uri in validated if "/CloudTrail-Digest/" in uri),
            deadline_check=self._check_deadline,
        )
        self._last_digest_receipts = digest_receipts
        self._last_log_digest_receipts = log_digest_receipts
        output: list[tuple[str, str, bytes]] = []
        for uri in expected_log_uris:
            self._check_deadline()
            bucket, key = _parse_s3_uri(uri)
            pinned_version, pinned_sha256 = pinned[uri]
            require_exact_current_version(
                self.s3,
                bucket=bucket,
                key=key,
                version_id=pinned_version,
                expected_bucket_owner=self.account_id,
                deadline_check=self._check_deadline,
            )
            version_id = pinned_version
            response, raw = read_version_bytes(
                self.s3,
                bucket=bucket,
                key=key,
                version_id=version_id,
                expected_bucket_owner=self.account_id,
                maximum_bytes=_MAX_LOG_BYTES,
                deadline_check=self._check_deadline,
            )
            self._check_deadline()
            if hashlib.sha256(raw).hexdigest() != pinned_sha256:
                raise EvidenceIncomplete("CloudTrail log bytes changed during digest validation")
            if len(raw) > _MAX_LOG_BYTES:
                raise EvidenceContradiction("CloudTrail log object exceeds compressed size limit")
            if response.get("ServerSideEncryption") not in {"aws:kms", "aws:kms:dsse"}:
                raise EvidenceIncomplete("CloudTrail log lacks expected KMS encryption")
            with gzip.GzipFile(fileobj=BytesIO(raw), mode="rb") as stream:
                uncompressed = stream.read(_MAX_LOG_UNCOMPRESSED + 1)
            if len(uncompressed) > _MAX_LOG_UNCOMPRESSED:
                raise EvidenceContradiction("CloudTrail log exceeds uncompressed size limit")
            if hashlib.sha256(uncompressed).hexdigest() != digest_hashes[uri]:
                raise EvidenceIncomplete("CloudTrail log bytes differ from the signed digest hash")
            require_exact_current_version(
                self.s3,
                bucket=bucket,
                key=key,
                version_id=pinned_version,
                expected_bucket_owner=self.account_id,
                deadline_check=self._check_deadline,
            )
            output.append((uri, version_id, uncompressed))
        return tuple(output)


def _validated_log_hashes(
    client: Any,
    *,
    cloudtrail_client: Any,
    bucket: str,
    account_id: str,
    region: str,
    start_time: datetime,
    end_time: datetime,
    expected_log_uris: tuple[str, ...],
    validated_digest_uris: tuple[str, ...],
    deadline_check: Callable[[], None] = lambda: None,
) -> tuple[
    dict[str, str],
    tuple[tuple[str, str, str], ...],
    dict[str, tuple[str, str, str]],
]:
    """Read log hashes only from pinned digest versions with valid RSA signatures."""
    hashes: dict[str, str] = {}
    digest_documents: list[tuple[dict[str, Any], tuple[str, str, str]]] = []
    public_keys: list[dict[str, Any]] = []
    digest_receipts: list[tuple[str, str, str]] = []
    token: str | None = None
    while True:
        deadline_check()
        request: dict[str, Any] = {
            "StartTime": start_time.astimezone(UTC),
            "EndTime": end_time.astimezone(UTC),
        }
        if token:
            request["NextToken"] = token
        key_page = cloudtrail_client.list_public_keys(**request)
        deadline_check()
        public_keys.extend(key_page.get("PublicKeyList", []))
        token = key_page.get("NextToken")
        if not token:
            break
        if len(public_keys) > 128:
            raise EvidenceIncomplete("CloudTrail public key inventory exceeds its bound")
    for uri in validated_digest_uris:
        deadline_check()
        digest_bucket, digest_key = _parse_s3_uri(uri)
        if digest_bucket != bucket or not digest_key.endswith(".json.gz"):
            continue
        version_id = resolve_sole_current_version(
            client,
            bucket=digest_bucket,
            key=digest_key,
            expected_bucket_owner=account_id,
            deadline_check=deadline_check,
        )
        digest_response, compressed = read_version_bytes(
            client,
            bucket=digest_bucket,
            key=digest_key,
            version_id=version_id,
            expected_bucket_owner=account_id,
            maximum_bytes=16 * 1024 * 1024,
            deadline_check=deadline_check,
        )
        deadline_check()
        if digest_response.get("VersionId") != version_id:
            raise EvidenceIncomplete("CloudTrail digest read returned a different version")
        if digest_response.get("ServerSideEncryption") not in {"aws:kms", "aws:kms:dsse"}:
            raise EvidenceIncomplete("CloudTrail digest lacks expected KMS encryption")
        with gzip.GzipFile(fileobj=BytesIO(compressed), mode="rb") as stream:
            raw = stream.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise EvidenceContradiction("CloudTrail digest exceeds its uncompressed size bound")
        document = strict_json(raw, maximum=16 * 1024 * 1024)
        if not isinstance(document, dict) or not isinstance(document.get("logFiles"), list):
            raise EvidenceIncomplete("validated CloudTrail digest omits its log hash inventory")
        if (
            document.get("digestS3Bucket") != digest_bucket
            or document.get("digestS3Object") != digest_key
            or document.get("digestSignatureAlgorithm") != "SHA256withRSA"
        ):
            raise EvidenceContradiction("CloudTrail digest identity or signature algorithm differs")
        digest_end = document.get("digestEndTime")
        fingerprint = document.get("digestPublicKeyFingerprint")
        metadata = digest_response.get("Metadata")
        signature_hex = metadata.get("signature") if isinstance(metadata, dict) else None
        signature_algorithm = (
            metadata.get("signature-algorithm") if isinstance(metadata, dict) else None
        )
        if (
            not isinstance(digest_end, str)
            or not isinstance(fingerprint, str)
            or not isinstance(signature_hex, str)
            or signature_algorithm != "sha256withrsa"
        ):
            raise EvidenceIncomplete("CloudTrail digest signature metadata is unavailable")
        matching_keys = [
            row
            for row in public_keys
            if row.get("Fingerprint") == fingerprint
            and isinstance(row.get("ValidityStartTime"), datetime)
            and isinstance(row.get("ValidityEndTime"), datetime)
            and row["ValidityStartTime"] <= _parse_utc(digest_end) <= row["ValidityEndTime"]
        ]
        if len(matching_keys) != 1:
            raise EvidenceIncomplete("CloudTrail digest public key fingerprint is not unique")
        key_value = matching_keys[0].get("Value")
        if not isinstance(key_value, bytes):
            raise EvidenceIncomplete("CloudTrail public key has an unsupported encoding")
        try:
            public_key = serialization.load_der_public_key(key_value)
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise ValueError("not an RSA public key")
            signed = "\n".join(
                (
                    digest_end,
                    f"{digest_bucket}/{digest_key}",
                    hashlib.sha256(raw).hexdigest(),
                    str(document.get("previousDigestSignature", "")),
                )
            ).encode("utf-8")
            public_key.verify(
                bytes.fromhex(signature_hex),
                signed,
                padding.PKCS1v15(),
                crypto_hashes.SHA256(),
            )
        except Exception as exc:
            raise EvidenceIncomplete("CloudTrail digest signature verification failed") from exc
        digest_receipt = (uri, version_id, hashlib.sha256(compressed).hexdigest())
        digest_documents.append((document, digest_receipt))
        require_exact_current_version(
            client,
            bucket=digest_bucket,
            key=digest_key,
            version_id=version_id,
            expected_bucket_owner=account_id,
            deadline_check=deadline_check,
        )
        digest_receipts.append(digest_receipt)
    digest_receipts.sort()
    digest_by_log_uri: dict[str, tuple[str, str, str]] = {}
    for uri in expected_log_uris:
        target_bucket, target_key = _parse_s3_uri(uri)
        matches: list[tuple[str, tuple[str, str, str]]] = []
        for document, receipt in digest_documents:
            for row in document["logFiles"]:
                if (
                    isinstance(row, dict)
                    and row.get("s3Bucket") == target_bucket
                    and row.get("s3Object") == target_key
                    and row.get("hashAlgorithm") == "SHA-256"
                    and isinstance(row.get("hashValue"), str)
                    and re.fullmatch(r"[0-9a-f]{64}", row["hashValue"])
                ):
                    matches.append((row["hashValue"], receipt))
        if len(matches) != 1:
            raise EvidenceIncomplete("CloudTrail log has no unique authenticated digest hash")
        hashes[uri] = matches[0][0]
        digest_by_log_uri[uri] = matches[0][1]
    return hashes, tuple(digest_receipts), digest_by_log_uri


def _invocation_prefix_inventory(
    client: Any, bucket: str, prefix: str, account_id: str
) -> tuple[tuple[str, str, bool], ...]:
    """Inventory every version under the Bedrock prefix with owner scoping."""
    values: list[tuple[str, str, bool]] = []
    key_marker: str | None = None
    version_marker: str | None = None
    for _page in range(32):
        request: dict[str, Any] = {
            "Bucket": bucket,
            "Prefix": prefix,
            "ExpectedBucketOwner": account_id,
        }
        if key_marker is not None:
            request["KeyMarker"] = key_marker
        if version_marker is not None:
            request["VersionIdMarker"] = version_marker
        response = client.list_object_versions(**request)
        if response.get("DeleteMarkers"):
            raise EvidenceIncomplete("invocation prefix contains a delete marker")
        for row in response.get("Versions", []):
            key, version_id = row.get("Key"), row.get("VersionId")
            if (
                not isinstance(key, str)
                or not key.startswith(prefix)
                or not isinstance(version_id, str)
                or not version_id
                or version_id == "null"
                or type(row.get("IsLatest")) is not bool
            ):
                raise EvidenceIncomplete("invocation prefix version inventory is malformed")
            values.append((key, version_id, row["IsLatest"]))
            if len(values) > 4096:
                raise EvidenceIncomplete("invocation prefix version inventory exceeds its bound")
        if response.get("IsTruncated") is not True:
            return tuple(sorted(values))
        key_marker = response.get("NextKeyMarker")
        version_marker = response.get("NextVersionIdMarker")
        if not isinstance(key_marker, str) or not key_marker:
            raise EvidenceIncomplete("invocation prefix pagination markers are malformed")
    raise EvidenceIncomplete("invocation prefix pagination exceeded its bound")


def parse_cloudtrail_logs(
    validated: tuple[tuple[str, str, bytes], ...],
    *,
    digest_receipts_by_log: dict[str, tuple[str, str, str]],
    maximum_uncompressed: int = _MAX_LOG_UNCOMPRESSED,
) -> tuple[tuple[dict[str, Any], ...], tuple[tuple[str, str, str, str], ...]]:
    events: list[dict[str, Any]] = []
    total = 0
    seen_ids: dict[str, str] = {}
    event_sources: dict[str, str] = {}
    event_receipts: dict[str, tuple[str, str, str, str]] = {}
    for uri, _version_id, uncompressed in validated:
        total += len(uncompressed)
        if total > maximum_uncompressed:
            raise EvidenceContradiction("CloudTrail proof window exceeds its size budget")
        document = strict_json(uncompressed, maximum=maximum_uncompressed)
        if not isinstance(document, dict) or not isinstance(document.get("Records"), list):
            raise EvidenceContradiction("CloudTrail log file has no Records array")
        for event in document["Records"]:
            if not isinstance(event, dict):
                raise EvidenceContradiction("CloudTrail Records contains a non-object")
            _require_supported_event_version(event)
            event_id = event.get("eventID")
            if not isinstance(event_id, str) or not event_id:
                raise EvidenceIncomplete("CloudTrail event omits eventID")
            digest = canonical_event_digest(event)
            previous = seen_ids.get(event_id)
            if previous is not None:
                if previous != digest or event_sources[event_id] != uri:
                    raise EvidenceContradiction("CloudTrail eventID has conflicting deliveries")
                continue
            seen_ids[event_id] = digest
            event_sources[event_id] = uri
            digest_receipt = digest_receipts_by_log.get(uri)
            if digest_receipt is None:
                raise EvidenceIncomplete("CloudTrail event has no authenticated digest identity")
            event_receipts[event_id] = (event_id, *digest_receipt)
            events.append(event)
    return tuple(events), tuple(sorted(event_receipts.values()))


def validate_session_logs(
    *,
    resource_map: QualificationResourceMap,
    binding: DeploymentBinding,
    s3_client: Any,
    cloudtrail_client: Any,
    credentials: Any,
    start_time: datetime,
    end_time: datetime,
    aws_binary: str | None = None,
    run_process: Any = None,
    timeout_seconds: int = 120,
    deadline_monotonic: float | None = None,
) -> DigestValidatedLogs:
    """Enumerate each required UTC day, then validate only original trail files.

    CloudTrail's infrastructure contract uses the default ``AWSLogs`` prefix.
    Listing is bounded to the session window and each requested file is later
    checked against the signed digest chain by :class:`CloudTrailDigestVerifier`.
    """
    if start_time.tzinfo is None or end_time.tzinfo is None or end_time < start_time:
        raise ValueError("CloudTrail session window must be ordered and timezone-aware")
    start = start_time.astimezone(UTC)
    end = end_time.astimezone(UTC)
    if (end - start).total_seconds() > 86_400:
        raise EvidenceIncomplete("CloudTrail session window exceeds one day")
    cloudtrail = resource_map.cloudtrail
    if not cloudtrail.arn or not cloudtrail.bucket or not cloudtrail.log_validation_enabled:
        raise EvidenceIncomplete("pinned map does not enable validated CloudTrail delivery")
    prefix_root = f"AWSLogs/{binding.account_id}/CloudTrail/{binding.region}/"
    day = start.replace(hour=0, minute=0, second=0, microsecond=0)
    last_day = end.replace(hour=0, minute=0, second=0, microsecond=0)
    expected: set[str] = set()

    def check_deadline() -> None:
        if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
            raise EvidenceIncomplete("qualification delivery deadline expired during log discovery")

    paginator = s3_client.get_paginator("list_objects_v2")
    while day <= last_day:
        prefix = f"{prefix_root}{day:%Y/%m/%d}/"
        for page in paginator.paginate(Bucket=cloudtrail.bucket, Prefix=prefix):
            check_deadline()
            for item in page.get("Contents", []):
                key = item.get("Key") if isinstance(item, dict) else None
                if isinstance(key, str) and key.startswith(prefix) and key.endswith(".json.gz"):
                    expected.add(f"s3://{cloudtrail.bucket}/{key}")
                    if len(expected) > 4096:
                        raise EvidenceIncomplete("CloudTrail session file set exceeds its bound")
        day += timedelta(days=1)
    if not expected:
        raise EvidenceIncomplete("CloudTrail has not delivered a session log file")
    verifier = CloudTrailDigestVerifier(
        trail_arn=cloudtrail.arn,
        bucket=cloudtrail.bucket,
        prefix="AWSLogs",
        region=binding.region,
        account_id=binding.account_id,
        s3_client=s3_client,
        cloudtrail_client=cloudtrail_client,
        credentials=credentials,
        aws_binary=aws_binary,
        run_process=run_process or subprocess.run,
        timeout_seconds=timeout_seconds,
        deadline_monotonic=deadline_monotonic,
    )
    result = verifier.validate_records(
        expected_log_uris=tuple(sorted(expected)),
        start_time=start,
        end_time=end,
    )
    check_deadline()
    return result
