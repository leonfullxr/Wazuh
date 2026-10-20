from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from ai_soc.qualification.models import ProbeInvocationConfig

GateStatus = Literal["PASS", "FAIL", "NOT_RUN", "NOT_CONFIGURED"]
GateDataSource = Literal["aws_client", "nightly_client", "inline_manifest", "unconfigured"]
_ACCOUNT = re.compile(r"^[0-9]{12}$")
_SHA256 = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$")
_GIT_SHA40 = re.compile(r"^[0-9a-f]{40}$")


class GateId(StrEnum):
    LV_PLATFORM = "LV-PLATFORM"
    LV_IDENTITY = "LV-IDENTITY"
    LV_MCP = "LV-MCP"
    LV_SITE = "LV-SITE"
    LV_NETWORK = "LV-NETWORK"
    LV_STATE = "LV-STATE"
    LV_MODEL = "LV-MODEL"
    LV_CONTENT = "LV-CONTENT"
    LV_OBSERVABILITY = "LV-OBSERVABILITY"
    LV_NIGHTLY = "LV-NIGHTLY"
    LV_UI = "LV-UI"


class AcceptanceId(StrEnum):
    GP3 = "GP3"
    GP4 = "GP4"


class ObligationStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_RUN = "NOT_RUN"
    NOT_CONFIGURED = "NOT_CONFIGURED"


class EvidenceKind(StrEnum):
    CLOUDTRAIL_EVENT = "cloudtrail_event"
    BEDROCK_REQUEST = "bedrock_request"
    S3_VERSION = "s3_version"
    FILE_SHA256 = "file_sha256"


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    kind: EvidenceKind
    identifier: str
    sha256: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.kind, str):
            try:
                object.__setattr__(self, "kind", EvidenceKind(self.kind))
            except ValueError as exc:
                raise ValueError("evidence kind must be a registered enum") from exc
        if not isinstance(self.kind, EvidenceKind):
            raise ValueError("evidence kind must be a registered enum")
        if (
            not isinstance(self.identifier, str)
            or not self.identifier.strip()
            or any(char in self.identifier for char in "\r\n\x00")
        ):
            raise ValueError("evidence identifier must be a nonempty single-line value")
        if self.kind == EvidenceKind.FILE_SHA256 and self.sha256 is None:
            raise ValueError("file evidence references require a lowercase SHA-256")
        if self.sha256 is not None and (
            not isinstance(self.sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", self.sha256)
        ):
            raise ValueError("evidence sha256 must be lowercase SHA-256")


@dataclass(frozen=True, slots=True)
class DeploymentBinding:
    """Observed deployment identity carried by every live gate result."""

    account_id: str
    region: str
    cluster_arn: str
    service_arn: str
    task_definition_arn: str
    deployment_name: str
    deployment_id: str | None
    image_digest: str
    service_sha: str
    content_sha: str
    configuration_sha256: str

    def __post_init__(self) -> None:
        if not _ACCOUNT.fullmatch(self.account_id):
            raise ValueError("observed account_id must be a 12-digit AWS account ID")
        if not all(
            (
                self.region,
                self.cluster_arn,
                self.service_arn,
                self.task_definition_arn,
                self.deployment_name,
            )
        ):
            raise ValueError("observed region and ECS deployment ARNs must be nonempty")
        if self.deployment_id is not None and not self.deployment_id.strip():
            raise ValueError("deployment_id must be nonempty when supplied")
        expected_arn_prefix = (
            f"arn:aws(?:-[a-z0-9-]+)?:ecs:{re.escape(self.region)}:{self.account_id}:"
        )
        for arn, resource in (
            (self.cluster_arn, "cluster"),
            (self.service_arn, "service"),
            (self.task_definition_arn, "task-definition"),
        ):
            if not re.fullmatch(expected_arn_prefix + resource + r"/.+", arn):
                raise ValueError(f"observed {resource} ARN must match account and region")
        if not _SHA256.fullmatch(self.image_digest):
            raise ValueError("observed image_digest must be a SHA-256 digest")
        if not self.image_digest.startswith("sha256:"):
            object.__setattr__(self, "image_digest", f"sha256:{self.image_digest}")
        if not _GIT_SHA40.fullmatch(self.service_sha) or not _GIT_SHA40.fullmatch(self.content_sha):
            raise ValueError("observed service_sha and content_sha must be git SHAs")
        if not re.fullmatch(r"[0-9a-f]{64}", self.configuration_sha256):
            raise ValueError("observed configuration_sha256 must be lowercase SHA-256")


def matches_expected_binding(observed: DeploymentBinding, expected: DeploymentBinding) -> bool:
    """Match every configured pin; deployment IDs are mandatory on both sides."""
    names = (
        "account_id",
        "region",
        "cluster_arn",
        "service_arn",
        "task_definition_arn",
        "deployment_name",
        "image_digest",
        "service_sha",
        "content_sha",
        "configuration_sha256",
    )
    return (
        observed.deployment_id is not None
        and expected.deployment_id is not None
        and all(getattr(observed, name) == getattr(expected, name) for name in names)
        and observed.deployment_id == expected.deployment_id
    )


@dataclass(frozen=True, slots=True)
class GateObligation:
    obligation_id: str
    description: str


@dataclass(frozen=True, slots=True)
class ObligationResult:
    obligation_id: str
    status: ObligationStatus
    detail: str
    evidence_refs: tuple[EvidenceReference, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.obligation_id, str) or not self.obligation_id.strip():
            raise ValueError("obligation ID must be a nonempty string")
        if not isinstance(self.status, ObligationStatus):
            raise ValueError("obligation status must be a registered enum")
        if not isinstance(self.detail, str) or len(self.detail) > 2048:
            raise ValueError("obligation detail must be a bounded string")
        if not isinstance(self.evidence_refs, tuple) or any(
            not isinstance(reference, EvidenceReference) for reference in self.evidence_refs
        ):
            raise ValueError("obligation evidence must contain typed references")


@dataclass(frozen=True, slots=True)
class KnownResultView:
    """Typed adapter for a known compatibility row nested in result diagnostics."""

    kind: Literal["contributor", "nightly", "network"]
    view_id: str
    diagnostics: dict[str, Any]
    obligation_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class LiveGateResult:
    gate_id: GateId
    owners: tuple[str, ...]
    inputs_manifest_sha256: str
    service_sha: str
    content_sha: str
    artifact_digest: str
    status: GateStatus
    commands: tuple[str, ...]
    results: dict[str, Any]
    evidence_refs: tuple[EvidenceReference, ...]
    checked_at: str
    binding: DeploymentBinding | None
    expected_binding: DeploymentBinding
    obligations: tuple[ObligationResult, ...] = ()
    acceptance_results: tuple[LiveAcceptanceResult, ...] = ()
    qualification_receipts: tuple[QualificationReceipt, ...] = ()
    data_source: GateDataSource | None = None
    result_views: tuple[KnownResultView, ...] = field(default=(), repr=False, compare=False)
    verified_observations: tuple[Any, ...] = field(default=(), repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.gate_id, GateId):
            raise ValueError("live gate result requires a registered gate ID")
        if self.status not in {"PASS", "FAIL", "NOT_RUN", "NOT_CONFIGURED"}:
            raise ValueError("live gate result has an invalid status")
        if any(not isinstance(item, ObligationResult) for item in self.obligations):
            raise ValueError("live gate result contains an untyped obligation")
        if len({item.obligation_id for item in self.obligations}) != len(self.obligations):
            raise ValueError("live gate result contains duplicate obligation IDs")
        if any(not isinstance(item, EvidenceReference) for item in self.evidence_refs):
            raise ValueError("live gate result contains an untyped evidence reference")
        if not isinstance(self.verified_observations, tuple):
            raise ValueError("verified observations must be process-local typed capabilities")
        if any(not isinstance(item, KnownResultView) for item in self.result_views):
            raise ValueError("known result views must use the typed result-view model")
        if any(not isinstance(item, QualificationReceipt) for item in self.qualification_receipts):
            raise ValueError("qualification receipts must use the strict receipt model")

    def to_dict(self) -> dict[str, Any]:
        from scripts.staging.certification import normalize_live_result

        normalized = normalize_live_result(self)
        serialized = asdict(replace(normalized, verified_observations=(), result_views=()))
        # Capabilities are process-local and must never become self-asserted JSON.
        serialized.pop("verified_observations", None)
        serialized["results"] = _serialize_result_views(
            serialized["results"], normalized.result_views, normalized.obligations
        )
        serialized["qualification_receipts"] = [
            receipt.to_dict() for receipt in self.qualification_receipts
        ]
        return redact_secrets(serialized)


def _serialize_result_views(
    results: dict[str, Any],
    views: tuple[KnownResultView, ...],
    obligations: tuple[ObligationResult, ...],
) -> dict[str, Any]:
    """Render registered compatibility rows from normalized typed obligations."""
    output = dict(results)
    rows = {row.obligation_id: row for row in obligations}
    contributors = dict(output.get("contributors", {}))
    network = dict(output.get("network", {}))
    nightly = dict(output.get("nightly", {}))
    for view in views:
        view_rows = tuple(rows[item] for item in view.obligation_ids if item in rows)
        if view.kind == "contributor":
            payload = dict(view.diagnostics)
            if "status" in payload:
                payload["status"] = _summarize_view_rows(view_rows)
            if "evidence_refs" in payload:
                payload["evidence_refs"] = [
                    asdict(reference) for row in view_rows for reference in row.evidence_refs
                ]
            contributors[view.view_id] = payload
        elif view.kind == "nightly":
            nightly = dict(view.diagnostics)
            if "status" in nightly:
                nightly["status"] = _summarize_view_rows(view_rows)
        else:
            network = dict(view.diagnostics)
            network["obligations"] = [
                {
                    "obligation_id": row.obligation_id,
                    "status": row.status.value,
                    "detail": row.detail,
                    "evidence_refs": [asdict(reference) for reference in row.evidence_refs],
                }
                for row in view_rows
            ]
    if views:
        if contributors:
            output["contributors"] = contributors
        if nightly:
            output["nightly"] = nightly
        if network:
            output["network"] = network
    return output


def _summarize_view_rows(rows: tuple[ObligationResult, ...]) -> GateStatus:
    if rows and all(row.status == ObligationStatus.PASS for row in rows):
        return "PASS"
    if any(row.status == ObligationStatus.FAIL for row in rows):
        return "FAIL"
    return "NOT_RUN"


@dataclass(frozen=True, slots=True)
class LiveAcceptanceResult:
    acceptance_id: AcceptanceId
    gate_id: GateId
    status: GateStatus
    binding: DeploymentBinding | None
    obligation: ObligationResult
    evidence_refs: tuple[EvidenceReference, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return redact_secrets(asdict(self))


@dataclass(frozen=True, slots=True)
class QualificationReceipt:
    """Strict persisted reference to a coordinator-owned qualification run."""

    session_id: str
    invocation_id: str
    run_id: str
    started_by: str
    gate_id: GateId
    contributor_id: str
    task_slots: tuple[str, ...]
    task_arns: tuple[str, ...]
    deadline_utc: str
    probe_spec: ProbeInvocationConfig | None
    launch_requests: tuple[dict[str, Any], ...]
    state: Literal["intent", "launched", "stopping", "stopped", "ambiguous"]

    def __post_init__(self) -> None:
        for name, value in (
            ("session_id", self.session_id),
            ("invocation_id", self.invocation_id),
            ("run_id", self.run_id),
            ("started_by", self.started_by),
            ("contributor_id", self.contributor_id),
            ("deadline_utc", self.deadline_utc),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"qualification receipt {name} must be nonempty")
        if not isinstance(self.gate_id, GateId):
            raise ValueError("qualification receipt gate ID must be registered")
        if (
            not self.task_slots
            or len(set(self.task_slots)) != len(self.task_slots)
            or any(not isinstance(slot, str) or not slot for slot in self.task_slots)
        ):
            raise ValueError("qualification receipt task slots must be unique and nonempty")
        if any(not isinstance(arn, str) or not arn for arn in self.task_arns):
            raise ValueError("qualification receipt task ARNs must be nonempty strings")
        if self.probe_spec is not None and not isinstance(self.probe_spec, ProbeInvocationConfig):
            raise ValueError("qualification receipt ProbeSpec must use the strict model")
        if not isinstance(self.launch_requests, tuple) or any(
            not isinstance(request, dict) for request in self.launch_requests
        ):
            raise ValueError("qualification receipt launch requests must be typed objects")

    def to_dict(self) -> dict[str, Any]:
        serialized = asdict(self)
        serialized["probe_spec"] = (
            self.probe_spec.model_dump(mode="json") if self.probe_spec is not None else {}
        )
        return redact_secrets(serialized)

    @classmethod
    def from_dict(cls, value: object) -> QualificationReceipt:
        fields = {
            "session_id",
            "invocation_id",
            "run_id",
            "started_by",
            "gate_id",
            "contributor_id",
            "task_slots",
            "task_arns",
            "deadline_utc",
            "probe_spec",
            "launch_requests",
            "state",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("qualification receipt has an unknown or missing field")
        if not isinstance(value["task_slots"], list) or not isinstance(value["task_arns"], list):
            raise ValueError("qualification receipt task lists are malformed")
        if not isinstance(value["launch_requests"], list):
            raise ValueError("qualification receipt launch requests are malformed")
        try:
            gate_id = GateId(value["gate_id"])
        except (TypeError, ValueError) as exc:
            raise ValueError("qualification receipt gate ID is unknown") from exc
        return cls(
            session_id=value["session_id"],
            invocation_id=value["invocation_id"],
            run_id=value["run_id"],
            started_by=value["started_by"],
            gate_id=gate_id,
            contributor_id=value["contributor_id"],
            task_slots=tuple(value["task_slots"]),
            task_arns=tuple(value["task_arns"]),
            deadline_utc=value["deadline_utc"],
            probe_spec=(
                None
                if value["probe_spec"] == {}
                else ProbeInvocationConfig.model_validate(value["probe_spec"])
            ),
            launch_requests=tuple(value["launch_requests"]),
            state=value["state"],
        )


def _secret_text(value: str) -> bool:
    return bool(
        re.search(
            r"(?i)(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|"
            r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+|-----BEGIN [A-Z ]+-----|"
            r"Bearer\s+[A-Za-z0-9._~+/-]+=*|gh[pousr]_[A-Za-z0-9_]{20,}|"
            r"github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})",
            value,
        )
    )


_SECRET_KEYS = frozenset(
    {
        "password",
        "private_key",
        "privatekey",
        "api_key",
        "apikey",
        "client_secret",
        "secret_value",
        "secret_string",
        "secret_binary",
        "aws_secret_access_key",
        "secret_access_key",
        "access_key",
        "session_token",
        "security_token",
        "authorization",
        "bearer",
        "credential",
        "credentials",
        "token_value",
        "access_token",
        "refresh_token",
    }
)


def redact_secrets(value: Any, *, key: str = "") -> Any:
    """Redact secret-bearing values before evidence is serialized."""
    if key.lower() in _SECRET_KEYS:
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): redact_secrets(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_secrets(item) for item in value]
    if isinstance(value, str) and _secret_text(value):
        return "[REDACTED]"
    return value


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def exit_code_for(status: GateStatus) -> int:
    if status == "PASS":
        return 0
    if status == "FAIL":
        return 1
    return 2
