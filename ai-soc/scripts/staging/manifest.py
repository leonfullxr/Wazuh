from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from scripts.staging.models import AcceptanceId, DeploymentBinding, EvidenceReference, GateId

_GIT_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_KEYS = frozenset(
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
_PEM_BLOCK = re.compile(r"-----BEGIN [A-Z ]+-----")
_SECRET_VALUE = re.compile(
    r"(?i)(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+|"
    r"Bearer\s+[A-Za-z0-9._~+/-]+=*|gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})"
)


class ArtifactPins(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service_sha: str
    content_sha: str
    artifact_digest: str

    @field_validator("service_sha", "content_sha")
    @classmethod
    def _git_sha(cls, value: str) -> str:
        if not _GIT_SHA40.fullmatch(value):
            raise ValueError("artifact pin must be a 40-character lowercase git sha")
        return value

    @field_validator("artifact_digest")
    @classmethod
    def _digest_sha(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("artifact digest must be a 64-character lowercase sha256")
        return value


class ExpectedDeploymentBinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    account_id: str
    region: str
    cluster_arn: str
    service_arn: str
    task_definition_arn: str
    deployment_name: str
    deployment_id: str | None = None
    image_digest: str
    service_sha: str
    content_sha: str
    configuration_sha256: str

    @field_validator("account_id")
    @classmethod
    def _account_id(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9]{12}", value):
            raise ValueError("deployment account_id must be a 12-digit AWS account ID")
        return value

    @field_validator(
        "region", "cluster_arn", "service_arn", "task_definition_arn", "deployment_name"
    )
    @classmethod
    def _required_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("deployment region and deployment_name must be nonempty")
        return value

    @model_validator(mode="after")
    def _ecs_arns_match_scope(self) -> ExpectedDeploymentBinding:
        arn_prefix = f"arn:aws(?:-[a-z0-9-]+)?:ecs:{re.escape(self.region)}:{self.account_id}:"
        for arn, resource in (
            (self.cluster_arn, "cluster"),
            (self.service_arn, "service"),
            (self.task_definition_arn, "task-definition"),
        ):
            if not re.fullmatch(arn_prefix + resource + r"/.+", arn):
                raise ValueError(
                    f"expected {resource} ARN must match configured account and region"
                )
        return self

    @field_validator("deployment_id")
    @classmethod
    def _deployment_id(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("deployment_id must be nonempty when supplied")
        return value

    @field_validator("image_digest")
    @classmethod
    def _image_digest(cls, value: str) -> str:
        if not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", value):
            raise ValueError("deployment image_digest must be a SHA-256 digest")
        return value if value.startswith("sha256:") else f"sha256:{value}"

    @field_validator("service_sha", "content_sha")
    @classmethod
    def _source_hash(cls, value: str) -> str:
        if not _GIT_SHA40.fullmatch(value):
            raise ValueError("deployment source pins must be 40-character lowercase git SHAs")
        return value

    @field_validator("configuration_sha256")
    @classmethod
    def _configuration_hash(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("configuration_sha256 must be lowercase SHA-256")
        return value

    def to_observed_binding(self) -> DeploymentBinding:
        return DeploymentBinding(**self.model_dump())


class NightlyBaselineInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sha256: str
    en_cases: int
    es_cases: int
    drop_rate: float
    independently_reviewed: bool

    @field_validator("sha256")
    @classmethod
    def _baseline_hash(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("baseline sha256 must be lowercase hex")
        return value


class NightlyCaseInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    language: Literal["en", "es"]
    outcome: Literal["completed", "no_findings", "invalid_json", "provider_failure"]
    route_matches: bool
    valid_candidates: int = 0
    dropped_candidates: int = 0
    evidence_refs: tuple[EvidenceReference, ...] = ()


class NightlyGateInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    required_case_ids: tuple[str, ...]
    baseline: NightlyBaselineInput
    results: tuple[NightlyCaseInput, ...] | None = None


class NetworkGateInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    environment_id: str
    hostname: str
    secret_id: str
    secret_version: str
    ca_sha256: str
    indexer_origin: str

    @field_validator("ca_sha256")
    @classmethod
    def _ca_hash(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("ca_sha256 must be lowercase hex")
        return value


class GateInputs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nightly: NightlyGateInput | None = None
    network: tuple[NetworkGateInput, ...] | NetworkGateInput | None = None
    adapter: dict[str, Any] | None = None


class StagingManifestV3(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["3"]
    gate_id: GateId
    acceptance_ids: tuple[AcceptanceId, ...]
    owners: tuple[str, ...]
    artifacts: ArtifactPins
    expected_deployment: ExpectedDeploymentBinding
    commands: tuple[str, ...]
    evidence_refs: tuple[str, ...] = ()
    inputs: GateInputs = Field(default_factory=GateInputs)

    @field_validator("acceptance_ids")
    @classmethod
    def _acceptance(cls, value: tuple[AcceptanceId, ...]) -> tuple[AcceptanceId, ...]:
        return value

    @field_validator("owners", "commands")
    @classmethod
    def _nonempty_strings(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("owners and commands must be nonempty")
        return value

    @model_validator(mode="after")
    def _gate_acceptance_binding(self) -> StagingManifestV3:
        if self.expected_deployment.service_sha != self.artifacts.service_sha:
            raise ValueError("expected deployment service_sha does not match artifacts.service_sha")
        if self.expected_deployment.content_sha != self.artifacts.content_sha:
            raise ValueError("expected deployment content_sha does not match artifacts.content_sha")
        if self.expected_deployment.image_digest != f"sha256:{self.artifacts.artifact_digest}":
            raise ValueError(
                "expected deployment image_digest does not match artifacts.artifact_digest"
            )
        if self.gate_id == GateId.LV_NIGHTLY and AcceptanceId.GP3 not in self.acceptance_ids:
            raise ValueError("LV-NIGHTLY requires GP3 in acceptance_ids")
        if self.gate_id == GateId.LV_NETWORK and AcceptanceId.GP4 not in self.acceptance_ids:
            raise ValueError("LV-NETWORK requires GP4 in acceptance_ids")
        for acceptance_id in self.acceptance_ids:
            expected_gate = {
                AcceptanceId.GP3: GateId.LV_NIGHTLY,
                AcceptanceId.GP4: GateId.LV_NETWORK,
            }[acceptance_id]
            if self.gate_id != expected_gate:
                raise ValueError(f"{acceptance_id.value} belongs to {expected_gate.value}")
        return self

    @model_validator(mode="after")
    def _gate_inputs_present(self) -> StagingManifestV3:
        if self.gate_id == GateId.LV_NIGHTLY and self.inputs.nightly is None:
            raise ValueError("LV-NIGHTLY requires inputs.nightly")
        if self.gate_id == GateId.LV_NETWORK and self.inputs.network is None:
            raise ValueError("LV-NETWORK requires inputs.network")
        return self


def manifest_sha256(raw: dict[str, Any]) -> str:
    payload = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _walk_for_secrets(value: object, path: str) -> list[str]:
    violations: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            child_path = f"{path}.{key_text}" if path else key_text
            if key_text.lower() in _FORBIDDEN_KEYS:
                violations.append(f"forbidden key name at {child_path}")
            violations.extend(_walk_for_secrets(child, child_path))
        return violations
    if isinstance(value, list):
        for index, child in enumerate(value):
            violations.extend(_walk_for_secrets(child, f"{path}[{index}]"))
        return violations
    if isinstance(value, str):
        if _PEM_BLOCK.search(value):
            violations.append(f"embedded PEM material at {path}")
        if _SECRET_VALUE.search(value):
            violations.append(f"suspected secret value at {path}")
    return violations


def load_manifest_v3(raw: object) -> StagingManifestV3:
    if not isinstance(raw, dict):
        raise ValueError("manifest must be a JSON object")
    violations = _walk_for_secrets(raw, "")
    if violations:
        raise ValueError(violations[0])
    return StagingManifestV3.model_validate(raw)


def parse_manifest(raw: object) -> tuple[str, StagingManifestV3 | None]:
    if not isinstance(raw, dict):
        raise ValueError("manifest must be a JSON object")
    version = cast(dict[object, object], raw).get("schema_version")
    if version in {"1", "2"}:
        return str(version), None
    if version == "3":
        return "3", load_manifest_v3(raw)
    raise ValueError("unsupported staging manifest schema")
