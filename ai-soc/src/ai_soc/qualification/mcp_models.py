from __future__ import annotations

from enum import StrEnum
from urllib.parse import urlsplit

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, ValidationError, field_validator

from ai_soc.contracts.models import AskRequest, PageRequest
from ai_soc.qualification.binding import DeploymentBinding as DeploymentBinding
from ai_soc.qualification.state_models import StateProbeInputs as StateProbeInputs


class GateId(StrEnum):
    LV_MCP = "LV-MCP"


class ProbeContractError(Exception):
    def __init__(self, phase: str, error: ValidationError) -> None:
        locations = sorted(
            ".".join(str(part) for part in item["loc"])
            for item in error.errors(include_input=False)
        )
        super().__init__(f"{phase}:{','.join(locations)}")


class McpNegativeTokenRefs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    wrong_resource: str
    wrong_issuer: str
    wrong_scope: str


class McpWrongIssuerInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issuer: AnyHttpUrl
    jwks_uri: AnyHttpUrl

    @field_validator("issuer", "jwks_uri")
    @classmethod
    def _https_only(cls, value: AnyHttpUrl) -> AnyHttpUrl:
        if urlsplit(str(value)).scheme != "https":
            raise ValueError("wrong-issuer metadata and JWKS must use HTTPS")
        return value


class LvMcpInputs(BaseModel):
    """Nonsecret MCP target and OAuth references for the live transport probe."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint: AnyHttpUrl
    rest_endpoint: AnyHttpUrl
    token_endpoint: AnyHttpUrl
    resource: AnyHttpUrl
    issuer: AnyHttpUrl
    client_id: str
    synthetic_subject: str
    access_token_ref: str
    id_token_ref: str
    browser_cookie_ref: str
    csrf_token_ref: str
    evidence_bucket: str
    evidence_prefix: str
    probe_timeout_seconds: int = Field(default=600, ge=60, le=1800)
    negative_token_refs: McpNegativeTokenRefs
    wrong_issuer: McpWrongIssuerInput
    origin: AnyHttpUrl
    disallowed_origin: AnyHttpUrl
    ask_request: AskRequest
    page_request: PageRequest
    timeout_seconds: float = Field(default=15, gt=0, le=60)

    @field_validator(
        "endpoint",
        "rest_endpoint",
        "token_endpoint",
        "resource",
        "issuer",
        "origin",
        "disallowed_origin",
    )
    @classmethod
    def _https_or_loopback(cls, value: AnyHttpUrl) -> AnyHttpUrl:
        parsed = urlsplit(str(value))
        if parsed.scheme == "https":
            return value
        if parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}:
            return value
        raise ValueError("MCP URLs must use HTTPS; HTTP is allowed only for loopback tests")

    @field_validator(
        "client_id",
        "synthetic_subject",
        "access_token_ref",
        "id_token_ref",
        "browser_cookie_ref",
        "csrf_token_ref",
        "evidence_bucket",
        "evidence_prefix",
    )
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("OAuth and qualification input values must be nonempty")
        return value

    @field_validator("evidence_prefix")
    @classmethod
    def _qualification_prefix(cls, value: str) -> str:
        if value.strip("/") != "qualification/lv-mcp":
            raise ValueError("evidence prefix must be qualification/lv-mcp")
        return "qualification/lv-mcp"
