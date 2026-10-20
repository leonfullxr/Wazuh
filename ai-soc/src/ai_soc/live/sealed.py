"""Sealed live boot document validated before process start."""

from __future__ import annotations

from typing import Literal

from pydantic import field_validator, model_validator

from ai_soc.config import ServiceConfig
from ai_soc.contracts.models import BuildProvenance, StrictModel


class AlbIdentitySettings(StrictModel):
    signer_arn: str
    issuer: str
    client_id: str
    groups_claim: str = "groups"


class McpIdentitySettings(StrictModel):
    issuer: str
    resource: str
    jwks_uri: str

    @field_validator("jwks_uri")
    @classmethod
    def jwks_uri_is_pinned_https(cls, value: str) -> str:
        if not value.startswith("https://") or value.endswith("/"):
            raise ValueError("jwks_uri must be a pinned HTTPS URL")
        path = value.split("://", 1)[1]
        if "/" not in path or path.endswith("/"):
            raise ValueError("jwks_uri must include a non-root path")
        return value


class MappingProfileRecord(StrictModel):
    profile_id: str
    fields: dict[str, str]
    alert_projection: tuple[str, ...]
    vulnerability_projection: tuple[str, ...]
    tie_break_field: str | None = None


class ContentPackLocation(StrictModel):
    uri: str
    pack_sha256: str

    @field_validator("uri")
    @classmethod
    def uri_scheme(cls, value: str) -> str:
        if not value.startswith(("s3://", "file://")):
            raise ValueError("content pack URI must use s3:// or file://")
        return value

    @field_validator("pack_sha256")
    @classmethod
    def pack_digest(cls, value: str) -> str:
        if len(value) != 64 or not all(ch in "0123456789abcdef" for ch in value):
            raise ValueError("pack_sha256 must be a lowercase SHA-256 hex digest")
        return value


class QualificationResourceMapPin(StrictModel):
    bucket: str
    key: str
    version_id: str
    sha256: str

    @field_validator("bucket", "key", "version_id")
    @classmethod
    def pin_component_nonempty(cls, value: str) -> str:
        if not value.strip() or value == "null" or any(char in value for char in "\r\n"):
            raise ValueError(
                "qualification resource map pin components must be non-empty and versioned"
            )
        return value

    @field_validator("sha256")
    @classmethod
    def map_digest(cls, value: str) -> str:
        if len(value) != 64 or not all(ch in "0123456789abcdef" for ch in value):
            raise ValueError("qualification resource map sha256 must be lowercase hexadecimal")
        return value


# Staging's established name aliases the shared sealed-document contract.
QualificationMapPin = QualificationResourceMapPin


class LiveSealedDocument(StrictModel):
    schema_version: Literal[1] = 1
    service: ServiceConfig
    alb: AlbIdentitySettings
    mcp: McpIdentitySettings
    browser_origin: str
    dynamodb_table: str
    standing_rules: str
    mapping_profiles: tuple[MappingProfileRecord, ...]
    content_pack: ContentPackLocation
    provenance: BuildProvenance
    feedback_queue_url: str
    audit_queue_url: str
    mcp_allowed_origins: tuple[str, ...] = ()
    ca_bundle_pem: str | None = None
    qualification: QualificationResourceMapPin | None = None

    @field_validator("browser_origin")
    @classmethod
    def browser_origin_is_https(cls, value: str) -> str:
        if not value.startswith("https://") or value.endswith("/"):
            raise ValueError("browser origin must be an exact HTTPS origin")
        return value

    @field_validator("standing_rules")
    @classmethod
    def standing_rules_nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("standing rules are required")
        return value

    @field_validator("dynamodb_table")
    @classmethod
    def table_name(cls, value: str) -> str:
        if not value or len(value) > 255:
            raise ValueError("dynamodb table name is required")
        return value

    @model_validator(mode="after")
    def live_only(self) -> LiveSealedDocument:
        if self.service.mode != "live":
            raise ValueError("sealed document requires live service mode")
        if not self.service.sites:
            raise ValueError("sealed document requires site registry entries")
        return self
