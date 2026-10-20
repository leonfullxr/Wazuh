"""Explicit, strict deployment configuration with no environment or home reads."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator

from ai_soc.contracts.models import ConfigBounds, ModelCapability, SiteConfig, StrictModel


class ServiceConfig(StrictModel):
    mode: Literal["fixture", "live"]
    guardrail_identifier: str
    guardrail_version: str
    bounds: ConfigBounds = Field(default_factory=ConfigBounds)
    sites: tuple[SiteConfig, ...] = ()
    models: tuple[ModelCapability, ...] = ()
    fixture_signing_key: SecretStr | None = None
    fixture_indexer_url: str | None = None
    audit_queue_url: str | None = None
    ca_bundle_path: str | None = None
    ca_bundle_sha256: str | None = None

    @field_validator("guardrail_identifier")
    @classmethod
    def guardrail_is_not_placeholder(cls, value: str) -> str:
        if not value.strip() or value.strip().upper() == "DRAFT":
            raise ValueError("a configured guardrail identifier is required")
        return value

    @field_validator("guardrail_version")
    @classmethod
    def guardrail_version_is_numbered(cls, value: str) -> str:
        if not value.isascii() or not value.isdecimal() or value[0] == "0":
            raise ValueError("guardrail version must be a positive numeric version")
        return value

    @model_validator(mode="after")
    def validate_mode(self) -> ServiceConfig:
        if self.mode == "live":
            if self.fixture_signing_key is not None or self.fixture_indexer_url is not None:
                raise ValueError("fixture provider settings are forbidden in live mode")
            if not self.sites or not self.models:
                raise ValueError("live mode requires explicit site and model registries")
            if not self.ca_bundle_path or not self.ca_bundle_sha256:
                raise ValueError("live mode requires a version-pinned CA bundle and digest")
            if any(model.id.startswith("fixture-") for model in self.models):
                raise ValueError("fixture model capabilities are forbidden in live mode")
        return self
