"""Shared strict inputs for the state gate and packaged qualification task."""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StateProbeInputs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    table_name: str = Field(min_length=3, max_length=255)
    evidence_bucket: str = Field(min_length=3, max_length=63)
    evidence_prefix: str = "lv-state"
    expected_bucket_owner: str | None = None
    replica_kill_replacement: bool = Field(default=False, strict=True)

    @field_validator("table_name", "evidence_bucket")
    @classmethod
    def safe_name(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
            raise ValueError("state table and evidence bucket names must be simple identifiers")
        return value

    @field_validator("evidence_prefix")
    @classmethod
    def safe_prefix(cls, value: str) -> str:
        if not value or value.startswith("/") or ".." in value or "\\" in value:
            raise ValueError("evidence_prefix must be a safe relative S3 prefix")
        return value.rstrip("/")

    @field_validator("expected_bucket_owner")
    @classmethod
    def owner_id(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[0-9]{12}", value):
            raise ValueError("expected_bucket_owner must be a 12-digit account ID")
        return value
