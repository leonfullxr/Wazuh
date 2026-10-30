"""Server-owned site configuration for the read-only workspace pipeline."""

from __future__ import annotations

import json
import os
import ssl
import stat
from contextlib import ExitStack
from pathlib import Path
from typing import Literal

import httpx
import psycopg
from pydantic import BaseModel, ConfigDict, Field, SecretStr, StrictBool, model_validator

from ai_soc.workspace.backfill import BackfillSite
from ai_soc.workspace.context import ContextSources
from ai_soc.workspace.ingest.indexer_reader import IndexerReader
from ai_soc.workspace.normalize.models import load_profile


class PipelineSite(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    site_id: str = Field(min_length=1, max_length=128)
    label: str = Field(min_length=1, max_length=256)
    wazuh_version: str
    indexer_url: str
    ca_file: Path
    credential_file: Path
    index_pattern: str = "wazuh-alerts-*"
    expected_roles: tuple[str, ...]
    full_visibility_attestation: str = Field(min_length=1)
    context_sources: ContextSources = Field(default_factory=ContextSources)
    context_history: tuple[ContextSources, ...] = ()
    correlation_enabled: StrictBool = False

    @model_validator(mode="after")
    def correlation_version(self) -> PipelineSite:
        if self.correlation_enabled and self.wazuh_version != "4.14.7":
            raise ValueError("correlation runtime is qualified only for Wazuh 4.14.7")
        return self


class PipelineConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    database_env_file: Path
    sites: tuple[PipelineSite, ...] = Field(min_length=1)


class PipelineCredential(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    username: str = Field(min_length=1)
    password: SecretStr


class _Identity(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    backend_roles: list[str]
    roles: list[str]


def _private_json(path: Path) -> object:
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError("credential files must be accessible only to their owner")
    if path.stat().st_size > 65_536:
        raise ValueError("configuration file exceeds its byte bound")
    return json.loads(path.read_text())


def load_pipeline_config(path: Path) -> PipelineConfig:
    try:
        config = PipelineConfig.model_validate(_private_json(path))
    except Exception:
        raise ValueError("workspace pipeline configuration is missing or invalid") from None
    ids = [site.site_id for site in config.sites]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate workspace pipeline site")
    for site in config.sites:
        url = httpx.URL(site.indexer_url)
        if url.scheme != "https" or url.username or url.password or url.query or url.fragment:
            raise ValueError(
                "pipeline indexer URLs require HTTPS without credentials or query data"
            )
        if not site.expected_roles or not site.index_pattern:
            raise ValueError("pipeline roles and source pattern must be explicit")
        load_profile(site.wazuh_version)
    return config


def app_dsn(config: PipelineConfig) -> str:
    value = os.environ.get("WS_APP_DATABASE_URL")
    if value:
        return value
    if stat.S_IMODE(config.database_env_file.stat().st_mode) & 0o077:
        raise ValueError("database credentials file must be private")
    for line in config.database_env_file.read_text().splitlines():
        if line.startswith("WS_APP_DATABASE_URL="):
            return line.partition("=")[2]
    raise ValueError("restricted workspace database credentials are not configured")


class PipelineRuntime:
    def __init__(self, config: PipelineConfig) -> None:
        self.config = config
        self._stack = ExitStack()
        self._sites: dict[str, BackfillSite] = {}

    def __enter__(self) -> PipelineRuntime:
        return self

    def __exit__(self, *_: object) -> None:
        self._stack.close()

    def connect(self) -> psycopg.Connection:
        return psycopg.connect(app_dsn(self.config), autocommit=True)

    def resolve_site(self, site_id: str) -> BackfillSite:
        existing = self._sites.get(site_id)
        if existing is not None:
            return existing
        settings = next((site for site in self.config.sites if site.site_id == site_id), None)
        if settings is None:
            raise PermissionError("worker is not configured for the requested site")
        try:
            credential = PipelineCredential.model_validate(_private_json(settings.credential_file))
        except Exception:
            raise ValueError("pipeline credential reference is missing or invalid") from None
        context = ssl.create_default_context(cafile=str(settings.ca_file))
        client = self._stack.enter_context(
            httpx.Client(
                base_url=settings.indexer_url, verify=context, follow_redirects=False, timeout=30
            )
        )
        auth = httpx.BasicAuth(credential.username, credential.password.get_secret_value())
        response = client.get("/_plugins/_security/authinfo", auth=auth)
        if response.status_code != 200:
            raise PermissionError("pipeline identity qualification failed")
        if len(response.content) > 65_536:
            raise PermissionError("pipeline identity response exceeds its byte bound")
        try:
            identity = _Identity.model_validate_json(response.content)
        except ValueError:
            raise PermissionError("pipeline identity response is malformed") from None
        if identity.backend_roles or set(identity.roles) != set(settings.expected_roles):
            raise PermissionError("pipeline identity has unexpected inherited roles")
        site = BackfillSite(
            site_id=settings.site_id,
            authorized_sites=frozenset(item.site_id for item in self.config.sites),
            index_pattern=settings.index_pattern,
            profile=load_profile(settings.wazuh_version),
            reader=IndexerReader(client, auth=auth),
        )
        self._sites[site_id] = site
        return site
