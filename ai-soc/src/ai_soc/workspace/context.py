"""SHA-pinned offline context inputs for workspace enrichment."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from ai_soc.content.catalog import load_content_catalog
from ai_soc.contracts.models import BuildProvenance
from ai_soc.workspace.triage.enrich import (
    ContextAdapter,
    ContextObservation,
    KevSnapshotAdapter,
    OpenVulnerabilitySnapshot,
)

_MAX_CONTEXT_BYTES = 16 * 1024 * 1024
_CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}", re.ASCII)
_SEVERITIES = frozenset({"critical", "high", "medium", "low"})


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class SnapshotReference(_StrictModel):
    path: Path
    sha256: str

    @field_validator("path", mode="before")
    @classmethod
    def parse_path(cls, value: object) -> object:
        return Path(value) if isinstance(value, str) else value

    @field_validator("path")
    @classmethod
    def absolute_path(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("context snapshot paths must be absolute")
        return value

    @field_validator("sha256")
    @classmethod
    def valid_digest(cls, value: str) -> str:
        if re.fullmatch(r"[0-9a-f]{64}", value, re.ASCII) is None:
            raise ValueError("context snapshot sha256 must be lowercase hexadecimal")
        return value


class KevContextReference(_StrictModel):
    path: Path
    pack_sha256: str
    provenance: BuildProvenance
    source_id: str = Field(min_length=1, max_length=128)

    @field_validator("path", mode="before")
    @classmethod
    def parse_path(cls, value: object) -> object:
        return Path(value) if isinstance(value, str) else value

    @field_validator("path")
    @classmethod
    def absolute_path(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("KEV content pack paths must be absolute")
        return value

    @field_validator("pack_sha256")
    @classmethod
    def valid_digest(cls, value: str) -> str:
        if re.fullmatch(r"[0-9a-f]{64}", value, re.ASCII) is None:
            raise ValueError("KEV pack sha256 must be lowercase hexadecimal")
        return value

    @model_validator(mode="after")
    def provenance_matches_pack_pin(self) -> KevContextReference:
        if self.pack_sha256 != self.provenance.pack_sha256:
            raise ValueError("KEV pack sha256 must match its approved build provenance")
        return self


class ContextSources(_StrictModel):
    """Optional, independently configured offline sources for one site."""

    vulnerability: SnapshotReference | None = None
    geoip: SnapshotReference | None = None
    kev: KevContextReference | None = None


class VulnerabilitySourceProvenance(_StrictModel):
    kind: Literal["wazuh_read_only_export"]
    index_pattern: Literal["wazuh-states-vulnerabilities-*"]
    query_sha256: str
    export_sha256: str
    complete: bool

    @field_validator("query_sha256", "export_sha256")
    @classmethod
    def valid_digest(cls, value: str) -> str:
        if re.fullmatch(r"[0-9a-f]{64}", value, re.ASCII) is None:
            raise ValueError("source provenance digests must be lowercase hexadecimal")
        return value


class VulnerabilityFact(_StrictModel):
    cve: str = Field(min_length=13, max_length=32)
    severity: str = Field(min_length=1, max_length=32)

    @field_validator("cve")
    @classmethod
    def valid_cve(cls, value: str) -> str:
        if _CVE_PATTERN.fullmatch(value) is None:
            raise ValueError("vulnerability records require canonical CVE identifiers")
        return value


class VulnerabilityAgent(_StrictModel):
    agent_id: str = Field(min_length=1, max_length=128)
    complete: bool
    vulnerabilities: tuple[VulnerabilityFact, ...] = Field(max_length=20_000)

    @model_validator(mode="after")
    def unique_cves(self) -> VulnerabilityAgent:
        cves = [item.cve for item in self.vulnerabilities]
        if len(cves) != len(set(cves)):
            raise ValueError("vulnerability agent row contains duplicate CVEs")
        return self


class VulnerabilitySnapshot(_StrictModel):
    schema_version: Literal[1]
    site_id: str = Field(min_length=1, max_length=128)
    source_id: str = Field(min_length=1, max_length=128)
    source_version: str = Field(min_length=1, max_length=128)
    captured_at: AwareDatetime
    expires_at: AwareDatetime
    provenance: VulnerabilitySourceProvenance
    agents: tuple[VulnerabilityAgent, ...] = Field(max_length=20_000)

    @model_validator(mode="after")
    def unique_agents(self) -> VulnerabilitySnapshot:
        ids = [item.agent_id for item in self.agents]
        if len(ids) != len(set(ids)):
            raise ValueError("vulnerability snapshot contains duplicate agent rows")
        return self


class GeoIpSourceProvenance(_StrictModel):
    kind: Literal["offline_geoip_snapshot"]
    database_version: str = Field(min_length=1, max_length=128)
    complete: bool


class GeoIpEntry(_StrictModel):
    address: str = Field(min_length=1, max_length=64)
    score_value: float = Field(ge=0.0, le=1.0)
    country_code: str | None = Field(default=None, min_length=2, max_length=2)
    classification: str = Field(min_length=1, max_length=64)

    @field_validator("address")
    @classmethod
    def canonical_public_address(cls, value: str) -> str:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("GeoIP addresses must be valid IP literals") from exc
        if not address.is_global or str(address) != value:
            raise ValueError("GeoIP entries must use canonical public IP addresses")
        return value


class GeoIpSnapshot(_StrictModel):
    schema_version: Literal[1]
    site_id: str = Field(min_length=1, max_length=128)
    source_id: str = Field(min_length=1, max_length=128)
    source_version: str = Field(min_length=1, max_length=128)
    captured_at: AwareDatetime
    expires_at: AwareDatetime
    provenance: GeoIpSourceProvenance
    addresses: tuple[GeoIpEntry, ...] = Field(max_length=250_000)

    @model_validator(mode="after")
    def unique_addresses(self) -> GeoIpSnapshot:
        values = [item.address for item in self.addresses]
        if len(values) != len(set(values)):
            raise ValueError("GeoIP snapshot contains duplicate addresses")
        return self


class _VulnerabilityContextAdapter:
    def __init__(self, snapshot: VulnerabilitySnapshot, sha256: str) -> None:
        self._snapshot = snapshot
        self._sha256 = sha256
        self._agents = {(snapshot.site_id, row.agent_id): row for row in snapshot.agents}

    def fetch(
        self,
        *,
        site_id: str,
        group_id: str,
        group_revision: str,
        member_snapshots: tuple[dict[str, Any], ...],
        as_of: datetime,
    ) -> ContextObservation:
        del group_id, group_revision
        agent_ids = _agent_ids(member_snapshots)
        rows = [self._agents.get((site_id, agent_id)) for agent_id in agent_ids]
        metadata = _source_metadata(self._snapshot, self._sha256)
        if self._snapshot.site_id != site_id or not agent_ids or any(row is None for row in rows):
            return _unavailable_with_metadata(
                "vuln",
                "complete vulnerability state is unavailable for a group agent",
                as_of,
                metadata,
            )
        if not self._snapshot.provenance.complete:
            return _unavailable_with_metadata(
                "vuln", "vulnerability export coverage is incomplete", as_of, metadata
            )
        known_rows = cast(list[VulnerabilityAgent], rows)
        if any(not row.complete for row in known_rows):
            return _unavailable_with_metadata(
                "vuln", "vulnerability export is incomplete for a group agent", as_of, metadata
            )
        if any(
            fact.severity.casefold() not in _SEVERITIES
            for row in known_rows
            for fact in row.vulnerabilities
        ):
            return _unavailable_with_metadata(
                "vuln", "vulnerability export contains an unknown severity", as_of, metadata
            )
        state = _freshness(self._snapshot.captured_at, self._snapshot.expires_at, as_of)
        if state is not None:
            return ContextObservation(
                source_version=_source_version(self._snapshot, self._sha256),
                availability="unavailable",
                value={"reason": state, **metadata},
                fetched_at=self._snapshot.captured_at,
                expires_at=self._snapshot.expires_at,
            )
        facts = [fact for row in known_rows for fact in row.vulnerabilities]
        cves = sorted({fact.cve for fact in facts})
        high_cves = sorted(
            {fact.cve for fact in facts if fact.severity.casefold() in {"high", "critical"}}
        )
        return ContextObservation(
            source_version=_source_version(self._snapshot, self._sha256),
            availability="available",
            value={
                "score_value": float(bool(high_cves)),
                "open_cve_count": len(cves),
                "high_severity_cves": high_cves,
                **metadata,
            },
            fetched_at=self._snapshot.captured_at,
            expires_at=self._snapshot.expires_at,
        )


class _GeoIpContextAdapter:
    def __init__(self, snapshot: GeoIpSnapshot, sha256: str) -> None:
        self._snapshot = snapshot
        self._sha256 = sha256
        self._addresses = {item.address: item for item in snapshot.addresses}

    def fetch(
        self,
        *,
        site_id: str,
        group_id: str,
        group_revision: str,
        member_snapshots: tuple[dict[str, Any], ...],
        as_of: datetime,
    ) -> ContextObservation:
        del group_id, group_revision
        public_addresses = _public_member_addresses(member_snapshots)
        metadata = _source_metadata(self._snapshot, self._sha256)
        if self._snapshot.site_id != site_id:
            return _unavailable_with_metadata(
                "geoip", "GeoIP snapshot belongs to another site", as_of, metadata
            )
        if not self._snapshot.provenance.complete:
            return _unavailable_with_metadata(
                "geoip", "GeoIP snapshot coverage is incomplete", as_of, metadata
            )
        if not public_addresses or any(
            address not in self._addresses for address in public_addresses
        ):
            return _unavailable_with_metadata(
                "geoip", "complete public address context is unavailable", as_of, metadata
            )
        state = _freshness(self._snapshot.captured_at, self._snapshot.expires_at, as_of)
        if state is not None:
            return ContextObservation(
                source_version=_source_version(self._snapshot, self._sha256),
                availability="stale",
                value={"reason": state, **metadata},
                fetched_at=self._snapshot.captured_at,
                expires_at=self._snapshot.expires_at,
            )
        records = [self._addresses[address] for address in public_addresses]
        return ContextObservation(
            source_version=_source_version(self._snapshot, self._sha256),
            availability="available",
            value={
                "score_value": max(row.score_value for row in records),
                "addresses": [
                    {
                        "address": row.address,
                        "country_code": row.country_code,
                        "classification": row.classification,
                        "score_value": row.score_value,
                    }
                    for row in records
                ],
                **metadata,
            },
            fetched_at=self._snapshot.captured_at,
            expires_at=self._snapshot.expires_at,
        )


def load_site_context(
    site_id: str, sources: ContextSources
) -> tuple[dict[str, ContextAdapter], str]:
    """Load and verify all configured inputs before a worker claims any job."""
    adapters: dict[str, ContextAdapter] = {}
    identities: dict[str, object] = {"schema_version": 1, "site_id": site_id}
    vulnerability: VulnerabilitySnapshot | None = None
    vulnerability_sha: str | None = None
    if sources.vulnerability is not None:
        vulnerability, vulnerability_sha = _load_snapshot(
            sources.vulnerability, VulnerabilitySnapshot
        )
        if vulnerability.site_id != site_id:
            raise ValueError("vulnerability snapshot site_id does not match its site config")
        adapters["vuln"] = _VulnerabilityContextAdapter(vulnerability, vulnerability_sha)
        identities["vulnerability"] = vulnerability_sha
    else:
        identities["vulnerability"] = None

    if sources.geoip is not None:
        snapshot, sha256 = _load_snapshot(sources.geoip, GeoIpSnapshot)
        if snapshot.site_id != site_id:
            raise ValueError("GeoIP snapshot site_id does not match its site config")
        adapters["geoip"] = _GeoIpContextAdapter(snapshot, sha256)
        identities["geoip"] = sha256
    else:
        identities["geoip"] = None

    if sources.kev is not None:
        reference = sources.kev
        if not reference.path.is_dir():
            raise ValueError("approved KEV content pack path is not a directory")
        if reference.pack_sha256 != reference.provenance.pack_sha256:
            raise ValueError("KEV pack sha256 must match its approved build provenance")
        catalog = load_content_catalog(reference.path, provenance=reference.provenance)
        kev_index = catalog.kev_index
        open_vulnerabilities: Mapping[tuple[str, str], OpenVulnerabilitySnapshot] = {}
        if vulnerability is not None:
            assert vulnerability_sha is not None
            open_vulnerabilities = {
                (site_id, row.agent_id): OpenVulnerabilitySnapshot(
                    site_id=site_id,
                    agent_id=row.agent_id,
                    cves=tuple(item.cve for item in row.vulnerabilities),
                    source_version=vulnerability.source_version,
                    fetched_at=vulnerability.captured_at,
                    expires_at=vulnerability.expires_at,
                    availability=(
                        "available"
                        if vulnerability.provenance.complete and row.complete
                        else "unavailable"
                    ),
                    source_id=vulnerability.source_id,
                    source_sha256=vulnerability_sha,
                )
                for row in vulnerability.agents
            }
        adapters["kev"] = KevSnapshotAdapter(
            kev_index,
            open_vulnerabilities,
            source_id=reference.source_id,
            source_sha256=reference.pack_sha256,
            open_vulnerability_source_id=(
                None if vulnerability is None else vulnerability.source_id
            ),
            open_vulnerability_source_sha256=vulnerability_sha,
        )
        identities["kev"] = {
            "pack_sha256": reference.pack_sha256,
            "content_sha": reference.provenance.content_sha,
            "source_id": reference.source_id,
        }
    else:
        identities["kev"] = None
    canonical = json.dumps(identities, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return adapters, hashlib.sha256(canonical).hexdigest()


def _load_snapshot[ModelT: BaseModel](
    reference: SnapshotReference, model: type[ModelT]
) -> tuple[ModelT, str]:
    try:
        if not reference.path.is_file():
            raise ValueError("context snapshot path is not a regular file")
        with reference.path.open("rb") as stream:
            raw = stream.read(_MAX_CONTEXT_BYTES + 1)
    except OSError as exc:
        raise ValueError("context snapshot cannot be read") from exc
    if len(raw) > _MAX_CONTEXT_BYTES:
        raise ValueError("context snapshot exceeds its byte bound")
    sha256 = hashlib.sha256(raw).hexdigest()
    if sha256 != reference.sha256:
        raise ValueError("context snapshot digest differs from its configured pin")
    try:
        return model.model_validate_json(raw), sha256
    except Exception as exc:
        raise ValueError("context snapshot schema is invalid") from exc


def _agent_ids(members: tuple[dict[str, Any], ...]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                value
                for member in members
                if isinstance((value := member.get("agent_id")), str) and value
            }
        )
    )


def _public_member_addresses(members: tuple[dict[str, Any], ...]) -> tuple[str, ...]:
    result: set[str] = set()
    for member in members:
        for key in ("src_ip", "dst_ip"):
            value = member.get(key)
            if not isinstance(value, str):
                continue
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if address.is_global:
                result.add(str(address))
    return tuple(sorted(result))


def _freshness(captured_at: datetime, expires_at: datetime, as_of: datetime) -> str | None:
    if captured_at > as_of:
        return "context snapshot was captured after the frozen cutoff"
    if expires_at <= as_of:
        return "context snapshot expired by the frozen cutoff"
    return None


def _source_version(snapshot: VulnerabilitySnapshot | GeoIpSnapshot, sha256: str) -> str:
    return f"{snapshot.source_id}:{snapshot.source_version}:sha256:{sha256}"


def _source_metadata(
    snapshot: VulnerabilitySnapshot | GeoIpSnapshot, sha256: str
) -> dict[str, object]:
    return {
        "source_id": snapshot.source_id,
        "source_version": snapshot.source_version,
        "source_sha256": sha256,
        "source_captured_at": snapshot.captured_at.isoformat(),
        "source_expires_at": snapshot.expires_at.isoformat(),
        "source_provenance": snapshot.provenance.model_dump(mode="json"),
    }


def _unavailable_with_metadata(
    source: str, reason: str, as_of: datetime, metadata: dict[str, object]
) -> ContextObservation:
    del as_of
    digest = str(metadata["source_sha256"])
    fetched_at = datetime.fromisoformat(str(metadata["source_captured_at"]))
    expires_at_value = metadata["source_expires_at"]
    expires_at = None if expires_at_value is None else datetime.fromisoformat(str(expires_at_value))
    return ContextObservation(
        source_version=f"{metadata['source_id']}:{metadata['source_version']}:sha256:{digest}",
        availability="unavailable",
        value={"reason": reason, "context_source": source, **metadata},
        fetched_at=fetched_at,
        expires_at=expires_at,
    )
