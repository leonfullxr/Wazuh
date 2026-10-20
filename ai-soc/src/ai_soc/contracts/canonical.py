"""Canonical evidence and policy hashing shared by every evidence producer."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import Enum
from typing import cast

from pydantic import BaseModel

from .models import SiteConfig

type CanonicalValue = (
    None | bool | int | float | str | list["CanonicalValue"] | dict[str, "CanonicalValue"]
)


def _normal(value: object) -> CanonicalValue:
    if isinstance(value, BaseModel):
        dumped = cast(dict[str, object], value.model_dump(mode="json", exclude_none=False))
        return _normal(dumped)
    if isinstance(value, Enum):
        return value.value  # type: ignore[return-value]
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("canonical timestamps require a timezone")
        return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if value is None or isinstance(value, (bool, int, float, str)):
        if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
            raise ValueError("non-finite values are forbidden")
        return value
    if isinstance(value, (list, tuple)):
        sequence = cast(list[object] | tuple[object, ...], value)
        return [_normal(item) for item in sequence]
    if isinstance(value, dict):
        mapping = cast(dict[object, object], value)
        if any(not isinstance(key, str) for key in mapping):
            raise TypeError("canonical object keys must be strings")
        return {key: _normal(mapping[key]) for key in sorted(str(key) for key in mapping)}
    raise TypeError(f"unsupported canonical value type: {type(value).__name__}")


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        _normal(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def sha256_hex(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def evidence_id(
    *,
    question_id: str,
    environment_id: str,
    topic_id: str,
    fetch_id: str | None,
    check_id: str | None,
    kind: str,
    source: object,
    snapshot_key: str,
    values: object,
) -> str:
    if (fetch_id is None) == (check_id is None):
        raise ValueError("exactly one of fetch_id or check_id is required")
    payload = {
        "v": 1,
        "question_id": question_id,
        "environment_id": environment_id,
        "topic_id": topic_id,
        "fetch_id": fetch_id,
        "check_id": check_id,
        "kind": kind,
        "source": source,
        "snapshot_key": snapshot_key,
        "values": values,
    }
    return "ev1_" + sha256_hex(payload)


def config_hash(configuration: object) -> str:
    return sha256_hex(configuration)


def site_config_hash(site: SiteConfig) -> str:
    return sha256_hex(
        {
            "environment_id": site.environment_id,
            "group_role_map": {
                group: tuple(sorted(set(roles))) for group, roles in site.group_role_map.items()
            },
            "role_visibility": site.role_visibility,
            "composite_role_visibility": site.composite_role_visibility,
            "allowed_templates": tuple(
                sorted(template.value for template in site.allowed_templates)
            ),
            "allowed_index_patterns": {
                family.value: tuple(sorted(set(patterns)))
                for family, patterns in site.allowed_index_patterns.items()
            },
            "ca_secret_version": site.ca_secret_version,
            "ca_sha256": site.ca_sha256,
            "jwt_issuer": site.jwt_issuer,
            "jwt_audience": site.jwt_audience,
            "mapping_profile": site.mapping_profile,
            "policy_version": site.policy_version,
            "dls_attestation_version": site.dls_attestation_version,
            "expectations": tuple(
                sorted(site.expectations, key=lambda expectation: expectation.expectation_id)
            ),
        }
    )


def policy_hash(
    config_digest: str, roles: tuple[str, ...], visibility: str, dls_version: str
) -> str:
    return sha256_hex(
        {
            "config_hash": config_digest,
            "backend_roles": sorted(set(roles)),
            "visibility": visibility,
            "effective_permission_scope": dls_version,
        }
    )


def owner_key(issuer: str, subject: str) -> str:
    if not issuer or not subject or "\0" in issuer or "\0" in subject:
        raise ValueError("verified issuer and subject must be nonempty opaque strings")
    return hashlib.sha256(f"{issuer}\0{subject}".encode()).hexdigest()
