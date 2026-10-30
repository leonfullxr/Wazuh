"""Typed mapping profile and normalized alert values."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import cast


class ProfileError(ValueError):
    """A mapping profile is invalid or does not cover the requested Wazuh release."""


class NormalizeError(ValueError):
    """A source alert cannot be normalized safely."""


@dataclass(frozen=True, slots=True)
class EntityRef:
    kind: str
    value: str
    role: str
    classification: str | None = None


@dataclass(frozen=True, slots=True)
class MappingProfile:
    profile_id: str
    wazuh_version: str
    time_field: str
    fields: Mapping[str, tuple[str, ...]]
    entity_fields: Mapping[str, tuple[str, ...]]


@dataclass(frozen=True, slots=True)
class NormalizedAlert:
    event_ts: datetime
    wazuh_id: str | None
    rule_id: str | None
    rule_level: int | None
    rule_description: str | None
    rule_groups: tuple[str, ...]
    mitre_tactics: tuple[str, ...]
    mitre_techniques: tuple[str, ...]
    agent_id: str | None
    agent_name: str | None
    agent_ip: str | None
    manager: str | None
    decoder: str | None
    location: str | None
    src_ip: str | None
    dst_ip: str | None
    src_user: str | None
    dst_user: str | None
    gaps: tuple[str, ...]
    entities: tuple[EntityRef, ...]


def _profile_path() -> Path:
    return Path(__file__).resolve().parents[4] / "content" / "workspace" / "profiles"


def load_profile(wazuh_version: str, *, profile_dir: Path | None = None) -> MappingProfile:
    """Load the exact version profile. No major/minor fallback is permitted."""
    if not wazuh_version or any(char not in "0123456789." for char in wazuh_version):
        raise ProfileError("unsupported Wazuh release")
    source = (profile_dir or _profile_path()) / f"wazuh-{wazuh_version}.yaml"
    try:
        import yaml

        loaded = cast(object, yaml.safe_load(source.read_text(encoding="utf-8")))
    except (OSError, UnicodeError) as exc:
        raise ProfileError("unsupported Wazuh release") from exc
    except Exception as exc:
        raise ProfileError("mapping profile is invalid") from exc
    if not isinstance(loaded, dict):
        raise ProfileError("mapping profile has an invalid shape")
    values = cast(dict[object, object], loaded)
    if set(values) != {
        "schema_version",
        "profile_id",
        "wazuh_version",
        "time_field",
        "fields",
        "entity_fields",
    }:
        raise ProfileError("mapping profile has an invalid shape")
    if values["schema_version"] != "1" or values["wazuh_version"] != wazuh_version:
        raise ProfileError("mapping profile release does not match the requested release")
    fields = _path_map(values["fields"])
    entity_fields = _path_map(values["entity_fields"])
    required = {
        "event_ts",
        "wazuh_id",
        "rule_id",
        "rule_level",
        "rule_description",
        "rule_groups",
        "mitre_tactics",
        "mitre_techniques",
        "agent_id",
        "agent_name",
        "agent_ip",
        "manager",
        "decoder",
        "location",
        "src_ip",
        "dst_ip",
        "src_user",
        "dst_user",
    }
    if set(fields) != required:
        raise ProfileError("mapping profile fields are incomplete")
    expected_entities = {"process", "file", "hash", "cve"}
    if set(entity_fields) != expected_entities:
        raise ProfileError("mapping profile entity fields are incomplete")
    profile_id = values["profile_id"]
    time_field = values["time_field"]
    if not isinstance(profile_id, str) or not profile_id:
        raise ProfileError("mapping profile id is invalid")
    if not isinstance(time_field, str) or not time_field:
        raise ProfileError("mapping profile time field is invalid")
    return MappingProfile(
        profile_id,
        wazuh_version,
        time_field,
        MappingProxyType(fields),
        MappingProxyType(entity_fields),
    )


def _path_map(value: object) -> dict[str, tuple[str, ...]]:
    if not isinstance(value, dict):
        raise ProfileError("mapping profile path map is invalid")
    entries = cast(dict[object, object], value)
    result: dict[str, tuple[str, ...]] = {}
    for key, paths in entries.items():
        if not isinstance(key, str) or not key or not isinstance(paths, list):
            raise ProfileError("mapping profile path map is invalid")
        path_values = cast(list[object], paths)
        if any(not isinstance(path, str) or not path for path in path_values):
            raise ProfileError("mapping profile path list is invalid")
        result[key] = tuple(cast(str, path) for path in path_values)
    return result
