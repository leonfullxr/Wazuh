"""Deterministic, ordered alias resolution for captured Wazuh alerts."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import cast

from .models import EntityRef, MappingProfile, NormalizedAlert, NormalizeError

_MISSING = object()


def normalize_alert(raw: dict[str, object], profile: MappingProfile) -> NormalizedAlert:
    """Normalize a source document without changing or enriching the raw payload."""
    values = {name: _resolve(raw, paths) for name, paths in profile.fields.items()}
    timestamp = source_event_timestamp(raw, profile)
    invalid_fields: list[str] = []
    rule_level = _integer(values["rule_level"])
    if values["rule_level"] is not _MISSING and rule_level is None:
        invalid_fields.append("rule_level")
    normalized = {
        name: _scalar(value)
        for name, value in values.items()
        if name
        not in {"event_ts", "rule_level", "rule_groups", "mitre_tactics", "mitre_techniques"}
    }
    agent_ip = _ip(normalized["agent_ip"], "agent_ip", invalid_fields)
    src_ip = _ip(normalized["src_ip"], "src_ip", invalid_fields)
    dst_ip = _ip(normalized["dst_ip"], "dst_ip", invalid_fields)
    groups = _strings(values["rule_groups"])
    tactics = _strings(values["mitre_tactics"])
    techniques = _strings(values["mitre_techniques"])
    src_user = _domainless(normalized["src_user"])
    dst_user = _domainless(normalized["dst_user"])
    entity_values = {name: _resolve(raw, paths) for name, paths in profile.entity_fields.items()}
    entities = _entities(
        normalized,
        agent_ip=agent_ip,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_user=src_user,
        dst_user=dst_user,
        entity_values=entity_values,
    )
    gaps = tuple(
        dict.fromkeys(
            [name for name, value in values.items() if name != "event_ts" and _is_missing(value)]
            + invalid_fields
        )
    )
    return NormalizedAlert(
        event_ts=timestamp,
        wazuh_id=_optional_text(normalized["wazuh_id"]),
        rule_id=_optional_text(normalized["rule_id"]),
        rule_level=rule_level,
        rule_description=_optional_text(normalized["rule_description"]),
        rule_groups=groups,
        mitre_tactics=tactics,
        mitre_techniques=techniques,
        agent_id=_optional_text(normalized["agent_id"]),
        agent_name=_optional_text(normalized["agent_name"]),
        agent_ip=agent_ip,
        manager=_optional_text(normalized["manager"]),
        decoder=_optional_text(normalized["decoder"]),
        location=_optional_text(normalized["location"]),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_user=src_user,
        dst_user=dst_user,
        gaps=gaps,
        entities=entities,
    )


def source_event_timestamp(raw: dict[str, object], profile: MappingProfile) -> datetime:
    """Read only the source timestamp needed for immutable registry identity."""
    paths = profile.fields["event_ts"]
    selected = _resolve(raw, paths)
    timestamp = _timestamp(selected)
    for path in paths:
        candidate = _resolve(raw, (path,))
        if candidate is not _MISSING and _timestamp(candidate) != timestamp:
            raise NormalizeError("source event timestamp aliases disagree")
    return timestamp


def _resolve(raw: dict[str, object], paths: tuple[str, ...]) -> object:
    for path in paths:
        current: object = raw
        for segment in path.split("."):
            if isinstance(current, dict):
                mapping = cast(dict[object, object], current)
                if segment in mapping:
                    current = mapping[segment]
                else:
                    current = _MISSING
                    break
            else:
                current = _MISSING
                break
        if current is not _MISSING and current is not None:
            return current
    return _MISSING


def _is_missing(value: object) -> bool:
    return value is _MISSING or value is None or value == "" or value == []


def _scalar(value: object) -> object | None:
    if value is _MISSING or value is None:
        return None
    if isinstance(value, (dict, list)):
        return None
    return value


def _optional_text(value: object) -> str | None:
    if value is None or value is _MISSING or isinstance(value, bool):
        return None
    if not isinstance(value, (str, int, float)):
        return None
    text = str(value).strip()
    return text or None


def _timestamp(value: object) -> datetime:
    text = _optional_text(value)
    if text is None:
        raise NormalizeError("source event timestamp is missing")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise NormalizeError("source event timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise NormalizeError("source event timestamp must include a timezone")
    return parsed.astimezone(UTC)


def _integer(value: object) -> int | None:
    scalar = _scalar(value)
    if scalar is None:
        return None
    if isinstance(scalar, bool) or not isinstance(scalar, (str, int, float)):
        return None
    try:
        parsed = int(scalar)
    except (TypeError, ValueError):
        return None
    if isinstance(scalar, float) and not scalar.is_integer():
        return None
    if parsed < 0 or parsed > 32767:
        return None
    return parsed


def _strings(value: object) -> tuple[str, ...]:
    if value is _MISSING or value is None:
        return ()
    candidates: list[object] = cast(list[object], value) if isinstance(value, list) else [value]
    result: list[str] = []
    for candidate in candidates:
        if isinstance(candidate, dict):
            mapping = cast(dict[str, object], candidate)
            candidate = mapping.get("name") or mapping.get("id") or mapping.get("number")
        if not isinstance(candidate, (str, int)) or isinstance(candidate, bool):
            continue
        item = str(candidate).strip()
        if item and item not in result:
            result.append(item)
    return tuple(result)


def _ip(value: object, field: str, invalid_fields: list[str]) -> str | None:
    text = _optional_text(value)
    if text is None:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        invalid_fields.append(field)
        return None


def _domainless(value: object) -> str | None:
    text = _optional_text(value)
    if text is None:
        return None
    if "\\" in text:
        text = text.rsplit("\\", 1)[1]
    if "@" in text:
        text = text.split("@", 1)[0]
    text = text.strip()
    return text or None


def _entities(
    fields: dict[str, object],
    *,
    agent_ip: str | None,
    src_ip: str | None,
    dst_ip: str | None,
    src_user: str | None,
    dst_user: str | None,
    entity_values: dict[str, object],
) -> tuple[EntityRef, ...]:
    refs: list[EntityRef] = []
    _add(refs, "host", _optional_text(fields["agent_id"]), "agent")
    _add(refs, "host", _optional_text(fields["agent_name"]), "agent")
    _add_ip(refs, agent_ip, "agent")
    _add_ip(refs, src_ip, "src")
    _add_ip(refs, dst_ip, "dst")
    _add(refs, "user", src_user, "src")
    _add(refs, "user", dst_user, "dst")
    for key, kind, role in (
        ("process", "process", "subject"),
        ("file", "file", "target"),
        ("hash", "hash", "target"),
        ("cve", "cve", "subject"),
    ):
        for item in _strings(entity_values[key]):
            _add(refs, kind, item, role)
    _add(refs, "rule", _optional_text(fields["rule_id"]), "subject")
    return tuple(refs)


def _add(refs: list[EntityRef], kind: str, value: str | None, role: str) -> None:
    if value is None:
        return
    ref = EntityRef(kind, value, role)
    if ref not in refs:
        refs.append(ref)


def _add_ip(refs: list[EntityRef], value: str | None, role: str) -> None:
    if value is None:
        return
    classification = "private" if ipaddress.ip_address(value).is_private else "public"
    ref = EntityRef("ip", value, role, classification)
    if ref not in refs:
        refs.append(ref)
