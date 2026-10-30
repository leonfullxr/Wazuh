"""Offline CISA KEV import, verification, and immutable public lookup."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from types import MappingProxyType
from typing import BinaryIO, Literal, cast

from ai_soc.contracts.canonical import canonical_bytes, sha256_hex
from ai_soc.contracts.models import (
    KevCatalog,
    KevEntry,
    KevMetadata,
    KevNotice,
    KevPolicy,
    KevSnapshot,
)

_MAX_INPUT = 32 * 1024 * 1024
_CHUNK = 64 * 1024
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}", re.ASCII)
_INTEGER_TOKEN = re.compile(r"-?(?:0|[1-9][0-9]*)")


class KevLookupError(RuntimeError):
    """A lookup could not read the immutable index."""


class KevImportError(ValueError):
    """A bounded KEV source is invalid or incomplete."""


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise KevImportError("duplicate JSON object key")
        result[key] = value
    return result


def _integer(value: str) -> int:
    if len(value.lstrip("-")) > 10:
        raise KevImportError("integer exceeds ten digits")
    return int(value)


def _reject_float(_: str) -> object:
    raise KevImportError("non-integer numbers are forbidden")


def _reject_constant(_: str) -> object:
    raise KevImportError("non-finite numbers are forbidden")


def _preflight_json(text: str) -> None:
    """Check structural and token budgets without constructing a JSON object tree."""
    index = 0
    length = len(text)

    def whitespace() -> None:
        nonlocal index
        while index < length and text[index] in " \t\r\n":
            index += 1

    def string(*, key: bool = False) -> str:
        nonlocal index
        start = index
        if index >= length or text[index] != '"':
            raise KevImportError("invalid JSON string token")
        index += 1
        escaped = False
        raw_bytes = 1
        raw_limit = 386 if key else 98306
        while index < length:
            char = text[index]
            index += 1
            raw_bytes += len(char.encode("utf-8"))
            if raw_bytes > raw_limit:
                raise KevImportError("JSON string token exceeds preflight bound")
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                try:
                    decoded = cast(str, json.loads(text[start:index]))
                except (ValueError, json.JSONDecodeError) as exc:
                    raise KevImportError("invalid JSON string token") from exc
                try:
                    decoded_bytes = len(decoded.encode("utf-8"))
                except UnicodeEncodeError as exc:
                    raise KevImportError("JSON string is not valid Unicode") from exc
                if decoded_bytes > (64 if key else 16384):
                    raise KevImportError("JSON key or string exceeds its byte limit")
                return decoded
            elif ord(char) < 0x20:
                raise KevImportError("control character in JSON string")
        raise KevImportError("truncated JSON string")

    def value(depth: int, path: str) -> None:
        nonlocal index
        whitespace()
        if depth > 8 or index >= length:
            raise KevImportError("JSON nesting or token structure is invalid")
        char = text[index]
        if char == '"':
            string()
            return
        if char == "{":
            start = index
            index += 1
            whitespace()
            members = 0
            keys: set[str] = set()
            if index < length and text[index] == "}":
                index += 1
                return
            while True:
                whitespace()
                key = string(key=True)
                if key in keys:
                    raise KevImportError("duplicate JSON object key")
                keys.add(key)
                members += 1
                if members > 32:
                    raise KevImportError("JSON object exceeds 32 members")
                whitespace()
                if index >= length or text[index] != ":":
                    raise KevImportError("invalid JSON object separator")
                index += 1
                value(depth + 1, f"{path}.{key}")
                if path.startswith("$.vulnerabilities[") and _entry_size_exceeds(
                    text, start, index
                ):
                    raise KevImportError("vulnerability entry exceeds 65536 bytes")
                whitespace()
                if path.startswith("$.vulnerabilities[") and _entry_size_exceeds(
                    text, start, index + 1
                ):
                    raise KevImportError("vulnerability entry exceeds 65536 bytes")
                if index < length and text[index] == "}":
                    index += 1
                    if path.startswith("$.vulnerabilities[") and _entry_size_exceeds(
                        text, start, index
                    ):
                        raise KevImportError("vulnerability entry exceeds 65536 bytes")
                    return
                if index >= length or text[index] != ",":
                    raise KevImportError("invalid JSON object delimiter")
                index += 1
        if char == "[":
            index += 1
            whitespace()
            count = 0
            limit = 4096 if path == "$.vulnerabilities" else 64
            if index < length and text[index] == "]":
                index += 1
                return
            while True:
                count += 1
                if count > limit:
                    raise KevImportError("JSON array exceeds its member limit")
                item_start = index
                value(depth + 1, f"{path}[{count - 1}]")
                whitespace()
                if path == "$.vulnerabilities" and _entry_size_exceeds(text, item_start, index + 1):
                    raise KevImportError("vulnerability entry exceeds 65536 bytes")
                if index < length and text[index] == "]":
                    index += 1
                    return
                if index >= length or text[index] != ",":
                    raise KevImportError("invalid JSON array delimiter")
                index += 1
        if text.startswith(("true", "false", "null"), index):
            token = next(item for item in ("true", "false", "null") if text.startswith(item, index))
            index += len(token)
            return
        number = _INTEGER_TOKEN.match(text, index)
        if number is not None:
            start, end = number.span()
            digit_start = start + (text[start] == "-")
            if end - digit_start > 10:
                raise KevImportError("integer exceeds ten digits")
            index = end
            if index < length and text[index] in ".eE":
                raise KevImportError("non-integer numbers are forbidden")
            return
        raise KevImportError("invalid JSON value")

    value(0, "$")
    whitespace()
    if index != length:
        raise KevImportError("trailing JSON data")


def _entry_size_exceeds(text: str, start: int, end: int) -> bool:
    byte_count = 0
    for position in range(start, end):
        byte_count += len(text[position].encode("utf-8"))
        if byte_count > 65536:
            return True
    return False


def _bounded_read(stream: BinaryIO) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = stream.read(_CHUNK)
        if not chunk:
            break
        if len(chunk) > _CHUNK:
            raise KevImportError("input stream exceeded the 64 KiB read size")
        total += len(chunk)
        if total > _MAX_INPUT:
            raise KevImportError("KEV input exceeds 32 MiB")
        chunks.append(chunk)
    raw = b"".join(chunks)
    if raw.startswith((b"\x1f\x8b", b"PK\x03\x04", b"BZh", b"\xfd7zXZ")):
        raise KevImportError("compressed KEV inputs are not accepted")
    return raw


def _check_shape(value: object, *, depth: int = 0, path: str = "$") -> None:
    if depth > 8:
        raise KevImportError("JSON nesting exceeds eight levels")
    if isinstance(value, dict):
        mapping = cast(dict[object, object], value)
        if len(mapping) > 32:
            raise KevImportError("JSON object exceeds 32 members")
        for key, child in mapping.items():
            if not isinstance(key, str):
                raise KevImportError("JSON object keys must be strings")
            if len(key.encode("utf-8")) > 64:
                raise KevImportError("JSON key exceeds 64 UTF-8 bytes")
            _check_shape(child, depth=depth + 1, path=f"{path}.{key}")
    elif isinstance(value, list):
        items = cast(list[object], value)
        limit = 4096 if path == "$.vulnerabilities" else 64
        if len(items) > limit:
            raise KevImportError("JSON array exceeds its member limit")
        for index, child in enumerate(items):
            _check_shape(child, depth=depth + 1, path=f"{path}[{index}]")
    elif isinstance(value, str) and len(value.encode("utf-8")) > 16384:
        raise KevImportError("JSON string exceeds 16384 UTF-8 bytes")


def _parse_datetime(value: object) -> datetime:
    if not isinstance(value, str):
        raise KevImportError("dateReleased must be a timezone-aware timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise KevImportError("dateReleased is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise KevImportError("dateReleased must include a timezone")
    return parsed.astimezone(UTC)


def _parse_date(value: object, field: str) -> date:
    if not isinstance(value, str):
        raise KevImportError(f"{field} must be a calendar date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise KevImportError(f"{field} is invalid") from exc
    if parsed.isoformat() != value:
        raise KevImportError(f"{field} must use YYYY-MM-DD")
    return parsed


def _validate_catalog(root: object) -> tuple[str, datetime, list[KevEntry]]:
    if not isinstance(root, dict):
        raise KevImportError("catalog root must be an object")
    data = cast(dict[str, object], root)
    if "next" in data or "links" in data or "pagination" in data:
        raise KevImportError("pagination wrappers are not complete catalogs")
    required = {"catalogVersion", "dateReleased", "count", "vulnerabilities"}
    if not required.issubset(data):
        raise KevImportError("catalog metadata is incomplete")
    version = data["catalogVersion"]
    count = data["count"]
    vulnerabilities_value = data["vulnerabilities"]
    published = _parse_datetime(data["dateReleased"])
    if not isinstance(version, str) or not version or len(version.encode("utf-8")) > 128:
        raise KevImportError("catalogVersion must be a nonempty string of at most 128 bytes")
    if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
        raise KevImportError("count must be a positive integer")
    if not isinstance(vulnerabilities_value, list) or not vulnerabilities_value:
        raise KevImportError("vulnerabilities must be a nonempty array")
    vulnerabilities = cast(list[object], vulnerabilities_value)
    if len(vulnerabilities) > 4096:
        raise KevImportError("catalog exceeds 4096 entries")
    if count != len(vulnerabilities):
        raise KevImportError("declared record count does not match the complete array")
    entries: list[KevEntry] = []
    seen: set[str] = set()
    publication_day = published.date()
    for entry_obj in vulnerabilities:
        if not isinstance(entry_obj, dict):
            raise KevImportError("vulnerability entries must be objects")
        entry = cast(dict[str, object], entry_obj)
        encoded_entry = canonical_bytes(entry)
        if len(encoded_entry) > 65536:
            raise KevImportError("vulnerability entry exceeds 65536 bytes")
        cve = entry.get("cveID")
        if not isinstance(cve, str) or len(cve.encode("ascii", errors="ignore")) != len(cve):
            raise KevImportError("cveID must be an ASCII CVE identifier")
        if len(cve) > 32 or _CVE.fullmatch(cve) is None:
            raise KevImportError("cveID is malformed")
        if cve in seen:
            raise KevImportError("duplicate CVE identifier")
        seen.add(cve)
        if "dateAdded" not in entry:
            raise KevImportError("dateAdded is required")
        added = _parse_date(entry["dateAdded"], "dateAdded")
        if added > publication_day:
            raise KevImportError("dateAdded is after catalog publication")
        if "dueDate" in entry:
            _parse_date(entry["dueDate"], "dueDate")
        entries.append(KevEntry(cve=cve, added_on=added))
    return version, published, sorted(entries, key=lambda item: item.cve)


def import_kev_catalog(
    stream: BinaryIO,
    *,
    retrieved_at: datetime,
    policy: KevPolicy,
    notice: KevNotice,
    clock: datetime,
) -> tuple[KevCatalog, bytes]:
    """Normalize a local complete CISA JSON file; no URL is ever dereferenced."""
    if retrieved_at.tzinfo is None or retrieved_at.utcoffset() is None:
        raise KevImportError("retrieval time must be timezone-aware")
    if clock.tzinfo is None or clock.utcoffset() is None:
        raise KevImportError("import clock must be timezone-aware")
    raw = _bounded_read(stream)
    raw_digest = hashlib.sha256(raw).hexdigest()
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise KevImportError("input must be UTF-8") from exc
    _preflight_json(text)
    try:
        root = json.loads(
            text,
            object_pairs_hook=_object,
            parse_int=_integer,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise KevImportError("input is malformed, truncated, or has trailing data") from exc
    _check_shape(root)
    version, published, entries = _validate_catalog(root)
    retrieved = retrieved_at.astimezone(UTC)
    now = clock.astimezone(UTC)
    if retrieved < published:
        raise KevImportError("retrieval precedes publication")
    if retrieved > now:
        raise KevImportError("retrieval is after importer clock")
    normalized = {
        "normalizer_version": "cisa-kev/1",
        "entries": [e.model_dump(mode="json") for e in entries],
    }
    normalized_digest = hashlib.sha256(canonical_bytes(normalized)).hexdigest()
    metadata = KevMetadata(
        catalog_version=version,
        record_count=len(entries),
        published_at=published,
        retrieved_at=retrieved,
        raw_sha256=raw_digest,
        normalized_sha256=normalized_digest,
        policy=policy,
        notice=notice,
    )
    return KevCatalog(metadata=metadata, entries=tuple(entries)), raw


def serialized_catalog(catalog: KevCatalog) -> bytes:
    """Return the reproducible canonical source record written by the CLI."""
    return canonical_bytes(catalog)


def normalized_digest(entries: tuple[KevEntry, ...] | list[KevEntry]) -> str:
    return hashlib.sha256(
        canonical_bytes(
            {
                "normalizer_version": "cisa-kev/1",
                "entries": [entry.model_dump(mode="json") for entry in entries],
            }
        )
    ).hexdigest()


def verify_snapshot(snapshot: KevSnapshot) -> None:
    if snapshot.metadata.normalized_sha256 != normalized_digest(snapshot.entries):
        raise ValueError("KEV normalized digest mismatch")
    if snapshot.metadata.record_count != len(snapshot.entries):
        raise ValueError("KEV record count mismatch")


@dataclass(frozen=True, slots=True)
class KevLookupIndex:
    """Read-only CVE/date index containing only approved public KEV data."""

    snapshot: KevSnapshot
    _entries: Mapping[str, date]

    @classmethod
    def create(cls, snapshot: KevSnapshot) -> KevLookupIndex:
        verify_snapshot(snapshot)
        return cls(
            snapshot, MappingProxyType({entry.cve: entry.added_on for entry in snapshot.entries})
        )

    def lookup(
        self, value: object
    ) -> tuple[Literal["hit", "not_listed", "invalid_cve"], date | None]:
        if not isinstance(value, str) or len(value) > 32 or _CVE.fullmatch(value) is None:
            return "invalid_cve", None
        added_on = self._entries.get(value)
        return ("not_listed", None) if added_on is None else ("hit", added_on)


def lookup_kev(
    index: KevLookupIndex | None,
    value: object,
) -> tuple[Literal["hit", "not_listed", "invalid_cve", "unavailable"], date | None]:
    if index is None:
        return "unavailable", None
    return index.lookup(value)


def freshness(snapshot: KevSnapshot, evaluation_at: datetime) -> tuple[str, datetime, datetime]:
    if evaluation_at.tzinfo is None or evaluation_at.utcoffset() is None:
        raise ValueError("evaluation time must be timezone-aware")
    metadata = snapshot.metadata
    valid_from = max(metadata.published_at, metadata.retrieved_at, snapshot.approved_at)
    expires_at = metadata.published_at + timedelta(seconds=metadata.policy.max_age_seconds)
    evaluated = evaluation_at.astimezone(UTC)
    if evaluated < valid_from:
        return "not_yet_valid", valid_from, expires_at
    if evaluated >= expires_at:
        return "stale", valid_from, expires_at
    return "fresh", valid_from, expires_at


def policy_identity(policy: KevPolicy) -> str:
    return sha256_hex(policy)
