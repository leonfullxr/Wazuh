"""Reviewed Markdown knowledge records packed for deterministic workspace retrieval."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from datetime import date, datetime
from pathlib import PurePosixPath
from typing import Literal, cast

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ai_soc.contracts.canonical import canonical_bytes

MAX_KNOWLEDGE_CHUNK_BYTES = 4096
MAX_KNOWLEDGE_RULE_IDS = 32
MAX_KNOWLEDGE_CHUNKS = 128
_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$", re.ASCII)
_RULE_ID = re.compile(r"^[0-9]{1,16}$", re.ASCII)
_ATTACK = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$", re.ASCII)
_CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.ASCII)
_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_HIDDEN_MARKUP = re.compile(
    r"<\s*(?:script|style|template|iframe|object|embed|meta|link)\b|"
    r"\b(?:hidden|display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)\b",
    re.IGNORECASE,
)
_COMMAND_OR_URL = re.compile(
    r"(?m)^\s*(?:[$>]\s*)?(?:curl|wget|ssh|bash|sh|powershell|systemctl|kubectl)\s+\S|"
    r"https?://"
)


class KnowledgeBuildError(ValueError):
    """A knowledge source is unsafe or does not satisfy the reviewed contract."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class KnowledgeApplicability(_StrictModel):
    rule_ids: tuple[str, ...] = Field(default=(), max_length=MAX_KNOWLEDGE_RULE_IDS)
    rule_groups: tuple[str, ...] = Field(default=(), max_length=32)
    attack_techniques: tuple[str, ...] = Field(default=(), max_length=32)
    cves: tuple[str, ...] = Field(default=(), max_length=32)

    @model_validator(mode="after")
    def validate_keys(self) -> KnowledgeApplicability:
        groups = (
            ("rule id", self.rule_ids, _RULE_ID),
            ("rule group", self.rule_groups, _ID),
            ("ATT&CK technique", self.attack_techniques, _ATTACK),
            ("CVE", self.cves, _CVE),
        )
        for label, values, pattern in groups:
            if len(values) != len(set(values)) or tuple(sorted(values)) != values:
                raise ValueError(f"{label} keys must be unique and sorted")
            if any(pattern.fullmatch(value) is None for value in values):
                raise ValueError(f"invalid {label} key")
        return self


class KnowledgeFrontMatter(_StrictModel):
    id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=256)
    kind: Literal["runbook", "reference", "rule_note", "rule note", "policy"]
    language: Literal["en", "es", "English", "Spanish"]
    applies_to: KnowledgeApplicability | None = None
    rule_ids: tuple[str, ...] = Field(default=(), max_length=MAX_KNOWLEDGE_RULE_IDS)
    rule_groups: tuple[str, ...] = Field(default=(), max_length=32)
    attack_techniques: tuple[str, ...] = Field(default=(), max_length=32)
    cves: tuple[str, ...] = Field(default=(), max_length=32)
    reviewer: str = Field(min_length=1, max_length=256)
    review_date: date
    expiry: date | None = None

    @field_validator("id")
    @classmethod
    def valid_id(cls, value: str) -> str:
        if _ID.fullmatch(value) is None:
            raise ValueError("knowledge id must be lowercase ASCII")
        return value

    @field_validator("title", "reviewer")
    @classmethod
    def meaningful_text(cls, value: str) -> str:
        if value != value.strip() or not value.strip():
            raise ValueError("knowledge metadata text must be non-blank and trimmed")
        return value

    @model_validator(mode="after")
    def valid_dates(self) -> KnowledgeFrontMatter:
        if self.expiry is not None and self.expiry <= self.review_date:
            raise ValueError("knowledge expiry must be after its review date")
        direct = self.direct_applicability
        if self.applies_to is not None and any(
            (direct.rule_ids, direct.rule_groups, direct.attack_techniques, direct.cves)
        ):
            raise ValueError("knowledge applicability must be nested or top-level, not both")
        return self

    @property
    def language_code(self) -> Literal["en", "es"]:
        return "en" if self.language in ("en", "English") else "es"

    @property
    def kind_code(self) -> Literal["runbook", "reference", "rule_note", "policy"]:
        return "rule_note" if self.kind == "rule note" else self.kind

    @property
    def direct_applicability(self) -> KnowledgeApplicability:
        return KnowledgeApplicability(
            rule_ids=self.rule_ids,
            rule_groups=self.rule_groups,
            attack_techniques=self.attack_techniques,
            cves=self.cves,
        )

    @property
    def applicability(self) -> KnowledgeApplicability:
        return self.applies_to or self.direct_applicability


class PackedKnowledgeChunk(_StrictModel):
    chunk_id: str
    section: str
    ordinal: int = Field(ge=0)
    text: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class PackedKnowledgeDocument(_StrictModel):
    schema_version: Literal["1"] = "1"
    document_id: str
    title: str
    kind: Literal["runbook", "reference", "rule_note", "policy"]
    language: Literal["en", "es"]
    applies_to: KnowledgeApplicability
    reviewer: str
    review_date: date
    expiry: date | None
    source_path: str
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    content_version: str = Field(pattern=r"^[0-9a-f]{40}$")
    chunks: tuple[PackedKnowledgeChunk, ...] = Field(min_length=1, max_length=MAX_KNOWLEDGE_CHUNKS)


def parse_knowledge_document(
    path: str, raw: bytes, *, content_version: str, cutoff: datetime
) -> PackedKnowledgeDocument:
    """Validate one reviewed Markdown source and produce stable bounded chunks."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise KnowledgeBuildError(f"knowledge file is not UTF-8: {path}") from exc
    _reject_hidden_text(path, text)
    metadata, body = _front_matter(path, text)
    try:
        front = KnowledgeFrontMatter.model_validate(metadata)
    except ValueError as exc:
        raise KnowledgeBuildError(f"knowledge front matter is invalid: {path}") from exc
    cutoff_date = cutoff.date()
    if front.review_date > cutoff_date:
        raise KnowledgeBuildError(f"knowledge review date is after approval: {path}")
    if front.expiry is not None and front.expiry <= cutoff_date:
        raise KnowledgeBuildError(f"knowledge document is expired at approval: {path}")
    expected = f"knowledge/{front.id}.md"
    if PurePosixPath(path).as_posix() != expected:
        raise KnowledgeBuildError(f"knowledge path must match its id: {path}")
    chunks = _chunks(front.id, front.title, body)
    return PackedKnowledgeDocument(
        document_id=front.id,
        title=front.title,
        kind=front.kind_code,
        language=front.language_code,
        applies_to=front.applicability,
        reviewer=front.reviewer,
        review_date=front.review_date,
        expiry=front.expiry,
        source_path=path,
        source_sha256=hashlib.sha256(raw).hexdigest(),
        content_version=content_version,
        chunks=chunks,
    )


def _front_matter(path: str, text: str) -> tuple[object, str]:
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        raise KnowledgeBuildError(f"knowledge front matter is required: {path}")
    try:
        end = lines.index("---", 1)
    except ValueError as exc:
        raise KnowledgeBuildError(f"knowledge front matter is unterminated: {path}") from exc
    try:
        raw_metadata = cast(object, yaml.safe_load("\n".join(lines[1:end])))
    except yaml.YAMLError as exc:
        raise KnowledgeBuildError(f"knowledge front matter is invalid: {path}") from exc
    body = "\n".join(lines[end + 1 :]).strip()
    if not isinstance(raw_metadata, dict) or not body:
        raise KnowledgeBuildError(f"knowledge metadata and body are required: {path}")
    raw_items = cast(dict[object, object], raw_metadata)
    metadata: dict[str, object] = {}
    for key, value in raw_items.items():
        if not isinstance(key, str):
            raise KnowledgeBuildError(f"knowledge metadata keys must be strings: {path}")
        metadata[key] = value
    return metadata, body


def _reject_hidden_text(path: str, text: str) -> None:
    if _HTML_COMMENT.search(text) or _HIDDEN_MARKUP.search(text):
        raise KnowledgeBuildError(f"hidden markup is forbidden in knowledge: {path}")
    if _COMMAND_OR_URL.search(text):
        raise KnowledgeBuildError(f"command or URL instructions are forbidden in knowledge: {path}")
    for char in text:
        if char in "\n\t" or char == " ":
            continue
        if unicodedata.category(char) in {"Cf", "Cc", "Cs", "Co"}:
            raise KnowledgeBuildError(f"hidden or control characters are forbidden: {path}")


def _chunks(document_id: str, title: str, body: str) -> tuple[PackedKnowledgeChunk, ...]:
    sections: list[tuple[str, list[str]]] = []
    current_title = title
    current: list[str] = []
    for line in body.splitlines():
        heading = _HEADING.match(line)
        if heading:
            if any(item.strip() for item in current):
                sections.append((current_title, current))
            current_title = heading.group(2).strip()
            current = [line]
        else:
            current.append(line)
    if any(item.strip() for item in current):
        sections.append((current_title, current))
    chunks: list[PackedKnowledgeChunk] = []
    for section_index, (section, lines) in enumerate(sections):
        slug = _slug(section) or f"section-{section_index + 1}"
        for part_index, chunk_text in enumerate(_bounded_parts("\n".join(lines).strip())):
            digest = hashlib.sha256(chunk_text.encode("utf-8")).hexdigest()
            suffix = f"-{part_index + 1}" if part_index else ""
            chunk_id = f"{document_id}#{slug}{suffix}-{digest[:12]}"
            chunks.append(
                PackedKnowledgeChunk(
                    chunk_id=chunk_id,
                    section=section,
                    ordinal=len(chunks),
                    text=chunk_text,
                    sha256=digest,
                )
            )
    if not chunks or len(chunks) > MAX_KNOWLEDGE_CHUNKS:
        raise KnowledgeBuildError("knowledge document has no chunks or too many chunks")
    return tuple(chunks)


def _bounded_parts(text: str) -> tuple[str, ...]:
    if len(text.encode("utf-8")) <= MAX_KNOWLEDGE_CHUNK_BYTES:
        return (text,)
    paragraphs = re.split(r"\n\s*\n", text)
    parts: list[str] = []
    current = ""
    for paragraph in paragraphs:
        candidate = f"{current}\n\n{paragraph}" if current else paragraph
        if len(candidate.encode("utf-8")) <= MAX_KNOWLEDGE_CHUNK_BYTES:
            current = candidate
            continue
        if current:
            parts.append(current)
            current = ""
        while len(paragraph.encode("utf-8")) > MAX_KNOWLEDGE_CHUNK_BYTES:
            split = _utf8_prefix(paragraph, MAX_KNOWLEDGE_CHUNK_BYTES)
            parts.append(split)
            paragraph = paragraph[len(split) :].lstrip()
        current = paragraph
    if current:
        parts.append(current)
    return tuple(parts)


def _utf8_prefix(value: str, size: int) -> str:
    raw = value.encode("utf-8")[:size]
    while True:
        try:
            return raw.decode("utf-8").rstrip()
        except UnicodeDecodeError:
            raw = raw[:-1]


def _slug(value: str) -> str:
    value = unicodedata.normalize("NFKD", value.casefold())
    value = "".join(char for char in value if not unicodedata.combining(char))
    return re.sub(r"[^a-z0-9]+", "-", value).strip("-")[:64]


def packed_document_bytes(document: PackedKnowledgeDocument) -> bytes:
    return canonical_bytes(document.model_dump(mode="json"))
