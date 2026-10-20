"""Read-only Git tree validation and reproducible content artifacts."""

from __future__ import annotations

import base64
import hashlib
import html
import io
import json
import math
import os
import re
import subprocess
import tarfile
import tempfile
import unicodedata
from collections.abc import Iterable, Mapping
from datetime import date
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Literal, TypeVar, cast

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ValidationError

from ai_soc.content.catalog import safe_relative_path
from ai_soc.content.finding_catalog import (
    CatalogError,
    validate_definitions,
    validate_prompt_contexts,
    validate_references,
)
from ai_soc.contracts.canonical import canonical_bytes
from ai_soc.contracts.models import (
    SHA256,
    CompareCountStep,
    ConfigBounds,
    ContentId,
    CueCatalog,
    DetachedApproval,
    EmbeddingManifest,
    ExpectationDefinition,
    ExpectationMatchStep,
    FetchStep,
    FieldPresentStep,
    FindingTemplate,
    FiniteFloat,
    GoldenCase,
    PackManifest,
    PlaybookDefinition,
    RecordAgeStep,
    ReportConfigurationMissingStep,
    SolvedCase,
    SourceManifest,
    StrictModel,
    TopicDefinition,
    TopicPromptPack,
)

T = TypeVar("T", bound=BaseModel)
YamlValue = dict[str, object] | list[object] | str | int | float | bool | None


class _TopicCardVector(StrictModel):
    """Pinned L2 vector input; text is derived only from approved topic metadata."""

    schema_version: Literal["1"]
    topic_id: ContentId
    vector: list[FiniteFloat]


class _PackedTopicCard(StrictModel):
    schema_version: Literal["1"]
    topic_id: ContentId
    text_en: str
    text_es: str
    vector: list[FiniteFloat]


class _DocsManifest(StrictModel):
    schema_version: Literal["1"]
    files: dict[str, SHA256]


_FORBIDDEN_COMMAND = re.compile(
    r"(?im)(?:^|\s)(?:curl|wget|ssh|bash|sh|powershell|systemctl|kubectl)\b|https?://"
)
_SECRET = re.compile(
    r"(?i)(?:AKIA[0-9A-Z]{16}|(?:aws_secret_access_key|password|client_secret|private_key)\s*[:=]\s*\S+)"
)
_MAX_FILE = ConfigBounds().content_file_bytes
_MAX_TOTAL = ConfigBounds().content_total_bytes
_MAX_FILES = ConfigBounds().content_files


class ContentBuildError(ValueError):
    """Safe, actionable content validation failure."""


def _topic_card_texts(topics: tuple[TopicDefinition, ...]) -> dict[str, dict[str, str]]:
    cards: dict[str, dict[str, str]] = {}
    for topic in topics:
        localized: dict[str, str] = {}
        for language in ("en", "es"):
            parts = [topic.name.en if language == "en" else topic.name.es]
            parts.extend(alias.text for alias in topic.aliases if alias.language == language)
            if topic.public_document and topic.public_document.language == language:
                parts.append(topic.public_document.heading)
            localized[language] = "\n".join(dict.fromkeys(parts))
        cards[topic.topic_id] = localized
    return cards


def _validate_topic_cards(
    manifest: EmbeddingManifest | None,
    topics: tuple[TopicDefinition, ...],
    vectors: tuple[_TopicCardVector, ...],
    goldens: tuple[GoldenCase, ...],
) -> None:
    if manifest is None:
        if vectors:
            raise ContentBuildError("topic-card vectors require an embedding manifest")
        return
    by_topic = {item.topic_id: item for item in vectors}
    if len(by_topic) != len(vectors) or set(by_topic) != {topic.topic_id for topic in topics}:
        raise ContentBuildError("embedding manifest needs one vector for every topic")
    cards = _topic_card_texts(topics)
    corpus_sha = _sha256(canonical_bytes(cards))
    vector_payload = {topic_id: by_topic[topic_id].vector for topic_id in sorted(by_topic)}
    vector_sha = _sha256(canonical_bytes(vector_payload))
    golden_payload = [
        item.model_dump(mode="json") for item in sorted(goldens, key=lambda case: case.case_id)
    ]
    golden_sha = _sha256(canonical_bytes(golden_payload))
    if (
        corpus_sha != manifest.corpus_sha256
        or vector_sha != manifest.vector_sha256
        or golden_sha != manifest.golden_sha256
    ):
        raise ContentBuildError("embedding manifest hashes do not match cards, vectors, or goldens")
    if (
        not math.isfinite(manifest.threshold)
        or not -1 <= manifest.threshold <= 1
        or not math.isfinite(manifest.minimum_margin)
        or manifest.minimum_margin < 0
    ):
        raise ContentBuildError("embedding threshold or margin is outside finite cosine bounds")
    for topic_id, card in by_topic.items():
        if len(card.vector) != manifest.dimensions:
            raise ContentBuildError(f"topic vector dimension mismatch: {topic_id}")
        norm = math.sqrt(math.fsum(value * value for value in card.vector))
        if not math.isfinite(norm) or not math.isclose(norm, 1.0, rel_tol=1e-5, abs_tol=1e-5):
            raise ContentBuildError(f"topic vector is not L2 normalized: {topic_id}")


class _UniqueSafeLoader(yaml.SafeLoader):
    pass


_UniqueSafeLoader.yaml_implicit_resolvers = {
    key: [(tag, pattern) for tag, pattern in resolvers if tag != "tag:yaml.org,2002:timestamp"]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def _construct_mapping(
    loader: _UniqueSafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[object, object]:
    loader.flatten_mapping(node)
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        if not isinstance(key_node, yaml.ScalarNode):
            raise ContentBuildError("YAML mapping keys must be scalar strings")
        key = cast(object, loader.construct_object(key_node, deep=deep))  # pyright: ignore[reportUnknownMemberType]
        if not isinstance(key, str):
            raise ContentBuildError("YAML mapping keys must be strings")
        if key in result:
            raise ContentBuildError(f"duplicate YAML key: {key!r}")
        result[key] = cast(object, loader.construct_object(value_node, deep=deep))  # pyright: ignore[reportUnknownMemberType]
    return result


_UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)


def _git(source: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(source), *args],
            check=True,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ContentBuildError(f"git operation failed: {args[0]}") from exc
    return result.stdout.decode("utf-8").strip()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normal_form(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", unicodedata.normalize("NFKC", value).casefold())
    return "".join(char for char in decomposed if not unicodedata.combining(char))


def cue_catalog_digest(catalog: CueCatalog) -> str:
    payload = catalog.model_dump(mode="json", exclude_none=False, exclude={"sha256"})
    return _sha256(canonical_bytes(payload))


def approval_payload(approval: DetachedApproval) -> bytes:
    """Canonical detached signature payload; signature is never inside the source tree."""
    values = approval.model_dump(mode="json", exclude={"signature"})
    return canonical_bytes(values)


def verify_detached_approval(
    approval: DetachedApproval,
    trust_roots: Mapping[str, str],
    *,
    allow_fixture: bool = False,
) -> None:
    if approval.mode == "fixture" and not allow_fixture:
        raise ContentBuildError("fixture approval is not valid in live mode")
    encoded = trust_roots.get(approval.key_id)
    if not encoded:
        raise ContentBuildError("approval key is not trusted")
    try:
        public_bytes = base64.b64decode(encoded, validate=True)
        signature = base64.b64decode(approval.signature, validate=True)
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(
            signature, approval_payload(approval)
        )
    except (ValueError, InvalidSignature) as exc:
        raise ContentBuildError("detached approval signature is invalid") from exc


def _decode_document(path: str, data: bytes) -> YamlValue:
    suffix = PurePosixPath(path).suffix.lower()
    try:
        if suffix in {".yaml", ".yml"}:
            text = data.decode("utf-8")
            events = tuple(
                cast(Iterable[yaml.events.Event], yaml.parse(text))  # pyright: ignore[reportUnknownMemberType]
            )
            if any(isinstance(event, yaml.events.AliasEvent) for event in events):
                raise ContentBuildError(f"YAML aliases are not allowed: {path}")
            if any(
                isinstance(event, yaml.events.NodeEvent)
                and event.anchor is not None
                or isinstance(
                    event,
                    (
                        yaml.events.ScalarEvent,
                        yaml.events.SequenceStartEvent,
                        yaml.events.MappingStartEvent,
                    ),
                )
                and event.tag is not None
                for event in events
            ):
                raise ContentBuildError(f"YAML anchors and tags are not allowed: {path}")
            value: object = cast(object, yaml.load(text, Loader=_UniqueSafeLoader))
        elif suffix == ".json":
            value = cast(object, json.loads(data))
        else:
            raise ContentBuildError(f"unsupported structured content file: {path}")
    except (UnicodeDecodeError, yaml.YAMLError, json.JSONDecodeError) as exc:
        raise ContentBuildError(f"invalid structured content file: {path}") from exc
    if value is None or isinstance(value, (dict, list, str, int, float, bool)):
        return cast(YamlValue, value)
    raise ContentBuildError(f"unsupported YAML value in {path}")


def _model[T: BaseModel](model: type[T], value: object, path: str) -> T:
    try:
        return model.model_validate_json(canonical_bytes(value))
    except (ValidationError, TypeError, ValueError) as exc:
        raise ContentBuildError(f"schema validation failed for {path}") from exc


def _markdown_html(
    source: str, expected_heading: str, expected_anchor: str, language: str
) -> bytes:
    lines = source.replace("\r\n", "\n").replace("\r", "\n").splitlines()
    headings = [line[2:].strip() for line in lines if line.startswith("# ")]
    if expected_heading not in headings:
        raise ContentBuildError(f"document heading is missing: {expected_heading}")
    slug = (
        re.sub(r"[^\w -]", "", expected_heading.casefold(), flags=re.UNICODE)
        .strip()
        .replace(" ", "-")
    )
    if slug != expected_anchor:
        raise ContentBuildError("document anchor does not match the stable heading slug")
    output = ["<!doctype html>", f'<html lang="{language}"><meta charset="utf-8">', "<body>"]
    paragraph: list[str] = []

    def flush() -> None:
        if paragraph:
            output.append("<p>" + html.escape(" ".join(paragraph)) + "</p>")
            paragraph.clear()

    for line in lines:
        match = re.match(r"^(#{1,6})\s+(.+?)\s*#*\s*$", line)
        if match:
            flush()
            level, title = len(match.group(1)), match.group(2)
            anchor = (
                re.sub(r"[^\w -]", "", title.casefold(), flags=re.UNICODE).strip().replace(" ", "-")
            )
            output.append(
                f'<h{level} id="{html.escape(anchor, quote=True)}">{html.escape(title)}</h{level}>'
            )
        elif not line.strip():
            flush()
        else:
            paragraph.append(line.strip())
    flush()
    output.extend(["</body></html>", ""])
    return "\n".join(output).encode("utf-8")


def _markdown_section(source: str, expected_heading: str) -> str:
    """Keep the exact LF-normalized source lines for a heading and its descendants."""
    lines = source.replace("\r\n", "\n").replace("\r", "\n").splitlines(keepends=True)
    start: int | None = None
    level = 0
    for index, line in enumerate(lines):
        match = re.match(r"^(#{1,6})\s+(.+?)\s*#*\s*(?:\n)?$", line)
        if match and match.group(2) == expected_heading:
            start = index
            level = len(match.group(1))
            break
    if start is None:
        raise ContentBuildError(f"document heading is missing: {expected_heading}")
    end = len(lines)
    for index in range(start + 1, len(lines)):
        match = re.match(r"^(#{1,6})\s+", lines[index])
        if match and len(match.group(1)) <= level:
            end = index
            break
    return "".join(lines[start:end])


def _source_files(source: Path, commit: str) -> dict[str, bytes]:
    status = _git(source, "status", "--porcelain", "--untracked-files=no")
    if status:
        raise ContentBuildError("tracked source tree is dirty")
    listing = _git(source, "ls-tree", "-r", "-z", commit)
    entries = [entry for entry in listing.split("\0") if entry]
    if len(entries) > _MAX_FILES:
        raise ContentBuildError("content tree exceeds the file count limit")
    files: dict[str, bytes] = {}
    total = 0
    for entry in entries:
        metadata, name = entry.split("\t", 1)
        mode, object_type, _object_sha = metadata.split(" ", 2)
        safe_relative_path(name)
        if not (name.startswith("content/") or name.startswith("public-docs/")):
            continue
        filename = PurePosixPath(name).name.casefold()
        if filename.startswith(".") or any(
            marker in filename for marker in ("credential", "private-key", "password", "secret")
        ):
            raise ContentBuildError(f"hidden or credential-like content path is forbidden: {name}")
        if object_type != "blob" or mode != "100644":
            raise ContentBuildError(
                f"content tree contains a symlink, executable, or submodule: {name}"
            )
        raw = subprocess.run(
            ["git", "-C", str(source), "show", f"{commit}:{name}"],
            check=True,
            capture_output=True,
            timeout=15,
        ).stdout
        if len(raw) > _MAX_FILE:
            raise ContentBuildError(f"content file exceeds the byte limit: {name}")
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ContentBuildError(f"content file is not UTF-8: {name}") from exc
        if "\r" in decoded:
            raise ContentBuildError(f"content file must use stable LF line endings: {name}")
        if _SECRET.search(decoded):
            raise ContentBuildError(f"secret-like value in content source: {name}")
        total += len(raw)
        if total > _MAX_TOTAL:
            raise ContentBuildError("content tree exceeds the total byte limit")
        files[name] = raw
    return files


def _load_records(
    files: Mapping[str, bytes],
) -> tuple[
    SourceManifest,
    tuple[TopicDefinition, ...],
    tuple[CueCatalog, ...],
    tuple[PlaybookDefinition, ...],
    tuple[ExpectationDefinition, ...],
    tuple[FindingTemplate, ...],
    tuple[_TopicCardVector, ...],
    tuple[SolvedCase, ...],
    tuple[GoldenCase, ...],
]:
    manifest_path = next(
        (
            path
            for path in ("content/manifest.yaml", "content/manifest.yml", "content/manifest.json")
            if path in files
        ),
        None,
    )
    if manifest_path is None:
        raise ContentBuildError("content/manifest.yaml is required")
    manifest = _model(
        SourceManifest, _decode_document(manifest_path, files[manifest_path]), manifest_path
    )
    if len(manifest.topics) != len(set(manifest.topics)):
        raise ContentBuildError("source manifest contains duplicate topic IDs")
    if not manifest.license.strip():
        raise ContentBuildError("source manifest license must not be empty")
    for language, cue_path in manifest.cue_files.items():
        path = safe_relative_path(cue_path).as_posix()
        if language not in {"en", "es"} or path not in files:
            raise ContentBuildError(f"manifest cue file is absent or invalid: {cue_path}")
    records: dict[str, list[BaseModel]] = {
        "topics": [],
        "cues": [],
        "playbooks": [],
        "expectations": [],
        "finding-templates": [],
        "topic-cards": [],
        "solved-cases": [],
        "golden": [],
    }
    cue_paths: set[str] = set()
    supported_groups = {
        "topics",
        "cues",
        "playbooks",
        "expectations",
        "finding-templates",
        "finding_templates",
        "solved-cases",
        "solved_cases",
        "golden",
        "topic-cards",
    }
    topic_ids: set[str] = set()
    for path, raw in sorted(files.items()):
        parts = PurePosixPath(path).parts
        if parts[0] == "public-docs":
            if PurePosixPath(path).suffix.lower() != ".md":
                raise ContentBuildError(f"unsupported public document file: {path}")
            continue
        if len(parts) < 3 or parts[0] != "content" or path == manifest_path:
            continue
        group = parts[1]
        if group not in supported_groups:
            raise ContentBuildError(f"unsupported content record group: {group}")
        suffix = PurePosixPath(path).suffix.lower()
        if suffix not in {".json", ".yaml", ".yml"}:
            raise ContentBuildError(f"unsupported content record file: {path}")
        payload = _decode_document(path, raw)
        if group == "topics":
            topic = _model(TopicDefinition, payload, path)
            if topic.topic_id in topic_ids:
                raise ContentBuildError(f"duplicate topic ID: {topic.topic_id}")
            topic_ids.add(topic.topic_id)
            records[group].append(topic)
        elif group == "cues":
            cue_paths.add(path)
            records[group].append(_model(CueCatalog, payload, path))
        elif group == "playbooks":
            records[group].append(_model(PlaybookDefinition, payload, path))
        elif group == "expectations":
            records[group].append(_model(ExpectationDefinition, payload, path))
        elif group in {"finding-templates", "finding_templates"}:
            records["finding-templates"].append(_model(FindingTemplate, payload, path))
        elif group in {"solved-cases", "solved_cases"}:
            records["solved-cases"].append(_model(SolvedCase, payload, path))
        elif group == "golden":
            records[group].append(_model(GoldenCase, payload, path))
        elif group == "topic-cards":
            card = _model(_TopicCardVector, payload, path)
            if path != f"content/topic-cards/{card.topic_id}.json":
                raise ContentBuildError(f"topic card path does not match topic ID: {path}")
            records[group].append(card)

    topics = tuple(item for item in records["topics"] if isinstance(item, TopicDefinition))
    cue_catalogs = tuple(item for item in records["cues"] if isinstance(item, CueCatalog))
    playbooks = tuple(item for item in records["playbooks"] if isinstance(item, PlaybookDefinition))
    expectations = tuple(
        item for item in records["expectations"] if isinstance(item, ExpectationDefinition)
    )
    templates = tuple(
        item for item in records["finding-templates"] if isinstance(item, FindingTemplate)
    )
    topic_cards = tuple(
        item for item in records["topic-cards"] if isinstance(item, _TopicCardVector)
    )
    solved_cases = tuple(item for item in records["solved-cases"] if isinstance(item, SolvedCase))
    golden = tuple(item for item in records["golden"] if isinstance(item, GoldenCase))
    if set(manifest.topics) != topic_ids:
        raise ContentBuildError("source manifest topic list does not match topic records")
    if cue_paths != set(manifest.cue_files.values()):
        raise ContentBuildError("source manifest cue files do not match cue records")
    topics_by_id = {topic.topic_id: topic for topic in topics}
    topics = tuple(topics_by_id[topic_id] for topic_id in manifest.topics)
    _validate_topic_cards(manifest.embedding, topics, topic_cards, golden)
    return (
        manifest,
        topics,
        cue_catalogs,
        playbooks,
        expectations,
        templates,
        topic_cards,
        solved_cases,
        golden,
    )


def _validate_finding_templates(templates: tuple[FindingTemplate, ...]) -> None:
    try:
        validate_definitions(templates)
    except CatalogError as error:
        raise ContentBuildError(str(error)) from error


def _validate_cross_references(
    files: Mapping[str, bytes],
    topics: tuple[TopicDefinition, ...],
    cues: tuple[CueCatalog, ...],
    playbooks: tuple[PlaybookDefinition, ...],
    expectations: tuple[ExpectationDefinition, ...],
    templates: tuple[FindingTemplate, ...],
    cases: tuple[SolvedCase, ...],
    goldens: tuple[GoldenCase, ...],
) -> None:
    topic_map = {topic.topic_id: topic for topic in topics}
    if len({case.case_id for case in cases}) != len(cases):
        raise ContentBuildError("duplicate solved case IDs")
    if len({case.case_id for case in goldens}) != len(goldens):
        raise ContentBuildError("duplicate golden case IDs")
    if any(item.topic_id not in topic_map for item in expectations):
        raise ContentBuildError("expectation references an unknown topic")
    if len({pb.playbook_id for pb in playbooks}) != len(playbooks):
        raise ContentBuildError("duplicate playbook IDs")
    playbook_map = {pb.playbook_id: pb for pb in playbooks}
    expectation_map = {item.expectation_id: item for item in expectations}
    if len(expectation_map) != len(expectations):
        raise ContentBuildError("duplicate expectation IDs")
    template_map = {item.template_id: item for item in templates}
    if len(template_map) != len(templates):
        raise ContentBuildError("duplicate finding template IDs")
    aliases: dict[tuple[str, str], set[str]] = {}
    alias_ids: set[str] = set()
    cue_alias_ids: set[str] = set()
    cue_ids: set[str] = set()
    cue_languages: set[str] = set()
    ambiguity_map: dict[str, set[str]] = {}
    for catalog in cues:
        for entry in catalog.ambiguities:
            key = _normal_form(entry.normalized)
            if key in ambiguity_map:
                raise ContentBuildError(f"duplicate ambiguity rule: {entry.normalized}")
            ambiguity_map[key] = set(entry.topic_ids)
    for topic in topics:
        if topic.playbook_id is not None:
            playbook = playbook_map.get(topic.playbook_id)
            if playbook is None or playbook.topic_id != topic.topic_id:
                raise ContentBuildError(
                    f"topic {topic.topic_id} references an absent or cross-topic playbook"
                )
        for alias in topic.aliases:
            if alias.topic_id != topic.topic_id:
                raise ContentBuildError("alias is attached to a different topic")
            if alias.alias_id in alias_ids:
                raise ContentBuildError(f"duplicate alias ID: {alias.alias_id}")
            alias_ids.add(alias.alias_id)
            if _normal_form(alias.text) != _normal_form(alias.normalized):
                raise ContentBuildError(
                    f"alias normalized value does not match text: {alias.alias_id}"
                )
            key = alias.language, _normal_form(alias.normalized)
            aliases.setdefault(key, set()).add(alias.topic_id)
        document = topic.public_document
        if document is not None:
            path = safe_relative_path(document.source_path).as_posix()
            if not path.startswith("public-docs/"):
                raise ContentBuildError("public document source must be under public-docs")
            safe_relative_path(document.published_path)
            raw = files.get(path)
            if raw is None:
                raise ContentBuildError(f"document source is absent from approved tree: {path}")
            if _sha256(raw) != document.sha256:
                raise ContentBuildError(f"document content hash mismatch: {path}")
            text = raw.decode("utf-8")
            if _SECRET.search(text):
                raise ContentBuildError(f"secret-like value in public document: {path}")
        for template_id in topic.finding_template_ids:
            template = template_map.get(template_id)
            if template is not None and template.topic_id != topic.topic_id:
                raise ContentBuildError("topic references a cross-topic finding template")
    for template in templates:
        if template.topic_id != "_records" and template.topic_id not in topic_map:
            raise ContentBuildError("finding template references an unknown topic")
    for catalog in cues:
        if cue_catalog_digest(catalog) != catalog.sha256:
            raise ContentBuildError("cue catalog digest does not match its records")
        for cue in catalog.cues:
            if cue.cue_id in cue_ids:
                raise ContentBuildError(f"duplicate cue ID: {cue.cue_id}")
            cue_ids.add(cue.cue_id)
            cue_languages.add(cue.language)
            if _normal_form(cue.text) != _normal_form(cue.normalized):
                raise ContentBuildError(f"cue normalized value does not match text: {cue.cue_id}")
            if cue.negation_rule is not None and cue.negation_rule != "direct_negation":
                raise ContentBuildError(f"unsupported cue negation rule: {cue.negation_rule}")
        for alias in catalog.aliases:
            if alias.topic_id not in topic_map:
                raise ContentBuildError(
                    f"cue catalog alias references unknown topic: {alias.topic_id}"
                )
            if alias.alias_id in alias_ids or alias.alias_id in cue_alias_ids:
                raise ContentBuildError(f"duplicate alias ID: {alias.alias_id}")
            cue_alias_ids.add(alias.alias_id)
            if _normal_form(alias.text) != _normal_form(alias.normalized):
                raise ContentBuildError(
                    f"alias normalized value does not match text: {alias.alias_id}"
                )
            aliases.setdefault((alias.language, _normal_form(alias.normalized)), set()).add(
                alias.topic_id
            )
    if cue_languages != {"en", "es"}:
        raise ContentBuildError("content cue set must include English and Spanish")
    for (_language, normalized), topics_for_alias in aliases.items():
        if len(topics_for_alias) > 1:
            approved = ambiguity_map.get(_normal_form(normalized))
            if approved != topics_for_alias:
                raise ContentBuildError(f"unreviewed cross-topic alias collision: {normalized}")
    for normalized, approved in ambiguity_map.items():
        if len(approved) < 2 or not any(
            _normal_form(alias_normalized) == normalized and topic_set == approved
            for (_language, alias_normalized), topic_set in aliases.items()
        ):
            raise ContentBuildError(f"stale or invalid ambiguity rule: {normalized}")
    for playbook in playbooks:
        if playbook.topic_id not in topic_map:
            raise ContentBuildError(f"playbook references unknown topic: {playbook.topic_id}")
        known_fetches: set[str] = set()
        known_checks: set[str] = set()
        step_ids: set[str] = set()
        if len(playbook.steps) > 10:
            raise ContentBuildError("playbook exceeds ten steps")
        for step in playbook.steps:
            if step.step_id in step_ids:
                raise ContentBuildError(f"duplicate playbook step ID: {step.step_id}")
            step_ids.add(step.step_id)
            if isinstance(step, FetchStep):
                if step.fetch_id in known_fetches or step.fetch_id in known_checks:
                    raise ContentBuildError(f"duplicate playbook output ID: {step.fetch_id}")
                known_fetches.add(step.fetch_id)
            else:
                if step.check_id in known_fetches or step.check_id in known_checks:
                    raise ContentBuildError(f"duplicate playbook output ID: {step.check_id}")
                known_checks.add(step.check_id)
                refs: list[str] = []
                if isinstance(step, CompareCountStep):
                    refs = [step.left_fetch_id]
                    if step.right.kind == "fetch_count":
                        refs.append(step.right.fetch_id)
                elif isinstance(step, (FieldPresentStep, ExpectationMatchStep, RecordAgeStep)):
                    refs = [step.fetch_id]
                for ref in refs:
                    if ref not in known_fetches:
                        raise ContentBuildError(
                            f"playbook has forward or unknown fetch reference: {ref}"
                        )
                if isinstance(step, ExpectationMatchStep):
                    expectation = expectation_map.get(step.expectation_id)
                    if (
                        expectation is None
                        or expectation.topic_id != playbook.topic_id
                        or expectation.field != step.field
                    ):
                        raise ContentBuildError(
                            "playbook has unknown or cross-topic expectation: "
                            f"{step.expectation_id}"
                        )
                if (
                    isinstance(step, ReportConfigurationMissingStep)
                    and step.expectation_id not in expectation_map
                ):
                    raise ContentBuildError(
                        f"playbook has unknown expectation: {step.expectation_id}"
                    )
                if isinstance(step, CompareCountStep) and step.op not in {"eq", "gte", "lte"}:
                    raise ContentBuildError("unsupported count comparison")
        if _FORBIDDEN_COMMAND.search(playbook.internal_context):
            raise ContentBuildError("playbook context contains command or URL instructions")
    for case in cases:
        if case.topic_id not in topic_map:
            raise ContentBuildError(f"solved case references unknown topic: {case.topic_id}")
        if not case.synthetic:
            raise ContentBuildError("non-synthetic solved case is forbidden in this pack")
        attestation = case.anonymization_attestation
        if not attestation.reviewer_id.strip():
            raise ContentBuildError("solved case anonymization reviewer must not be empty")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", attestation.date):
            raise ContentBuildError("solved case anonymization date must use YYYY-MM-DD")
        try:
            date.fromisoformat(attestation.date)
        except ValueError as exc:
            raise ContentBuildError("solved case anonymization date is invalid") from exc
        if case.promotion_status == "approved" and case.review_record is None:
            raise ContentBuildError("approved solved case requires a detached review record")
        if _SECRET.search(case.description):
            raise ContentBuildError("secret-like value in solved case")
    # GoldenCase schema validation above checks its typed input and expected payload.
    if not cues:
        raise ContentBuildError("at least one bilingual cue catalog is required")
    _validate_finding_templates(templates)
    try:
        validate_references(templates, topics, playbooks)
    except CatalogError as error:
        raise ContentBuildError(str(error)) from error


def validate_git_content(
    source: Path,
    commit: str,
    attestation_path: Path,
    trust_root_path: Path,
    *,
    allow_fixture: bool = False,
) -> tuple[SourceManifest, dict[str, bytes], DetachedApproval]:
    source = source.resolve(strict=True)
    if not source.is_dir() or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ContentBuildError("source must be a Git directory and commit a full lowercase SHA")
    actual_commit = _git(source, "rev-parse", "--verify", f"{commit}^{{commit}}")
    if actual_commit != commit:
        raise ContentBuildError("requested commit did not resolve exactly")
    tree_sha = _git(source, "rev-parse", f"{commit}^{{tree}}")
    files = _source_files(source, commit)
    (
        manifest,
        topics,
        cues,
        playbooks,
        expectations,
        templates,
        _,
        cases,
        goldens,
    ) = _load_records(files)
    try:
        approval = DetachedApproval.model_validate_json(attestation_path.read_bytes())
    except ValidationError as exc:
        raise ContentBuildError(
            f"detached approval schema invalid: {exc.errors(include_url=False)}"
        ) from exc
    parsed_trust_roots: object = cast(
        object, json.loads(trust_root_path.read_text(encoding="utf-8"))
    )
    if not isinstance(parsed_trust_roots, dict):
        raise ContentBuildError("trust root must be a key ID to base64 public key object")
    trust_roots: dict[str, str] = {}
    raw_roots = cast(dict[object, object], parsed_trust_roots)
    for key, value in raw_roots.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ContentBuildError("trust root must be a key ID to base64 public key object")
        trust_roots[key] = value
    if (
        approval.repository != manifest.repository
        or approval.commit != commit
        or approval.tree_sha != tree_sha
    ):
        raise ContentBuildError(
            "detached approval repository, commit, or tree does not match source"
        )
    verify_detached_approval(approval, trust_roots, allow_fixture=allow_fixture)
    _validate_cross_references(
        files, topics, cues, playbooks, expectations, templates, cases, goldens
    )
    return manifest, files, approval


def _canonical_model(model: BaseModel) -> bytes:
    return canonical_bytes(model.model_dump(mode="json", exclude_none=False))


def build_content_pack(
    source: Path,
    commit: str,
    attestation: Path,
    trust_root: Path,
    out: Path,
    *,
    allow_fixture: bool = False,
) -> PackManifest:
    manifest, files, approval = validate_git_content(
        source, commit, attestation, trust_root, allow_fixture=allow_fixture
    )
    resolved_out = out.resolve()
    if resolved_out == source.resolve() or source.resolve() in resolved_out.parents:
        raise ContentBuildError("output directory must be outside the source repository")
    raw_tree_sha = _sha256(
        canonical_bytes({name: _sha256(data) for name, data in sorted(files.items())})
    )
    (
        manifest,
        topics,
        cue_catalogs,
        playbooks,
        expectations,
        templates,
        topic_cards,
        cases,
        goldens,
    ) = _load_records(files)
    cue_sha = _sha256(canonical_bytes(sorted(catalog.sha256 for catalog in cue_catalogs)))
    public_docs: dict[str, bytes] = {}
    contexts: list[TopicPromptPack] = []
    for topic in topics:
        document = topic.public_document
        document_section: str | None = None
        missing: list[str] = []
        if document is None:
            missing.append("public_document")
        else:
            source_text = files[safe_relative_path(document.source_path).as_posix()].decode("utf-8")
            document_section = _markdown_section(source_text, document.heading)
            rendered = _markdown_html(
                source_text, document.heading, document.anchor, document.language
            )
            destination = f"{document.language}/{document.published_path.rsplit('/', 1)[-1]}"
            public_docs[destination] = rendered
        if topic.playbook_id is None:
            missing.append("playbook")
        playbook_context = next(
            (
                playbook.internal_context
                for playbook in playbooks
                if playbook.playbook_id == topic.playbook_id
            ),
            None,
        )
        for language in ("en", "es"):
            context_value = {
                "schema_version": "1",
                "topic_id": topic.topic_id,
                "language": language,
                "content_sha": commit,
                "document_section": document_section,
                "internal_context": playbook_context,
                "missing": missing,
            }
            context_value["sha256"] = _sha256(canonical_bytes(context_value))
            contexts.append(TopicPromptPack.model_validate(context_value))
    try:
        validate_prompt_contexts(contexts, templates)
    except CatalogError as error:
        raise ContentBuildError(str(error)) from error
    public_doc_hashes = {name: _sha256(data) for name, data in sorted(public_docs.items())}
    docs_sha = _sha256(canonical_bytes(public_doc_hashes))
    pack_items: dict[str, bytes] = {}
    groups = {
        "topics": topics,
        "cues": cue_catalogs,
        "playbooks": playbooks,
        "expectations": expectations,
        "finding-templates": templates,
        "solved-cases": cases,
        "golden": goldens,
    }
    for group, records in groups.items():
        for record in records:
            if group == "finding-templates":
                record_id = cast(FindingTemplate, record).template_id
            else:
                record_id = cast(
                    str,
                    next(
                        (
                            getattr(record, key)
                            for key in (
                                "topic_id",
                                "cue_id",
                                "playbook_id",
                                "expectation_id",
                                "case_id",
                                "sha256",
                            )
                            if hasattr(record, key)
                        ),
                        group,
                    ),
                )
            output_path = f"pack/{group}/{record_id}.json"
            if output_path in pack_items:
                raise ContentBuildError(f"duplicate generated content pack path: {output_path}")
            pack_items[output_path] = _canonical_model(record)
    card_texts = _topic_card_texts(topics)
    for card in topic_cards:
        packed_card = _PackedTopicCard(
            schema_version="1",
            topic_id=card.topic_id,
            text_en=card_texts[card.topic_id]["en"],
            text_es=card_texts[card.topic_id]["es"],
            vector=card.vector,
        )
        pack_items[f"pack/topic-cards/{card.topic_id}.json"] = _canonical_model(packed_card)
    for context in contexts:
        pack_items[f"pack/context/{context.topic_id}-{context.language}.json"] = _canonical_model(
            context
        )
    pack_sha = _sha256(
        canonical_bytes({name: _sha256(data) for name, data in sorted(pack_items.items())})
    )
    file_entries = [
        {"path": name, "sha256": _sha256(data), "bytes": len(data)}
        for name, data in sorted(
            {**pack_items, **{f"docs/{k}": v for k, v in public_docs.items()}}.items()
        )
    ]
    pack_manifest_value = {
        "schema_version": "1",
        "service_contract_version": "1",
        "source_repository": str(manifest.repository),
        "content_sha": commit,
        "source_tree_sha256": raw_tree_sha,
        "pack_sha256": pack_sha,
        "docs_manifest_sha256": docs_sha,
        "cue_pack_sha": cue_sha,
        "review_attestation": str(approval.review_record),
        "files": file_entries,
        "embedding": manifest.embedding.model_dump(mode="json") if manifest.embedding else None,
    }
    typed_manifest = PackManifest.model_validate(pack_manifest_value)
    provenance = {
        "source_repository": str(manifest.repository),
        "content_sha": commit,
        "source_tree_sha256": raw_tree_sha,
        "pack_sha256": pack_sha,
        "docs_manifest_sha256": docs_sha,
        "cue_pack_sha": cue_sha,
        "approval_key_id": approval.key_id,
        "mode": approval.mode,
    }
    output_files = {
        **pack_items,
        **{f"docs/{name}": data for name, data in public_docs.items()},
        "docs-manifest.json": canonical_bytes({"schema_version": "1", "files": public_doc_hashes}),
        "provenance.json": canonical_bytes(provenance),
        "manifest.json": _canonical_model(typed_manifest),
    }
    source_epoch = int(_git(source, "show", "-s", "--format=%ct", commit))
    archive_buffer = io.BytesIO()
    with tarfile.open(fileobj=archive_buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in sorted(output_files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = source_epoch
            info.mode = 0o444
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    output_files["content.tar"] = archive_buffer.getvalue()
    output_files["archive.sha256"] = (_sha256(output_files["content.tar"]) + "\n").encode()
    resolved_out.parent.mkdir(parents=True, exist_ok=True)
    if resolved_out.exists():
        raise ContentBuildError("output directory already exists")
    with tempfile.TemporaryDirectory(prefix="ai-soc-content-") as temp_dir:
        staging = Path(temp_dir) / "artifact"
        staging.mkdir()
        for name, data in sorted(output_files.items()):
            destination = staging / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            os.chmod(destination, 0o444)
        os.replace(staging, resolved_out)
    return typed_manifest


def verify_content_pack(pack: Path, contract_version: str = "1") -> None:
    try:
        manifest = PackManifest.model_validate_json((pack / "manifest.json").read_bytes())
    except (OSError, ValidationError) as exc:
        raise ContentBuildError("pack manifest is missing or invalid") from exc
    if manifest.service_contract_version != contract_version:
        raise ContentBuildError("pack contract version mismatch")
    if len({file.path for file in manifest.files}) != len(manifest.files):
        raise ContentBuildError("pack manifest contains duplicate paths")
    for file in manifest.files:
        path = pack / file.path
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(pack.resolve(strict=True))
            raw = resolved.read_bytes()
        except (OSError, ValueError) as exc:
            raise ContentBuildError(f"manifest file missing or escaping pack: {file.path}") from exc
        if len(raw) != file.bytes or _sha256(raw) != file.sha256:
            raise ContentBuildError(f"manifest file hash mismatch: {file.path}")
    # The manifest hash excludes itself and is over canonical content records only.
    pack_records = {
        item.path: _sha256((pack / item.path).read_bytes())
        for item in manifest.files
        if item.path.startswith("pack/")
    }
    if _sha256(canonical_bytes(pack_records)) != manifest.pack_sha256:
        raise ContentBuildError("pack content digest mismatch")
    docs_files = {
        item.path.removeprefix("docs/"): item.sha256
        for item in manifest.files
        if item.path.startswith("docs/")
    }
    try:
        docs_manifest = _DocsManifest.model_validate_json(
            (pack / "docs-manifest.json").read_bytes()
        )
        if docs_manifest.files != docs_files:
            raise ValueError
    except (OSError, ValidationError, ValueError) as exc:
        raise ContentBuildError("public docs manifest is invalid") from exc
    if _sha256(canonical_bytes(docs_files)) != manifest.docs_manifest_sha256:
        raise ContentBuildError("public docs manifest digest mismatch")
    expected_files = {item.path for item in manifest.files} | {
        "manifest.json",
        "docs-manifest.json",
        "provenance.json",
        "content.tar",
        "archive.sha256",
    }
    actual_paths = {
        path.relative_to(pack).as_posix()
        for path in pack.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if actual_paths != expected_files or any((pack / name).is_symlink() for name in expected_files):
        raise ContentBuildError("pack contains missing, extra, or linked files")
    total_size = sum((pack / name).stat().st_size for name in expected_files)
    if total_size > ConfigBounds().pack_bytes:
        raise ContentBuildError("content pack exceeds its byte limit")
    archive_bytes = (pack / "content.tar").read_bytes()
    archive_hash = _sha256(archive_bytes)
    if (pack / "archive.sha256").read_text(encoding="ascii") != f"{archive_hash}\n":
        raise ContentBuildError("content archive digest mismatch")
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
            archive_names = set(archive.getnames())
            expected_members = expected_files - {"content.tar", "archive.sha256"}
            if archive_names != expected_members or len(archive_names) != len(archive.getnames()):
                raise ContentBuildError("content archive inventory is invalid")
            for name in sorted(expected_members):
                member = archive.extractfile(name)
                if member is None or member.read() != (pack / name).read_bytes():
                    raise ContentBuildError(f"content archive member mismatch: {name}")
    except (OSError, tarfile.TarError) as exc:
        raise ContentBuildError("content archive is invalid") from exc


def load_topic_card_vectors(pack: Path) -> Mapping[str, tuple[float, ...]]:
    """Read immutable, manifest-bound topic vectors; disabled packs return an empty mapping."""
    verify_content_pack(pack)
    manifest = PackManifest.model_validate_json((pack / "manifest.json").read_bytes())
    if manifest.embedding is None:
        return MappingProxyType({})
    vectors: dict[str, tuple[float, ...]] = {}
    for path in sorted((pack / "pack/topic-cards").glob("*.json")):
        card = _PackedTopicCard.model_validate_json(path.read_bytes())
        if path.name != f"{card.topic_id}.json" or card.topic_id in vectors:
            raise ContentBuildError("topic vector path or ID is invalid")
        if len(card.vector) != manifest.embedding.dimensions:
            raise ContentBuildError("topic vector dimension does not match pack manifest")
        norm = math.sqrt(math.fsum(value * value for value in card.vector))
        if not math.isclose(norm, 1.0, rel_tol=1e-5, abs_tol=1e-5):
            raise ContentBuildError("topic vector is not L2 normalized")
        vectors[card.topic_id] = tuple(float(value) for value in card.vector)
    if not vectors:
        raise ContentBuildError("embedding manifest has no topic vectors")
    topic_ids = {
        TopicDefinition.model_validate_json(path.read_bytes()).topic_id
        for path in sorted((pack / "pack/topics").glob("*.json"))
    }
    if set(vectors) != topic_ids:
        raise ContentBuildError("embedding vectors do not match packed topics")
    vector_payload = {topic_id: list(vectors[topic_id]) for topic_id in sorted(vectors)}
    if _sha256(canonical_bytes(vector_payload)) != manifest.embedding.vector_sha256:
        raise ContentBuildError("topic vector hash does not match embedding manifest")
    return MappingProxyType(vectors)
