"""Validated, immutable view of one approved content pack."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast

from ai_soc.content.finding_catalog import (
    validate_definitions,
    validate_prompt_contexts,
    validate_references,
)
from ai_soc.contracts.models import (
    BuildProvenance,
    CueCatalog,
    ExpectationDefinition,
    FindingTemplate,
    PackManifest,
    PlaybookDefinition,
    TopicDefinition,
    TopicPromptPack,
)


@dataclass(frozen=True, slots=True)
class ContentCatalog:
    """An in-memory catalog whose records came from a validated immutable pack."""

    provenance: BuildProvenance
    cue_catalog: CueCatalog
    topic_records: tuple[TopicDefinition, ...]
    prompt_packs: tuple[TopicPromptPack, ...]
    playbook_records: tuple[PlaybookDefinition, ...] = ()
    expectations: tuple[ExpectationDefinition, ...] = ()
    templates: tuple[FindingTemplate, ...] = ()

    def __post_init__(self) -> None:
        topic_ids = [topic.topic_id for topic in self.topic_records]
        if len(topic_ids) != len(set(topic_ids)):
            raise ValueError("duplicate topic IDs in catalog")
        prompt_keys = [(pack.topic_id, pack.language) for pack in self.prompt_packs]
        if len(prompt_keys) != len(set(prompt_keys)):
            raise ValueError("duplicate topic prompt pack")
        definitions = validate_definitions(self.templates)
        validate_references(definitions, self.topic_records, self.playbook_records)
        validate_prompt_contexts(self.prompt_packs, definitions)

    def manifest(self) -> BuildProvenance:
        return self.provenance

    def topics(self) -> tuple[TopicDefinition, ...]:
        return self.topic_records

    def topic(self, topic_id: str) -> TopicDefinition | None:
        return next((topic for topic in self.topic_records if topic.topic_id == topic_id), None)

    def cues(self) -> CueCatalog:
        return self.cue_catalog

    def topic_context(self, topic_id: str, *, language: str) -> TopicPromptPack:
        for pack in self.prompt_packs:
            if pack.topic_id == topic_id and pack.language == language:
                return pack
        raise KeyError(f"no prompt context for topic {topic_id!r} in {language!r}")

    def expectation(self, expectation_id: str, *, topic_id: str) -> ExpectationDefinition | None:
        return next(
            (
                expectation
                for expectation in self.expectations
                if expectation.expectation_id == expectation_id and expectation.topic_id == topic_id
            ),
            None,
        )

    def playbook(self, playbook_id: str) -> PlaybookDefinition | None:
        return next(
            (playbook for playbook in self.playbook_records if playbook.playbook_id == playbook_id),
            None,
        )

    def finding_templates(self, topic_id: str) -> tuple[FindingTemplate, ...]:
        return tuple(template for template in self.templates if template.topic_id == topic_id)


def safe_relative_path(value: str) -> PurePosixPath:
    """Return a canonical repository relative path or reject it."""
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != value
    ):
        raise ValueError(f"unsafe repository path: {value!r}")
    return path


def catalog_from_records(
    provenance: BuildProvenance,
    cues: CueCatalog,
    topics: tuple[TopicDefinition, ...],
    packs: tuple[TopicPromptPack, ...],
    playbooks: tuple[PlaybookDefinition, ...] = (),
    expectations: tuple[ExpectationDefinition, ...] = (),
    templates: tuple[FindingTemplate, ...] = (),
) -> ContentCatalog:
    """Typed constructor used by the pack loader without leaking implementation types."""
    return ContentCatalog(
        provenance,
        cues,
        topics,
        packs,
        playbooks,
        expectations,
        templates,
    )


def load_content_catalog(pack: Path, *, provenance: BuildProvenance) -> ContentCatalog:
    """Load an already verified immutable pack into the frozen ContentCatalog port."""
    from ai_soc.content.builder import verify_content_pack

    verify_content_pack(pack)
    manifest = PackManifest.model_validate_json((pack / "manifest.json").read_bytes())
    if (
        manifest.content_sha != provenance.content_sha
        or manifest.pack_sha256 != provenance.pack_sha256
        or manifest.docs_manifest_sha256 != provenance.docs_manifest_sha256
        or str(manifest.source_repository) != provenance.content_repository
    ):
        raise ValueError("runtime provenance does not match the verified content pack")
    topic_records: list[TopicDefinition] = []
    cue_records: list[CueCatalog] = []
    prompt_packs: list[TopicPromptPack] = []
    playbooks: list[PlaybookDefinition] = []
    expectations: list[ExpectationDefinition] = []
    templates: list[FindingTemplate] = []
    for path in sorted((pack / "pack").rglob("*.json")):
        data = cast(object, json.loads(path.read_bytes()))
        if path.parent.name == "topics":
            if not isinstance(data, dict):
                raise ValueError("topic pack record must be an object")
            topic_data = cast(dict[str, object], data)
            topic_records.append(TopicDefinition.model_validate_json(json.dumps(topic_data)))
        elif path.parent.name == "cues":
            cue_records.append(CueCatalog.model_validate_json(path.read_bytes()))
        elif path.parent.name == "playbooks":
            playbooks.append(PlaybookDefinition.model_validate_json(path.read_bytes()))
        elif path.parent.name == "expectations":
            expectations.append(ExpectationDefinition.model_validate_json(path.read_bytes()))
        elif path.parent.name == "finding-templates":
            templates.append(FindingTemplate.model_validate_json(path.read_bytes()))
        elif path.parent.name == "context":
            prompt_packs.append(TopicPromptPack.model_validate_json(path.read_bytes()))
    cue_catalog = CueCatalog(
        version="1",
        sha256=manifest.cue_pack_sha,
        cues=[cue for record in cue_records for cue in record.cues],
        aliases=[alias for record in cue_records for alias in record.aliases],
        ambiguities=[item for record in cue_records for item in record.ambiguities],
    )
    return ContentCatalog(
        provenance,
        cue_catalog,
        tuple(topic_records),
        tuple(prompt_packs),
        tuple(playbooks),
        tuple(expectations),
        tuple(templates),
    )
