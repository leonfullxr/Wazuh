"""Approved topic-local finding template rules shared by content, runtime and provider."""

from __future__ import annotations

import json
import re
import string
from collections.abc import Iterable, Sequence
from typing import cast

from pydantic import ValidationError

from ai_soc.contracts.canonical import canonical_bytes
from ai_soc.contracts.models import (
    CheckOutcome,
    FetchStep,
    FindingRelationSameFetch,
    FindingRelationSameRecord,
    FindingTemplate,
    PlaybookDefinition,
    RecordAgeStep,
    TopicDefinition,
    TopicPromptPack,
)

TOPIC_CONTEXT_LABEL = "APPROVED TOPIC CONTEXT (data): "
MAX_TEMPLATES_PER_TOPIC = 20
MAX_TOPIC_CONTEXT_BYTES = 65_536

_UNBACKED_AGENT_STOPWORDS = frozenset(
    {
        "failed",
        "fail",
        "failing",
        "broken",
        "falla",
        "fallo",
        "fall\u00f3",
        "fallando",
        "roto",
    }
)
_UNBACKED_AGENT_LITERAL = re.compile(
    r"\b(?:agent|agente)\s+(?P<id>[A-Za-z][A-Za-z0-9._-]{1,63})\b",
    re.I,
)
_UNBACKED_AGENT_NUMERIC = re.compile(
    r"\b(?:agent|agente)\s+(?P<id>\d+[A-Za-z0-9._-]*)\b",
    re.I,
)
_UNBACKED_LITERAL = re.compile(
    r"\bCVE-[0-9]{4}-[0-9]{4,}\b|"
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b|"
    r"\b(?:rule|regla)\s+(?:id\s+)?[0-9]{2,}\b|"
    r"\b(?:count|cuenta)\s+(?:of\s+)?[0-9]{2,}\b",
    re.I,
)


class CatalogError(ValueError):
    """An approved finding template catalog failed a shared strict rule."""


def _reference(record: object) -> str:
    value = getattr(record, "template_id", None)
    if isinstance(value, str) and value:
        return value
    return "unknown"


def definition_bytes(record: FindingTemplate) -> bytes:
    """Return canonical JSON bytes for one definition after a strict typed reconstruction."""
    try:
        raw = canonical_bytes(record.model_dump(mode="json", exclude_none=False))
    except (AttributeError, TypeError, ValueError) as exc:
        raise CatalogError(
            f"finding template failed strict reconstruction: {_reference(record)}"
        ) from exc
    try:
        FindingTemplate.model_validate_json(raw, strict=True)
    except (ValidationError, TypeError, ValueError) as exc:
        raise CatalogError(
            f"finding template failed strict reconstruction: {_reference(record)}"
        ) from exc
    return raw


def catalog_bytes(records: Iterable[FindingTemplate]) -> bytes:
    """Return the complete ordered canonical JSON array bytes for one catalog."""
    return b"[" + b",".join(definition_bytes(record) for record in records) + b"]"


def _definitions_from_record_bytes(records: Sequence[bytes]) -> tuple[FindingTemplate, ...]:
    rebuilt: list[FindingTemplate] = []
    for raw in records:
        try:
            rebuilt.append(FindingTemplate.model_validate_json(raw, strict=True))
        except (ValidationError, TypeError, ValueError) as exc:
            raise CatalogError("finding template failed strict reconstruction") from exc
    _reject_duplicate_ids(rebuilt)
    return tuple(rebuilt)


def definitions_from_bytes(payload: bytes) -> tuple[FindingTemplate, ...]:
    """Rehydrate a detached ordered catalog from its complete canonical array bytes."""
    try:
        parsed: object = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError):
        raise CatalogError("finding template catalog is not valid JSON") from None
    if not isinstance(parsed, list):
        raise CatalogError("finding template catalog is not an array")
    records: list[bytes] = []
    for item in cast(list[object], parsed):
        if not isinstance(item, dict):
            raise CatalogError("finding template catalog entry is not an object")
        try:
            records.append(canonical_bytes(cast(dict[str, object], item)))
        except (TypeError, ValueError) as exc:
            raise CatalogError("finding template catalog entry is not canonical") from exc
    return _definitions_from_record_bytes(records)


def definitions_from_models(records: Iterable[FindingTemplate]) -> tuple[FindingTemplate, ...]:
    """Strictly reconstruct ordered definitions so mutated or copied models cannot bypass typing."""
    return _definitions_from_record_bytes(tuple(definition_bytes(record) for record in records))


def _reject_duplicate_ids(templates: Sequence[FindingTemplate]) -> None:
    seen: set[str] = set()
    for template in templates:
        if template.template_id in seen:
            raise CatalogError("duplicate finding template IDs")
        seen.add(template.template_id)


def _has_unbacked_agent_literal(text: str) -> bool:
    if _UNBACKED_AGENT_NUMERIC.search(text):
        return True
    for match in _UNBACKED_AGENT_LITERAL.finditer(text):
        token = match.group("id")
        if token.casefold() not in _UNBACKED_AGENT_STOPWORDS:
            return True
    return False


def _template_placeholders_valid(template: FindingTemplate) -> bool:
    expected = set(template.required_bindings)
    for source in (template.texts.en, template.texts.es):
        fields: set[str] = set()
        try:
            for _, field, format_spec, conversion in string.Formatter().parse(source):
                if field is None:
                    continue
                if format_spec or conversion or "[" in field or "." in field:
                    return False
                fields.add(field)
        except ValueError:
            return False
        if fields != expected:
            return False
    return True


def _template_literal_segments(text: str) -> str:
    parts: list[str] = []
    for literal, _field, _format_spec, _conversion in string.Formatter().parse(text):
        if literal:
            parts.append(literal)
    return "".join(parts)


def _validate_template_rules(template: FindingTemplate) -> None:
    if not _template_placeholders_valid(template):
        raise CatalogError(
            f"finding template placeholders do not match bindings: {template.template_id}"
        )
    binding_ids = set(template.required_bindings)
    for relation in template.relations:
        if isinstance(relation, FindingRelationSameRecord | FindingRelationSameFetch):
            if not relation.bindings or not set(relation.bindings).issubset(binding_ids):
                raise CatalogError(
                    f"finding template relation references unknown bindings: {template.template_id}"
                )
        else:
            if relation.count_binding not in binding_ids:
                raise CatalogError(
                    f"finding template relation references unknown count binding: "
                    f"{template.template_id}"
                )
            if not set(relation.entity_bindings).issubset(binding_ids):
                raise CatalogError(
                    f"finding template relation references unknown entity bindings: "
                    f"{template.template_id}"
                )
    for source in (template.texts.en, template.texts.es):
        literals = _template_literal_segments(source)
        if _has_unbacked_agent_literal(literals) or _UNBACKED_LITERAL.search(literals):
            raise CatalogError(
                f"finding template embeds an unbacked literal value: {template.template_id}"
            )


def _validate_prerequisite_declarations(template: FindingTemplate) -> None:
    if "check" in template.allowed_evidence_kinds and not template.required_check_outcomes:
        raise CatalogError(
            f"finding template allows check evidence without a prerequisite: {template.template_id}"
        )
    seen: set[str] = set()
    for requirement in template.required_check_outcomes:
        if requirement.check_id in seen:
            raise CatalogError(
                f"finding template declares a duplicate check prerequisite: {template.template_id}"
            )
        seen.add(requirement.check_id)


def validate_definitions(records: Iterable[FindingTemplate]) -> tuple[FindingTemplate, ...]:
    """Apply every shared definition rule and return the detached ordered definitions."""
    templates = definitions_from_models(records)
    counts: dict[str, int] = {}
    for template in templates:
        _validate_template_rules(template)
        _validate_prerequisite_declarations(template)
        counts[template.topic_id] = counts.get(template.topic_id, 0) + 1
    for topic_id in sorted(counts):
        if counts[topic_id] > MAX_TEMPLATES_PER_TOPIC:
            raise CatalogError(f"topic exceeds 20 approved finding templates: {topic_id}")
    return templates


def validate_references(
    templates: Iterable[FindingTemplate],
    topics: Iterable[TopicDefinition],
    playbooks: Iterable[PlaybookDefinition],
) -> None:
    """Bind definitions to approved topics, topic template lists and playbook check declarations."""
    ordered = tuple(templates)
    _reject_duplicate_ids(ordered)
    playbook_records = tuple(playbooks)
    _reject_duplicate_playbook_ids(playbook_records)
    topic_map = {topic.topic_id: topic for topic in topics}
    playbook_map = {playbook.playbook_id: playbook for playbook in playbook_records}
    for template in ordered:
        if template.topic_id != "_records" and template.topic_id not in topic_map:
            raise CatalogError("finding template references an unknown topic")
    for playbook in playbook_records:
        known_fetches: dict[str, FetchStep] = {}
        for step in playbook.steps:
            if isinstance(step, FetchStep):
                known_fetches[step.fetch_id] = step
            elif isinstance(step, RecordAgeStep):
                fetch = known_fetches.get(step.fetch_id)
                if fetch is None:
                    raise CatalogError(
                        f"playbook has forward or unknown fetch reference: {step.fetch_id}"
                    )
                if not str(fetch.template_id).endswith("_rows_v1"):
                    raise CatalogError(
                        f"record_age step must read a rows template: {step.check_id}"
                    )
    template_map = {template.template_id: template for template in ordered}
    for topic in topics:
        for template_id in topic.finding_template_ids:
            template = template_map.get(template_id)
            if template is not None and template.topic_id != topic.topic_id:
                raise CatalogError("topic references a cross-topic finding template")
    for template in ordered:
        if not template.required_check_outcomes:
            continue
        topic = topic_map.get(template.topic_id)
        playbook = (
            playbook_map.get(topic.playbook_id)
            if topic is not None and topic.playbook_id is not None
            else None
        )
        if playbook is None or playbook.topic_id != template.topic_id:
            raise CatalogError(
                f"finding template requires checks from an unassociated playbook: "
                f"{template.template_id}"
            )
        declared: dict[str, int] = {}
        for step in playbook.steps:
            if not isinstance(step, FetchStep):
                declared[step.check_id] = declared.get(step.check_id, 0) + 1
        for requirement in template.required_check_outcomes:
            declarations = declared.get(requirement.check_id, 0)
            if declarations == 0:
                raise CatalogError(
                    f"finding template requires an undeclared playbook check: "
                    f"{template.template_id}"
                )
            if declarations > 1:
                raise CatalogError(
                    f"finding template requires a duplicated playbook check: {template.template_id}"
                )
        _validate_record_age_citations(template, playbook)


def _validate_record_age_citations(template: FindingTemplate, playbook: PlaybookDefinition) -> None:
    record_age_ids = {step.check_id for step in playbook.steps if isinstance(step, RecordAgeStep)}
    cited = [
        requirement
        for requirement in template.required_check_outcomes
        if requirement.check_id in record_age_ids
    ]
    if not cited:
        return
    disclosure_shape = (
        len(template.required_check_outcomes) == 1
        and cited[0].outcome == CheckOutcome.failed
        and template.kind == "observation"
        and list(template.allowed_evidence_kinds) == ["check"]
        and len(template.required_bindings) == 1
    )
    if not disclosure_shape:
        raise CatalogError(
            f"finding template cites a record_age check outside the failed disclosure shape: "
            f"{template.template_id}"
        )


def _reject_duplicate_playbook_ids(playbooks: Sequence[PlaybookDefinition]) -> None:
    seen: set[str] = set()
    for playbook in playbooks:
        if playbook.playbook_id in seen:
            raise CatalogError("duplicate approved playbook IDs")
        seen.add(playbook.playbook_id)


def topic_context_payload(
    pack: TopicPromptPack, templates: Sequence[FindingTemplate]
) -> dict[str, object]:
    """Return the one approved topic system payload: existing metadata plus the full catalog."""
    return {
        "topic_id": pack.topic_id,
        "language": pack.language,
        "content_sha": pack.content_sha,
        "document_section": pack.document_section,
        "internal_context": pack.internal_context,
        "missing": list(pack.missing),
        "finding_templates": [
            template.model_dump(mode="json", exclude_none=False) for template in templates
        ],
    }


def topic_context_bytes(pack: TopicPromptPack, templates: Sequence[FindingTemplate]) -> bytes:
    """Return the canonical JSON bytes of the approved topic system payload."""
    return canonical_bytes(topic_context_payload(pack, templates))


def topic_context_text(pack: TopicPromptPack, templates: Sequence[FindingTemplate]) -> str:
    """Return the exact labeled topic system text emitted before the second checkpoint."""
    return TOPIC_CONTEXT_LABEL + topic_context_bytes(pack, templates).decode("utf-8")


def _assert_topic_context_size(pack: TopicPromptPack, text: str) -> None:
    if len(text.encode("utf-8")) > MAX_TOPIC_CONTEXT_BYTES:
        raise CatalogError(f"approved topic context exceeds 65536 UTF-8 bytes: {pack.topic_id}")


def validate_topic_context(pack: TopicPromptPack, records: Iterable[FindingTemplate]) -> str:
    """Return the approved topic system text after the definition, scope and bound rules."""
    templates = validate_definitions(records)
    if not templates:
        raise CatalogError("topic has no approved finding templates")
    for template in templates:
        if template.topic_id != pack.topic_id:
            raise CatalogError(
                f"finding template is not approved for this topic: {template.template_id}"
            )
    text = topic_context_text(pack, templates)
    _assert_topic_context_size(pack, text)
    return text


def validate_prompt_contexts(
    packs: Iterable[TopicPromptPack], records: Iterable[FindingTemplate]
) -> None:
    """Validate the complete emitted topic system text for every approved language context."""
    templates = validate_definitions(records)
    for pack in packs:
        topic_templates = tuple(
            template for template in templates if template.topic_id == pack.topic_id
        )
        _assert_topic_context_size(pack, topic_context_text(pack, topic_templates))
