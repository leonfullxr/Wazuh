"""Strict candidate validation and safe bilingual template rendering."""

from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import math
import re
import string
import unicodedata
from collections.abc import Mapping
from typing import cast

from pydantic import ValidationError

from ai_soc.contracts.models import (
    CheckOutcome,
    EvidenceItem,
    EvidencePack,
    EvidenceSourceBucket,
    EvidenceSourceCount,
    EvidenceSourceRow,
    FieldId,
    Filter,
    FindingCandidate,
    FindingCandidateSet,
    FindingRelationAggregateScope,
    FindingRelationSameFetch,
    FindingRelationSameRecord,
    FindingTemplate,
    JudgmentResult,
    JudgmentState,
    RawJudgment,
    RemovedFinding,
    RemovedReason,
    RenderedFinding,
    ValidationContext,
)

MAX_FINDING_OUTPUT_BYTES = 65_536
MAX_FINDINGS = 20
MAX_FINDING_TEXT_BYTES = 8_192
MAX_BOUND_TEXT_UTF8_BYTES = 256
_BOUND_URL_PATTERN = re.compile(r"(?i)(?:https?://|www\.)")
_BOUND_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]")
_MISSING_VALUE = object()
_MAX_JSON_DEPTH = 16
_MAX_JSON_MEMBERS = 4096
_MAX_JSON_ARRAY_ITEMS = 1024


class BoundTextRejected(ValueError):
    """Bound evidence text failed the safe rendering policy."""


class FindingValidator:
    def validate(
        self, raw: RawJudgment, pack: EvidencePack, *, context: ValidationContext
    ) -> JudgmentResult:
        if not _context_matches(pack, context):
            return _terminal(JudgmentState.invalid_output, "evidence_unavailable")
        if raw.guardrail_intervened or raw.stop_reason in {
            "content_filtered",
            "guardrail_intervened",
        }:
            return _terminal(
                JudgmentState.guardrail_blocked,
                "guardrail_blocked",
                language=context.language,
            )
        if raw.stop_reason in {"max_tokens", "model_context_window_exceeded"}:
            return _terminal(JudgmentState.invalid_output, "invalid_output")
        if raw.stop_reason not in {"end_turn", "stop_sequence"}:
            return _terminal(JudgmentState.model_unavailable, "model_unavailable")
        if _duplicate_template_id(context.templates):
            return _terminal(JudgmentState.invalid_output, "invalid_output")
        try:
            encoded = raw.text.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            return _terminal(JudgmentState.invalid_output, "invalid_output")
        if len(encoded) > MAX_FINDING_OUTPUT_BYTES:
            return _terminal(JudgmentState.invalid_output, "invalid_output")
        try:
            if not _json_depth_valid(raw.text):
                return _terminal(JudgmentState.invalid_output, "invalid_output")
            member_count = 0

            def parse_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
                nonlocal member_count
                member_count += len(pairs)
                if member_count > _MAX_JSON_MEMBERS:
                    raise ValueError("finding JSON member bound exceeded")
                result: dict[str, object] = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("duplicate JSON object key")
                    result[key] = value
                return result

            document = json.loads(
                raw.text,
                parse_constant=_reject_constant,
                object_pairs_hook=parse_pairs,
            )
            if not _json_array_bounds(document):
                return _terminal(JudgmentState.invalid_output, "invalid_output")
            candidate_set = FindingCandidateSet.model_validate_json(raw.text, strict=True)
        except (json.JSONDecodeError, ValidationError, ValueError, TypeError):
            return _terminal(JudgmentState.invalid_output, "invalid_output")
        if len(candidate_set.findings) > MAX_FINDINGS:
            return _terminal(JudgmentState.invalid_output, "invalid_output")
        if not candidate_set.findings:
            return JudgmentResult(
                state=JudgmentState.no_findings,
                sentences=[],
                removed=[],
                message=_judgment_status_message(JudgmentState.no_findings, context.language),
            )

        evidence, conflicts = _evidence_index(pack)
        templates = {template.template_id: template for template in context.templates}
        rendered: list[RenderedFinding] = []
        removed: list[RemovedFinding] = []
        finding_id_counts: dict[str, int] = {}
        for candidate in candidate_set.findings:
            finding_id_counts[candidate.finding_id] = (
                finding_id_counts.get(candidate.finding_id, 0) + 1
            )
        for candidate in candidate_set.findings:
            digest = _candidate_hash(candidate)
            if finding_id_counts[candidate.finding_id] > 1:
                removed.append(_removed(candidate.finding_id, RemovedReason.duplicate_id, digest))
                continue
            reason = _validate_candidate(candidate, pack, context, evidence, conflicts, templates)
            if reason is not None:
                removed.append(_removed(candidate.finding_id, reason, digest))
                continue
            template = templates[candidate.template_id]
            try:
                text = _render(template, candidate, evidence, context.language)
            except BoundTextRejected:
                removed.append(
                    _removed(candidate.finding_id, RemovedReason.unsupported_value, digest)
                )
                continue
            except (KeyError, ValueError, UnicodeError):
                removed.append(
                    _removed(candidate.finding_id, RemovedReason.unknown_template, digest)
                )
                continue
            if len(text.encode("utf-8")) > MAX_FINDING_TEXT_BYTES:
                removed.append(_removed(candidate.finding_id, RemovedReason.invalid_schema, digest))
                continue
            rendered.append(
                RenderedFinding(
                    finding_id=candidate.finding_id,
                    kind=candidate.kind,
                    text=text,
                    evidence_ids=candidate.evidence_ids,
                )
            )
        if rendered:
            return JudgmentResult(
                state=JudgmentState.validated, sentences=rendered, removed=removed
            )
        return JudgmentResult(state=JudgmentState.all_removed, sentences=[], removed=removed)


def _context_matches(pack: EvidencePack, context: ValidationContext) -> bool:
    if pack.topic_id != context.topic_pack.topic_id:
        return False
    if (
        pack.content_sha != context.content_sha
        or pack.content_sha != context.topic_pack.content_sha
    ):
        return False
    if pack.policy_hash != context.policy_hash or pack.topic_id != context.topic_pack.topic_id:
        return False
    if context.language != context.topic_pack.language:
        return False
    if tuple(pack.checks) != tuple(context.expected_checks):
        return False
    return True


def _duplicate_template_id(templates: tuple[FindingTemplate, ...]) -> bool:
    seen: set[str] = set()
    for template in templates:
        if template.template_id in seen:
            return True
        seen.add(template.template_id)
    return False


def _evidence_index(pack: EvidencePack) -> tuple[dict[str, EvidenceItem], set[str]]:
    indexed: dict[str, EvidenceItem] = {}
    conflicts: set[str] = set()
    for item in pack.items:
        current = indexed.get(item.evidence_id)
        if current is not None and current != item:
            conflicts.add(item.evidence_id)
        else:
            indexed[item.evidence_id] = item
    return indexed, conflicts


def _validate_candidate(
    candidate: FindingCandidate,
    pack: EvidencePack,
    context: ValidationContext,
    evidence: Mapping[str, EvidenceItem],
    conflicts: set[str],
    templates: Mapping[str, FindingTemplate],
) -> RemovedReason | None:
    cited = set(candidate.evidence_ids)
    bound_ids = {binding.evidence_id for binding in candidate.bindings.values()}
    if len(cited) != len(candidate.evidence_ids) or cited != bound_ids:
        return RemovedReason.bad_binding
    if any(evidence_id in conflicts for evidence_id in cited):
        return RemovedReason.bad_binding
    if any(evidence_id not in evidence for evidence_id in cited):
        return RemovedReason.unknown_evidence
    items = {key: evidence[key] for key in cited}
    if any(item.topic_id != pack.topic_id for item in items.values()):
        return RemovedReason.cross_topic
    template = templates.get(candidate.template_id)
    if template is None or template.topic_id != pack.topic_id:
        return RemovedReason.unknown_template
    if template.kind != candidate.kind:
        return RemovedReason.invalid_schema
    if set(candidate.bindings) != set(template.required_bindings):
        return RemovedReason.bad_binding
    for binding_id, allowed_fields in template.required_bindings.items():
        binding = candidate.bindings[binding_id]
        if binding.field not in allowed_fields:
            return RemovedReason.bad_binding
        item = evidence.get(binding.evidence_id)
        if item is None:
            return RemovedReason.unknown_evidence
        if item.kind not in template.allowed_evidence_kinds:
            return RemovedReason.unsupported_value
        if not _supported_value(item, binding.field):
            return RemovedReason.unsupported_value
    if not _template_placeholders_valid(template):
        return RemovedReason.unknown_template
    required_check_ids = {item.check_id for item in template.required_check_outcomes}
    for binding in candidate.bindings.values():
        item = evidence[binding.evidence_id]
        if item.kind == "check" and item.check_id not in required_check_ids:
            return RemovedReason.bad_binding
    for requirement in template.required_check_outcomes:
        matched = [
            check for check in context.expected_checks if check.check_id == requirement.check_id
        ]
        if len(matched) != 1 or matched[0].outcome != requirement.outcome:
            return RemovedReason.failed_prerequisite
    for relation in template.relations:
        if not _relation_holds(relation, candidate, evidence):
            return RemovedReason.bad_relation
    if _has_nonfinite_binding(candidate, evidence):
        return RemovedReason.unsupported_value
    return None


def _supported_value(item: EvidenceItem, field: FieldId | str) -> bool:
    key = field.value if isinstance(field, FieldId) else field
    value = _value_for(item, key)
    if value is _MISSING_VALUE:
        return False
    if value is None:
        return False
    if key == "count":
        if not isinstance(value, int) or isinstance(value, bool):
            return False
        if item.values.get("approximate", False) is True or item.values.get("relation") != "eq":
            return False
        return True
    if key == "outcome":
        return isinstance(value, str) and value in {outcome.value for outcome in CheckOutcome}
    if key == "matched_nothing":
        return isinstance(value, list) and all(
            isinstance(member, str) and member in {field_id.value for field_id in FieldId}
            for member in cast(list[object], value)
        )
    if field == FieldId.rule_level:
        return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 16
    if field == FieldId.vulnerability_severity:
        return isinstance(value, str) and value in {"Critical", "High", "Medium", "Low"}
    if field in {FieldId.data_srcip, FieldId.data_dstip}:
        if not isinstance(value, str):
            return False
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return False
        return True
    if field == FieldId.vulnerability_id:
        return isinstance(value, str) and re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", value) is not None
    if field in {FieldId.timestamp, FieldId.vulnerability_detected_at}:
        if not isinstance(value, str):
            return False
        try:
            from datetime import datetime

            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return False
        return parsed.tzinfo is not None and parsed.utcoffset() is not None
    if field == FieldId.rule_groups:
        return isinstance(value, list) and all(
            isinstance(item, str) for item in cast(list[object], value)
        )
    return isinstance(value, str)


def _field_key(field: FieldId | str) -> str:
    return field.value if isinstance(field, FieldId) else field


def _value_for(item: EvidenceItem, name: str) -> object:
    for field, value in item.values.items():
        key = _field_key(field)
        if key == name:
            return value
    return _MISSING_VALUE


def _relation_holds(
    relation: FindingRelationSameRecord | FindingRelationSameFetch | FindingRelationAggregateScope,
    candidate: FindingCandidate,
    evidence: Mapping[str, EvidenceItem],
) -> bool:
    if isinstance(relation, FindingRelationSameRecord):
        bound = [candidate.bindings.get(binding_id) for binding_id in relation.bindings]
        if not bound or any(binding is None for binding in bound):
            return False
        items: list[EvidenceItem] = []
        for binding in bound:
            if binding is None:
                return False
            item = evidence.get(binding.evidence_id)
            if item is None or item.kind != "row" or not isinstance(item.source, EvidenceSourceRow):
                return False
            items.append(item)
        first = items[0]
        if not isinstance(first.source, EvidenceSourceRow):
            return False
        first_snapshot = first.snapshot.key
        for item in items[1:]:
            if not isinstance(item.source, EvidenceSourceRow):
                return False
            if item.source != first.source or item.snapshot.key != first_snapshot:
                return False
        return True
    if isinstance(relation, FindingRelationSameFetch):
        bound = [candidate.bindings.get(binding_id) for binding_id in relation.bindings]
        if not bound or any(binding is None for binding in bound):
            return False
        fetch_ids: set[str] = set()
        snapshot_keys: set[str] = set()
        for binding in bound:
            if binding is None:
                return False
            item = evidence.get(binding.evidence_id)
            if item is None or item.fetch_id is None:
                return False
            fetch_ids.add(item.fetch_id)
            snapshot_keys.add(item.snapshot.key)
        return len(fetch_ids) == 1 and len(snapshot_keys) == 1
    count_binding = candidate.bindings.get(relation.count_binding)
    if count_binding is None:
        return False
    count_item = evidence.get(count_binding.evidence_id)
    if count_item is None or count_binding.field != "count" or count_item.kind != "aggregate":
        return False
    if not _supported_value(count_item, "count"):
        return False
    if not relation.entity_bindings:
        return False
    if count_item.fetch_id is None:
        return False
    count_snapshot = count_item.snapshot.key
    for binding_id, expected_field in relation.entity_bindings.items():
        binding = candidate.bindings.get(binding_id)
        if binding is None or _field_key(binding.field) != _field_key(expected_field):
            return False
        entity = evidence.get(binding.evidence_id)
        if (
            entity is None
            or entity.kind != "row"
            or entity.fetch_id != count_item.fetch_id
            or entity.snapshot.key != count_snapshot
        ):
            return False
        if not _aggregate_entity_proven(count_item, entity, expected_field):
            return False
    return True


def _aggregate_entity_proven(
    count_item: EvidenceItem, entity: EvidenceItem, field: FieldId | str
) -> bool:
    field_key = _field_key(field)
    entity_value = _value_for(entity, field_key)
    if entity_value is _MISSING_VALUE:
        return False
    source = count_item.source
    if isinstance(source, EvidenceSourceBucket):
        if _field_key(source.group_field) != field_key:
            return False
        return source.key == entity_value or str(source.key) == str(entity_value)
    if isinstance(source, EvidenceSourceCount):
        return _filters_prove_entity_value(source.filters, field_key, entity_value)
    return False


def _filters_prove_entity_value(
    filters: list[Filter], field_key: str, entity_value: object
) -> bool:
    for raw_filter in filters:
        if _field_key(raw_filter.field) != field_key or raw_filter.op != "eq":
            continue
        if raw_filter.value == entity_value:
            return True
    return False


def _has_nonfinite_binding(
    candidate: FindingCandidate, evidence: Mapping[str, EvidenceItem]
) -> bool:
    for binding in candidate.bindings.values():
        item = evidence.get(binding.evidence_id)
        if item is None:
            continue
        key = binding.field.value if isinstance(binding.field, FieldId) else binding.field
        value = _value_for(item, key)
        if isinstance(value, float) and not math.isfinite(value):
            return True
    return False


def _render(
    template: FindingTemplate,
    candidate: FindingCandidate,
    evidence: Mapping[str, EvidenceItem],
    language: str,
) -> str:
    source = template.texts.en if language == "en" else template.texts.es
    values: dict[str, str] = {}
    for binding_id, binding in candidate.bindings.items():
        item = evidence[binding.evidence_id]
        key = binding.field.value if isinstance(binding.field, FieldId) else binding.field
        raw = _value_for(item, key)
        if raw is _MISSING_VALUE:
            raise ValueError("approved binding value is absent")
        display_text = _bound_display_text(raw)
        literal = html.escape(display_text, quote=True)
        field_key = key.value if isinstance(key, FieldId) else key
        if field_key in {FieldId.agent_name.value, FieldId.package_name.value}:
            literal = literal.replace("\\", "\\\\").replace("⟦", "\\⟦").replace("⟧", "\\⟧")
            literal = f"⟦{literal}⟧"
        values[binding_id] = literal
    expected = set(template.required_bindings)
    if not expected.issubset(values):
        raise ValueError("template is missing one or more bound values")
    return source.format_map(values)


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


def _display(value: object) -> str:
    if isinstance(value, list):
        return ", ".join(_display(item) for item in cast(list[object], value))
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _bound_display_text(value: object) -> str:
    text = _display(value)
    encoded = text.encode("utf-8")
    if len(encoded) > MAX_BOUND_TEXT_UTF8_BYTES:
        raise BoundTextRejected("bound text exceeds length limit")
    if _BOUND_URL_PATTERN.search(text):
        raise BoundTextRejected("bound text contains URL-like content")
    if _BOUND_CONTROL_CHARS.search(text):
        raise BoundTextRejected("bound text contains control characters")
    if any(unicodedata.category(char) in {"Cc", "Cf", "Zl", "Zp"} for char in text):
        raise BoundTextRejected("bound text contains line or format separators")
    return text


def _judgment_status_message(state: JudgmentState, language: str) -> str | None:
    catalog: dict[JudgmentState, dict[str, str]] = {
        JudgmentState.no_findings: {
            "en": "No supported findings were produced for this topic.",
            "es": "No se produjeron hallazgos admitidos para este tema.",
        },
        JudgmentState.guardrail_blocked: {
            "en": "The judgment was suppressed by the safety guardrail.",
            "es": "El juicio fue bloqueado por la barrera de seguridad.",
        },
    }
    localized = catalog.get(state)
    if localized is None:
        return None
    return localized.get(language, localized["en"])


def _candidate_hash(candidate: FindingCandidate) -> str:
    canonical = json.dumps(
        candidate.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _removed(finding_id: str, reason: RemovedReason, digest: str) -> RemovedFinding:
    return RemovedFinding(finding_id=finding_id, reason=reason, candidate_sha256=digest)


def _terminal(state: JudgmentState, reason: str, *, language: str = "en") -> JudgmentResult:
    # Left-out state is conveyed by the application through this deterministic
    # status helper; JudgmentResult intentionally remains the frozen wire model.
    return JudgmentResult(
        state=state,
        sentences=[],
        removed=[],
        message=_judgment_status_message(state, language),
    )


def _reject_constant(value: str) -> None:
    raise ValueError(f"nonfinite JSON token: {value}")


def _json_depth_valid(text: str) -> bool:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > _MAX_JSON_DEPTH:
                return False
        elif character in "]}":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0 and not in_string


def _json_array_bounds(value: object) -> bool:
    pending: list[object] = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            pending.extend(cast(dict[str, object], current).values())
        elif isinstance(current, list):
            values = cast(list[object], current)
            if len(values) > _MAX_JSON_ARRAY_ITEMS:
                return False
            pending.extend(values)
    return True
