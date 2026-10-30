"""Validate factual template selections and render them in controlled language."""

from __future__ import annotations

import html
import json
from collections.abc import Mapping
from decimal import Decimal
from hashlib import sha256
from typing import Any, Literal, cast
from uuid import UUID

from ai_soc.validation.findings import (
    BoundTextRejected,
)
from ai_soc.validation.findings import (
    _bound_display_text as _shared_bound_text,  # pyright: ignore[reportPrivateUsage]
)
from ai_soc.workspace.model.schemas import (
    NARRATIVE_SELECTION_ADAPTER,
    AlertFact,
    CitationReference,
    FrozenIncidentPack,
    GroupFact,
    MemberCountSelection,
    MemberScoreSelection,
    MissingScoresSelection,
    NarrativeSelection,
    OmittedAlertsSelection,
    RemovedSelection,
    RuleObservedSelection,
    ValidatedNarrative,
)

MAX_OUTPUT_BYTES = 32 * 1024


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite number")


def _digest_selection(value: object) -> str:
    try:
        encoded = json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    except (TypeError, ValueError, UnicodeError):
        encoded = type(value).__name__.encode("ascii", "replace")
    return sha256(encoded).hexdigest()


def _static_result(pack: FrozenIncidentPack, error: str) -> ValidatedNarrative:
    return ValidatedNarrative(
        status="invalid_structure",
        pack_digest=pack.content_digest,
        selections=(),
        citations=(),
        removals=(),
        label_en="Unvalidated AI summary",
        label_es="Resumen de IA no validado",
        rendered_en="",
        rendered_es="",
        static_error=error,  # type: ignore[arg-type]
    )


def _bindings(
    selection: NarrativeSelection,
    *,
    pack: FrozenIncidentPack,
    groups: dict[str, GroupFact],
    alerts: dict[str, AlertFact],
) -> tuple[bool, str | None, CitationReference | None]:
    incident_id = pack.incident_reference.reference_id
    if isinstance(selection, MemberCountSelection):
        if selection.incident_reference_id != incident_id:
            return False, "unknown_citation", None
        if selection.count != pack.coverage.membership_count:
            return False, "incorrect_binding", None
        return True, None, CitationReference(kind="incident", fact_id=incident_id)
    if isinstance(selection, MemberScoreSelection):
        fact = groups.get(selection.group_fact_id)
        if fact is None:
            return False, "unknown_citation", None
        if fact.score is None:
            return False, "incorrect_binding", None
        if selection.group_id != fact.group_id or selection.score != fact.score:
            return False, "incorrect_binding", None
        return True, None, CitationReference(kind="group", fact_id=fact.fact_id)
    if isinstance(selection, RuleObservedSelection):
        fact = alerts.get(selection.alert_fact_id)
        if fact is None:
            return False, "unknown_citation", None
        binding = (selection.group_id, selection.rule_id, selection.agent_id, selection.event_at)
        expected = (fact.group_id, fact.rule_id, fact.agent_id, fact.event_at)
        if fact.rule_id is None or binding != expected:
            return False, "incorrect_binding", None
        return True, None, CitationReference(kind="alert", fact_id=fact.fact_id)
    if isinstance(selection, MissingScoresSelection):
        if selection.incident_reference_id != incident_id:
            return False, "unknown_citation", None
        if selection.count != pack.coverage.score_unknown_count or selection.count == 0:
            return False, "incorrect_binding", None
        return True, None, CitationReference(kind="incident", fact_id=incident_id)
    if selection.incident_reference_id != incident_id:
        return False, "unknown_citation", None
    if selection.count != pack.coverage.omitted_alert_facts or selection.count == 0:
        return False, "incorrect_binding", None
    return True, None, CitationReference(kind="incident", fact_id=incident_id)


def _selection_key(selection: NarrativeSelection) -> tuple[str, str]:
    if isinstance(
        selection, (MemberCountSelection, MissingScoresSelection, OmittedAlertsSelection)
    ):
        return selection.template, selection.incident_reference_id
    if isinstance(selection, MemberScoreSelection):
        return selection.template, selection.group_fact_id
    return selection.template, selection.alert_fact_id


def _safe_scalar(value: str) -> str:
    return html.escape(value, quote=True)


def _validate_rendered_text(selection: NarrativeSelection) -> None:
    if isinstance(selection, MemberScoreSelection):
        _shared_bound_text(selection.group_id)
    elif isinstance(selection, RuleObservedSelection):
        _shared_bound_text(selection.group_id)
        _shared_bound_text(selection.rule_id)
        if selection.agent_id is not None:
            _shared_bound_text(selection.agent_id)


def _render(selection: NarrativeSelection) -> tuple[str, str]:
    if isinstance(selection, MemberCountSelection):
        return (
            f"The incident contains {selection.count} evidence groups.",
            f"El incidente contiene {selection.count} grupos de evidencia.",
        )
    if isinstance(selection, MemberScoreSelection):
        group = _safe_scalar(selection.group_id)
        score = format(Decimal(str(selection.score)), "f")
        if "." in score:
            score = score.rstrip("0").rstrip(".")
        return (
            f"Group {group} has a recorded score of {score}.",
            f"El grupo {group} tiene una puntuación registrada de {score}.",
        )
    if isinstance(selection, RuleObservedSelection):
        rule = _safe_scalar(selection.rule_id)
        event_at = selection.event_at.isoformat()
        if selection.agent_id is None:
            return (
                f"Rule {rule} was observed at {event_at}.",
                f"La regla {rule} se observó a las {event_at}.",
            )
        agent = _safe_scalar(selection.agent_id)
        return (
            f"Rule {rule} was observed on agent {agent} at {event_at}.",
            f"La regla {rule} se observó en el agente {agent} a las {event_at}.",
        )
    if isinstance(selection, MissingScoresSelection):
        return (
            f"A score is unavailable for {selection.count} evidence groups.",
            f"No hay puntuación disponible para {selection.count} grupos de evidencia.",
        )
    return (
        f"{selection.count} alert facts were omitted from this evidence pack.",
        f"Se omitieron {selection.count} datos de alerta de este paquete de evidencia.",
    )


def validate_incident_narrative(
    raw_json: str | bytes,
    *,
    expected_site_id: str,
    expected_incident_id: UUID,
    expected_revision_id: UUID,
    pack: FrozenIncidentPack,
) -> ValidatedNarrative:
    """Validate JSON-only template selections against one exact frozen pack.

    Invalid structure produces a static terminal result. Invalid individual
    selections are removed with only a static reason and digest retained.
    """
    if (
        pack.site_id != expected_site_id
        or pack.incident_id != expected_incident_id
        or pack.incident_revision_id != expected_revision_id
    ):
        return _static_result(pack, "pack_identity_mismatch")
    if isinstance(raw_json, str):
        try:
            raw = raw_json.encode("utf-8")
        except UnicodeError:
            return _static_result(pack, "invalid_json")
    else:
        raw = raw_json
    if len(raw) > MAX_OUTPUT_BYTES:
        return _static_result(pack, "output_too_large")
    try:
        payload = json.loads(
            raw,
            object_pairs_hook=_json_pairs,
            parse_constant=_reject_constant,
        )
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return _static_result(pack, "invalid_json")
    if not isinstance(payload, dict):
        return _static_result(pack, "invalid_envelope")
    envelope = cast(Mapping[str, object], payload)
    if set(envelope) != {"selections"}:
        return _static_result(pack, "invalid_envelope")
    raw_selections = envelope["selections"]
    if not isinstance(raw_selections, list):
        return _static_result(pack, "invalid_envelope")
    selection_items = cast(list[object], raw_selections)
    if len(selection_items) > 8:
        return _static_result(pack, "invalid_envelope")

    group_by_id = {fact.fact_id: fact for fact in pack.group_facts}
    alert_by_id = {fact.fact_id: fact for fact in pack.alert_facts}
    accepted: list[NarrativeSelection] = []
    citations: list[CitationReference] = []
    removals: list[RemovedSelection] = []
    seen: set[tuple[str, str]] = set()
    for item in selection_items:
        item_digest = _digest_selection(item)
        try:
            item_json = json.dumps(item, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
            selection = NARRATIVE_SELECTION_ADAPTER.validate_json(item_json, strict=True)
        except (ValueError, TypeError, UnicodeError):
            removals.append(
                RemovedSelection(reason="invalid_selection", selection_digest=item_digest)
            )
            continue
        unique_key = _selection_key(selection)
        if unique_key in seen:
            removals.append(
                RemovedSelection(reason="duplicate_selection", selection_digest=item_digest)
            )
            continue
        seen.add(unique_key)
        valid, reason, citation = _bindings(
            selection, pack=pack, groups=group_by_id, alerts=alert_by_id
        )
        if not valid or citation is None:
            removals.append(
                RemovedSelection(
                    reason=cast(
                        Literal[
                            "invalid_selection",
                            "unknown_citation",
                            "incorrect_binding",
                            "duplicate_selection",
                        ],
                        reason or "incorrect_binding",
                    ),
                    selection_digest=item_digest,
                )
            )
            continue
        try:
            _validate_rendered_text(selection)
        except BoundTextRejected:
            removals.append(
                RemovedSelection(reason="invalid_selection", selection_digest=item_digest)
            )
            continue
        accepted.append(selection)
        citations.append(citation)
    rendered = [_render(selection) for selection in accepted]
    status = "validated" if accepted else "all_removed"
    return ValidatedNarrative(
        status=status,
        pack_digest=pack.content_digest,
        selections=tuple(accepted),
        citations=tuple(citations),
        removals=tuple(removals),
        label_en="Unvalidated AI summary",
        label_es="Resumen de IA no validado",
        rendered_en=" ".join(sentence[0] for sentence in rendered),
        rendered_es=" ".join(sentence[1] for sentence in rendered),
        static_error=None,
    )
