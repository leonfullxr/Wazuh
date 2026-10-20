"""Deterministic bounded EN/ES query grammar; never calls a model or backend."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC
from typing import Literal, cast
from uuid import uuid4

from ai_soc.contracts.canonical import canonical_bytes
from ai_soc.contracts.models import (
    AliasDefinition,
    AskRequest,
    Clarified,
    Clarify,
    Effort,
    FetchSpec,
    FieldId,
    Filter,
    FollowupRecord,
    GroupField,
    MatchedSpan,
    Planned,
    PlanProvenance,
    PolicyHash,
    QuestionPlan,
    Refused,
    TemplateId,
    TopicPlan,
    VerifiedPrincipal,
)
from ai_soc.contracts.ports import Clock, ContentCatalog
from ai_soc.planning.followup_routing import window_only_followup
from ai_soc.planning.windows import WindowParseError, parse_window


@dataclass(frozen=True, slots=True)
class _Hit:
    start: int
    end: int
    identifier: str
    language: str
    kind: str
    topic_id: str | None = None


@dataclass(slots=True)
class _Clause:
    start: int
    end: int
    text: str
    cues: list[_Hit]
    aliases: list[_Hit]


@dataclass(slots=True)
class _TopicWork:
    document: bool
    failure: bool
    judgment: bool
    fetches: list[FetchSpec]
    cues: list[str]
    aliases: list[str]


_DEFAULT_CUES = (
    ("fetch_show_en", "en", "show", "fetch", None),
    ("fetch_fetch_en", "en", "fetch", "fetch", None),
    ("fetch_alerts_en", "en", "alerts", "fetch", None),
    ("fetch_records_en", "en", "records", "fetch", None),
    ("fetch_count_en", "en", "count", "fetch", None),
    ("fetch_how_many_en", "en", "how many", "fetch", None),
    ("fetch_last_en", "en", "last", "fetch", None),
    ("fetch_agent_en", "en", "agent", "fetch", None),
    ("fetch_show_es", "es", "muestra", "fetch", None),
    ("fetch_mostrar_es", "es", "mostrar", "fetch", None),
    ("fetch_alertas_es", "es", "alertas", "fetch", None),
    ("fetch_registros_es", "es", "registros", "fetch", None),
    ("fetch_cuenta_es", "es", "cuenta", "fetch", None),
    ("fetch_cuantas_es", "es", "cuántas", "fetch", None),
    ("fetch_ultimos_es", "es", "últimos", "fetch", None),
    ("fetch_agente_es", "es", "agente", "fetch", None),
    ("judgment_recommend_en", "en", "recommend", "judgment", None),
    ("judgment_fix_en", "en", "what should i fix", "judgment", None),
    ("judgment_assess_en", "en", "assess", "judgment", None),
    ("judgment_think_en", "en", "what do you think", "judgment", None),
    ("judgment_recommend_es", "es", "recomienda", "judgment", None),
    ("judgment_recommend_es_subj", "es", "recomiendes", "judgment", None),
    ("judgment_fix_es", "es", "qué debería corregir", "judgment", None),
    ("judgment_assess_es", "es", "evalúa", "judgment", None),
    ("judgment_think_es", "es", "qué opinas", "judgment", None),
    ("failure_failing_en", "en", "failing", "failure", None),
    ("failure_failed_en", "en", "failed", "failure", None),
    ("failure_broken_en", "en", "broken", "failure", None),
    ("failure_working_en", "en", "not working", "failure", None),
    ("failure_falla_es", "es", "falla", "failure", None),
    ("failure_fallando_es", "es", "fallando", "failure", None),
    ("failure_roto_es", "es", "roto", "failure", None),
    ("failure_no_funciona_es", "es", "no funciona", "failure", None),
    ("keep_en", "en", "keep those alerts", "keep", None),
    ("keep_en_records", "en", "use the previous records", "keep", None),
    ("keep_es", "es", "conserva esas alertas", "keep", None),
    ("keep_es_records", "es", "usa los registros anteriores", "keep", None),
    ("continue_en", "en", "continue the left-out", "continue", None),
    ("continue_es", "es", "continúa los juicios pendientes", "continue", None),
)

_QUOTES = (('"', '"'), ("'", "'"), ("`", "`"), ("“", "”"), ("‘", "’"))
_FILTER_PATTERNS: tuple[tuple[FieldId, re.Pattern[str], Literal["eq", "gte"]], ...] = (
    (
        FieldId.agent_id,
        re.compile(r"\b(?:agent|agente)\s+(?:id\s+|id\s*=\s*)([A-Za-z0-9_.-]+)", re.I),
        "eq",
    ),
    (
        FieldId.agent_name,
        re.compile(r"\b(?:agent|agente)\s+(?:name|nombre)\s+(['\"])(.*?)\1", re.I),
        "eq",
    ),
    (FieldId.rule_id, re.compile(r"\b(?:rule|regla)\s+id\s+([A-Za-z0-9_.-]+)", re.I), "eq"),
    (
        FieldId.rule_level,
        re.compile(r"\b(?:level|nivel)\s+(?:at least|al menos|=)\s*(\d+)\b", re.I),
        "gte",
    ),
    (FieldId.data_srcip, re.compile(r"\b(?:source IP|IP origen)\s+([0-9a-fA-F:.]+)\b", re.I), "eq"),
    (
        FieldId.data_dstip,
        re.compile(r"\b(?:destination IP|IP destino)\s+([0-9a-fA-F:.]+)\b", re.I),
        "eq",
    ),
    (FieldId.vulnerability_id, re.compile(r"\b(CVE-\d{4}-\d{4,})\b", re.I), "eq"),
    (
        FieldId.rule_groups,
        re.compile(r"\b(?:group|grupo)\s+(?!by\b|por\b)([a-z][a-z0-9_-]{0,63})\b", re.I),
        "eq",
    ),
    (
        FieldId.vulnerability_severity,
        re.compile(
            r"\b(?:vulnerability )?severity\s+(?:is\s+|=\s*)(low|medium|high|critical)\b",
            re.I,
        ),
        "eq",
    ),
)

_REVIEWED_GROUPS = frozenset(
    {"authentication_failed", "authentication_success", "firewall", "sshd", "syscheck"}
)


def _fold(text: str) -> str:
    result: list[str] = []
    for char in unicodedata.normalize("NFKC", text).casefold():
        decomposed = unicodedata.normalize("NFKD", char)
        result.extend(piece for piece in decomposed if not unicodedata.combining(piece))
    return "".join(result)


def _fold_with_offsets(text: str) -> tuple[str, list[int], list[int]]:
    folded: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    index = 0
    while index < len(text):
        stop = index + 1
        while stop < len(text) and unicodedata.combining(text[stop]):
            stop += 1
        normalized = unicodedata.normalize("NFKC", text[index:stop]).casefold()
        expanded = "".join(
            value
            for char in normalized
            for value in unicodedata.normalize("NFKD", char)
            if not unicodedata.combining(value)
        )
        folded.extend(expanded)
        starts.extend([index] * len(expanded))
        ends.extend([stop] * len(expanded))
        index = stop
    return "".join(folded), starts, ends


def protect_quoted(text: str) -> tuple[str, list[tuple[int, int]]]:
    chars = list(text)
    protected: list[tuple[int, int]] = []
    index = 0
    while index < len(text):
        pair = next(
            ((opening, closing) for opening, closing in _QUOTES if text.startswith(opening, index)),
            None,
        )
        if pair is None:
            index += 1
            continue
        opening, closing = pair
        end = text.find(closing, index + len(opening))
        if end < 0:
            end = len(text)
        stop = min(len(text), end + len(closing))
        if opening == "'" and index > 0 and text[index - 1].isalnum():
            index += 1
            continue
        protected.append((index, stop))
        for position in range(index, stop):
            chars[position] = " "
        index = stop
    for match in re.finditer(r"```.*?```|^\s*\|.*\|\s*$", "".join(chars), re.S | re.M):
        protected.append(match.span())
        for position in range(*match.span()):
            chars[position] = " "
    return "".join(chars), protected


def phrase_hits(text: str, entries: Sequence[tuple[str, str, str, str, str | None]]) -> list[_Hit]:
    folded, start_offsets, end_offsets = _fold_with_offsets(text)
    hits: list[_Hit] = []
    for identifier, language, phrase, kind, topic_id in sorted(
        entries, key=lambda e: len(_fold(e[2])), reverse=True
    ):
        needle = _fold(phrase)
        if not needle:
            continue
        pattern = re.compile(r"(?<![\w])" + re.escape(needle) + r"(?![\w])", re.UNICODE)
        for match in pattern.finditer(folded):
            hits.append(
                _Hit(
                    start_offsets[match.start()],
                    end_offsets[match.end() - 1],
                    identifier,
                    language,
                    kind,
                    topic_id,
                )
            )
    hits.sort(key=lambda hit: (-(hit.end - hit.start), hit.start, hit.identifier))
    chosen: list[_Hit] = []
    for hit in hits:
        if any(hit.start < prior.end and prior.start < hit.end for prior in chosen):
            continue
        chosen.append(hit)
    return sorted(chosen, key=lambda hit: (hit.start, hit.end, hit.identifier))


def entry_tables(
    catalog: ContentCatalog,
) -> tuple[list[tuple[str, str, str, str, str | None]], list[AliasDefinition]]:
    cues = catalog.cues()
    cue_entries: list[tuple[str, str, str, str, str | None]] = [
        (str(cue.cue_id), cue.language, cue.text, cue.kind, None) for cue in cues.cues
    ]
    known = {entry[0] for entry in cue_entries}
    cue_entries.extend(item for item in _DEFAULT_CUES if item[0] not in known)
    aliases = [alias for topic in catalog.topics() for alias in topic.aliases]
    aliases.extend(cues.aliases)
    deduplicated: dict[str, AliasDefinition] = {alias.alias_id: alias for alias in aliases}
    return cue_entries, list(deduplicated.values())


def has_deterministic_route(question: str, catalog: ContentCatalog, language: str) -> bool:
    """Whether a reviewed cue or alias should keep deterministic planning in charge."""
    if language not in {"en", "es"}:
        return True
    unquoted, _spans = protect_quoted(question)
    cue_entries, aliases = entry_tables(catalog)
    return bool(phrase_hits(unquoted, cue_entries)) or bool(_alias_matches(unquoted, aliases, []))


def _cue_matches(text: str, definitions: list[tuple[str, str, str, str, str | None]]) -> list[_Hit]:
    hits = phrase_hits(text, definitions)
    # Built-in recognized negation suppresses only the immediately negated cue.
    accepted: list[_Hit] = []
    for hit in hits:
        before = _fold(text[: hit.start]).rstrip()
        if hit.kind == "judgment" and re.search(r"(?:\bdo not|\bdon't|\bno)$", before):
            continue
        if (
            hit.kind == "failure"
            and hit.identifier.startswith("failure_")
            and (
                "not " in _fold(text[hit.start : hit.end])
                or "no " in _fold(text[hit.start : hit.end])
            )
        ):
            pass
        accepted.append(hit)
    return accepted


def _alias_matches(
    text: str, aliases: list[AliasDefinition], protected: list[tuple[int, int]]
) -> list[_Hit]:
    raw = [
        (str(alias.alias_id), alias.language, alias.text, "alias", str(alias.topic_id))
        for alias in aliases
    ]
    return [
        hit
        for hit in phrase_hits(text, raw)
        if not any(a <= hit.start < b or a < hit.end <= b for a, b in protected)
    ]


def _clauses(text: str) -> list[tuple[int, int, str]]:
    # Sentence punctuation and semicolons scope cues. Coordinating commas remain in one clause.
    spans: list[tuple[int, int, str]] = []
    start = 0
    for match in re.finditer(r";+|[!?]+(?=\s|$)|(?<!\d)\.(?!\d)(?=\s|$)|\n+", text):
        if text[start : match.start()].strip():
            spans.append((start, match.start(), text[start : match.start()]))
        start = match.end()
    if text[start:].strip():
        spans.append((start, len(text), text[start:]))
    return spans


def _filter_match_outside_quotes(
    literal_clause: str, pattern: re.Pattern[str]
) -> re.Match[str] | None:
    _, quote_ranges = protect_quoted(literal_clause)
    for match in pattern.finditer(literal_clause):
        if any(start <= match.start() and match.end() <= end for start, end in quote_ranges):
            continue
        return match
    return None


def _filters(protected_clause: str, *, literal_clause: str) -> list[Filter]:
    filters: list[Filter] = []
    consumed: list[tuple[int, int]] = []
    for field, pattern, op in _FILTER_PATTERNS:
        if field in {FieldId.agent_id, FieldId.agent_name}:
            match = _filter_match_outside_quotes(literal_clause, pattern)
        else:
            match = pattern.search(protected_clause)
        if match:
            consumed.append(match.span())
            raw_value = match.group(2) if field == FieldId.agent_name else match.group(1)
            value: str | int = raw_value
            actual_op = op
            if field == FieldId.rule_level:
                value = int(raw_value)
                if re.search(r"\b(?:level|nivel)\s*=", match.group(0), re.I):
                    actual_op = "eq"
            elif field in {FieldId.data_srcip, FieldId.data_dstip}:
                value = str(ipaddress.ip_address(raw_value))
            elif field == FieldId.vulnerability_id:
                value = raw_value.upper()
            elif field == FieldId.rule_groups:
                value = raw_value.casefold()
                if value not in _REVIEWED_GROUPS:
                    raise ValueError("group is not in the reviewed filter vocabulary")
            elif field == FieldId.vulnerability_severity:
                value = raw_value.casefold()
            filters.append(Filter(field=field, op=actual_op, value=value))
    unsupported_filters = re.finditer(
        r"\b(?:agent|agente)\s+(?:id|name|nombre)\b|\b(?:rule|regla)\s+id\b|"
        r"\b(?:level|nivel)\s+(?:at least|al menos|=)|\b(?:group|grupo)\s+"
        r"(?!by\b|por\b)\w+|\b(?:source IP|destination IP|IP origen|IP destino)\b|"
        r"\bCVE-\w+|\b(?:vulnerability )?severity\b",
        protected_clause,
        re.I,
    )
    if any(
        not any(start <= match.start() and match.end() <= end for start, end in consumed)
        for match in unsupported_filters
    ):
        raise ValueError("unsupported filter syntax")
    if len(filters) > 10:
        raise ValueError("request exceeds the maximum filter count")
    return filters


def _clause_window_scope(clause: _Clause, *, timezone: str, clock: Clock) -> str | None:
    try:
        parsed = parse_window(clause.text, anchor_at=clock.now(), timezone=timezone)
        return parsed.window.source_text
    except WindowParseError:
        return None


def _fetch_options(
    text: str,
) -> tuple[int | None, Literal["latest", "earliest"], GroupField | None, str | None, bool]:
    folded = _fold(text)
    order: Literal["latest", "earliest"] | None = None
    if re.search(r"\b(?:earliest|mas antiguos)\b", folded):
        order = "earliest"
    if re.search(r"\b(?:latest|mas recientes)\b", folded):
        if order is not None:
            raise ValueError("conflicting order cues")
        order = "latest"
    order = order or "latest"
    top_matches = list(re.finditer(r"\b(?:top|primeros)\s+(\d+)\b", folded))
    if len({int(match.group(1)) for match in top_matches}) > 1:
        raise ValueError("conflicting top-N values")
    limit = int(top_matches[0].group(1)) if top_matches else None
    grouping = re.search(
        r"\b(?:by|por)\s+(agent|agente|rule|regla|level|nivel|severity|severidad)\b",
        folded,
    )
    group_by: GroupField | None = None
    if grouping:
        group_name = grouping.group(1)
        group_by = {
            "agent": GroupField.agent_id,
            "agente": GroupField.agent_id,
            "rule": GroupField.rule_id,
            "regla": GroupField.rule_id,
            "level": GroupField.rule_level,
            "nivel": GroupField.rule_level,
            "severity": GroupField.vulnerability_severity,
            "severidad": GroupField.vulnerability_severity,
        }[group_name]
    family: str | None = None
    if re.search(r"\b(?:vulnerabilit(?:y|ies)|vulnerabilidades?)\b", folded):
        family = "vulnerabilities"
    if re.search(r"\b(?:alerts?|alertas?)\b", folded):
        if family is not None:
            raise ValueError("conflicting index families")
        family = "alerts"
    count = bool(re.search(r"\b(?:count|how many|cuenta|cuantas)\b", folded))
    return limit, order, group_by, family, count


def _select_template(
    configured: TemplateId,
    *,
    family: str | None,
    count: bool,
    group_by: GroupField | None,
) -> TemplateId:
    selected_family = family or (
        "vulnerabilities" if configured.value.startswith("vulnerabilities_") else "alerts"
    )
    if group_by is not None:
        allowed = (
            {GroupField.agent_id, GroupField.vulnerability_severity}
            if selected_family == "vulnerabilities"
            else {GroupField.agent_id, GroupField.rule_id, GroupField.rule_level}
        )
        if group_by not in allowed:
            raise ValueError("group field is incompatible with the selected family")
        operation = "group"
    elif count:
        operation = "count"
    else:
        operation = "rows"
    return TemplateId(f"{selected_family}_{operation}_v1")


def _language(hits: list[_Hit], request: AskRequest) -> str:
    counts = {"en": 0, "es": 0}
    for hit in hits:
        counts[hit.language] += 1
    if counts["en"] == counts["es"]:
        return request.language_hint or "en"
    return "en" if counts["en"] > counts["es"] else "es"


def _clarify(
    kind: Literal[
        "missing_slots",
        "ambiguous_scope",
        "missing_subject",
        "semantic_suggestion",
        "model_selection",
    ],
    language: str,
    slots: list[str],
    question: str,
    suggested: str | None = None,
) -> Clarified:
    text = (
        "¿Puedes especificar el alcance de evidencia?"
        if language == "es"
        else "Please specify the evidence scope."
    )
    if kind == "missing_subject":
        text = "¿Sobre qué tema?" if language == "es" else "Which topic should I assess?"
    elif kind == "ambiguous_scope":
        text = (
            "¿A qué tema corresponde la consulta?"
            if language == "es"
            else "Which topic does the fetch belong to?"
        )
    return Clarified(
        clarify=Clarify(kind=kind, question=text, slots=slots, suggested_topic=suggested)
    )


def _match_span(hit: _Hit, original: str, kind: Literal["cue", "alias"]) -> MatchedSpan:
    # Current normalization preserves codepoint count for supported Latin EN/ES matching.
    return MatchedSpan(
        start=min(hit.start, len(original)),
        end=min(hit.end, len(original)),
        kind=kind,
        id=hit.identifier,
    )


def plan(
    request: AskRequest,
    principal: VerifiedPrincipal,
    previous: FollowupRecord | None,
    catalog: ContentCatalog,
    *,
    policy_hash: PolicyHash,
    clock: Clock,
) -> Planned | Clarified | Refused:
    if previous is not None:
        from ai_soc.planning.followups import transform_followup

        transformed = transform_followup(
            request,
            principal,
            previous,
            catalog=catalog,
            policy_hash=policy_hash,
            clock=clock,
        )
        if transformed is not None:
            return transformed
    if window_only_followup(request.question, timezone=request.timezone, clock=clock):
        language = request.language_hint or "en"
        return _clarify("missing_slots", language, ["prior_plan"], question=request.question)
    question = request.question
    if len(question.encode("utf-8")) > 16384:
        return Refused(message="Question exceeds the supported size.")
    protected_text, protected = protect_quoted(question)
    cue_entries, aliases = entry_tables(catalog)
    cues = _cue_matches(protected_text, cue_entries)
    alias_hits = _alias_matches(protected_text, aliases, protected)
    aliases_by_id = {alias.alias_id: alias for alias in aliases}
    ambiguous_by_name = {
        _fold(item.normalized): set(item.topic_ids) for item in catalog.cues().ambiguities
    }
    for hit in alias_hits:
        alias = aliases_by_id.get(hit.identifier)
        if alias is not None:
            ambiguous = ambiguous_by_name.get(_fold(alias.normalized), set())
            if len(ambiguous) > 1:
                return _clarify(
                    "ambiguous_scope",
                    request.language_hint or alias.language,
                    [f"topic:{topic_id}" for topic_id in sorted(ambiguous)],
                    question,
                )
    all_hits = cues + alias_hits
    language = _language(all_hits, request)
    by_clause: list[_Clause] = []
    for start, end, clause in _clauses(protected_text):
        c_cues = [hit for hit in cues if start <= hit.start < end]
        c_aliases = [hit for hit in alias_hits if start <= hit.start < end]
        by_clause.append(_Clause(start, end, clause, c_cues, c_aliases))
    if not all_hits:
        return Refused(
            message="I could not map that request to a supported topic or read-only query."
        )

    final = by_clause[-1] if by_clause else None
    final_cues = final.cues if final else []
    shared_judgment: _Hit | None = None
    if (
        final
        and not final.aliases
        and final_cues
        and all(hit.kind == "judgment" for hit in final_cues)
    ):
        previous_clauses = by_clause[:-1]
        if previous_clauses and all(
            any(hit.kind in {"failure", "fetch"} for hit in clause.cues)
            and not any(hit.kind == "judgment" for hit in clause.cues)
            for clause in previous_clauses
        ):
            scope_keys: list[str | None] = []
            for clause in previous_clauses:
                if not any(hit.kind in {"failure", "fetch"} for hit in clause.cues):
                    continue
                scope_keys.append(
                    _clause_window_scope(clause, timezone=request.timezone, clock=clock)
                )
            declared_windows = {key for key in scope_keys if key is not None}
            if len(declared_windows) > 1:
                return _clarify("ambiguous_scope", language, ["judgment_scope"], question)
            else:
                shared_judgment = final_cues[-1]

    topic_work: dict[str, _TopicWork] = {}
    mention_order: list[str] = []
    for clause in by_clause:
        c_cues = clause.cues
        c_aliases = clause.aliases
        aliased_topics = list(
            dict.fromkeys(hit.topic_id for hit in c_aliases if hit.topic_id is not None)
        )
        fetch_cues = [hit for hit in c_cues if hit.kind == "fetch"]
        failure_cues = [hit for hit in c_cues if hit.kind == "failure"]
        judgment_cues = [hit for hit in c_cues if hit.kind == "judgment"]
        if fetch_cues and not aliased_topics:
            if alias_hits:
                return _clarify("ambiguous_scope", language, ["topic"], question)
            if any(key != "_records" for key in topic_work):
                return _clarify("ambiguous_scope", language, ["topic"], question)
            aliased_topics = ["_records"]
        is_shared_terminal = bool(shared_judgment and clause is final)
        if (
            judgment_cues
            and not (fetch_cues or failure_cues or aliased_topics)
            and not is_shared_terminal
        ):
            return _clarify("missing_subject", language, ["topic", "evidence_scope"], question)
        if not aliased_topics:
            if fetch_cues:
                return _clarify("ambiguous_scope", language, ["topic"], question)
            continue
        if fetch_cues and len(aliased_topics) > 1:
            # A shared fetch is safe only for explicit coordinated aliases in this same clause.
            pass
        window_match = None
        if fetch_cues:
            try:
                window_match = parse_window(
                    clause.text, anchor_at=clock.now(), timezone=request.timezone
                )
            except WindowParseError:
                return _clarify("missing_slots", language, ["window"], question)
        for topic_id in aliased_topics:
            if topic_id not in topic_work:
                topic_work[topic_id] = _TopicWork(topic_id != "_records", False, False, [], [], [])
                mention_order.append(topic_id)
            entry = topic_work[topic_id]
            entry.failure = entry.failure or bool(failure_cues)
            entry.judgment = entry.judgment or bool(judgment_cues or shared_judgment)
            entry.cues.extend(hit.identifier for hit in c_cues)
            entry.aliases.extend(hit.identifier for hit in c_aliases if hit.topic_id == topic_id)
            if fetch_cues:
                if window_match is None:
                    return _clarify("missing_slots", language, ["window"], question)
                topic = catalog.topic(topic_id) if topic_id != "_records" else None
                if topic_id == "_records":
                    bindings: list[tuple[str, TemplateId, list[Filter]]] = [
                        ("records_alerts", TemplateId.alerts_rows_v1, [])
                    ]
                elif topic is None:
                    return _clarify("ambiguous_scope", language, ["topic"], question)
                else:
                    bindings = [
                        (
                            f"{topic_id}_fetch_{index + 1}",
                            TemplateId(binding.template_id),
                            binding.filters,
                        )
                        for index, binding in enumerate(topic.fetch_bindings)
                    ]
                    if not bindings:
                        return _clarify("missing_slots", language, ["configured_fetch"], question)
                try:
                    filters = _filters(
                        clause.text,
                        literal_clause=question[clause.start : clause.end],
                    )
                    limit, order, group_by, family, count = _fetch_options(clause.text)
                    for fetch_id, template_id, bound_filters in bindings:
                        selected_template = _select_template(
                            template_id,
                            family=family,
                            count=count,
                            group_by=group_by,
                        )
                        fetch_spec = FetchSpec(
                            fetch_id=fetch_id,
                            template_id=selected_template,
                            window=window_match.window,
                            filters=list(bound_filters) + filters,
                            limit=limit,
                            order=order,
                            group_by=group_by,
                        )
                        if any(
                            existing.fetch_id == fetch_spec.fetch_id for existing in entry.fetches
                        ):
                            continue
                        entry.fetches.append(fetch_spec)
                except (ValueError, TypeError):
                    return _clarify("missing_slots", language, ["supported_filter"], question)

    if not topic_work:
        if any(hit.kind == "judgment" for hit in cues):
            return _clarify("missing_subject", language, ["topic", "evidence_scope"], question)
        return Refused(
            message="I could not map that request to a supported topic or read-only query."
        )
    # A terminal judgment binds only complete preceding fetch/failure clauses.
    if shared_judgment is not None:
        for item in topic_work.values():
            item.judgment = True
    elif (
        cues
        and any(hit.kind == "judgment" for hit in cues)
        and not any(item.judgment for item in topic_work.values())
    ):
        return _clarify("ambiguous_scope", language, ["judgment_scope"], question)
    topics: list[TopicPlan] = []
    for ordinal, topic_id in enumerate(mention_order):
        item = topic_work[topic_id]
        topic = catalog.topic(topic_id) if topic_id != "_records" else None
        failure = item.failure
        topics.append(
            TopicPlan(
                topic_id=topic_id,
                ordinal=ordinal,
                document=item.document,
                failure=failure,
                judgment=item.judgment,
                fetches=item.fetches,
                playbook_id=topic.playbook_id if failure and topic else None,
                cue_ids=list(dict.fromkeys(item.cues)),
                alias_ids=list(dict.fromkeys(item.aliases)),
            )
        )
    now = clock.now().astimezone(UTC)
    provenance = PlanProvenance(
        cue_pack_sha=catalog.cues().sha256,
        normalized_question_hash=hashlib.sha256(_fold(question).encode("utf-8")).hexdigest(),
        origin="new",
        matched_spans=[
            _match_span(hit, question, "alias" if hit.topic_id else "cue")
            for hit in sorted(all_hits, key=lambda h: h.start)
        ],
    )
    built = QuestionPlan(
        question_id=uuid4(),
        environment_id=request.environment_id,
        owner_key=principal.owner_key,
        content_sha=catalog.manifest().content_sha,
        policy_hash=policy_hash,
        language=cast(Literal["en", "es"], language),
        timezone=request.timezone,
        anchor_at=now,
        topics=topics,
        model_id=request.model_id,
        effort=Effort(request.effort) if request.effort is not None else None,
        provenance=provenance,
    )
    if len(canonical_bytes(built)) > 131072:
        return _clarify("missing_slots", language, ["narrower_scope"], question)
    return Planned(plan=built)


class DeterministicPlanner:
    """Configured Planner port implementation over one immutable ContentCatalog."""

    __slots__ = ("_catalog",)

    def __init__(self, catalog: ContentCatalog) -> None:
        self._catalog = catalog

    def plan(
        self,
        request: AskRequest,
        principal: VerifiedPrincipal,
        previous: FollowupRecord | None,
        *,
        policy_hash: PolicyHash,
        clock: Clock,
    ) -> Planned | Clarified | Refused:
        return plan(
            request,
            principal,
            previous,
            self._catalog,
            policy_hash=policy_hash,
            clock=clock,
        )
