"""Immutable, owner/site-bound transformations of validated prior plans."""

from __future__ import annotations

import hashlib
from datetime import UTC
from typing import Literal
from uuid import uuid4

from ai_soc.contracts.models import (
    AskRequest,
    Clarified,
    Clarify,
    FollowupRecord,
    MatchedSpan,
    Planned,
    PlanProvenance,
    PolicyHash,
    QuestionPlan,
    Refused,
    ResolvedWindow,
    TopicPlan,
    VerifiedPrincipal,
)
from ai_soc.contracts.ports import Clock, ContentCatalog
from ai_soc.planning.followup_routing import window_only_followup
from ai_soc.planning.parser import entry_tables, phrase_hits, protect_quoted
from ai_soc.planning.windows import WindowParseError, parse_window


class InvalidContinuation(ValueError):
    """Continuation topic selection violates the left-out contract."""


def _clarify(
    language: str,
    kind: Literal[
        "missing_slots",
        "ambiguous_scope",
        "missing_subject",
        "semantic_suggestion",
        "model_selection",
    ],
    slots: list[str],
) -> Clarified:
    question = (
        "¿Puedes concretar el seguimiento?" if language == "es" else "Please clarify the follow-up."
    )
    return Clarified(clarify=Clarify(kind=kind, question=question, slots=slots))


def _mentions(request: AskRequest, catalog: ContentCatalog) -> list[tuple[str, int, int, str]]:
    _, aliases = entry_tables(catalog)
    entries = [(str(a.alias_id), a.language, a.text, "alias", str(a.topic_id)) for a in aliases]
    protected, ranges = protect_quoted(request.question)
    hits = phrase_hits(protected, entries)
    return [
        (str(hit.topic_id), hit.start, hit.end, hit.identifier)
        for hit in hits
        if hit.topic_id
        and not any(start <= hit.start < end or start < hit.end <= end for start, end in ranges)
    ]


def transform_followup(
    request: AskRequest,
    principal: VerifiedPrincipal,
    previous: FollowupRecord | None,
    *,
    catalog: ContentCatalog,
    policy_hash: PolicyHash,
    clock: Clock,
) -> Planned | Clarified | Refused | None:
    """Return a transformed plan for a recognized continuation, or None for a new question."""
    if previous is None:
        return None
    if (
        previous.owner_key != principal.owner_key
        or previous.environment_id != request.environment_id
        or request.followup_id != previous.followup_id
        or request.followup_revision != previous.revision
    ):
        return Refused(message="The previous plan is unavailable for this request.")
    plan = previous.plan
    now = clock.now().astimezone(UTC)
    if (
        now >= previous.expires_at.astimezone(UTC)
        or plan.content_sha != catalog.manifest().content_sha
        or plan.owner_key != principal.owner_key
        or plan.environment_id != request.environment_id
        or plan.policy_hash != policy_hash
    ):
        return Refused(message="The previous plan is unavailable for this request.")
    language = request.language_hint or plan.language
    mentions = _mentions(request, catalog)
    cue_entries, _ = entry_tables(catalog)
    protected_question, _ = protect_quoted(request.question)
    cues = phrase_hits(protected_question, cue_entries)
    folded = request.question.casefold()
    selected_text = request.continue_topic_ids
    continue_cue = (
        any(hit.kind == "continue" for hit in cues)
        or "continue the left-out" in folded
        or "continúa los juicios pendientes" in folded
    )
    if request.continue_topic_ids is not None and not continue_cue:
        raise InvalidContinuation("continuation topic IDs require a left-out cue")
    keep_cue = (
        any(hit.kind == "keep" for hit in cues)
        or "keep those alerts" in folded
        or "conserva esas alertas" in folded
    )
    has_window_followup = window_only_followup(
        request.question, timezone=request.timezone, clock=clock
    )
    origin: str
    selected_plans: list[TopicPlan]
    if continue_cue:
        stage_topics = {item.topic_id for item in previous.leftout_stages}
        allowed = set(previous.leftout_topic_ids)
        if allowed != stage_topics:
            return Refused(message="The previous plan is unavailable for this request.")
        if selected_text is not None and not set(selected_text) <= allowed:
            raise InvalidContinuation("continuation topic IDs must be a left-out subset")
        if not allowed:
            return Refused(message="The previous plan is unavailable for this request.")
        if selected_text is not None:
            mentioned_ids = list(dict.fromkeys(topic_id for topic_id, *_ in mentions))
            if mentioned_ids and set(mentioned_ids) != set(selected_text):
                return _clarify(language, "ambiguous_scope", ["continuation_selection"])
            selected_ids = list(selected_text)
        elif mentions:
            selected_ids = list(dict.fromkeys(topic_id for topic_id, *_ in mentions))
            if not set(selected_ids) <= allowed:
                return _clarify(language, "missing_slots", ["left_out_topic"])
        else:
            selected_ids = [topic.topic_id for topic in plan.topics if topic.topic_id in allowed]
        selected_plans = [
            topic
            for topic in plan.topics
            if topic.topic_id in selected_ids and topic.topic_id in allowed
        ]
        if not selected_plans:
            return _clarify(language, "missing_slots", ["left_out_topic"])
        origin = "leftout_followup"
    elif keep_cue:
        selected_ids = list(dict.fromkeys(topic_id for topic_id, *_ in mentions))
        if len(selected_ids) != 1:
            return _clarify(language, "missing_slots", ["one_topic"])
        selected_plans = [topic for topic in plan.topics if topic.topic_id == selected_ids[0]]
        if len(selected_plans) != 1 or not selected_plans[0].fetches:
            return _clarify(language, "missing_slots", ["matching_previous_fetch"])
        origin = "explicit_keep"
    elif has_window_followup:
        selected_plans = list(plan.topics)
        origin = "window_followup"
    else:
        return None
    window = None
    if has_window_followup or keep_cue:
        try:
            window = parse_window(
                request.question, anchor_at=clock.now(), timezone=request.timezone
            ).window
        except WindowParseError:
            if has_window_followup:
                return _clarify(language, "missing_slots", ["window"])
            window = None
    transformed: list[TopicPlan] = []
    for topic in selected_plans:
        fetches = topic.fetches
        playbook_window: ResolvedWindow | None = topic.playbook_window
        if window is not None:
            fetches = [fetch.model_copy(update={"window": window}) for fetch in fetches]
            if topic.playbook_id is not None:
                playbook_window = window
        transformed.append(
            topic.model_copy(
                update={
                    "fetches": fetches,
                    "playbook_window": playbook_window,
                    "judgment": topic.judgment
                    if origin in {"window_followup", "leftout_followup"}
                    else bool(topic.judgment and keep_cue),
                },
                deep=True,
            )
        )
    now = clock.now().astimezone(UTC)
    new_plan: QuestionPlan = plan.model_copy(
        update={
            "question_id": uuid4(),
            "anchor_at": now,
            "timezone": request.timezone,
            "topics": transformed,
            "model_id": request.model_id or plan.model_id,
            "effort": request.effort or plan.effort,
            "provenance": PlanProvenance(
                cue_pack_sha=catalog.cues().sha256,
                normalized_question_hash=hashlib.sha256(
                    " ".join(folded.split()).encode()
                ).hexdigest(),
                origin=origin,
                previous_question_id=plan.question_id,
                matched_spans=[
                    MatchedSpan(start=start, end=end, kind="alias", id=alias_id)
                    for _, start, end, alias_id in mentions
                ],
            ),
        },
        deep=True,
    )
    return Planned(plan=new_plan)
