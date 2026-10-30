"""Safe bounded YAML chain rules and deterministic concrete-witness evaluation.

`where_any` requires every listed field selector to match (any value within each
selector); `any_of` matches at least one flat selector alternative.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
from bisect import bisect_right
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, cast

import yaml
from pydantic import ValidationError

from ai_soc.workspace.triage.grouping import digest

from .models import (
    MISSING_TEXT,
    ChainMatch,
    ChainRule,
    ChainStage,
    ChainStageEvidence,
    CorrelationInput,
    CorrelationObservation,
    FieldName,
    Selector,
    SelectorAlternative,
    utc,
)

MAX_SEARCH_NODES = 500_000
MAX_MATCHES = 10_000
FIELDS = {
    "agent.id",
    "src_ip",
    "dst_ip",
    "src_user",
    "dst_user",
    "rule_id",
    "decoder",
    "syscheck.path",
    "syscheck.event",
    "rule_groups",
}


def _check_unique_mappings(node: Any, visited: set[int] | None = None) -> None:
    if node is None:
        return
    visited = set() if visited is None else visited
    if id(node) in visited:
        return
    visited.add(id(node))
    if isinstance(node, yaml.MappingNode):
        keys: set[tuple[str, str]] = set()
        for key_node, value_node in node.value:
            if not isinstance(key_node, yaml.ScalarNode):
                raise ValueError("chain rule mapping keys must be scalars")
            marker = (key_node.tag, key_node.value)
            if marker in keys:
                raise ValueError(f"duplicate YAML mapping key: {key_node.value}")
            keys.add(marker)
            _check_unique_mappings(key_node, visited)
            _check_unique_mappings(value_node, visited)
    elif isinstance(node, yaml.SequenceNode):
        for item in node.value:
            _check_unique_mappings(item, visited)


def _keys(value: Any, allowed: set[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{where} must be a mapping")
    raw_mapping = cast(dict[Any, Any], value)
    if any(not isinstance(key, str) for key in raw_mapping):
        raise ValueError(f"{where} must be a mapping")
    mapping = cast(dict[str, Any], raw_mapping)
    unknown: set[str] = set(mapping) - allowed
    if unknown:
        raise ValueError(f"unsupported {where} keys: {sorted(unknown)}")
    return mapping


def _duration(value: Any, where: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]*(s|m|h)", value):
        raise ValueError(f"{where} must be a positive duration in seconds, minutes, or hours")
    amount = int(value[:-1]) * {"s": 1, "m": 60, "h": 3600}[value[-1]]
    if amount > 86400:
        raise ValueError(f"{where} exceeds 24 hours")
    return amount


def _milliseconds(value: Any, where: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]*ms", value):
        raise ValueError(f"{where} must be a positive integer duration in milliseconds")
    amount = int(value[:-2])
    if amount > 10_000:
        raise ValueError(f"{where} exceeds 10000 milliseconds")
    return amount


def _selector(field: Any, values: Any) -> Selector:
    if not isinstance(field, str) or field not in FIELDS:
        raise ValueError(f"unsupported selector field: {field}")
    parsed: tuple[str, ...]
    if isinstance(values, str):
        parsed = (values,)
    elif isinstance(values, list):
        values_list = cast(list[Any], values)
        if not values_list or not all(isinstance(value, str) for value in values_list):
            raise ValueError("selector values must be a string or nonempty string list")
        parsed = tuple(cast(str, value) for value in values_list)
    else:
        raise ValueError("selector values must be a string or nonempty string list")
    if len(parsed) > 64 or any(len(value) > 256 for value in parsed):
        raise ValueError("selector value cap exceeded")
    if field == "syscheck.path":
        for pattern in parsed:
            if (
                "[" in pattern
                or "]" in pattern
                or "\\" in pattern
                or "?" in pattern
                or "**" in pattern
            ):
                raise ValueError("unsupported path glob syntax")
            if not pattern.startswith("/") or ".." in pattern.split("/"):
                raise ValueError("path selectors must be absolute and cannot traverse parents")
            if pattern.count("*") > 2:
                raise ValueError("path glob has too many wildcards")
    return Selector(field=cast(FieldName, field), values=parsed)


def _selector_list(raw: Any, where: str) -> tuple[Selector, ...]:
    if raw is None:
        return ()
    entries: list[tuple[Any, Any]]
    if isinstance(raw, dict):
        entries = list(cast(dict[Any, Any], raw).items())
    elif isinstance(raw, list):
        entries = []
        for item in cast(list[Any], raw):
            item_map = _keys(item, FIELDS, where)
            entries.extend(item_map.items())
    else:
        raise ValueError(f"{where} must be a mapping or list of flat mappings")
    if len(entries) > 16:
        raise ValueError(f"{where} selector cap exceeded")
    return tuple(_selector(field, values) for field, values in entries)


def _selector_alternatives(raw: Any) -> tuple[SelectorAlternative, ...]:
    if not isinstance(raw, list):
        raise ValueError("any_of must be a nonempty list of flat selector mappings")
    raw_alternatives = cast(list[Any], raw)
    if not raw_alternatives or len(raw_alternatives) > 16:
        raise ValueError("any_of must be a nonempty list of flat selector mappings")
    alternatives: list[SelectorAlternative] = []
    for raw_alternative in raw_alternatives:
        alternative = _keys(raw_alternative, FIELDS, "any_of alternative")
        if not alternative or len(alternative) > 16:
            raise ValueError("any_of alternative must have 1 to 16 selectors")
        alternatives.append(
            SelectorAlternative(
                selectors=tuple(_selector(field, values) for field, values in alternative.items())
            )
        )
    return tuple(alternatives)


def load_chain_rule(path: Path) -> ChainRule:
    with path.open("rb") as source:
        raw_bytes = source.read(65_537)
    return parse_chain_rule(raw_bytes)


def parse_chain_rule(raw_bytes: bytes) -> ChainRule:
    """Validate retained UTF-8 policy bytes without filesystem I/O under a lease."""
    if len(raw_bytes) > 65_536:
        raise ValueError("chain rule exceeds 64 KiB")
    try:
        source_yaml = raw_bytes.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError("chain policy must be UTF-8") from exc
    try:
        depth = 0
        event_count = 0
        parse: Any = yaml.parse  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        events = cast(Iterable[yaml.events.Event], parse(raw_bytes, Loader=yaml.SafeLoader))
        for event in events:
            event_count += 1
            if event_count > 4096 or getattr(event, "anchor", None) is not None:
                raise ValueError("YAML node/alias limit exceeded")
            if isinstance(event, (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent)):
                depth += 1
                if depth > 32:
                    raise ValueError("YAML nesting limit exceeded")
            elif isinstance(event, (yaml.events.MappingEndEvent, yaml.events.SequenceEndEvent)):
                depth -= 1
        compose: Any = yaml.compose  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        _check_unique_mappings(compose(raw_bytes, Loader=yaml.SafeLoader))
        raw = yaml.safe_load(raw_bytes)
    except (yaml.YAMLError, RecursionError) as exc:
        raise ValueError("invalid safe YAML chain rule") from exc
    root = _keys(
        raw,
        {
            "id",
            "version",
            "name",
            "window",
            "scope",
            "join",
            "stages",
            "output",
            "status",
            "qualification",
        },
        "rule",
    )
    if root.get("status") is not None and root.get("status") != "experimental":
        raise ValueError("only experimental candidate rules are supported")
    if "qualification" in root:
        qualification = _keys(
            root["qualification"], {"capture_id", "evidence", "execution"}, "qualification"
        )
        if any(not isinstance(value, str) or len(value) > 500 for value in qualification.values()):
            raise ValueError("qualification fields must be bounded strings")
    scope = _keys(root.get("scope"), {"same_agent"}, "scope")
    if "same_agent" not in scope:
        raise ValueError("scope.same_agent is required")
    join = _keys(root.get("join"), {"primary", "fallback", "fallback_confidence"}, "join")
    output = _keys(
        root.get("output"),
        {
            "min_required_stages",
            "require_stages",
            "promote_score",
            "confidence_cap_without_actor_fields",
            "confidence_cap_with_order_tolerance",
        },
        "output",
    )
    if not isinstance(root.get("stages"), list) or len(root["stages"]) > 8:
        raise ValueError("stages must be a list of at most eight stages")
    stages: list[ChainStage] = []
    allowed_stage = {
        "id",
        "rule_id",
        "any_rule_id",
        "rule_group",
        "where_any",
        "any_of",
        "after",
        "after_tolerance",
        "max_gap",
        "same_fields",
        "actor_match",
        "confidence",
        "maps_to",
    }
    for raw_stage in cast(list[Any], root["stages"]):
        stage = _keys(raw_stage, allowed_stage, "stage")
        if "id" not in stage or "confidence" not in stage or "maps_to" not in stage:
            raise ValueError("stage requires id, confidence, and maps_to")
        any_rules: Any = stage.get("any_rule_id", ())
        if isinstance(any_rules, str):
            any_rules = (any_rules,)
        elif isinstance(any_rules, list):
            any_rules = tuple(cast(str, item) for item in cast(list[Any], any_rules))
        where_any = _selector_list(stage.get("where_any"), "where_any")
        any_of_raw = stage.get("any_of")
        any_of = () if any_of_raw is None else _selector_alternatives(any_of_raw)
        same_raw: Any = stage.get("same_fields", {})
        same_fields: tuple[tuple[FieldName, FieldName], ...]
        if isinstance(same_raw, dict):
            raw_pairs: tuple[tuple[Any, Any], ...] = tuple(cast(dict[Any, Any], same_raw).items())
        elif isinstance(same_raw, list):
            pair_list: list[tuple[Any, Any]] = []
            for pair in cast(list[Any], same_raw):
                if not isinstance(pair, str) or pair.count(":") != 1:
                    raise ValueError("same_fields list entries must be field pairs")
                left, right = pair.split(":")
                pair_list.append((left, right))
            raw_pairs = tuple(pair_list)
            if len(raw_pairs) != len(cast(list[Any], same_raw)):
                raise ValueError("same_fields list entries must be field pairs")
        else:
            raise ValueError("same_fields must be a field-pair mapping or list")
        if any(
            len(pair) != 2 or pair[0] not in FIELDS or pair[1] not in FIELDS for pair in raw_pairs
        ):
            raise ValueError("unsupported same_fields field")
        same_fields = tuple(
            (cast(FieldName, pair[0]), cast(FieldName, pair[1])) for pair in raw_pairs
        )
        stages.append(
            ChainStage(
                id=stage["id"],
                rule_id=stage.get("rule_id"),
                any_rule_id=any_rules,
                rule_group=stage.get("rule_group"),
                where_any=where_any,
                any_of=any_of,
                after=stage.get("after"),
                after_tolerance_ms=(
                    _milliseconds(stage["after_tolerance"], "after_tolerance")
                    if "after_tolerance" in stage
                    else None
                ),
                max_gap_seconds=None
                if stage.get("max_gap") is None
                else _duration(stage["max_gap"], "max_gap"),
                same_fields=same_fields,
                actor_match=stage.get("actor_match", False),
                confidence=stage["confidence"],
                maps_to=stage["maps_to"],
            )
        )

    has_order_tolerance = any(stage.after_tolerance_ms is not None for stage in stages)
    if has_order_tolerance and "confidence_cap_with_order_tolerance" not in output:
        raise ValueError("order-tolerance confidence cap is required for tolerant stages")
    if not has_order_tolerance and "confidence_cap_with_order_tolerance" in output:
        raise ValueError("order-tolerance confidence cap is forbidden without tolerant stages")

    def fields_for(label: str, fields: Any) -> tuple[FieldName, ...]:
        if isinstance(fields, str):
            fields = (fields,)
        if not isinstance(fields, (tuple, list)):
            raise ValueError(f"join.{label} must contain allowlisted fields")
        field_values: tuple[Any, ...] = tuple(cast(Iterable[Any], fields))
        if any(field not in FIELDS for field in field_values):
            raise ValueError(f"join.{label} must contain allowlisted fields")
        return tuple(cast(FieldName, field) for field in field_values)

    primary = fields_for("primary", join.get("primary"))
    fallback = fields_for("fallback", join.get("fallback", ()))
    require: Any = output.get("require_stages", ())
    if not isinstance(require, list):
        raise ValueError("require_stages must be a list")
    required_raw = cast(list[Any], require)
    if any(not isinstance(value, str) for value in required_raw):
        raise ValueError("require_stages must contain strings")
    required_stages = tuple(cast(str, value) for value in required_raw)
    try:
        return ChainRule(
            id=root["id"],
            version=root["version"],
            name=root["name"],
            window_seconds=_duration(root["window"], "window"),
            same_agent=scope.get("same_agent", False),
            primary=primary,
            fallback=fallback,
            fallback_confidence=join.get("fallback_confidence", 0.0),
            stages=tuple(stages),
            min_required_stages=output["min_required_stages"],
            require_stages=required_stages,
            promote_score=output["promote_score"],
            confidence_cap_without_actor_fields=output["confidence_cap_without_actor_fields"],
            confidence_cap_with_order_tolerance=output.get("confidence_cap_with_order_tolerance"),
            content_digest=hashlib.sha256(raw_bytes).hexdigest(),
            source_yaml=source_yaml,
        )
    except (KeyError, TypeError, ValidationError) as exc:
        raise ValueError(f"invalid chain rule: {exc}") from exc


def _field(obs: CorrelationObservation, field: str) -> tuple[str, ...]:
    raw: str | tuple[str, ...] | None = {
        "agent.id": obs.agent_id,
        "src_ip": obs.src_ip,
        "dst_ip": obs.dst_ip,
        "src_user": obs.src_user,
        "dst_user": obs.dst_user,
        "rule_id": obs.rule_id,
        "decoder": obs.decoder,
        "syscheck.path": obs.file_path,
        "syscheck.event": obs.file_event,
        "rule_groups": obs.rule_groups,
    }[field]
    values = raw if isinstance(raw, tuple) else (() if raw is None else (raw,))
    return tuple(value for value in values if value.strip().casefold() not in MISSING_TEXT)


def _path_match(value: str, pattern: str) -> bool:
    parts, patterns = value.split("/"), pattern.split("/")
    if not value.startswith("/") or any(part in {".", ".."} for part in parts):
        return False
    return len(parts) == len(patterns) and all(
        fnmatch.fnmatchcase(part, glob) for part, glob in zip(parts, patterns, strict=True)
    )


def _selector_match(obs: CorrelationObservation, selector: Selector) -> bool:
    actual = _field(obs, selector.field)
    if selector.field == "syscheck.path":
        return any(_path_match(value, pattern) for value in actual for pattern in selector.values)
    return bool(set(actual) & set(selector.values))


def _matches_stage(obs: CorrelationObservation, stage: ChainStage) -> bool:
    if stage.rule_id is not None and obs.rule_id != stage.rule_id:
        return False
    if stage.any_rule_id and obs.rule_id not in stage.any_rule_id:
        return False
    if stage.rule_group is not None and stage.rule_group not in obs.rule_groups:
        return False
    if stage.where_any and not all(_selector_match(obs, selector) for selector in stage.where_any):
        return False
    return not stage.any_of or any(
        all(_selector_match(obs, selector) for selector in alternative.selectors)
        for alternative in stage.any_of
    )


def _comparison(
    previous: CorrelationObservation,
    current: CorrelationObservation,
    rule: ChainRule,
    stage: ChainStage,
) -> tuple[bool, bool, bool]:
    if rule.same_agent:
        left, right = _field(previous, "agent.id"), _field(current, "agent.id")
        if not left or not right or left != right:
            return False, False, False
    pairs = list(stage.same_fields or tuple((field, field) for field in rule.primary))
    actor_pair = ("dst_user", "src_user")
    if stage.actor_match and actor_pair not in pairs:
        pairs.append(actor_pair)
    missing_primary = False
    missing_actor = False
    for left_field, right_field in pairs:
        left, right = _field(previous, left_field), _field(current, right_field)
        if left and right and left != right:
            return False, False, False
        if not left or not right:
            if stage.actor_match and (left_field, right_field) == actor_pair:
                missing_actor = True
            else:
                missing_primary = True
    if missing_primary:
        if not rule.fallback:
            return False, False, False
        for field in rule.fallback:
            left, right = _field(previous, field), _field(current, field)
            if not left or not right or left != right:
                return False, False, False
        return True, True, missing_actor
    return True, False, missing_actor


def _order_tolerance_applied(
    rule: ChainRule, selected: tuple[CorrelationObservation | None, ...]
) -> bool:
    for index, stage in enumerate(rule.stages):
        witness = selected[index]
        if stage.after_tolerance_ms is None or witness is None:
            continue
        earlier = [value for value in selected[:index] if value is not None]
        if earlier and utc(witness.event_ts) <= max(utc(value.event_ts) for value in earlier):
            return True
    return False


def _make_match(
    rule: ChainRule,
    inputs: CorrelationInput,
    anchor: CorrelationObservation,
    selected: tuple[CorrelationObservation | None, ...],
    fallback_used: bool,
    missing_actor: bool,
    input_digest: str,
) -> ChainMatch:
    order_tolerance_applied = _order_tolerance_applied(rule, selected)
    matched = [
        (rule.stages[index], value) for index, value in enumerate(selected) if value is not None
    ]
    matched_stage_ids = {stage.id for stage, _ in matched}
    missing = tuple(stage.id for stage in rule.stages if stage.id not in matched_stage_ids)
    stage_by_id = {stage.id: stage for stage in rule.stages}
    reasons = tuple(
        f"{stage_id}: blocked because predecessor {stage_by_id[stage_id].after} is missing"
        if stage_by_id[stage_id].after in missing
        else f"{stage_id}: no compatible concrete witness"
        for stage_id in missing
    )
    missing_actor = missing_actor or any(
        value.file_path is not None and not value.src_user and not value.dst_user
        for _, value in matched
    )
    if missing_actor:
        reasons += ("Actor continuity is unavailable for one or more selected stages",)
    if order_tolerance_applied:
        reasons += ("Order tolerance applied to a syscheck persistence witness",)
    confidence = min((stage.confidence for stage, _ in matched), default=0.0)
    if fallback_used:
        confidence = min(confidence, rule.fallback_confidence)
    if missing_actor:
        confidence = min(confidence, rule.confidence_cap_without_actor_fields)
    if order_tolerance_applied:
        confidence = min(confidence, rule.confidence_cap_with_order_tolerance or 0.0)
    required_met = set(rule.require_stages) <= matched_stage_ids
    anchor_identity = digest([anchor.agent_id, anchor.src_ip, anchor.dst_user])
    chain_id = digest(
        [
            inputs.site_id,
            "workspace.chain.v1",
            rule.id,
            rule.version,
            anchor.group_id,
            anchor_identity,
        ]
    )
    frozen = {
        "input_digest": input_digest,
        "rule_content_digest": rule.content_digest,
        "rule_id": rule.id,
        "rule_version": rule.version,
        "stages": [
            (
                stage.id,
                value.alert_key,
                value.group_id,
                value.group_revision,
                utc(value.event_ts).isoformat(),
            )
            for stage, value in matched
        ],
        "missing": missing,
        "fallback_used": fallback_used,
        "order_tolerance_applied": order_tolerance_applied,
        "confidence": confidence,
    }
    matched_group_ids = {value.group_id for _, value in matched}
    scores = [group.score for group in inputs.groups if group.group_id in matched_group_ids]
    score = (
        None
        if not scores
        or len(scores) != len(matched_group_ids)
        or any(value is None for value in scores)
        else min(
            100.0,
            max(float(value) for value in scores if value is not None) + 10 * len(matched),
        )
    )
    is_candidate = len(matched) >= rule.min_required_stages and required_met
    eligible = (
        score is not None
        and score >= rule.promote_score
        and len(matched) >= rule.min_required_stages
        and required_met
    )
    return ChainMatch(
        site_id=inputs.site_id,
        chain_id=chain_id,
        revision_digest=digest(
            {
                **frozen,
                "score": score,
                "is_candidate": is_candidate,
                "eligible_for_promotion": eligible,
                "reasons": reasons,
            }
        ),
        rule_id=rule.id,
        rule_version=rule.version,
        anchor_alert_key=anchor.alert_key,
        anchor_identity=anchor_identity,
        stages=tuple(
            ChainStageEvidence(
                stage_id=stage.id,
                alert_key=value.alert_key,
                group_id=value.group_id,
                group_revision=value.group_revision,
                event_ts=value.event_ts,
                confidence=stage.confidence,
            )
            for stage, value in matched
        ),
        missing_stages=missing,
        reasons=reasons,
        fallback_used=fallback_used,
        order_tolerance_applied=order_tolerance_applied,
        confidence=confidence,
        score=score,
        is_candidate=is_candidate,
        eligible_for_promotion=eligible,
    )


type _SelectionRank = tuple[int, bool, float, tuple[tuple[datetime, str], ...]]


def ranked_selection_confidence(
    rule: ChainRule,
    confidence: float,
    *,
    fallback_used: bool,
    missing_actor: bool,
    tolerance_applied: bool,
) -> float:
    if fallback_used:
        confidence = min(confidence, rule.fallback_confidence)
    if missing_actor:
        confidence = min(confidence, rule.confidence_cap_without_actor_fields)
    if tolerance_applied:
        confidence = min(confidence, rule.confidence_cap_with_order_tolerance or 0.0)
    return confidence


@dataclass(frozen=True)
class _Selection:
    rank: _SelectionRank
    anchor: CorrelationObservation
    observations: tuple[CorrelationObservation | None, ...]
    fallback_used: bool
    missing_actor: bool


@dataclass
class _BestSelections:
    candidate: _Selection | None = None
    partial: _Selection | None = None

    def consider(self, selection: _Selection, is_candidate: bool) -> None:
        previous = self.candidate if is_candidate else self.partial
        if previous is None or selection.rank < previous.rank:
            if is_candidate:
                self.candidate = selection
            else:
                self.partial = selection

    def best(self) -> _Selection | None:
        return self.candidate or self.partial


def evaluate_chain(rule: ChainRule, inputs: CorrelationInput) -> tuple[ChainMatch, ...]:
    """Allocate candidates in stable anchor-group order; retain unconsumed diagnostics."""
    observations = sorted(inputs.observations, key=lambda obs: (utc(obs.event_ts), obs.alert_key))
    candidates = {
        stage.id: tuple(obs for obs in observations if _matches_stage(obs, stage))
        for stage in rule.stages
    }
    times = {
        stage_id: tuple(utc(obs.event_ts) for obs in values)
        for stage_id, values in candidates.items()
    }
    stage_index = {stage.id: index for index, stage in enumerate(rule.stages)}
    anchor_groups: dict[
        tuple[str, str | None, str | None, str | None], list[CorrelationObservation]
    ] = {}
    for anchor in candidates[rule.stages[0].id]:
        key = (anchor.group_id, anchor.agent_id, anchor.src_ip, anchor.dst_user)
        anchor_groups.setdefault(key, []).append(anchor)
    ordered_anchors = sorted(
        (
            members
            for _, members in sorted(
                anchor_groups.items(), key=lambda item: tuple(value or "" for value in item[0])
            )
        ),
        key=lambda items: (
            items[0].group_id,
            items[0].agent_id or "",
            items[0].src_ip or "",
            items[0].dst_user or "",
        ),
    )
    consumed: set[str] = set()
    result: list[ChainMatch] = []
    work = 0
    input_digest = inputs.canonical_digest

    def tick() -> None:
        nonlocal work
        work += 1
        if work > MAX_SEARCH_NODES:
            raise ValueError("chain evaluation work cap exceeded")

    for anchors in ordered_anchors:
        selections = _BestSelections()
        for anchor in anchors:
            if anchor.alert_key in consumed:
                continue
            selected: list[CorrelationObservation | None] = [anchor]

            def search(
                index: int,
                fallback_used: bool,
                missing_actor: bool,
                active_anchor: CorrelationObservation = anchor,
                active_selected: list[CorrelationObservation | None] = selected,
                active_selections: _BestSelections = selections,
            ) -> None:
                tick()
                if index == len(rule.stages):
                    selected_stages = [
                        (rule.stages[position], value)
                        for position, value in enumerate(active_selected)
                        if value is not None
                    ]
                    ids = {stage.id for stage, _ in selected_stages}
                    tolerance_applied = _order_tolerance_applied(rule, tuple(active_selected))
                    confidence = ranked_selection_confidence(
                        rule,
                        min(stage.confidence for stage, _ in selected_stages),
                        fallback_used=fallback_used,
                        missing_actor=missing_actor,
                        tolerance_applied=tolerance_applied,
                    )
                    rank: _SelectionRank = (
                        -len(selected_stages),
                        tolerance_applied,
                        -confidence,
                        tuple(
                            (utc(value.event_ts), value.alert_key) for _, value in selected_stages
                        ),
                    )
                    entry = _Selection(
                        rank, active_anchor, tuple(active_selected), fallback_used, missing_actor
                    )
                    complete = (
                        len(selected_stages) >= rule.min_required_stages
                        and set(rule.require_stages) <= ids
                    )
                    active_selections.consider(entry, complete)
                    return
                stage = rule.stages[index]
                predecessor = (
                    None if stage.after is None else active_selected[stage_index[stage.after]]
                )
                if stage.after is None or predecessor is not None:
                    earlier = [value for value in active_selected if value is not None]
                    previous = predecessor or earlier[-1]
                    lower = max(utc(value.event_ts) for value in earlier)
                    if stage.after_tolerance_ms is not None and not any(
                        "syscheck" in value.rule_groups for value in earlier
                    ):
                        lower = max(
                            utc(active_anchor.event_ts),
                            lower - timedelta(milliseconds=stage.after_tolerance_ms),
                        )
                    upper = utc(active_anchor.event_ts) + timedelta(seconds=rule.window_seconds)
                    if stage.after is not None and stage.max_gap_seconds is not None:
                        upper = min(
                            upper, utc(previous.event_ts) + timedelta(seconds=stage.max_gap_seconds)
                        )
                    values = candidates[stage.id]
                    first = bisect_right(times[stage.id], lower)
                    last = bisect_right(times[stage.id], upper)
                    for option in values[first:last]:
                        tick()
                        if option.alert_key in consumed or any(
                            value is not None and value.alert_key == option.alert_key
                            for value in active_selected
                        ):
                            continue
                        okay, used_fallback, actor_unavailable = _comparison(
                            previous, option, rule, stage
                        )
                        if not okay:
                            continue
                        active_selected.append(option)
                        search(
                            index + 1,
                            fallback_used or used_fallback,
                            missing_actor or actor_unavailable,
                        )
                        active_selected.pop()
                active_selected.append(None)
                search(index + 1, fallback_used, missing_actor)
                active_selected.pop()

            search(1, False, False)
        best = selections.best()
        if best is None:
            continue
        match = _make_match(
            rule,
            inputs,
            best.anchor,
            best.observations,
            best.fallback_used,
            best.missing_actor,
            input_digest,
        )
        if match.is_candidate:
            consumed.update(stage.alert_key for stage in match.stages)
        result.append(match)
        if len(result) > MAX_MATCHES:
            raise ValueError("chain output cap exceeded")
    reconciled: list[ChainMatch] = []
    by_key = {observation.alert_key: observation for observation in observations}
    for match in result:
        if match.is_candidate or not any(stage.alert_key in consumed for stage in match.stages):
            reconciled.append(match)
            continue
        staged = {stage.stage_id: by_key[stage.alert_key] for stage in match.stages}
        retained: list[CorrelationObservation | None] = []
        for stage in rule.stages:
            witness = staged.get(stage.id)
            if witness is not None and witness.alert_key in consumed:
                witness = None
            if stage.after is not None and retained[stage_index[stage.after]] is None:
                witness = None
            retained.append(witness)
        diagnostic = _make_match(
            rule,
            inputs,
            by_key[match.anchor_alert_key],
            tuple(retained),
            match.fallback_used,
            any("Actor continuity" in reason for reason in match.reasons),
            input_digest,
        )
        reconciled.append(diagnostic)
    return tuple(reconciled)
