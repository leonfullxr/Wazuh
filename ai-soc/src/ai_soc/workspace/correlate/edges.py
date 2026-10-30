"""Bounded indexed shared-field edge generation; edges describe evidence only."""

from __future__ import annotations

import ipaddress
from bisect import bisect_left, bisect_right
from collections import defaultdict
from datetime import datetime, timedelta

from ai_soc.workspace.triage.grouping import digest

from .models import MISSING_TEXT, CorrelationInput, CorrelationObservation, EdgeDraft, EdgeType, utc

MAX_EDGE_WORK = 2_000_000
MAX_EDGES = 100_000
UNKNOWN = MISSING_TEXT


def _present(value: str | None) -> str | None:
    if value is None or value.strip().casefold() in UNKNOWN:
        return None
    return value


def _ip(value: str | None) -> tuple[str, bool] | None:
    if _present(value) is None:
        return None
    address = ipaddress.ip_address(value or "")
    return str(address), address.is_global


def _directed_witness(
    left: CorrelationObservation, right: CorrelationObservation
) -> tuple[CorrelationObservation, CorrelationObservation]:
    left_key = (utc(left.event_ts), left.alert_key)
    right_key = (utc(right.event_ts), right.alert_key)
    return (left, right) if left_key <= right_key else (right, left)


def build_edges(inputs: CorrelationInput) -> tuple[EdgeDraft, ...]:
    """Create one earliest concrete witness per unordered group pair and edge type.

    Each shared key is indexed by group and event time. A sweep probes one
    earliest in-window witness per other group via binary search; it never
    expands member Cartesian products. More than two million group probes or
    100,000 emitted edges fails the call instead of returning partial output.
    """
    groups = {group.group_id: group for group in inputs.groups}
    found: dict[
        tuple[str, str, EdgeType],
        tuple[
            tuple[object, ...],
            CorrelationObservation,
            CorrelationObservation,
            tuple[tuple[str, str], ...],
        ],
    ] = {}
    work = 0

    def key_values(
        obs: CorrelationObservation,
    ) -> list[tuple[EdgeType, tuple[str, ...], tuple[tuple[str, str], ...], float]]:
        values: list[tuple[EdgeType, tuple[str, ...], tuple[tuple[str, str], ...], float]] = []
        ip = _ip(obs.src_ip)
        user = _present(obs.dst_user)
        if ip is not None and user is not None:
            values.append(
                ("same_src_ip_user", (ip[0], user), (("src_ip", ip[0]), ("dst_user", user)), 7200)
            )
        agent = _present(obs.agent_id)
        users: set[str] = set()
        for candidate in (obs.src_user, obs.dst_user):
            normalized_user = _present(candidate)
            if normalized_user is not None:
                users.add(normalized_user)
        if agent is not None:
            for value in users:
                values.append(
                    ("same_user_host", (value, agent), (("user", value), ("agent.id", agent)), 7200)
                )
        if ip is not None and ip[1] and agent is not None:
            values.append(("same_src_ip", (ip[0],), (("src_ip", ip[0]),), 21600))
        for value in sorted({item.casefold() for item in obs.hashes}):
            normalized = _present(value)
            if normalized is not None:
                values.append(
                    ("same_hash", (normalized.casefold(),), (("hash", normalized),), 86400)
                )
        if agent is not None:
            values.append(("same_host", (agent,), (("agent.id", agent),), 3600))
        return values

    indexes: dict[tuple[EdgeType, tuple[str, ...]], dict[str, list[CorrelationObservation]]] = (
        defaultdict(lambda: defaultdict(list))
    )
    for observation in inputs.observations:
        for edge_type, key, _, _ in key_values(observation):
            indexes[(edge_type, key)][observation.group_id].append(observation)

    max_gaps: dict[EdgeType, float] = {
        "same_src_ip_user": 7200,
        "same_user_host": 7200,
        "same_src_ip": 21600,
        "same_hash": 86400,
        "same_host": 3600,
    }
    confidence: dict[EdgeType, tuple[float, bool, str]] = {
        "same_src_ip_user": (0.9, False, "shared source IP and destination user"),
        "same_user_host": (0.7, False, "shared user and agent"),
        "same_src_ip": (0.6, False, "shared public source IP across agents"),
        "same_hash": (0.8, False, "shared file hash"),
        "same_host": (0.3, True, "shared agent only"),
    }
    key_shared: dict[tuple[EdgeType, tuple[str, ...]], tuple[tuple[str, str], ...]] = {}
    for edge_type, key in indexes:
        if edge_type == "same_src_ip_user":
            fields = (("src_ip", key[0]), ("dst_user", key[1]))
        elif edge_type == "same_user_host":
            fields = (("user", key[0]), ("agent.id", key[1]))
        elif edge_type == "same_src_ip":
            fields = (("src_ip", key[0]),)
        elif edge_type == "same_hash":
            fields = (("hash", key[0]),)
        else:
            fields = (("agent.id", key[0]),)
        key_shared[(edge_type, key)] = fields

    for (edge_type, key), by_group in sorted(
        indexes.items(), key=lambda item: (item[0][0], item[0][1])
    ):
        if len(by_group) < 2:
            continue
        ordered_by_group = {
            group_id: sorted(members, key=lambda item: (utc(item.event_ts), item.alert_key))
            for group_id, members in by_group.items()
        }
        ordered_by_group_agent: dict[str, dict[str, list[CorrelationObservation]]] = {}
        times_by_group_agent: dict[str, dict[str, list[datetime]]] = {}
        if edge_type == "same_src_ip":
            ordered_by_group_agent = {group_id: defaultdict(list) for group_id in ordered_by_group}
            for group_id, members in ordered_by_group.items():
                for member in members:
                    assert member.agent_id is not None
                    ordered_by_group_agent[group_id][member.agent_id].append(member)
            times_by_group_agent = {
                group_id: {
                    agent_id: [utc(item.event_ts) for item in members]
                    for agent_id, members in agents.items()
                }
                for group_id, agents in ordered_by_group_agent.items()
            }
        times = {
            group_id: [utc(item.event_ts) for item in members]
            for group_id, members in ordered_by_group.items()
        }
        max_gap = max_gaps[edge_type]
        for members in ordered_by_group.values():
            for current in members:
                current_time = utc(current.event_ts)
                for other_group, other_members in ordered_by_group.items():
                    if other_group == current.group_id:
                        continue
                    other: CorrelationObservation | None = None
                    if edge_type == "same_src_ip":
                        for other_agent, agent_members in ordered_by_group_agent[
                            other_group
                        ].items():
                            if other_agent == current.agent_id:
                                continue
                            work += 1
                            if work > MAX_EDGE_WORK:
                                raise ValueError("edge correlation work cap exceeded")
                            agent_times = times_by_group_agent[other_group][other_agent]
                            low = bisect_left(
                                agent_times, current_time - timedelta(seconds=max_gap)
                            )
                            high = bisect_right(agent_times, current_time)
                            if high <= low:
                                continue
                            candidate = agent_members[low]
                            if (
                                utc(candidate.event_ts) == current_time
                                and candidate.alert_key >= current.alert_key
                            ):
                                continue
                            if other is None or (utc(candidate.event_ts), candidate.alert_key) < (
                                utc(other.event_ts),
                                other.alert_key,
                            ):
                                other = candidate
                    else:
                        work += 1
                        if work > MAX_EDGE_WORK:
                            raise ValueError("edge correlation work cap exceeded")
                        other_times = times[other_group]
                        low = bisect_left(other_times, current_time - timedelta(seconds=max_gap))
                        high = bisect_right(other_times, current_time)
                        if high > low:
                            candidate = other_members[low]
                            if not (
                                utc(candidate.event_ts) == current_time
                                and candidate.alert_key >= current.alert_key
                            ):
                                other = candidate
                    if other is None:
                        continue
                    delta = (current_time - utc(other.event_ts)).total_seconds()
                    if delta < 0 or delta > max_gap:
                        continue
                    pair = tuple(sorted((current.group_id, other.group_id)))
                    witness_from, witness_to = _directed_witness(current, other)
                    rank = (
                        utc(witness_from.event_ts),
                        witness_from.alert_key,
                        utc(witness_to.event_ts),
                        witness_to.alert_key,
                    )
                    key_out = (pair[0], pair[1], edge_type)
                    shared = key_shared[(edge_type, key)]
                    previous = found.get(key_out)
                    if previous is None or rank < previous[0]:
                        found[key_out] = (rank, witness_from, witness_to, shared)

    strong_pairs = {(a, b) for (a, b, edge_type) in found if edge_type != "same_host"}
    result: list[EdgeDraft] = []
    for (pair_from, pair_to, edge_type), (_, first, second, shared) in sorted(found.items()):
        if edge_type == "same_host" and (pair_from, pair_to) in strong_pairs:
            continue
        confidence_value, weak, reason = confidence[edge_type]
        from_group_model = groups[first.group_id]
        to_group_model = groups[second.group_id]
        delta = abs((utc(second.event_ts) - utc(first.event_ts)).total_seconds())
        edge_id = digest(
            [
                inputs.site_id,
                "workspace.edge.v1",
                inputs.computation_version,
                pair_from,
                pair_to,
                edge_type,
                from_group_model.revision,
                to_group_model.revision,
                first.alert_key,
                first.source_hash,
                utc(first.event_ts).isoformat(),
                second.alert_key,
                second.source_hash,
                utc(second.event_ts).isoformat(),
                shared,
            ]
        )
        result.append(
            EdgeDraft(
                site_id=inputs.site_id,
                edge_id=edge_id,
                from_group=first.group_id,
                from_revision=from_group_model.revision,
                to_group=second.group_id,
                to_revision=to_group_model.revision,
                edge_type=edge_type,
                confidence=confidence_value,
                weak=weak,
                reason=reason,
                time_delta_seconds=delta,
                from_alert_key=first.alert_key,
                to_alert_key=second.alert_key,
                shared_fields=shared,
            )
        )
        if len(result) > MAX_EDGES:
            raise ValueError("edge output cap exceeded")
    return tuple(result)
