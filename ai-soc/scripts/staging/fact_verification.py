"""Registered AWS fact-chain matching for authenticated qualification runs."""

from __future__ import annotations

import hashlib
from typing import Any

from scripts.staging.verifier import (
    _SEAL,
    EvidenceContradiction,
    EvidenceIncomplete,
    FactRequirement,
    VerifiedFact,
    VerifiedFactChain,
    VerifiedLaunch,
    _event_resources,
    _event_time,
    _parse_utc,
    _task_identity_matches,
    canonical_event_digest,
)


def _verify_fact_chain(
    launch: VerifiedLaunch,
    requirements: tuple[FactRequirement, ...],
    events: tuple[dict[str, Any], ...],
) -> VerifiedFactChain:
    """Match every registered direct-SDK fact to one unique AWS-recorded event."""
    if launch._seal is not _SEAL:
        raise EvidenceContradiction("unverified launch capability")
    facts: list[VerifiedFact] = []
    for requirement in requirements:
        matches: dict[str, tuple[dict[str, Any], str]] = {}
        for event in events:
            if (
                event.get("eventSource") != requirement.event_source
                or event.get("eventName") not in requirement.event_names
            ):
                continue
            if event.get("recipientAccountId") != launch.expectation.account_id:
                continue
            if event.get("awsRegion") != launch.expectation.region:
                continue
            fact_time = _event_time(event)
            if fact_time < _event_time({"eventTime": launch.started_at}):
                continue
            if fact_time > _parse_utc(launch.expectation.deadline_utc):
                continue
            if requirement.request_id_field == "$requestID":
                request_id_claim = event.get("requestID")
            else:
                request = event.get("requestParameters")
                request_id_claim = (
                    request.get(requirement.request_id_field) if isinstance(request, dict) else None
                )
            if request_id_claim != requirement.request_id_value:
                continue
            if requirement.resource_arn not in _event_resources(event):
                continue
            user = event.get("userIdentity")
            if not _task_identity_matches(user, launch):
                continue
            request_id, event_id = event.get("requestID"), event.get("eventID")
            if not isinstance(request_id, str) or not request_id or not isinstance(event_id, str):
                continue
            matches[event_id] = (event, canonical_event_digest(event))
        if len(matches) == 0:
            raise EvidenceIncomplete(f"required AWS fact is absent: {requirement.fact_id}")
        if len(matches) > 1:
            digests = {digest for _, digest in matches.values()}
            if len(digests) != 1:
                raise EvidenceIncomplete(f"required AWS fact is ambiguous: {requirement.fact_id}")
            # Duplicate deliveries of the same event are deduplicated by eventID
            # in parse_cloudtrail_logs; distinct event IDs remain ambiguous.
            raise EvidenceIncomplete(f"multiple AWS events match fact: {requirement.fact_id}")
        event, digest = next(iter(matches.values()))
        if event.get("errorCode") or event.get("errorMessage"):
            if requirement.outcome == "success":
                raise EvidenceContradiction(f"required AWS fact failed: {requirement.fact_id}")
        elif requirement.outcome == "failure":
            raise EvidenceContradiction(
                f"required AWS fact unexpectedly succeeded: {requirement.fact_id}"
            )
        facts.append(
            VerifiedFact(
                fact_id=requirement.fact_id,
                request_id=event["requestID"],
                event_id=event["eventID"],
                event_digest=digest,
                resource_arn=requirement.resource_arn,
                outcome="failure" if event.get("errorCode") else "success",
            )
        )
    chain_digest = hashlib.sha256(
        "\n".join(f"{fact.fact_id}:{fact.event_digest}" for fact in facts).encode()
    ).hexdigest()
    return VerifiedFactChain(
        _seal=_SEAL,
        launch=launch,
        facts=tuple(facts),
        chain_digest=chain_digest,
    )
