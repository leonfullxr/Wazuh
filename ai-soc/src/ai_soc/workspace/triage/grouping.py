"""Stable queue subjects, independent of deployment and model versions."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import UTC, datetime

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

FINGERPRINT_SPEC = "workspace.group.v1"


def digest(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(raw.encode()).hexdigest()


class GroupAlert(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    site_id: str = Field(min_length=1)
    alert_key: str = Field(min_length=1)
    source_hash: str = Field(min_length=1)
    event_ts: AwareDatetime
    rule_id: str | None
    agent_id: str | None
    primary_entity: str | None


class GroupDraft(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    site_id: str
    group_id: str
    fingerprint_spec: str
    fingerprint: str
    bucket_start: AwareDatetime
    first_ts: AwareDatetime
    last_ts: AwareDatetime
    member_keys: tuple[str, ...]
    revision: str


def group_alerts(alerts: tuple[GroupAlert, ...]) -> tuple[GroupDraft, ...]:
    """Group by UTC hour and explicit fingerprint; missing identities stay singletons."""
    buckets: dict[tuple[str, str, datetime], dict[str, GroupAlert]] = defaultdict(dict)
    for alert in alerts:
        bucket = alert.event_ts.astimezone(UTC).replace(minute=0, second=0, microsecond=0)
        fingerprint = digest(
            [
                alert.rule_id,
                alert.agent_id,
                alert.primary_entity,
                alert.alert_key if not alert.rule_id or not alert.agent_id else None,
            ]
        )
        key = (alert.site_id, fingerprint, bucket)
        previous = buckets[key].get(alert.alert_key)
        if previous is not None and previous != alert:
            raise ValueError("conflicting immutable alert inputs")
        buckets[key][alert.alert_key] = alert
    drafts: list[GroupDraft] = []
    for (site_id, fingerprint, bucket), members in sorted(buckets.items()):
        ordered = sorted(members.values(), key=lambda alert: alert.alert_key)
        group_id = digest([site_id, FINGERPRINT_SPEC, fingerprint, bucket.isoformat()])
        drafts.append(
            GroupDraft(
                site_id=site_id,
                group_id=group_id,
                fingerprint_spec=FINGERPRINT_SPEC,
                fingerprint=fingerprint,
                bucket_start=bucket,
                first_ts=min(alert.event_ts for alert in ordered),
                last_ts=max(alert.event_ts for alert in ordered),
                member_keys=tuple(alert.alert_key for alert in ordered),
                revision=digest(
                    [group_id, [(alert.alert_key, alert.source_hash) for alert in ordered]]
                ),
            )
        )
    return tuple(drafts)
