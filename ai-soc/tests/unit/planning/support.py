from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from ai_soc.content.catalog import ContentCatalog
from ai_soc.contracts.models import (
    AliasDefinition,
    BuildProvenance,
    CueCatalog,
    FetchBinding,
    TemplateId,
    TopicDefinition,
    VerifiedPrincipal,
)


def record_case(
    record_property: Callable[[str, str], None],
    *,
    requirements: tuple[str, ...],
    case_id: str,
    variant: str,
    fixture: Path | None = None,
    fixture_sha256: str | None = None,
) -> None:
    """Attach exact registered case metadata and digest of the input fixture bytes."""
    if (fixture is None) == (fixture_sha256 is None):
        raise ValueError("provide exactly one fixture path or exact fixture SHA-256")
    record_property("acceptance_ids", ",".join(requirements))
    record_property("case_id", case_id)
    record_property("variant", variant)
    if fixture_sha256 is not None:
        digest = fixture_sha256
    elif fixture is not None:
        digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
    else:
        raise AssertionError("fixture path or fixture SHA-256 was validated above")
    record_property("fixture_sha256", digest)


class FixedClock:
    def __init__(self, now: datetime = datetime(2026, 9, 30, 12, tzinfo=UTC)) -> None:
        self._now = now

    def now(self) -> datetime:
        return self._now

    def monotonic(self) -> float:
        return 0.0


def make_catalog(topic_names: tuple[str, ...] = ("ldap", "dns", "tls")) -> ContentCatalog:
    topics = tuple(
        TopicDefinition(
            topic_id=topic_id,
            name={"en": topic_id.upper(), "es": topic_id.upper()},
            aliases=[
                AliasDefinition(
                    alias_id=f"{topic_id}_en",
                    language="en",
                    text=topic_id.upper(),
                    normalized=topic_id,
                    boundary="word",
                    topic_id=topic_id,
                ),
                AliasDefinition(
                    alias_id=f"{topic_id}_es",
                    language="es",
                    text=topic_id.upper(),
                    normalized=topic_id,
                    boundary="word",
                    topic_id=topic_id,
                ),
            ],
            public_document=None,
            playbook_id=f"{topic_id}_checks",
            finding_template_ids=[],
            fetch_bindings=[FetchBinding(template_id=TemplateId.alerts_rows_v1, filters=[])],
        )
        for topic_id in topic_names
    )
    provenance = BuildProvenance(
        service_sha="0" * 40,
        content_repository="https://example.test/content",
        content_sha="1" * 40,
        pack_sha256="2" * 64,
        image_digest="sha256:" + "3" * 64,
        docs_origin="https://docs.example.test",
        docs_manifest_sha256="4" * 64,
    )
    cues = CueCatalog(version="1", sha256="5" * 64, cues=[], aliases=[], ambiguities=[])
    return ContentCatalog(provenance, cues, topics, ())


def make_principal() -> VerifiedPrincipal:
    return VerifiedPrincipal(
        issuer="https://idp.example.test",
        sub="analyst-1",
        owner_key="6" * 64,
        groups=("soc",),
        edge="fixture",
        authenticated_at=datetime(2026, 9, 30, 11, tzinfo=UTC),
        expires_at=datetime(2026, 9, 30, 13, tzinfo=UTC),
        assertion_hash="7" * 64,
    )
