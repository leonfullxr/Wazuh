from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TypedDict
from uuid import uuid4

import pytest
from content_fixture_support import build_seed
from pydantic import TypeAdapter

from ai_soc.content.builder import ContentBuildError
from ai_soc.contracts.models import (
    AskRequest,
    Clarified,
    FollowupRecord,
    HTTPSUrl,
    Planned,
    Refused,
    VerifiedPrincipal,
)
from ai_soc.planning.followups import transform_followup
from ai_soc.planning.parser import DeterministicPlanner

FIXTURE = Path(__file__).parent / "data/b2_g015_immutable_variants.json"
POLICY_HASH = "a" * 64
HTTPS_URL: TypeAdapter[HTTPSUrl] = TypeAdapter(HTTPSUrl)


class Positive(TypedDict):
    question: str
    expected_aliases: list[str]
    expected_playbook: str


class Negative(TypedDict):
    path: str
    expected_write_error: str


class Boundary(TypedDict):
    questions: list[str]
    expected_same_pack_hash: bool


class Failure(TypedDict):
    path: str
    mutation: str
    expected_error: str


class ImmutableFixture(TypedDict):
    positive: Positive
    negative: Negative
    boundary: Boundary
    failure: Failure


FIXTURE_ADAPTER: TypeAdapter[ImmutableFixture] = TypeAdapter(ImmutableFixture)


def _record(record_property: Callable[[str, str], None], variant: str) -> None:
    record_property("acceptance_ids", "G015")
    record_property("case_id", "B2-G015.immutable")
    record_property("variant", variant)
    record_property("fixture_sha256", hashlib.sha256(FIXTURE.read_bytes()).hexdigest())


def _principal() -> VerifiedPrincipal:
    return VerifiedPrincipal(
        issuer=HTTPS_URL.validate_python("https://idp.example.test"),
        sub="fixture-analyst",
        owner_key="6" * 64,
        groups=("soc",),
        edge="fixture",
        authenticated_at=datetime(2026, 9, 30, 11, tzinfo=UTC),
        expires_at=datetime(2026, 9, 30, 13, tzinfo=UTC),
        assertion_hash="7" * 64,
    )


@pytest.mark.parametrize("variant", ["positive", "negative", "boundary", "failure"])
def test_registered_pack_and_runtime_views_are_immutable(
    tmp_path: Path,
    record_property: Callable[[str, str], None],
    variant: str,
) -> None:
    _record(record_property, variant)
    fixture_data = FIXTURE_ADAPTER.validate_python(json.loads(FIXTURE.read_text(encoding="utf-8")))
    built = build_seed(tmp_path)
    topic_file = built.pack / "pack/topics/ldap.json"
    before = topic_file.read_bytes()
    pack_hash = built.catalog.manifest().pack_sha256

    if variant == "negative":
        fixture = fixture_data["negative"]
        assert topic_file.stat().st_mode & 0o222 == 0
        with pytest.raises(PermissionError):
            with topic_file.open("ab") as stream:
                stream.write(b"unapproved")
        assert topic_file.read_bytes() == before
        return

    if variant == "failure":
        fixture = fixture_data["failure"]
        os.chmod(topic_file, 0o600)
        topic_file.write_bytes(before + b" ")
        with pytest.raises(ContentBuildError, match=fixture["expected_error"]):
            from ai_soc.content.catalog import load_content_catalog

            load_content_catalog(built.pack, provenance=built.provenance)
        return

    planner = DeterministicPlanner(built.catalog)
    if variant == "boundary":
        fixture = fixture_data["boundary"]
        before_pack = {
            path.relative_to(built.pack).as_posix(): path.read_bytes()
            for path in built.pack.rglob("*")
            if path.is_file()
        }
        for question in fixture["questions"]:
            result = planner.plan(
                AskRequest(question=question, environment_id="fixture", timezone="UTC"),
                _principal(),
                None,
                policy_hash=POLICY_HASH,
                clock=_FixedClock(),
            )
            assert isinstance(result, (Clarified, Refused))
        after_pack = {
            path.relative_to(built.pack).as_posix(): path.read_bytes()
            for path in built.pack.rglob("*")
            if path.is_file()
        }
        assert before_pack == after_pack
        assert built.catalog.manifest().pack_sha256 == pack_hash
        return

    fixture = fixture_data["positive"]
    principal = _principal()
    previous = planner.plan(
        AskRequest(question=fixture["question"], environment_id="fixture", timezone="UTC"),
        principal,
        None,
        policy_hash=POLICY_HASH,
        clock=_FixedClock(),
    )
    assert isinstance(previous, Planned)
    followup_id = uuid4()
    record = FollowupRecord(
        followup_id=followup_id,
        owner_key=principal.owner_key,
        environment_id="fixture",
        revision=1,
        plan=previous.plan,
        answered_topic_ids=["ldap"],
        leftout_topic_ids=[],
        leftout_stages=[],
        created_at=datetime(2026, 9, 30, 12, tzinfo=UTC),
        expires_at=datetime(2026, 10, 1, 12, tzinfo=UTC),
    )
    topic = built.catalog.topic("ldap")
    assert topic is not None
    aliases_before = topic.aliases
    playbooks_before = built.catalog.playbook_records
    transformed = transform_followup(
        AskRequest(
            question="and for the last 24 hours",
            environment_id="fixture",
            timezone="UTC",
            followup_id=followup_id,
            followup_revision=1,
        ),
        principal,
        record,
        catalog=built.catalog,
        policy_hash=POLICY_HASH,
        clock=_FixedClock(),
    )
    assert isinstance(transformed, Planned)
    assert [alias.alias_id for alias in aliases_before] == fixture["expected_aliases"]
    assert [book.playbook_id for book in playbooks_before if book.topic_id == "ldap"] == [
        fixture["expected_playbook"]
    ]
    assert topic.aliases == aliases_before
    assert built.catalog.playbook_records == playbooks_before
    assert built.catalog.manifest().pack_sha256 == pack_hash
    assert topic_file.read_bytes() == before


class _FixedClock:
    def now(self) -> datetime:
        return datetime(2026, 9, 30, 12, tzinfo=UTC)

    def monotonic(self) -> float:
        return 0.0
