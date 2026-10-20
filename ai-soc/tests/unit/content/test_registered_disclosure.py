from __future__ import annotations

# pyright: reportPrivateUsage=false
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import TypedDict

import pytest
from content_fixture_support import BuiltSeed, build_seed
from pydantic import TypeAdapter

from ai_soc.content.builder import ContentBuildError, _validate_cross_references
from ai_soc.content.pointers import document_pointer

FIXTURE = Path(__file__).parent / "data/b2_g017_disclosure_variants.json"


class Positive(TypedDict):
    language: str
    expected_document: str
    expected_analyst_check: str
    expected_pointer_source: str


class Negative(TypedDict):
    private_instruction: str
    public_path: str
    must_not_disclose: bool


class Boundary(TypedDict):
    languages: list[str]
    public_document_language: str
    same_source_section_for_each_context: bool
    private_playbook: str


class Failure(TypedDict):
    private_source_path: str
    expected_error: str


class DisclosureFixture(TypedDict):
    positive: Positive
    negative: Negative
    boundary: Boundary
    failure: Failure


FIXTURE_ADAPTER: TypeAdapter[DisclosureFixture] = TypeAdapter(DisclosureFixture)


def _record(record_property: Callable[[str, str], None], variant: str) -> None:
    record_property("acceptance_ids", "G017")
    record_property("case_id", "B2-G017.disclosure")
    record_property("variant", variant)
    record_property("fixture_sha256", hashlib.sha256(FIXTURE.read_bytes()).hexdigest())


def _fixture() -> DisclosureFixture:
    return FIXTURE_ADAPTER.validate_python(json.loads(FIXTURE.read_text(encoding="utf-8")))


@pytest.mark.parametrize("variant", ["positive", "negative", "boundary", "failure"])
def test_registered_public_and_internal_content_remain_separate(
    tmp_path: Path,
    record_property: Callable[[str, str], None],
    variant: str,
) -> None:
    _record(record_property, variant)
    fixture_data = _fixture()
    built: BuiltSeed = build_seed(tmp_path)
    english = built.catalog.topic_context("ldap", language="en")
    internal = built.catalog.playbook("ldap_read_checks")
    assert internal is not None
    topic = built.catalog.topic("ldap")
    assert topic is not None and topic.public_document is not None

    if variant == "positive":
        fixture = fixture_data["positive"]
        expectation = built.catalog.expectation("ldap_service_group", topic_id="ldap")
        assert expectation is not None
        assert str(expectation.value) == "ldap"
        assert fixture["expected_analyst_check"] in internal.internal_context
        pointer = document_pointer(
            topic,
            language="en",
            content_sha=built.provenance.content_sha,
            docs_origin="https://docs.example.test",
        )
        assert pointer is not None
        assert pointer.source_path == fixture["expected_pointer_source"]
        assert pointer.heading == fixture["expected_document"]
        assert english.document_section is not None
        assert fixture["expected_document"] in english.document_section
        return

    if variant == "negative":
        fixture = fixture_data["negative"]
        public_output = (built.pack / fixture["public_path"]).read_text(encoding="utf-8")
        assert fixture["private_instruction"] not in public_output
        assert english.internal_context == internal.internal_context
        assert fixture["private_instruction"] in (english.internal_context or "")
        return

    if variant == "boundary":
        fixture = fixture_data["boundary"]
        source_document = (built.source / "public-docs/en/ldap.md").read_text(encoding="utf-8")
        assert english.document_section == source_document
        spanish = built.catalog.topic_context("ldap", language="es")
        assert spanish.document_section == source_document
        assert fixture["same_source_section_for_each_context"] is True
        assert english.internal_context == internal.internal_context
        assert spanish.internal_context == internal.internal_context
        assert topic.public_document.language == fixture["public_document_language"]
        assert internal.playbook_id == fixture["private_playbook"]
        return

    fixture = fixture_data["failure"]
    raw_private_playbook = (built.source / fixture["private_source_path"]).read_bytes()
    private_pointer_topic = topic.model_copy(
        update={
            "public_document": topic.public_document.model_copy(
                update={
                    "source_path": fixture["private_source_path"],
                    "sha256": hashlib.sha256(raw_private_playbook).hexdigest(),
                }
            )
        }
    )
    with pytest.raises(ContentBuildError, match=fixture["expected_error"]):
        _validate_cross_references(
            {},
            (private_pointer_topic,),
            (built.catalog.cues(),),
            built.catalog.playbook_records,
            tuple(item for item in built.catalog.expectations if item.topic_id == topic.topic_id),
            built.catalog.templates,
            (),
            (),
        )
