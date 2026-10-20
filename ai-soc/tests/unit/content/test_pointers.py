import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Literal

import pytest

from ai_soc.content.catalog import safe_relative_path
from ai_soc.content.pointers import document_pointer
from ai_soc.contracts.models import DocumentDefinition, LocaleText, TopicDefinition

G014_FIXTURE = Path(__file__).parent / "data/g014_pointer_variants.json"
G032_FIXTURE = Path(__file__).parent / "data/b2_g032_authority_variants.json"


def _fixture() -> dict[str, dict[str, str]]:
    return json.loads(G014_FIXTURE.read_text(encoding="utf-8"))


def _record_g014(record_property: Callable[[str, str], None], variant: str) -> None:
    record_property("acceptance_ids", "G014")
    record_property("case_id", "B2-G014.pointer")
    record_property("variant", variant)
    record_property("fixture_sha256", hashlib.sha256(G014_FIXTURE.read_bytes()).hexdigest())


def _record_g032(record_property: Callable[[str, str], None], variant: str) -> None:
    record_property("acceptance_ids", "G032")
    record_property("case_id", "B2-G032.authority")
    record_property("variant", variant)
    record_property("fixture_sha256", hashlib.sha256(G032_FIXTURE.read_bytes()).hexdigest())


def _topic(
    published_path: str,
    *,
    source_path: str = "public-docs/en/ldap.md",
    heading: str = "LDAP setup & guide",
    anchor: str = "ldap-setup-guide",
    language: Literal["en", "es"] = "en",
) -> TopicDefinition:
    return TopicDefinition(
        topic_id="ldap",
        name=LocaleText(en="LDAP", es="LDAP"),
        aliases=[],
        public_document=DocumentDefinition(
            document_id="ldap_doc",
            language=language,
            source_path=source_path,
            heading=heading,
            anchor=anchor,
            sha256="1" * 64,
            published_path=published_path,
        ),
        playbook_id=None,
        finding_template_ids=[],
        fetch_bindings=[],
    )


def test_registered_pointer_preserves_authoritative_source_and_immutable_revision(
    record_property: Callable[[str, str], None],
) -> None:
    _record_g014(record_property, "positive")
    fixture = _fixture()["positive"]
    pointer = document_pointer(
        _topic(fixture["published_path"], source_path=fixture["source_path"]),
        language="en",
        content_sha=fixture["content_sha"],
        docs_origin=fixture["docs_origin"],
    )
    assert pointer is not None
    assert pointer.source_path == fixture["source_path"]
    assert pointer.heading == fixture["heading"]
    assert str(pointer.url) == fixture["expected_url"]


def test_document_pointer_is_immutable_and_quotes_heading_anchor() -> None:
    pointer = document_pointer(
        _topic("en/ldap.html"),
        language="en",
        content_sha="2" * 40,
        docs_origin="https://docs.example.test",
    )
    assert pointer is not None
    assert str(pointer.url) == (
        "https://docs.example.test/commits/" + "2" * 40 + "/en/ldap.html#ldap-setup-guide"
    )
    assert pointer.document_sha256 == "1" * 64
    assert (
        document_pointer(
            _topic("en/ldap.html"),
            language="es",
            content_sha="2" * 40,
            docs_origin="https://docs.example.test",
        )
        is None
    )


def test_registered_pointer_cannot_substitute_another_language_source(
    record_property: Callable[[str, str], None],
) -> None:
    _record_g014(record_property, "negative")
    fixture = _fixture()["negative"]
    pointer = document_pointer(
        _topic(fixture["published_path"], language="en"),
        language="es",
        content_sha=fixture["content_sha"],
        docs_origin=fixture["docs_origin"],
    )
    assert pointer is None


def test_registered_pointer_encodes_path_and_anchor_without_changing_source_values(
    record_property: Callable[[str, str], None],
) -> None:
    _record_g014(record_property, "boundary")
    fixture = _fixture()["boundary"]
    pointer = document_pointer(
        _topic(
            fixture["published_path"],
            source_path=fixture["source_path"],
            heading=fixture["heading"],
            anchor=fixture["anchor"],
        ),
        language="en",
        content_sha=fixture["content_sha"],
        docs_origin=fixture["docs_origin"],
    )
    assert pointer is not None
    assert pointer.source_path == fixture["source_path"]
    assert pointer.heading == fixture["heading"]
    assert pointer.anchor == fixture["anchor"]
    assert str(pointer.url) == fixture["expected_url"]


def test_registered_pointer_rejects_invalid_commit_or_unsafe_path(
    record_property: Callable[[str, str], None],
) -> None:
    _record_g014(record_property, "failure")
    fixture = _fixture()["failure"]
    with pytest.raises(ValueError, match="content SHA"):
        document_pointer(
            _topic("en/ldap.html"),
            language="en",
            content_sha=fixture["invalid_content_sha"],
            docs_origin=fixture["docs_origin"],
        )
    with pytest.raises(ValueError, match="unsafe repository path"):
        document_pointer(
            _topic(fixture["unsafe_published_path"]),
            language="en",
            content_sha=fixture["content_sha"],
            docs_origin=fixture["docs_origin"],
        )


def test_g032_authority_does_not_substitute_a_different_language_source(
    record_property: Callable[[str, str], None],
) -> None:
    _record_g032(record_property, "negative")
    fixture = json.loads(G032_FIXTURE.read_text(encoding="utf-8"))["negative"]
    assert fixture["source_language"] == "en"
    assert fixture["requested_language"] == "es"
    assert (
        document_pointer(
            _topic("en/ldap.html"),
            language="es",
            content_sha=fixture["content_sha"],
            docs_origin=fixture["docs_origin"],
        )
        is None
    )


def test_g032_authority_keeps_exact_source_and_encoded_revision_anchor(
    record_property: Callable[[str, str], None],
) -> None:
    _record_g032(record_property, "boundary")
    fixture = json.loads(G032_FIXTURE.read_text(encoding="utf-8"))["boundary"]
    pointer = document_pointer(
        _topic(
            fixture["published_path"],
            source_path=fixture["source_path"],
            heading=fixture["heading"],
            anchor=fixture["anchor"],
        ),
        language="en",
        content_sha=fixture["content_sha"],
        docs_origin=fixture["docs_origin"],
    )
    assert pointer is not None
    assert pointer.source_path == fixture["source_path"]
    assert pointer.heading == fixture["heading"]
    assert pointer.anchor == fixture["anchor"]
    assert str(pointer.url) == fixture["expected_url"]


def test_g032_authority_fails_closed_for_invalid_revision_and_source_path() -> None:
    fixture = json.loads(G032_FIXTURE.read_text(encoding="utf-8"))["failure"]
    with pytest.raises(ValueError, match="content SHA"):
        document_pointer(
            _topic("en/ldap.html"),
            language="en",
            content_sha=fixture["invalid_content_sha"],
            docs_origin=fixture["docs_origin"],
        )
    with pytest.raises(ValueError, match="unsafe repository path"):
        document_pointer(
            _topic(fixture["unsafe_published_path"]),
            language="en",
            content_sha=fixture["content_sha"],
            docs_origin=fixture["docs_origin"],
        )


@pytest.mark.parametrize("path", ["../escape", "/absolute", "a//b", "a\\b", "./dot"])
def test_unsafe_pack_paths_fail_closed(path: str) -> None:
    with pytest.raises(ValueError, match="unsafe repository path"):
        safe_relative_path(path)


def test_document_pointer_rejects_traversal_even_for_direct_model_input() -> None:
    with pytest.raises(ValueError, match="unsafe repository path"):
        document_pointer(
            _topic("../../outside.html"),
            language="en",
            content_sha="2" * 40,
            docs_origin="https://docs.example.test",
        )
