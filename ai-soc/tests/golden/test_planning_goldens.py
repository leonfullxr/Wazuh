"""Run the portable planning goldens against deterministic planner invariants."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import TypeAdapter

from ai_soc.content.catalog import ContentCatalog
from ai_soc.contracts.models import (
    AliasDefinition,
    AskRequest,
    BuildProvenance,
    Clarified,
    CueCatalog,
    FetchBinding,
    FetchStep,
    HTTPSUrl,
    LocaleText,
    Planned,
    PlaybookDefinition,
    PlaybookStep,
    Refused,
    TemplateId,
    TopicDefinition,
    VerifiedPrincipal,
    WindowDefault,
)
from ai_soc.planning.parser import DeterministicPlanner

ROOT = Path(__file__).resolve().parents[2]
CASES: list[dict[str, Any]] = json.loads(
    (ROOT / "docs/golden_examples.json").read_text(encoding="utf-8")
)["cases"]
POLICY_HASH = "a" * 64


class FixedClock:
    def now(self) -> datetime:
        return datetime(2026, 9, 30, 12, tzinfo=UTC)

    def monotonic(self) -> float:
        return 0.0


def _catalog(expected_topics: list[dict[str, Any]]) -> ContentCatalog:
    topics: list[TopicDefinition] = []
    playbooks: list[PlaybookDefinition] = []
    for expected in expected_topics:
        topic_id = cast(str, expected["topic_id"])
        if topic_id == "_records":
            continue
        playbook_id = f"{topic_id}-checks"
        templates = cast(list[str], expected["fetch_templates"])
        failure = cast(bool, expected["failure"])
        # Failure playbooks own their configured fetch steps. Keeping these
        # out of direct bindings mirrors the reviewed runtime seam and prevents
        # the planner fixture from manufacturing duplicate fetch work.
        direct_templates = [] if failure else templates
        topics.append(
            TopicDefinition(
                topic_id=expected["topic_id"],
                name=LocaleText(en=topic_id, es=topic_id),
                aliases=[
                    AliasDefinition(
                        alias_id=f"{expected['topic_id']}-{language}",
                        language=language,
                        text=expected["topic_id"],
                        normalized=expected["topic_id"],
                        boundary="word",
                        topic_id=expected["topic_id"],
                    )
                    for language in ("en", "es")
                ],
                public_document=None,
                playbook_id=playbook_id,
                finding_template_ids=[],
                fetch_bindings=[
                    FetchBinding(template_id=TemplateId(template_id), filters=[])
                    for template_id in direct_templates
                ],
            )
        )
        if failure:
            playbooks.append(
                PlaybookDefinition(
                    playbook_id=playbook_id,
                    topic_id=topic_id,
                    title=LocaleText(en=f"{topic_id} checks", es=f"Comprobaciones {topic_id}"),
                    internal_context="Synthetic golden fixture playbook.",
                    steps=[
                        cast(
                            PlaybookStep,
                            FetchStep(
                                kind="fetch",
                                step_id=f"{topic_id}-step-{index}",
                                label=LocaleText(en=template_id, es=template_id),
                                fetch_id=f"{topic_id}-fetch-{index}",
                                template_id=TemplateId(template_id),
                                window_default=WindowDefault(unit="hours", amount=24),
                                filters=[],
                            ),
                        )
                        for index, template_id in enumerate(templates)
                    ],
                )
            )
    provenance = BuildProvenance(
        service_sha="0" * 40,
        content_repository="https://fixture.example.test/soc-content",
        content_sha="1" * 40,
        pack_sha256="2" * 64,
        image_digest="sha256:" + "3" * 64,
        docs_origin="https://docs.example.test",
        docs_manifest_sha256="4" * 64,
    )
    cues = CueCatalog(version="1", sha256="5" * 64, cues=[], aliases=[], ambiguities=[])
    return ContentCatalog(provenance, cues, tuple(topics), (), tuple(playbooks))


def _principal() -> VerifiedPrincipal:
    return VerifiedPrincipal(
        issuer=cast(
            HTTPSUrl,
            TypeAdapter(HTTPSUrl).validate_python("https://issuer.example.test"),
        ),
        sub="golden-analyst",
        owner_key="6" * 64,
        groups=("soc",),
        edge="fixture",
        authenticated_at=datetime(2026, 9, 30, 11, tzinfo=UTC),
        expires_at=datetime(2026, 9, 30, 13, tzinfo=UTC),
        assertion_hash="7" * 64,
    )


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["case_id"])
def test_formal_planning_golden(case: dict[str, Any], record_property: Any) -> None:
    """Compare product plans to expectation data authored independently of the parser."""
    record_property("acceptance_ids", ",".join(case["requirements"]))
    record_property("case_id", case["case_id"])
    record_property("variant", case["variant"])
    record_property("fixture_sha256", case["fixture_sha256"])

    expected = case["expected"]["payload"]
    expected_topics = expected.get("topic_plans", [])
    parser_payload = dict(case["input"]["payload"])
    # Model selection is validated at the application boundary; this harness
    # exercises the planner's frozen parser-only contract.
    parser_payload.pop("model_id", None)
    parser_payload.pop("effort", None)
    request = AskRequest.model_validate_json(json.dumps(parser_payload))
    catalog = _catalog(expected_topics)
    planner = DeterministicPlanner(catalog)
    result = planner.plan(
        request,
        _principal(),
        None,
        policy_hash=POLICY_HASH,
        clock=FixedClock(),
    )

    if isinstance(result, Planned):
        assert expected["planning_status"] == "planned"
        assert result.plan.language == expected["language"]
        actual_topics = result.plan.topics
        assert [topic.topic_id for topic in actual_topics] == [
            topic["topic_id"] for topic in expected_topics
        ]
        assert sum(topic.judgment for topic in actual_topics) == expected["judgment_candidates"]
        for actual, wanted in zip(actual_topics, expected_topics, strict=True):
            assert actual.document is wanted["document"]
            assert actual.failure is wanted["failure"]
            assert actual.judgment is wanted["judgment"]
            if wanted["failure"]:
                playbook_id = actual.playbook_id
                assert playbook_id is not None
                assert playbook_id == f"{wanted['topic_id']}-checks"
                configured = catalog.playbook(playbook_id)
                assert configured is not None
                configured_templates = [
                    step.template_id for step in configured.steps if isinstance(step, FetchStep)
                ]
                assert actual.fetches == []
            else:
                configured_templates = []
                assert actual.playbook_id is None
            direct_templates = [fetch.template_id for fetch in actual.fetches]
            assert direct_templates == ([] if wanted["failure"] else wanted["fetch_templates"])
            assert [*direct_templates, *configured_templates] == wanted["fetch_templates"]
            if "filter_agent_id" in wanted:
                assert actual.fetches[0].filters[0].value == wanted["filter_agent_id"]
    elif isinstance(result, Clarified):
        assert expected["planning_status"] == "clarify"
        assert result.clarify.kind == expected["clarify_kind"]
        assert expected["judgment_candidates"] == 0
    else:
        assert isinstance(result, Refused)
        assert expected["planning_status"] == "refused"
        assert expected["judgment_candidates"] == 0
