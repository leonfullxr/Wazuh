from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import cast
from uuid import uuid4

import pytest

from ai_soc.application.service import ApplicationService
from ai_soc.contracts.models import (
    AdmissionGrant,
    AskRequest,
    AuthorizedSite,
    BuildProvenance,
    Clarified,
    Clarify,
    Refused,
    SemanticSuggestion,
    VerifiedPrincipal,
)
from ai_soc.contracts.ports import SemanticSuggester

NOW = datetime(2026, 10, 3, 12, tzinfo=UTC)


class _Catalog:
    def __init__(self, topic: object | None = None) -> None:
        self._topic = topic

    def cues(self) -> SimpleNamespace:
        return SimpleNamespace(cues=[], aliases=[])

    def topics(self) -> list[object]:
        return [self._topic] if self._topic is not None else []

    def topic(self, topic_id: str) -> object | None:
        return self._topic if topic_id == "ldap" else None

    def manifest(self) -> BuildProvenance:
        return cast(BuildProvenance, object())


class _Clock:
    def now(self) -> datetime:
        return NOW


class _Admissions:
    def __init__(self) -> None:
        self.acquired = 0
        self.released = 0
        self.grant = AdmissionGrant(
            holder_id=uuid4(), slot_ids=("semantic",), expires_at=NOW, fence=1
        )

    async def acquire(self, *args: object) -> AdmissionGrant:
        self.acquired += 1
        return self.grant

    async def release(self, grant: AdmissionGrant) -> None:
        assert grant == self.grant
        self.released += 1


class _Runtime:
    def create(self, **kwargs: object) -> object:
        assert kwargs["operation"] == "semantic"
        assert kwargs["admission"] is not None
        return object()


class _Suggester:
    def __init__(
        self,
        result: SemanticSuggestion | None = None,
        error: Exception | None = None,
    ) -> None:
        self.calls = 0
        self.result = result
        self.error = error

    async def suggest(self, *args: object, **kwargs: object) -> SemanticSuggestion | None:
        self.calls += 1
        assert kwargs["language"] == "en"
        if self.error is not None:
            raise self.error
        return self.result


def _service(
    planner_result: object, suggester: _Suggester, *, topic: object | None = None
) -> tuple[ApplicationService, _Admissions]:
    service = object.__new__(ApplicationService)
    admissions = _Admissions()
    service.clock = _Clock()
    service.catalog = _Catalog(topic)
    service.planner = SimpleNamespace(plan=lambda *args, **kwargs: planner_result)
    service.site_policy = SimpleNamespace(
        authorize=lambda *_args: cast(
            AuthorizedSite,
            SimpleNamespace(policy_hash="1" * 64, config=SimpleNamespace(allowed_templates=())),
        )
    )
    service.admissions = admissions
    service.runtime = _Runtime()
    service.semantic_suggester = cast(SemanticSuggester, suggester)
    return service, admissions


@pytest.mark.asyncio
async def test_semantic_fallback_runs_after_deterministic_refusal_and_releases_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suggester = _Suggester()
    service, admissions = _service(Refused(message="Unsupported question."), suggester)

    async def answer_without_state(*_args: object, **_kwargs: object) -> str:
        return "deterministic refusal"

    monkeypatch.setattr(ApplicationService, "_unplanned_answer", answer_without_state)
    result = await service.ask(
        AskRequest(question="Tell me about an unfamiliar concept", environment_id="alpha"),
        cast(VerifiedPrincipal, SimpleNamespace(owner_key="a" * 64)),
    )

    assert result == "deterministic refusal"
    assert suggester.calls == 1
    assert admissions.acquired == admissions.released == 2


@pytest.mark.asyncio
async def test_semantic_fallback_is_not_called_for_deterministic_clarification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suggester = _Suggester()
    service, admissions = _service(
        Clarified(clarify=Clarify(kind="missing_slots", question="Which topic?", slots=["topic"])),
        suggester,
    )

    async def answer_without_state(*_args: object, **_kwargs: object) -> str:
        return "deterministic clarification"

    monkeypatch.setattr(ApplicationService, "_unplanned_answer", answer_without_state)
    result = await service.ask(
        AskRequest(question="Tell me about an unfamiliar concept", environment_id="alpha"),
        cast(VerifiedPrincipal, SimpleNamespace(owner_key="a" * 64)),
    )

    assert result == "deterministic clarification"
    assert suggester.calls == 0
    assert admissions.acquired == admissions.released == 1


@pytest.mark.asyncio
async def test_qualified_semantic_match_returns_localized_topic_clarification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suggestion = SemanticSuggestion(
        topic_id="ldap",
        score=0.91,
        margin=0.2,
        model_id="embedding-model",
        qualifies=True,
        near_threshold=False,
    )
    topic = SimpleNamespace(
        name=SimpleNamespace(en="Directory login", es="Inicio de sesión de directorio"),
        public_document=object(),
        fetch_bindings=(),
        aliases=(),
    )
    suggester = _Suggester(suggestion)
    service, admissions = _service(Refused(message="Unsupported question."), suggester, topic=topic)
    captured: dict[str, object] = {}

    async def answer_without_state(*_args: object, **kwargs: object) -> str:
        captured.update(kwargs)
        return "semantic clarification"

    monkeypatch.setattr(ApplicationService, "_unplanned_answer", answer_without_state)
    result = await service.ask(
        AskRequest(question="Tell me about an unfamiliar concept", environment_id="alpha"),
        cast(VerifiedPrincipal, SimpleNamespace(owner_key="a" * 64)),
    )

    clarify = captured["clarify"]
    assert result == "semantic clarification"
    assert clarify.kind == "semantic_suggestion"
    assert clarify.suggested_topic == "ldap"
    assert clarify.question == "Did you mean Directory login?"
    assert suggester.calls == 1
    assert admissions.acquired == admissions.released == 2


@pytest.mark.asyncio
async def test_unexpected_semantic_provider_error_propagates_and_releases_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = RuntimeError("fixture embedding failure")
    suggester = _Suggester(error=expected)
    service, admissions = _service(Refused(message="Unsupported question."), suggester)

    async def answer_without_state(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("unexpected provider error must not become an abstention")

    monkeypatch.setattr(ApplicationService, "_unplanned_answer", answer_without_state)
    with pytest.raises(RuntimeError, match="fixture embedding failure") as failure:
        await service.ask(
            AskRequest(question="Tell me about an unfamiliar concept", environment_id="alpha"),
            cast(VerifiedPrincipal, SimpleNamespace(owner_key="a" * 64)),
        )

    assert failure.value is expected
    assert suggester.calls == 1
    assert admissions.acquired == admissions.released == 2
