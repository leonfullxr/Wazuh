"""Immutable approved catalog snapshot captured before the judgment runner awaits."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, TypeVar
from uuid import UUID

from pydantic import BaseModel, TypeAdapter, ValidationError

from ai_soc.content.finding_catalog import (
    CatalogError,
    catalog_bytes,
    definitions_from_bytes,
    validate_topic_context,
)
from ai_soc.contracts.canonical import canonical_bytes
from ai_soc.contracts.models import (
    CheckResult,
    EvidencePack,
    FindingTemplate,
    JudgmentRequest,
    TopicPromptPack,
    ValidationContext,
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)
_EXPECTED_CHECKS = TypeAdapter(tuple[CheckResult, ...])


class CatalogUnavailable(ValueError):
    """The approved catalog or its binding metadata could not be trusted."""


def _encoded(model: BaseModel) -> bytes:
    try:
        return canonical_bytes(model.model_dump(mode="json", exclude_none=False))
    except (AttributeError, TypeError, ValueError) as exc:
        raise CatalogUnavailable("approved snapshot input is not serializable") from exc


def _decoded[ModelT: BaseModel](model_type: type[ModelT], payload: bytes) -> ModelT:
    try:
        return model_type.model_validate_json(payload, strict=True)
    except (ValidationError, TypeError, ValueError) as exc:
        raise CatalogUnavailable("approved snapshot payload is not reconstructible") from exc


@dataclass(frozen=True, slots=True)
class CatalogSnapshot:
    """Detached bytes that remain the only later authority for catalog and prompt rendering."""

    topic_id: str
    question_id: UUID
    language: Literal["en", "es"]
    question: str
    standing_rules: str
    topic_pack_bytes: bytes
    evidence_bytes: bytes
    expected_checks_bytes: bytes
    definitions_bytes: bytes

    def templates(self) -> tuple[FindingTemplate, ...]:
        try:
            return definitions_from_bytes(self.definitions_bytes)
        except CatalogError as error:
            raise CatalogUnavailable("approved catalog snapshot is not reconstructible") from error

    def topic_pack_view(self) -> TopicPromptPack:
        return _decoded(TopicPromptPack, self.topic_pack_bytes)

    def evidence_view(self) -> EvidencePack:
        return _decoded(EvidencePack, self.evidence_bytes)

    def expected_checks_view(self) -> tuple[CheckResult, ...]:
        try:
            return _EXPECTED_CHECKS.validate_json(self.expected_checks_bytes, strict=True)
        except (ValidationError, TypeError, ValueError) as exc:
            raise CatalogUnavailable("approved snapshot checks are not reconstructible") from exc

    def validation_context(self) -> ValidationContext:
        evidence = self.evidence_view()
        return ValidationContext(
            topic_pack=self.topic_pack_view(),
            templates=self.templates(),
            policy_hash=evidence.policy_hash,
            content_sha=evidence.content_sha,
            language=self.language,
            expected_checks=self.expected_checks_view(),
        )

    def request_view(self, request: JudgmentRequest) -> JudgmentRequest:
        return request.model_copy(
            update={
                "question": self.question,
                "standing_rules": self.standing_rules,
                "topic_pack": self.topic_pack_view(),
                "evidence": self.evidence_view(),
                "finding_templates": self.templates(),
            }
        )


def _capture(request: JudgmentRequest, pack: object, context: object) -> CatalogSnapshot:
    if not isinstance(pack, EvidencePack) or not isinstance(context, ValidationContext):
        raise CatalogUnavailable("judgment bindings are not typed catalog authority")
    request = _decoded(JudgmentRequest, _encoded(request))
    pack = _decoded(EvidencePack, _encoded(pack))
    context = _decoded(ValidationContext, _encoded(context))
    if (
        request.topic_id != pack.topic_id
        or request.topic_id != request.evidence.topic_id
        or request.topic_id != request.topic_pack.topic_id
        or request.topic_id != context.topic_pack.topic_id
    ):
        raise CatalogUnavailable("judgment topic bindings disagree")
    if (
        request.question_id != pack.question_id
        or request.question_id != request.evidence.question_id
    ):
        raise CatalogUnavailable("judgment question bindings disagree")
    if (
        request.language != context.language
        or request.language != context.topic_pack.language
        or request.language != request.topic_pack.language
    ):
        raise CatalogUnavailable("judgment language bindings disagree")
    if (
        context.content_sha != pack.content_sha
        or context.content_sha != context.topic_pack.content_sha
        or context.content_sha != request.topic_pack.content_sha
        or context.content_sha != request.evidence.content_sha
    ):
        raise CatalogUnavailable("judgment content revisions disagree")
    if (
        context.policy_hash != pack.policy_hash
        or context.policy_hash != request.evidence.policy_hash
    ):
        raise CatalogUnavailable("judgment policy bindings disagree")
    if canonical_bytes(context.topic_pack) != canonical_bytes(request.topic_pack):
        raise CatalogUnavailable("judgment topic prompt packs disagree")
    if canonical_bytes(pack) != canonical_bytes(request.evidence):
        raise CatalogUnavailable("judgment evidence packs disagree")
    if canonical_bytes(context.expected_checks) != canonical_bytes(pack.checks):
        raise CatalogUnavailable("judgment expected checks disagree")
    if any(check.topic_id != request.topic_id for check in pack.checks):
        raise CatalogUnavailable("judgment check evidence carries a foreign topic")
    definitions = catalog_bytes(request.finding_templates)
    if definitions != catalog_bytes(context.templates):
        raise CatalogUnavailable("judgment request and context catalogs disagree")
    validate_topic_context(request.topic_pack, request.finding_templates)
    snapshot = CatalogSnapshot(
        topic_id=request.topic_id,
        question_id=request.question_id,
        language=request.language,
        question=request.question,
        standing_rules=request.standing_rules,
        topic_pack_bytes=_encoded(request.topic_pack),
        evidence_bytes=_encoded(pack),
        expected_checks_bytes=canonical_bytes(pack.checks),
        definitions_bytes=definitions,
    )
    snapshot.topic_pack_view()
    snapshot.evidence_view()
    snapshot.expected_checks_view()
    snapshot.templates()
    snapshot.request_view(request)
    snapshot.validation_context()
    return snapshot


def capture_catalog_snapshot(
    request: JudgmentRequest, pack: object, context: object
) -> CatalogSnapshot:
    """Capture strict immutable catalog and binding bytes without awaiting anything."""
    try:
        return _capture(request, pack, context)
    except CatalogUnavailable:
        raise
    except CatalogError as error:
        raise CatalogUnavailable("approved catalog failed a shared strict rule") from error
    except (AttributeError, TypeError, ValidationError, ValueError) as error:
        raise CatalogUnavailable(
            "approved catalog bindings failed strict reconstruction"
        ) from error
