"""Answer and audit event assembly: receipts, answer shapes and the one audit event builder."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Literal
from uuid import UUID, uuid4

from ai_soc.contracts.canonical import canonical_bytes
from ai_soc.contracts.models import (
    Answer,
    AnswerStatus,
    AuditEvent,
    AuditFetchRecord,
    AuditRemovedFinding,
    BuildProvenance,
    Clarify,
    Effort,
    FetchResult,
    FetchSpec,
    FetchState,
    FetchStep,
    FollowupRecord,
    LeftOut,
    QuestionPlan,
    RemovedReason,
    ResolvedWindow,
    TemplateId,
    TopicAnswer,
    VerifiedPrincipal,
)
from ai_soc.contracts.ports import Clock, ContentCatalog
from ai_soc.feedback.receipts import FeedbackReceiptCodec
from ai_soc.query.playbooks import playbook_step_spec
from ai_soc.telemetry.outcomes import current_stage_outcomes


@dataclass(frozen=True)
class AnswerAssembly:
    catalog: ContentCatalog
    receipts: FeedbackReceiptCodec
    clock: Clock
    guardrail_identifier: str
    guardrail_version: str

    def answer(
        self,
        *,
        question_id: UUID,
        environment_id: str,
        language: Literal["en", "es"],
        owner_key: str,
        content_sha: str,
        cue_ids: list[str],
        topic_ids: list[str],
        status: AnswerStatus,
        manifest: BuildProvenance,
        trace_id: str,
        blocks: list[TopicAnswer] | None = None,
        left_out: list[LeftOut] | None = None,
        message: str | None = None,
        clarify: Clarify | None = None,
        followup: FollowupRecord | None = None,
    ) -> Answer:
        token = self.receipts.issue(
            question_id=question_id,
            owner_key=owner_key,
            environment_id=environment_id,
            content_sha=content_sha,
            cue_ids=cue_ids,
            topic_ids=topic_ids,
            outcome_code=status,
            now=self.clock.now(),
        )
        return Answer(
            question_id=question_id,
            environment_id=environment_id,
            language=language,
            status=status,
            blocks=blocks or [],
            message=message,
            clarify=clarify,
            followup_id=followup.followup_id if followup else None,
            followup_revision=followup.revision if followup else None,
            left_out=left_out or [],
            provenance=manifest,
            trace_id=trace_id,
            feedback_receipt=token,
        )

    def audit_event(
        self,
        answer: Answer,
        principal: VerifiedPrincipal,
        manifest: BuildProvenance,
        policy_hash: str,
        outcome: Literal["attempted", "completed", "cancelled"],
        *,
        plan: QuestionPlan | None,
        cue_ids: list[str],
        topic_ids: list[str],
        completion_id: UUID | None = None,
    ) -> AuditEvent:
        return AuditEvent(
            event_id=uuid4(),
            question_id=answer.question_id,
            trace_id=answer.trace_id,
            owner_key=principal.owner_key,
            environment_id=answer.environment_id,
            authenticated_issuer=principal.issuer,
            auth_edge=principal.edge,
            image_digest=manifest.image_digest,
            pack_sha256=manifest.pack_sha256,
            cue_ids=cue_ids,
            topic_ids=topic_ids,
            stage_outcomes=current_stage_outcomes(),
            removed_findings=audit_removed(answer),
            usage_by_topic=[
                block.judgment.usage for block in answer.blocks if block.judgment.usage is not None
            ],
            fetches=_audit_fetches(self.catalog, answer, plan) if plan is not None else [],
            outcome=outcome,
            completion_id=completion_id,
            model_id=plan.model_id if plan is not None else None,
            effort=Effort(plan.effort) if plan is not None and plan.effort is not None else None,
            service_sha=manifest.service_sha,
            content_sha=manifest.content_sha,
            policy_hash=policy_hash,
            answer_status=AnswerStatus(answer.status) if outcome == "completed" else None,
            guardrail_id=self.guardrail_identifier or None,
            guardrail_version=self.guardrail_version or None,
            created_at=self.clock.now(),
        )


def audit_removed(answer: Answer) -> list[AuditRemovedFinding]:
    return [
        AuditRemovedFinding(
            topic_id=block.topic_id,
            finding_id=finding.finding_id,
            reason=RemovedReason(finding.reason),
            candidate_sha256=finding.candidate_sha256,
        )
        for block in answer.blocks
        for finding in block.judgment.removed
    ]


def _playbook_fetch_spec(
    catalog: ContentCatalog, topic_id: str, fetch_id: str, window: ResolvedWindow
) -> FetchSpec | None:
    topic = catalog.topic(topic_id)
    if topic is None or topic.playbook_id is None:
        return None
    playbook = catalog.playbook(topic.playbook_id)
    if playbook is None:
        return None
    for step in playbook.steps:
        if isinstance(step, FetchStep) and step.fetch_id == fetch_id:
            return playbook_step_spec(step, window)
    return None


def audit_fetch_record(
    catalog: ContentCatalog, result: FetchResult, spec: FetchSpec | None
) -> AuditFetchRecord | None:
    if spec is None:
        spec = _playbook_fetch_spec(catalog, result.topic_id, result.fetch_id, result.window)
        if spec is None:
            return None
    return AuditFetchRecord(
        scope_hash=sha256(canonical_bytes(result.scope)).hexdigest(),
        window=spec.window,
        template_id=TemplateId(spec.template_id),
        query_sha256=sha256(canonical_bytes(spec)).hexdigest(),
        result_classification=FetchState(result.state),
        count=result.count,
        count_exact=(
            result.count.relation == "eq" and not result.count.approximate
            if result.count is not None
            else None
        ),
        evidence_checks=result.checks,
    )


def _audit_fetches(
    catalog: ContentCatalog, answer: Answer, plan: QuestionPlan
) -> list[AuditFetchRecord]:
    specs = {
        (topic.topic_id, fetch.fetch_id): fetch for topic in plan.topics for fetch in topic.fetches
    }
    records: list[AuditFetchRecord] = []
    for block in answer.blocks:
        for result in block.tables:
            record = audit_fetch_record(
                catalog, result, specs.get((result.topic_id, result.fetch_id))
            )
            if record is not None:
                records.append(record)
    return records
