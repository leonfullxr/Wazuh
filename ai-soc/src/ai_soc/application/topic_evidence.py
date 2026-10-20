"""Per-topic evidence gathering: playbook reads and checks, direct fetches and the evidence pack."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from hashlib import sha256
from uuid import uuid4

from ai_soc.application.errors import ServiceFailure
from ai_soc.contracts.canonical import canonical_bytes
from ai_soc.contracts.errors import public_error
from ai_soc.contracts.models import (
    AuthorizedSite,
    CheckResult,
    ErrorCode,
    EvidenceItem,
    EvidencePack,
    ExecutionContext,
    FetchResult,
    FetchState,
    LeftOut,
    LeftOutReason,
    QuestionPlan,
    StageName,
    StageSpan,
    TopicPlan,
    TraceContext,
    VerifiedPrincipal,
)
from ai_soc.contracts.ports import FetchExecutor, PlaybookExecutor
from ai_soc.telemetry.instrumentation import (
    fetch_stage_attributes,
    fetch_stage_outcome,
)
from ai_soc.telemetry.metrics import MetricExporter
from ai_soc.telemetry.operational import emit_fetch_result


@dataclass(frozen=True)
class TopicEvidenceResult:
    tables: list[FetchResult]
    checks: list[CheckResult]
    left_out: list[LeftOut]
    pack: EvidencePack | None


@dataclass
class TopicEvidence:
    playbooks: PlaybookExecutor
    fetches: FetchExecutor
    stage: Callable[[StageName, TraceContext], AbstractContextManager[StageSpan | None]]
    metrics: MetricExporter | None

    async def gather(
        self,
        topic: TopicPlan,
        *,
        plan: QuestionPlan,
        principal: VerifiedPrincipal,
        site: AuthorizedSite,
        build_pack: bool,
        execution: ExecutionContext,
    ) -> TopicEvidenceResult:
        tables: list[FetchResult] = []
        checks: list[CheckResult] = []
        playbook_items: list[EvidenceItem] = []
        left_out: list[LeftOut] = []
        if topic.failure and topic.playbook_id is not None:
            with self.stage(StageName.checks, execution.trace_context):
                run = await self.playbooks.run(
                    topic,
                    principal=principal,
                    site=site,
                    question_id=plan.question_id,
                    execution=execution,
                )
            tables.extend(run.fetches)
            checks.extend(run.checks)
            playbook_items.extend(item for item in run.items if item.kind == "check")
        for fetch in topic.fetches:
            execution.cancel.raise_if_cancelled()
            with self.stage(StageName.fetch, execution.trace_context) as span:
                result = await self.fetches.execute(
                    fetch,
                    topic_id=topic.topic_id,
                    question_id=plan.question_id,
                    principal=principal,
                    site=site,
                    execution=execution,
                )
                if span is not None:
                    span.set_outcome(fetch_stage_outcome(FetchState(result.state)))
                    span.record_attributes(fetch_stage_attributes(FetchState(result.state)))
                metrics = self.metrics
                if metrics is not None:
                    emit_fetch_result(metrics, FetchState(result.state))
            tables.append(result)
            if result.state == FetchState.unavailable:
                left_out.append(
                    LeftOut(
                        topic_id=topic.topic_id,
                        stage="fetch",
                        reason=LeftOutReason.evidence_unavailable,
                        retryable=True,
                    )
                )
        pack = evidence_pack(plan, topic, tables, checks, playbook_items) if build_pack else None
        return TopicEvidenceResult(tables=tables, checks=checks, left_out=left_out, pack=pack)


def evidence_pack(
    plan: QuestionPlan,
    topic: TopicPlan,
    tables: list[FetchResult],
    checks: list[CheckResult],
    extra_items: list[EvidenceItem] | None = None,
) -> EvidencePack:
    items: list[EvidenceItem] = []
    seen: set[str] = set()
    for table in tables:
        for item in table.items:
            if item.evidence_id in seen:
                continue
            items.append(item)
            seen.add(item.evidence_id)
    if extra_items:
        for item in extra_items:
            if item.evidence_id in seen:
                continue
            items.append(item)
            seen.add(item.evidence_id)
    if any(item.topic_id != topic.topic_id for item in items):
        raise ServiceFailure(
            public_error(
                ErrorCode.EVIDENCE_INVALID,
                "Evidence crossed topic boundaries.",
                trace_id=str(uuid4()),
            )
        )
    payload = {
        "schema_version": "1",
        "question_id": str(plan.question_id),
        "environment_id": plan.environment_id,
        "topic_id": topic.topic_id,
        "policy_hash": plan.policy_hash,
        "content_sha": plan.content_sha,
        "fetches": tables,
        "checks": checks,
        "items": items,
    }
    return EvidencePack(
        question_id=plan.question_id,
        environment_id=plan.environment_id,
        topic_id=topic.topic_id,
        policy_hash=plan.policy_hash,
        content_sha=plan.content_sha,
        fetches=tables,
        checks=checks,
        items=items,
        sha256=sha256(canonical_bytes(payload)).hexdigest(),
    )
