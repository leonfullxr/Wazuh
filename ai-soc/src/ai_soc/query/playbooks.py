"""Finite declarative playbook execution with typed operands and evidence checks."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID

from ai_soc.contracts.canonical import evidence_id as make_evidence_id
from ai_soc.contracts.canonical import sha256_hex
from ai_soc.contracts.models import (
    AuthorizedSite,
    CheckOutcome,
    CheckResult,
    CompareCountStep,
    ErrorCode,
    EvidenceItem,
    EvidenceSourceCheck,
    EvidenceValue,
    ExecutionContext,
    ExpectationDefinition,
    ExpectationMatchStep,
    FetchCountOperand,
    FetchResult,
    FetchSpec,
    FetchState,
    FetchStep,
    FieldId,
    FieldPresentStep,
    IndexFamily,
    IntegerOperand,
    PlaybookDefinition,
    PlaybookRun,
    RecordAgeStep,
    ResolvedWindow,
    SnapshotKind,
    SnapshotRef,
    TemplateId,
    TopicPlan,
    VerifiedPrincipal,
    Visibility,
    WindowDefault,
)
from ai_soc.contracts.ports import Clock, FetchExecutor
from ai_soc.query.evidence import EvidenceValues

RECORD_AGE_REPLAY_TOLERANCE = timedelta(seconds=300)
_RECORD_AGE_FIELDS = {
    IndexFamily.alerts: FieldId.timestamp,
    IndexFamily.vulnerabilities: FieldId.vulnerability_detected_at,
}


class PlaybookCatalog(Protocol):
    def playbook(self, playbook_id: str) -> PlaybookDefinition | None: ...
    def expectation(
        self, expectation_id: str, *, topic_id: str
    ) -> ExpectationDefinition | None: ...


class PlaybookExecutionError(ValueError):
    def __init__(self, code: ErrorCode = ErrorCode.CONTENT_INVALID) -> None:
        self.code = code
        super().__init__(code.value)


def resolve_default(default: WindowDefault, *, anchor: datetime) -> ResolvedWindow:
    if anchor.tzinfo is None or anchor.utcoffset() is None:
        raise ValueError("playbook clock must return an aware datetime")
    end = anchor.astimezone(UTC)
    duration = (
        timedelta(hours=default.amount)
        if default.unit == "hours"
        else timedelta(days=default.amount)
    )
    if duration > timedelta(days=90):
        raise PlaybookExecutionError()
    return ResolvedWindow(
        start=end - duration,
        end=end,
        semantics="rolling",
        source_text=f"playbook default: last {default.amount} {default.unit}",
        timezone="UTC",
        anchor_at=end,
    )


def playbook_step_spec(step: FetchStep, window: ResolvedWindow) -> FetchSpec:
    return FetchSpec(
        fetch_id=step.fetch_id,
        template_id=TemplateId(step.template_id),
        window=window,
        filters=step.filters,
    )


class DeclarativePlaybookExecutor:
    """Execute at most ten configured reads/checks; content is data, never code."""

    def __init__(
        self, catalog: PlaybookCatalog, fetcher: FetchExecutor, clock: Clock, *, content_sha: str
    ) -> None:
        self._catalog = catalog
        self._fetcher = fetcher
        self._clock = clock
        self._content_sha = content_sha

    async def run(
        self,
        plan: TopicPlan,
        *,
        principal: VerifiedPrincipal,
        site: AuthorizedSite,
        question_id: UUID,
        execution: ExecutionContext,
    ) -> PlaybookRun:
        if plan.playbook_id is None:
            return PlaybookRun(fetches=[], checks=[], items=[])
        playbook = self._catalog.playbook(plan.playbook_id)
        if playbook is None or playbook.topic_id != plan.topic_id or len(playbook.steps) > 10:
            raise PlaybookExecutionError()

        fetches: list[FetchResult] = []
        results: dict[str, FetchResult] = {}
        checks: list[CheckResult] = []
        items: list[EvidenceItem] = []
        anchor = self._clock.now()
        planned_fetches = {fetch.fetch_id: fetch for fetch in plan.fetches}
        override_window = plan.playbook_window
        for step in playbook.steps:
            if isinstance(step, FetchStep):
                if step.fetch_id in results:
                    raise PlaybookExecutionError()
                if step.fetch_id in planned_fetches:
                    fetch_spec = planned_fetches[step.fetch_id]
                else:
                    fetch_spec = playbook_step_spec(
                        step,
                        override_window or resolve_default(step.window_default, anchor=anchor),
                    )
                result = await self._fetcher.execute(
                    fetch_spec,
                    topic_id=plan.topic_id,
                    question_id=question_id,
                    principal=principal,
                    site=site,
                    execution=execution,
                )
                fetches.append(result)
                results[step.fetch_id] = result
                items.extend(result.items)
                continue

            if isinstance(step, CompareCountStep):
                left = results.get(step.left_fetch_id)
                right_result = (
                    results.get(step.right.fetch_id)
                    if isinstance(step.right, FetchCountOperand)
                    else None
                )
                right_literal = step.right.value if isinstance(step.right, IntegerOperand) else None
                left_count = _exact_count(left)
                right_count = (
                    _exact_count(right_result)
                    if isinstance(step.right, FetchCountOperand)
                    else right_literal
                )
                used = [r for r in (left, right_result) if r is not None]
                if any(r.state == FetchState.denied for r in used):
                    outcome = CheckOutcome.denied
                elif left_count is None or right_count is None:
                    outcome = CheckOutcome.unknown
                else:
                    outcome = (
                        CheckOutcome.passed
                        if _compare(left_count, step.op, right_count)
                        else CheckOutcome.failed
                    )
                check, item = self._make_check(
                    step.check_id,
                    step.step_id,
                    plan.topic_id,
                    step.label.en,
                    outcome,
                    [eid for result in used for eid in _result_evidence(result)],
                    question_id,
                    site,
                    used,
                )
            elif isinstance(step, FieldPresentStep):
                result = results.get(step.fetch_id)
                outcome = _input_state(result)
                if outcome is None:
                    assert result is not None
                    outcome = _quantified(
                        [row.values.get(step.field) is not None for row in result.rows],
                        step.quantifier,
                    )
                check, item = self._make_check(
                    step.check_id,
                    step.step_id,
                    plan.topic_id,
                    step.label.en,
                    outcome,
                    [row.evidence_id for row in result.rows] if result is not None else [],
                    question_id,
                    site,
                    [result] if result is not None else [],
                )
            elif isinstance(step, RecordAgeStep):
                result = results.get(step.fetch_id)
                if result is None:
                    raise PlaybookExecutionError()
                outcome, explanation = _record_age_reading(
                    result, anchor=anchor, max_age_seconds=step.max_age_seconds
                )
                check, item = self._make_check(
                    step.check_id,
                    step.step_id,
                    plan.topic_id,
                    step.label.en,
                    outcome,
                    _result_evidence(result),
                    question_id,
                    site,
                    [result],
                    message=explanation,
                    snapshot=_record_age_snapshot(result.snapshot, anchor=anchor, step=step),
                )
            elif isinstance(step, ExpectationMatchStep):
                result = results.get(step.fetch_id)
                expectation = self._expectation(step.expectation_id, plan.topic_id, site)
                outcome = _input_state(result)
                if outcome is None:
                    assert result is not None
                    if expectation is None:
                        outcome = CheckOutcome.not_configured
                    else:
                        outcome = _quantified(
                            [
                                _matches(row.values.get(step.field), expectation)
                                for row in result.rows
                            ],
                            step.quantifier,
                        )
                check, item = self._make_check(
                    step.check_id,
                    step.step_id,
                    plan.topic_id,
                    step.label.en,
                    outcome,
                    [row.evidence_id for row in result.rows] if result is not None else [],
                    question_id,
                    site,
                    [result] if result is not None else [],
                    expectation,
                )
            else:
                expectation = self._expectation(step.expectation_id, plan.topic_id, site)
                outcome = CheckOutcome.passed if expectation else CheckOutcome.not_configured
                check, item = self._make_check(
                    step.check_id,
                    step.step_id,
                    plan.topic_id,
                    step.label.en,
                    outcome,
                    [],
                    question_id,
                    site,
                    [],
                    expectation,
                )
            checks.append(check)
            items.append(item)
        return PlaybookRun(fetches=fetches, checks=checks, items=items)

    def _expectation(
        self, expectation_id: str, topic_id: str, site: AuthorizedSite
    ) -> ExpectationDefinition | None:
        configured = next(
            (
                e
                for e in site.config.expectations
                if e.expectation_id == expectation_id and e.topic_id == topic_id
            ),
            None,
        )
        return configured or self._catalog.expectation(expectation_id, topic_id=topic_id)

    def _make_check(
        self,
        check_id: str,
        step_id: str,
        topic_id: str,
        label: str,
        outcome: CheckOutcome,
        operand_ids: list[str],
        question_id: UUID,
        site: AuthorizedSite,
        fetch_results: list[FetchResult],
        expectation: ExpectationDefinition | None = None,
        *,
        message: str | None = None,
        snapshot: SnapshotRef | None = None,
    ) -> tuple[CheckResult, EvidenceItem]:
        ids = sorted(set(operand_ids))
        if snapshot is None:
            snapshots = {result.snapshot.key: result.snapshot for result in fetch_results}
            if len(snapshots) == 1:
                snapshot = next(iter(snapshots.values()))
            else:
                now = self._clock.now().astimezone(UTC)
                snapshot = SnapshotRef(
                    kind=SnapshotKind.first_page_only,
                    key=sha256_hex(
                        {"question_id": str(question_id), "topic_id": topic_id, "step_id": step_id}
                    ),
                    at=now,
                )
        source = EvidenceSourceCheck(step_id=step_id, operand_ids=ids)
        values: EvidenceValues = {
            "outcome": outcome.value,
            "operand_ids": ids,
            "expectation_id": expectation.expectation_id if expectation else None,
            "expectation_version": expectation.version if expectation else None,
        }
        digest = make_evidence_id(
            question_id=str(question_id),
            environment_id=site.config.environment_id,
            topic_id=topic_id,
            fetch_id=None,
            check_id=check_id,
            kind="check",
            source=source,
            snapshot_key=snapshot.key,
            values=values,
        )
        item = EvidenceItem(
            evidence_id=digest,
            topic_id=topic_id,
            fetch_id=None,
            check_id=check_id,
            kind="check",
            source=source,
            snapshot=snapshot,
            values=values,
            visibility=Visibility(site.visibility),
            scope_hash=sha256_hex(
                {
                    "environment_id": site.config.environment_id,
                    "policy_hash": site.policy_hash,
                    "content_sha": self._content_sha,
                    "snapshot": snapshot.key,
                    "step_id": step_id,
                }
            ),
        )
        check = CheckResult(
            check_id=check_id,
            topic_id=topic_id,
            label=label,
            outcome=outcome,
            evidence_ids=[digest],
            message=message or _outcome_message(outcome),
            expectation_id=expectation.expectation_id if expectation else None,
        )
        return check, item


def _exact_count(result: FetchResult | None) -> int | None:
    if (
        result is None
        or result.count is None
        or result.count.relation != "eq"
        or result.count.approximate
    ):
        return None
    return result.count.value


def _result_evidence(result: FetchResult) -> list[str]:
    if result.items:
        return [item.evidence_id for item in result.items]
    return []


def _input_state(result: FetchResult | None) -> CheckOutcome | None:
    if result is None or result.state == FetchState.unavailable:
        return CheckOutcome.unknown
    if result.state == FetchState.denied:
        return CheckOutcome.denied
    return None


def _compare(left: int, op: str, right: int) -> bool:
    return left == right if op == "eq" else left >= right if op == "gte" else left <= right


def _matches(actual: object, expectation: ExpectationDefinition) -> bool:
    if expectation.op == "exists":
        return actual is not None
    if actual is None:
        return False
    if expectation.op == "eq":
        return actual == expectation.value
    if expectation.op == "in":
        return isinstance(expectation.value, list) and actual in expectation.value
    if (
        isinstance(actual, bool)
        or not isinstance(actual, (int, float))
        or isinstance(expectation.value, bool)
        or not isinstance(expectation.value, int)
    ):
        return False
    return actual >= expectation.value if expectation.op == "gte" else actual <= expectation.value


def _quantified(values: list[bool], quantifier: str) -> CheckOutcome:
    if not values:
        return CheckOutcome.unknown
    return (
        CheckOutcome.passed
        if (all(values) if quantifier == "all" else any(values))
        else CheckOutcome.failed
    )


def _record_age_snapshot(
    source: SnapshotRef, *, anchor: datetime, step: RecordAgeStep
) -> SnapshotRef:
    at = anchor.astimezone(UTC)
    return SnapshotRef(
        kind=SnapshotKind(source.kind),
        key=sha256_hex(
            {
                "source": source.key,
                "anchor": at.isoformat(),
                "step_id": step.step_id,
                "max_age_seconds": step.max_age_seconds,
            }
        ),
        at=at,
    )


def _strict_timestamp(value: EvidenceValue | None) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.utcoffset() is None:
            return None
        return parsed.astimezone(UTC)
    except (ValueError, OverflowError):
        return None


def _record_age_reading(
    result: FetchResult, *, anchor: datetime, max_age_seconds: int
) -> tuple[CheckOutcome, str]:
    if result.state == FetchState.denied:
        return CheckOutcome.denied, _outcome_message(CheckOutcome.denied)
    unknown_prefix = "Check could not be confirmed: "
    if result.state == FetchState.unavailable:
        cause = str(result.error.code) if result.error is not None else "unavailable"
        return CheckOutcome.unknown, f"{unknown_prefix}the source read was {cause}."
    window = result.window
    lag = anchor - window.end
    if window.semantics != "rolling":
        return CheckOutcome.unknown, f"{unknown_prefix}the read window is {window.semantics}."
    if lag < timedelta(0):
        return CheckOutcome.unknown, f"{unknown_prefix}the read window ends after the read time."
    if lag > RECORD_AGE_REPLAY_TOLERANCE:
        tolerance = int(RECORD_AGE_REPLAY_TOLERANCE.total_seconds())
        return (
            CheckOutcome.unknown,
            f"{unknown_prefix}the read window ended more than {tolerance} s before the read time.",
        )
    field = _RECORD_AGE_FIELDS[result.scope.index_family]
    valid: list[datetime] = []
    for row in result.rows:
        parsed = _strict_timestamp(row.values.get(field))
        if parsed is not None and window.start <= parsed < window.end:
            valid.append(parsed)
    if not valid:
        if not result.rows:
            return CheckOutcome.unknown, f"{unknown_prefix}no rows were returned."
        return (
            CheckOutcome.unknown,
            f"{unknown_prefix}none of the {len(result.rows)} returned rows has a valid "
            "timestamp inside the read window.",
        )
    newest = max(valid)
    age = anchor - newest
    outcome = CheckOutcome.passed if age.total_seconds() <= max_age_seconds else CheckOutcome.failed
    invalid = len(result.rows) - len(valid)
    notes = " Based on returned rows only; this does not establish source health or completeness."
    if result.snapshot.kind == SnapshotKind.first_page_only:
        notes += " The read was a first-page read."
    if result.count is not None and result.count.approximate:
        notes += " The total count is approximate and was not used."
    return (
        outcome,
        f"Newest valid returned timestamp {newest.isoformat()} is "
        f"{age.total_seconds():.3f} s before the read time; limit {max_age_seconds} s; "
        f"{invalid} returned rows have no valid timestamp inside the read window.{notes}",
    )


def _outcome_message(outcome: CheckOutcome) -> str:
    return {
        CheckOutcome.passed: "Check passed.",
        CheckOutcome.failed: "Check failed.",
        CheckOutcome.unknown: "Check could not be confirmed.",
        CheckOutcome.denied: "The check was denied by site authorization.",
        CheckOutcome.not_configured: "No approved expectation is configured.",
    }[outcome]
