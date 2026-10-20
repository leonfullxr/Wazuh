"""Best-effort operational counters with finite CloudWatch dimensions."""

from __future__ import annotations

from ai_soc.contracts.models import ErrorCode, FetchState, RemovedReason

from .metrics import MetricExporter, MetricName, MetricSample, emit_safe


def emit_fetch_result(exporter: MetricExporter, state: FetchState) -> None:
    emit_safe(
        exporter,
        MetricSample(
            name=MetricName.fetch_result,
            value=1.0,
            unit="Count",
            fetch_state=state,
        ),
    )


def emit_removed_finding(exporter: MetricExporter, reason: RemovedReason) -> None:
    emit_safe(
        exporter,
        MetricSample(
            name=MetricName.removed_finding,
            value=1.0,
            unit="Count",
            removed_reason=reason,
        ),
    )


def emit_cache_tokens(exporter: MetricExporter, tokens: int) -> None:
    if tokens <= 0:
        return
    emit_safe(
        exporter,
        MetricSample(name=MetricName.cache_tokens, value=float(tokens), unit="Count"),
    )


def emit_budget_reserved(exporter: MetricExporter, tokens: int) -> None:
    if tokens <= 0:
        return
    emit_safe(
        exporter,
        MetricSample(name=MetricName.budget_reserved, value=float(tokens), unit="Count"),
    )


def emit_budget_charged(exporter: MetricExporter, tokens: int) -> None:
    if tokens <= 0:
        return
    emit_safe(
        exporter,
        MetricSample(name=MetricName.budget_charged, value=float(tokens), unit="Count"),
    )


def emit_content_provenance_failure(exporter: MetricExporter) -> None:
    emit_safe(
        exporter,
        MetricSample(name=MetricName.content_provenance_failure, value=1.0, unit="Count"),
    )


def emit_feedback_enqueue_failure(exporter: MetricExporter) -> None:
    emit_safe(
        exporter,
        MetricSample(name=MetricName.feedback_enqueue_failure, value=1.0, unit="Count"),
    )


def emit_lease_conflict(exporter: MetricExporter) -> None:
    emit_safe(
        exporter,
        MetricSample(name=MetricName.lease_conflict, value=1.0, unit="Count"),
    )


def emit_token_broker_failure(exporter: MetricExporter) -> None:
    emit_safe(
        exporter,
        MetricSample(name=MetricName.token_broker_failure, value=1.0, unit="Count"),
    )


def emit_recovery_lag_seconds(exporter: MetricExporter, seconds: float) -> None:
    emit_safe(
        exporter,
        MetricSample(name=MetricName.recovery_lag_seconds, value=seconds, unit="Seconds"),
    )


def emit_recovery_backlog(exporter: MetricExporter, count: int) -> None:
    if count < 0:
        return
    emit_safe(
        exporter,
        MetricSample(name=MetricName.recovery_backlog, value=float(count), unit="Count"),
    )


def emit_admission_rejected(exporter: MetricExporter) -> None:
    emit_safe(
        exporter,
        MetricSample(name=MetricName.admission_rejected, value=1.0, unit="Count"),
    )


def broker_failure_code(code: ErrorCode) -> bool:
    return code in {
        ErrorCode.TOKEN_BROKER_UNAVAILABLE,
        ErrorCode.AUTH_EXPIRED,
        ErrorCode.FORBIDDEN,
        ErrorCode.SITE_DENIED,
    }
