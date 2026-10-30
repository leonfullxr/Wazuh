"""Site and bounded-window operational and disposition metrics with real denominators."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, cast

import psycopg
from psycopg.pq import TransactionStatus


def ops_metrics(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    from_: datetime,
    to: datetime,
    now: datetime,
) -> dict[str, Any]:
    _validate(conn, site_id, from_, to, now, max_span=timedelta(days=30))
    source_counts = _required_row(
        conn.execute(
            """
        SELECT count(r.alert_key), count(a.alert_key) FILTER (WHERE a.normalized_at IS NOT NULL),
               count(a.alert_key) FILTER (WHERE cardinality(a.normalize_gaps) > 0),
               percentile_cont(0.50) WITHIN GROUP (
                   ORDER BY greatest(0, extract(epoch FROM a.ingested_at - a.event_ts))
               ),
               percentile_cont(0.95) WITHIN GROUP (
                   ORDER BY greatest(0, extract(epoch FROM a.ingested_at - a.event_ts))
               ),
               count(a.alert_key)
        FROM alert_registry AS r LEFT JOIN alerts AS a
          ON (a.site_id, a.alert_key, a.event_ts) = (r.site_id, r.alert_key, r.original_event_ts)
        WHERE r.site_id = %s AND r.original_event_ts >= %s AND r.original_event_ts < %s
        """,
            (site_id, from_, to),
        )
    )
    ingested, normalized, with_gaps = (
        int(source_counts[0]),
        int(source_counts[1]),
        int(source_counts[2]),
    )
    lag_denominator = int(source_counts[5])
    last_poll = _required_row(
        conn.execute(
            """SELECT max(finished_at) FROM pipeline_runs
               WHERE site_id = %s AND kind = 'poll' AND outcome = 'ok' AND finished_at <= %s""",
            (site_id, to),
        )
    )[0]
    checkpoint = _required_row(
        conn.execute(
            "SELECT max(updated_at) FROM checkpoints WHERE site_id = %s AND updated_at <= %s",
            (site_id, to),
        )
    )[0]
    mismatch = _required_row(
        conn.execute(
            """
        SELECT count(*) FILTER (WHERE alarm OR outcome IN ('mismatch', 'failed')),
               count(*)
        FROM alert_reconciliation
        WHERE site_id = %s AND hour >= %s AND hour < %s
        """,
            (site_id, from_, to),
        )
    )
    unassigned = _required_row(
        conn.execute(
            """
        SELECT count(*) FROM work_items AS w
        JOIN group_heads AS h USING (site_id, group_id)
        JOIN group_revisions AS current
          ON (current.site_id, current.group_id, current.revision) =
             (h.site_id, h.group_id, h.current_revision)
        WHERE w.site_id = %s AND w.owner_key IS NULL AND w.status IN ('new', 'in_progress')
          AND current.first_ts >= %s AND current.first_ts < %s
        """,
            (site_id, from_, to),
        )
    )[0]
    open_row = _required_row(
        conn.execute(
            """
        WITH current AS (
            SELECT gr.group_id, gr.first_ts
            FROM group_heads AS gh JOIN group_revisions AS gr
              ON (gr.site_id, gr.group_id, gr.revision) =
                 (gh.site_id, gh.group_id, gh.current_revision)
            WHERE gh.site_id = %s
        )
        SELECT count(*), percentile_cont(0.50) WITHIN GROUP (
                   ORDER BY extract(epoch FROM (%s - c.first_ts))
               ),
               percentile_cont(0.90) WITHIN GROUP (
                   ORDER BY extract(epoch FROM (%s - c.first_ts))
               ),
               max(extract(epoch FROM (%s - c.first_ts)))
        FROM current AS c JOIN work_items AS w USING (group_id)
        WHERE w.site_id = %s AND w.status IN ('new', 'in_progress')
          AND c.first_ts >= %s AND c.first_ts < %s
        """,
            (site_id, now, now, now, site_id, from_, to),
        )
    )
    backlog_delta = _required_row(
        conn.execute(
            """
        WITH created AS (
            SELECT count(*) AS count
            FROM group_revisions AS gr
            WHERE gr.site_id = %s AND gr.first_ts >= %s AND gr.first_ts < %s
              AND NOT EXISTS (
                  SELECT 1 FROM group_revisions AS prior
                  WHERE prior.site_id = gr.site_id AND prior.group_id = gr.group_id
                    AND (prior.created_at, prior.revision) < (gr.created_at, gr.revision)
              )
        ), transitions AS (
            SELECT coalesce(sum(
                (CASE WHEN h.after_value->>'status' IN ('new', 'in_progress') THEN 1 ELSE 0 END) -
                (CASE WHEN h.before_value->>'status' IN ('new', 'in_progress') THEN 1 ELSE 0 END)
            ), 0) AS delta, count(*) AS events
            FROM work_history AS h
            WHERE h.site_id = %s AND h.action IN ('status', 'bulk_status')
              AND h.at >= %s AND h.at < %s
        )
        SELECT created.count + transitions.delta, created.count + transitions.events
        FROM created CROSS JOIN transitions
        """,
            (site_id, from_, to, site_id, from_, to),
        )
    )
    ack = _required_row(
        conn.execute(
            """
        WITH first_ack AS (
            SELECT DISTINCT ON (h.group_id) h.group_id, h.at
            FROM work_history AS h
            WHERE h.site_id = %s AND h.action IN ('status', 'bulk_status')
              AND h.after_value->>'status' = 'in_progress'
              AND (h.before_value IS NULL OR h.before_value->>'status' <> 'in_progress')
            ORDER BY h.group_id, h.at, h.history_id
        )
        SELECT percentile_cont(0.50) WITHIN GROUP (
                   ORDER BY extract(epoch FROM (first_ack.at - gr.first_ts))
               ),
               percentile_cont(0.90) WITHIN GROUP (
                   ORDER BY extract(epoch FROM (first_ack.at - gr.first_ts))
               ),
               count(*)
        FROM first_ack JOIN LATERAL (
            SELECT first_ts FROM group_revisions AS gr
            WHERE gr.site_id = %s AND gr.group_id = first_ack.group_id
            ORDER BY created_at, revision LIMIT 1
        ) AS gr ON true
        WHERE first_ack.at >= %s AND first_ack.at < %s
        """,
            (site_id, site_id, from_, to),
        )
    )
    triage = _required_row(
        conn.execute(
            """
        WITH first_disposition AS (
            SELECT DISTINCT ON (d.group_id) d.group_id, d.at
            FROM dispositions AS d
            WHERE d.site_id = %s
            ORDER BY d.group_id, d.at, d.disposition_id
        )
        SELECT percentile_cont(0.50) WITHIN GROUP (
                   ORDER BY extract(epoch FROM (d.at - gr.first_ts))
               ),
               percentile_cont(0.90) WITHIN GROUP (
                   ORDER BY extract(epoch FROM (d.at - gr.first_ts))
               ),
               count(*)
        FROM first_disposition AS d JOIN LATERAL (
            SELECT first_ts FROM group_revisions AS gr
            WHERE gr.site_id = %s AND gr.group_id = d.group_id
            ORDER BY created_at, revision LIMIT 1
        ) AS gr ON true
        WHERE d.at >= %s AND d.at < %s
        """,
            (site_id, site_id, from_, to),
        )
    )
    dead_jobs = _required_row(
        conn.execute(
            """SELECT count(*), min(created_at) FROM jobs
               WHERE site_id = %s AND state = 'dead' AND created_at >= %s AND created_at < %s""",
            (site_id, from_, to),
        )
    )
    result = {
        "as_of": now.isoformat(),
        "window": {"from": from_.isoformat(), "to": to.isoformat()},
        "ingestion": {
            "ingested_alerts": _metric(ingested, ingested, "alerts", from_, to),
            "normalized_alerts": _metric(normalized, ingested, "alerts", from_, to),
            "alerts_with_normalization_gaps": _metric(with_gaps, normalized, "alerts", from_, to),
            "rejected_alerts": _unavailable_metric(
                "alerts rejected before registry insertion is not retained as a count", from_, to
            ),
            "ingest_lag_p50_seconds": _metric(
                _float_or_none(source_counts[3]), lag_denominator, "seconds", from_, to
            ),
            "ingest_lag_p95_seconds": _metric(
                _float_or_none(source_counts[4]), lag_denominator, "seconds", from_, to
            ),
            "last_successful_poll_at": None if last_poll is None else last_poll.isoformat(),
            "checkpoint_age_seconds": None
            if checkpoint is None
            else max(0, (now - checkpoint).total_seconds()),
            "closed_hour_reconciliation_mismatches": _metric(
                int(mismatch[0]), int(mismatch[1]), "hours", from_, to
            ),
        },
        "queue": {
            "unassigned_actionable_groups": _metric(
                int(unassigned), int(open_row[0]), "groups", from_, to
            ),
            "open_backlog": _metric(int(open_row[0]), int(open_row[0]), "groups", from_, to),
            "backlog_delta": _metric(
                int(backlog_delta[0]),
                int(backlog_delta[1]),
                "groups",
                from_,
                to,
                numerator=int(backlog_delta[0]),
            ),
            "queue_age_p50_seconds": _metric(
                _float_or_none(open_row[1]), int(open_row[0]), "seconds", from_, to
            ),
            "queue_age_p90_seconds": _metric(
                _float_or_none(open_row[2]), int(open_row[0]), "seconds", from_, to
            ),
            "queue_age_max_seconds": _metric(
                _float_or_none(open_row[3]), int(open_row[0]), "seconds", from_, to
            ),
            "time_to_acknowledge_p50_seconds": _metric(
                _float_or_none(ack[0]), int(ack[2]), "seconds", from_, to
            ),
            "time_to_acknowledge_p90_seconds": _metric(
                _float_or_none(ack[1]), int(ack[2]), "seconds", from_, to
            ),
            "time_to_triage_p50_seconds": _metric(
                _float_or_none(triage[0]), int(triage[2]), "seconds", from_, to
            ),
            "time_to_triage_p90_seconds": _metric(
                _float_or_none(triage[1]), int(triage[2]), "seconds", from_, to
            ),
        },
        "jobs": {
            "dead_job_count": _metric(int(dead_jobs[0]), int(dead_jobs[0]), "jobs", from_, to),
            "oldest_dead_job_at": None if dead_jobs[1] is None else dead_jobs[1].isoformat(),
        },
    }
    return result


def quality_metrics(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    from_: datetime,
    to: datetime,
    now: datetime,
    rule_id: str | None = None,
) -> dict[str, Any]:
    _validate(conn, site_id, from_, to, now, max_span=timedelta(days=90))
    disposition_rows = conn.execute(
        """
        WITH cohort AS (
            SELECT DISTINCT ON (gr.group_id) gr.group_id, gr.first_ts
            FROM group_revisions AS gr
            WHERE gr.site_id = %s AND gr.created_at <= %s
            ORDER BY gr.group_id, gr.created_at DESC, gr.revision DESC
        ), latest AS (
            SELECT DISTINCT ON (d.group_id) d.group_id, d.label, d.at
            FROM dispositions AS d JOIN cohort AS c USING (group_id)
            WHERE d.site_id = %s AND d.at < %s AND c.first_ts >= %s AND c.first_ts < %s
            ORDER BY d.group_id, d.at DESC, d.disposition_id DESC
        )
        SELECT label, count(*) FROM latest GROUP BY label ORDER BY label
        """,
        (site_id, to, site_id, to, from_, to),
    ).fetchall()
    shares = {str(label): int(count) for label, count in disposition_rows}
    totals = _required_row(
        conn.execute(
            """
        WITH cohort AS (
            SELECT DISTINCT ON (gr.group_id) gr.group_id, gr.first_ts
            FROM group_revisions AS gr
            WHERE gr.site_id = %s AND gr.created_at <= %s
            ORDER BY gr.group_id, gr.created_at DESC, gr.revision DESC
        )
        SELECT count(*) FROM cohort WHERE first_ts >= %s AND first_ts < %s
        """,
            (site_id, to, from_, to),
        )
    )[0]
    labelled = sum(shares.values())
    rules = cast(
        list[tuple[Any, ...]],
        conn.execute(
            """
        WITH current_groups AS (
            SELECT cohort.group_id, cohort.rule_id
            FROM (
                SELECT DISTINCT ON (gr.group_id) gr.group_id, gr.rule_id, gr.first_ts
                FROM group_revisions AS gr
                WHERE gr.site_id = %s AND gr.created_at <= %s
                ORDER BY gr.group_id, gr.created_at DESC, gr.revision DESC
            ) AS cohort
            WHERE cohort.first_ts >= %s AND cohort.first_ts < %s
        ), latest AS (
            SELECT DISTINCT ON (d.group_id) d.group_id, d.label
            FROM dispositions AS d
            WHERE d.site_id = %s AND d.at < %s
            ORDER BY d.group_id, d.at DESC, d.disposition_id DESC
        )
        SELECT g.rule_id, count(*) FILTER (WHERE d.label = 'true_positive') AS tp,
               count(*) FILTER (WHERE d.label = 'false_positive') AS fp,
               count(*) FILTER (WHERE d.label = 'benign_true_positive') AS benign_tp,
               count(*) FILTER (
                   WHERE d.label IN ('true_positive', 'false_positive')
               ) AS binary_denominator,
               count(*) FILTER (WHERE d.label IS NOT NULL) AS labelled
        FROM current_groups AS g LEFT JOIN latest AS d USING (group_id)
        WHERE (%s::text IS NULL OR g.rule_id = %s::text)
        GROUP BY g.rule_id ORDER BY g.rule_id NULLS LAST
        """,
            (site_id, to, from_, to, site_id, to, rule_id, rule_id),
        ).fetchall(),
    )
    per_rule: list[dict[str, Any]] = []
    for value, tp, fp, benign_tp, denominator, rule_labelled in rules:
        denominator = int(denominator)
        per_rule.append(
            {
                "rule_id": value,
                "true_positive": int(tp),
                "false_positive": int(fp),
                "benign_true_positive": int(benign_tp),
                "precision": None if denominator == 0 else int(tp) / denominator,
                "numerator": int(tp),
                "denominator": denominator,
                "labelled_groups": int(rule_labelled),
                "excluded_labels": ["benign_true_positive", "duplicate", "undetermined"],
                "score_versions": _score_versions(conn, site_id, value, from_, to),
            }
        )
    return {
        "as_of": now.isoformat(),
        "window": {"from": from_.isoformat(), "to": to.isoformat()},
        "label_coverage": _metric(
            labelled / int(totals) if totals else None,
            int(totals),
            "ratio",
            from_,
            to,
            numerator=labelled,
        ),
        "labelled_group_count": int(labelled),
        "group_count": int(totals),
        "disposition_shares": {
            label: _metric(count, labelled, "groups", from_, to)
            for label, count in sorted(shares.items())
        },
        "per_rule_precision": per_rule,
    }


def _score_versions(
    conn: psycopg.Connection[Any], site_id: str, rule_id: str | None, from_: datetime, to: datetime
) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT s.computation_version, count(DISTINCT s.group_id)
        FROM scores AS s JOIN group_revisions AS gr
          ON (gr.site_id, gr.group_id, gr.revision) = (s.site_id, s.group_id, s.group_revision)
        WHERE s.site_id = %s AND s.computed_at <= %s AND gr.created_at <= %s
          AND gr.rule_id IS NOT DISTINCT FROM %s
          AND gr.first_ts >= %s AND gr.first_ts < %s
        GROUP BY s.computation_version ORDER BY s.computation_version
        """,
        (site_id, to, to, rule_id, from_, to),
    ).fetchall()
    return [
        {"computation_version": str(version), "group_count": int(count)} for version, count in rows
    ]


def _metric(
    value: Any,
    denominator: int,
    unit: str,
    start: datetime,
    end: datetime,
    *,
    numerator: int | None = None,
) -> dict[str, Any]:
    actual_numerator = value if numerator is None and isinstance(value, int) else numerator
    return {
        "value": value if denominator > 0 else None,
        "unit": unit,
        "numerator": actual_numerator,
        "denominator": denominator,
        "coverage": 0.0 if denominator == 0 else min(1.0, denominator / denominator),
        "window": {"from": start.isoformat(), "to": end.isoformat()},
    }


def _unavailable_metric(reason: str, start: datetime, end: datetime) -> dict[str, Any]:
    return {
        "value": None,
        "unit": "alerts",
        "numerator": None,
        "denominator": None,
        "coverage": None,
        "window": {"from": start.isoformat(), "to": end.isoformat()},
        "availability": "unavailable",
        "reason": reason,
    }


def _validate(
    conn: psycopg.Connection[Any],
    site_id: str,
    start: datetime,
    end: datetime,
    now: datetime,
    *,
    max_span: timedelta,
) -> None:
    if conn.info.transaction_status is TransactionStatus.IDLE:
        raise PermissionError("metrics require an active site transaction")
    current = conn.execute("SELECT current_setting('app.site_id', true)").fetchone()
    if not site_id or current is None or current[0] != site_id:
        raise PermissionError("metrics require the active site's transaction")
    for value in (start, end, now):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("metrics timestamps must be timezone-aware")
    if end <= start or end - start > max_span or end > now:
        raise ValueError("metrics window must be ordered, bounded, and no later than now")


def _float_or_none(value: Any) -> float | None:
    return None if value is None else float(value)


def _required_row(cursor: psycopg.Cursor[Any]) -> tuple[Any, ...]:
    row = cursor.fetchone()
    if row is None:
        raise RuntimeError("aggregate metrics query unexpectedly returned no row")
    return cast(tuple[Any, ...], row)
