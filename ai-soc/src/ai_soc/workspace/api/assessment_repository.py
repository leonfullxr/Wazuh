"""Bounded group-assessment reads and append-only reviews in the site transaction."""

from datetime import datetime
from typing import Any
from uuid import uuid4

from psycopg.rows import dict_row

from ai_soc.contracts.canonical import canonical_bytes
from ai_soc.workspace.api.assessment_models import (
    AssessmentDetail,
    AssessmentEvidence,
    AssessmentProvenance,
    AssessmentReview,
    AssessmentReviewRequest,
    AssessmentState,
    AssessmentSummary,
)
from ai_soc.workspace.api.repository import WorkspaceRepository
from ai_soc.workspace.assessment.pack import EvidencePack
from ai_soc.workspace.assessment.scheduling import DEMO_PREPARE_KIND
from ai_soc.workspace.assessment.validation import Outcome
from ai_soc.workspace.audit_outbox import record_audit
from ai_soc.workspace.feedback import FeedbackConflict, idempotent_result, save_idempotent

_REVIEW_LIMIT = 50


def assessments_enabled(repo: WorkspaceRepository) -> bool:
    setting = repo.conn.execute(
        "SELECT enabled FROM group_assessment_sites WHERE site_id = %s", (repo.site_id,)
    ).fetchone()
    return setting is not None and bool(setting[0])


def assessment_records(
    repo: WorkspaceRepository, groups: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    if not groups:
        return {}
    with repo.conn.cursor(row_factory=dict_row) as cursor:
        cursor.execute(
            """
            SELECT target.group_id, chosen.request_id, chosen.group_revision,
                   chosen.computation_version, chosen.input_digest, chosen.exact,
                   chosen.outcome_status, chosen.verdict, chosen.band,
                   COALESCE(chosen.job_state, preparation.state) AS job_state
            FROM unnest(%s::text[], %s::text[], %s::text[], %s::text[])
                 AS target(group_id, revision, computation_version, input_digest)
            LEFT JOIN LATERAL (
                SELECT r.request_id, r.group_revision, r.computation_version, r.input_digest,
                       pin.exact, o.status AS outcome_status,
                       o.outcome->>'verdict' AS verdict, o.outcome->>'band' AS band,
                       j.state AS job_state
                FROM group_assessment_requests r
                JOIN jobs j USING (site_id, job_id)
                LEFT JOIN group_assessment_outcomes o USING (site_id, request_id)
                CROSS JOIN LATERAL (
                    SELECT ((r.group_revision, r.computation_version, r.input_digest) =
                            (target.revision, target.computation_version, target.input_digest))
                            IS TRUE AS exact
                ) pin
                WHERE r.site_id = %s AND r.group_id = target.group_id AND r.synthetic
                  AND (pin.exact OR o.status = 'accepted')
                ORDER BY CASE WHEN pin.exact AND o.status IS NOT NULL THEN 0
                              WHEN o.status = 'accepted' THEN 1 ELSE 2 END,
                         r.created_at DESC, r.job_id DESC
                LIMIT 1
            ) chosen ON true
            LEFT JOIN LATERAL (
                SELECT j.state FROM jobs j
                WHERE chosen.request_id IS NULL
                  AND j.site_id = %s AND j.kind = %s
                  AND j.payload->>'group_id' = target.group_id
                  AND j.payload->>'revision' = target.revision
                  AND j.payload->>'computation_version' = target.computation_version
                  AND j.payload->>'input_digest' = target.input_digest
                  AND j.payload->'synthetic' = 'true'::jsonb
                ORDER BY j.job_id DESC
                LIMIT 1
            ) preparation ON true
            """,
            (
                [group["group_id"] for group in groups],
                [group["revision"] for group in groups],
                [group["computation_version"] for group in groups],
                [group["input_digest"] for group in groups],
                repo.site_id,
                repo.site_id,
                DEMO_PREPARE_KIND,
            ),
        )
        return {row["group_id"]: row for row in cursor}


def assessment_summary(record: dict[str, Any]) -> AssessmentSummary:
    status = record.get("outcome_status")
    state: AssessmentState
    if status == "accepted":
        state = "preview" if record["exact"] else "stale"
        return AssessmentSummary(state=state, verdict=record["verdict"], band=record["band"])
    if status == "provider_unavailable":
        state = "provider_unavailable"
    elif status is not None or (record.get("request_id") and record.get("job_state") == "dead"):
        state = "no_assessment"
    elif record.get("job_state") in {"queued", "running"}:
        state = "pending"
    else:
        state = "not_selected"
    return AssessmentSummary(state=state, verdict=None, band=None)


def assessment_detail(
    repo: WorkspaceRepository, group: dict[str, Any], *, preview_enabled: bool
) -> AssessmentDetail:
    record: dict[str, Any] = {}
    enabled = assessments_enabled(repo)
    if enabled and preview_enabled:
        record = assessment_records(repo, [group])[group["group_id"]]
        summary = assessment_summary(record)
    else:
        summary = AssessmentSummary(
            state="shadow" if enabled else "disabled", verdict=None, band=None
        )
    request_id = record.get("request_id")
    if request_id is None:
        return AssessmentDetail(
            summary=summary,
            request_id=None,
            revision=group["revision"] if enabled and preview_enabled else None,
            outcome=None,
            evidence=[],
            gaps={},
            missing_fields=[],
            provenance=None,
            reviews=[],
        )

    with repo.conn.cursor(row_factory=dict_row) as cursor:
        row = cursor.execute(
            """
            SELECT r.evidence_pack, r.pack_digest, r.prompt_digest, r.catalog_version,
                   r.catalog_digest, a.provider, a.model, o.outcome, o.input_tokens,
                   o.output_tokens, o.latency_ms, o.finished_at
            FROM group_assessment_requests r
            LEFT JOIN group_assessment_outcomes o USING (site_id, request_id)
            LEFT JOIN group_assessment_attempts a USING (site_id, request_id, attempt)
            WHERE r.site_id = %s AND r.request_id = %s AND r.synthetic
            """,
            (repo.site_id, request_id),
        ).fetchone()
        if row is None:
            raise LookupError("assessment request is unavailable")
        pack = EvidencePack.from_dict(row["evidence_pack"])
        if pack.digest != row["pack_digest"] or (
            pack.site_id,
            pack.group_id,
            pack.revision,
            pack.score.computation_version,
            pack.score.input_digest,
        ) != (
            repo.site_id,
            group["group_id"],
            record["group_revision"],
            record["computation_version"],
            record["input_digest"],
        ):
            raise ValueError("assessment evidence does not match its request")
        cursor.execute(
            """
            SELECT review_id::text, request_id, decision, verdict, reason, actor_key, at
            FROM group_assessment_reviews
            WHERE site_id = %s AND request_id = %s
            ORDER BY at DESC, review_id DESC LIMIT %s
            """,
            (repo.site_id, request_id, _REVIEW_LIMIT),
        )
        reviews = [AssessmentReview.model_validate(item) for item in cursor]

    provenance = None
    if row["finished_at"] is not None:
        provenance = AssessmentProvenance.model_validate(
            {field: row[field] for field in AssessmentProvenance.model_fields}
        )
    return AssessmentDetail(
        summary=summary,
        request_id=request_id,
        revision=record["group_revision"],
        outcome=Outcome.model_validate(row["outcome"]) if row["outcome"] is not None else None,
        evidence=[
            AssessmentEvidence(id=item.id, kind=item.kind, fields=item.as_dict()["fields"])
            for item in pack.items
        ],
        gaps=dict(pack.gaps),
        missing_fields=list(pack.missing_fields),
        provenance=provenance,
        reviews=reviews,
    )


def review_assessment(
    repo: WorkspaceRepository,
    group_id: str,
    body: AssessmentReviewRequest,
    *,
    actor_key: str,
    idempotency_key: str,
    now: datetime,
) -> AssessmentReview:
    if not assessments_enabled(repo):
        raise LookupError("assessment is unavailable")
    request = body.model_dump(mode="json")
    route = f"/groups/{group_id}/assessment/review"
    prior = idempotent_result(repo.conn, repo.site_id, actor_key, route, idempotency_key, request)
    if prior is not None:
        return AssessmentReview.model_validate_json(canonical_bytes(prior))

    # Serializes against both group revision updates and assessment admission during scoring.
    head = repo.conn.execute(
        "SELECT 1 FROM group_heads WHERE site_id = %s AND group_id = %s FOR UPDATE",
        (repo.site_id, group_id),
    ).fetchone()
    if head is None:
        raise LookupError("unknown group")
    requested = repo.conn.execute(
        """
        SELECT 1 FROM group_assessment_requests
        WHERE site_id = %s AND group_id = %s AND request_id = %s AND synthetic
        """,
        (repo.site_id, group_id, body.request_id),
    ).fetchone()
    group = repo.group_detail(group_id)
    if requested is None or group is None:
        raise LookupError("unknown assessment")
    current = assessment_records(repo, [group])[group_id]
    summary = assessment_summary(current)
    if (
        current["request_id"] != body.request_id
        or summary.state != "preview"
        or summary.verdict is None
    ):
        raise FeedbackConflict("assessment changed since it was read")

    review = AssessmentReview(
        review_id=str(uuid4()),
        request_id=body.request_id,
        decision=body.decision,
        verdict=body.verdict or summary.verdict,
        reason=body.reason,
        actor_key=actor_key,
        at=now,
    )
    repo.conn.execute(
        """
        INSERT INTO group_assessment_reviews
          (site_id, review_id, request_id, decision, verdict, reason, actor_key, at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        (
            repo.site_id,
            review.review_id,
            review.request_id,
            review.decision,
            review.verdict,
            review.reason,
            review.actor_key,
            review.at,
        ),
    )
    record_audit(
        repo.conn,
        site_id=repo.site_id,
        kind="group_assessment_reviewed",
        actor_key=actor_key,
        payload={
            "group_id": group_id,
            "group_revision": group["revision"],
            "request_id": review.request_id,
            "review_id": review.review_id,
            "decision": review.decision,
            "verdict": review.verdict,
        },
    )
    save_idempotent(
        repo.conn,
        repo.site_id,
        actor_key,
        route,
        idempotency_key,
        request,
        review.model_dump(mode="json"),
        now,
    )
    return review
