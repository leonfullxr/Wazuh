"""Bind an immutable score to the fenced queue attempt that actually produced it."""

from __future__ import annotations

from typing import Any

import psycopg

from ai_soc.workspace.db import require_site_transaction
from ai_soc.workspace.jobs import Job
from ai_soc.workspace.triage.score import ScoreResult


def record_score_output(conn: psycopg.Connection[Any], *, job: Job, result: ScoreResult) -> None:
    """Record exact producer provenance inside the worker's live site transaction."""
    require_site_transaction(conn, job.site_id)
    if result.site_id != job.site_id or result.inputs.site_id != job.site_id:
        raise ValueError("score result belongs to a different site")
    expected_group = job.payload.get("group_id")
    expected_revision = job.payload.get("group_revision")
    if (
        result.group_id != expected_group
        or result.inputs.group_id != expected_group
        or result.inputs.group_revision != expected_revision
    ):
        raise ValueError("score result differs from the producing job's frozen group")
    conn.execute(
        """
        INSERT INTO score_job_outputs
            (site_id, job_id, group_id, group_revision, computation_version,
             input_digest, producing_attempt, producing_lease_token)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            job.site_id,
            job.job_id,
            result.group_id,
            result.inputs.group_revision,
            result.computation_version,
            result.input_digest,
            job.attempts,
            job.lease_token,
        ),
    )
