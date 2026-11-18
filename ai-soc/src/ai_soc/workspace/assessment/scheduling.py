"""Commit assessment admission with scoring and freeze provider input independently."""

from datetime import datetime
from hashlib import sha256
from typing import Any, Literal

import psycopg
from psycopg.types.json import Jsonb

from ai_soc.contracts.canonical import canonical_bytes, sha256_hex
from ai_soc.workspace.assessment.catalog import AssessmentCatalog, load_catalog
from ai_soc.workspace.assessment.pack import build_pack
from ai_soc.workspace.assessment.validation import build_prompt
from ai_soc.workspace.db import require_site_transaction
from ai_soc.workspace.jobs import Job, enqueue_job
from ai_soc.workspace.triage.score import ScoreResult

PREPARE_KIND = "prepare_group_assessment"
DEMO_PREPARE_KIND = "prepare_demo_assessment"
ASSESS_KIND = "assess_group"
DEMO_ASSESS_KIND = "assess_demo_group"


def prepare_key(
    group_id: str, revision: str, computation_version: str, input_digest: str, catalog_digest: str
) -> str:
    return sha256_hex([group_id, revision, computation_version, input_digest, catalog_digest])


def selected_in_sample(catalog: AssessmentCatalog, site_id: str, group_id: str) -> bool:
    number = int(sha256_hex([catalog.sample_seed, site_id, group_id])[:16], 16)
    return number * 10_000 < catalog.sample_basis_points * (1 << 64)


def schedule_assessment(
    conn: psycopg.Connection[Any], *, score: ScoreResult, now: datetime, synthetic: bool
) -> None:
    """Schedule exact score evidence without invoking a model in the scoring transaction."""
    site_id, group_id = score.site_id, score.group_id
    require_site_transaction(conn, site_id)
    catalog = load_catalog()
    prepare_kind = DEMO_PREPARE_KIND if synthetic else PREPARE_KIND
    conn.execute(
        "SELECT 1 FROM group_heads WHERE site_id=%s AND group_id=%s FOR UPDATE",
        (site_id, group_id),
    )
    selection: Literal["score_gate", "sample", "new_revision"]
    if score.total >= catalog.score_gate:
        selection = "score_gate"
    elif selected_in_sample(catalog, site_id, group_id):
        selection = "sample"
    elif conn.execute(
        "SELECT 1 WHERE EXISTS ("
        "SELECT 1 FROM group_assessment_requests WHERE site_id=%s AND group_id=%s AND synthetic=%s"
        ") OR EXISTS (SELECT 1 FROM jobs WHERE site_id=%s AND kind=%s AND payload->>'group_id'=%s)",
        (site_id, group_id, synthetic, site_id, prepare_kind, group_id),
    ).fetchone():
        selection = "new_revision"
    else:
        return
    revision = score.inputs.group_revision
    enqueue_job(
        conn,
        site_id=site_id,
        kind=prepare_kind,
        subject=prepare_key(
            group_id, revision, score.computation_version, score.input_digest, catalog.digest
        ),
        payload={
            "group_id": group_id,
            "revision": revision,
            "computation_version": score.computation_version,
            "input_digest": score.input_digest,
            "catalog": catalog.model_dump(mode="json"),
            "selection": selection,
            "synthetic": synthetic,
        },
        run_after=now,
    )


class AssessmentPreparation:
    def __init__(self, *, synthetic: bool) -> None:
        self.job_kinds = frozenset({DEMO_PREPARE_KIND if synthetic else PREPARE_KIND})

    def __call__(self, conn: psycopg.Connection[Any], jobs: tuple[Job, ...], now: datetime) -> None:
        for job in jobs:
            if job.kind not in self.job_kinds:
                raise ValueError("assessment preparation is outside its runtime")
            _prepare(conn, job, now)


def _prepare(conn: psycopg.Connection[Any], job: Job, now: datetime) -> None:
    payload = job.payload
    catalog = AssessmentCatalog.model_validate_json(canonical_bytes(payload["catalog"]))
    group_id = str(payload["group_id"])
    revision = str(payload["revision"])
    version = str(payload["computation_version"])
    digest = str(payload["input_digest"])
    synthetic = job.kind == DEMO_PREPARE_KIND
    if payload["synthetic"] is not synthetic or job.subject != prepare_key(
        group_id, revision, version, digest, catalog.digest
    ):
        raise ValueError("assessment preparation does not bind the exact score")
    prior = conn.execute(
        "SELECT 1 FROM group_assessment_requests WHERE site_id=%s AND group_id=%s "
        "AND group_revision=%s AND computation_version=%s AND input_digest=%s "
        "AND catalog_digest=%s",
        (job.site_id, group_id, revision, version, digest, catalog.digest),
    ).fetchone()
    if prior:
        return
    manifest = conn.execute(
        "SELECT manifest->'score_output' FROM score_manifests WHERE site_id=%s AND group_id=%s "
        "AND group_revision=%s AND computation_version=%s AND input_digest=%s",
        (job.site_id, group_id, revision, version, digest),
    ).fetchone()
    if manifest is None:
        raise LookupError("assessment score is unavailable")
    score = ScoreResult.model_validate_json(canonical_bytes(manifest[0]))
    if (
        score.site_id,
        score.group_id,
        score.inputs.group_revision,
        score.computation_version,
        score.input_digest,
    ) != (job.site_id, group_id, revision, version, digest):
        raise ValueError("assessment score does not match frozen identity")
    pack = build_pack(conn, score=score, as_of=score.inputs.as_of)
    prompt = build_prompt(pack, catalog)
    prompt_digest = sha256(prompt).hexdigest()
    request_id = sha256_hex([job.site_id, job.subject, pack.digest, prompt_digest])
    job_id = enqueue_job(
        conn,
        site_id=job.site_id,
        kind=DEMO_ASSESS_KIND if synthetic else ASSESS_KIND,
        subject=request_id,
        payload={"request_id": request_id},
        run_after=now,
    )
    conn.execute(
        """
        INSERT INTO group_assessment_requests
          (site_id, request_id, group_id, group_revision, computation_version, input_digest,
           pack_digest, prompt_digest, catalog_digest, catalog_version, catalog, evidence_pack,
           prompt, job_id, selection, synthetic, created_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        (
            job.site_id,
            request_id,
            group_id,
            revision,
            version,
            digest,
            pack.digest,
            prompt_digest,
            catalog.digest,
            catalog.version,
            Jsonb(catalog.model_dump(mode="json")),
            Jsonb(pack.as_dict()),
            prompt,
            job_id,
            payload["selection"],
            payload["synthetic"],
            now,
        ),
    )
