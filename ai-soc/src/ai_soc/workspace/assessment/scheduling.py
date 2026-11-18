"""Commit assessment admission with scoring and freeze provider input independently."""

from datetime import datetime
from hashlib import sha256
from typing import Any, Literal
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from ai_soc.contracts.canonical import canonical_bytes, sha256_hex
from ai_soc.workspace.assessment.catalog import AssessmentCatalog, load_catalog
from ai_soc.workspace.assessment.chain import ChainPin, build_chain_pack
from ai_soc.workspace.assessment.pack import EvidencePack, build_pack
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
        "SELECT 1 FROM group_assessment_requests WHERE site_id=%s AND group_id=%s AND synthetic=%s "
        "AND chain_id IS NULL"
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


def schedule_chain_assessments(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    manifest_id: UUID,
    now: datetime,
    synthetic: bool,
) -> None:
    """Admit only candidates published by this manifest with a pinned anchor score."""
    require_site_transaction(conn, site_id)
    candidates = conn.execute(
        """
        SELECT h.chain_id, h.revision_digest
        FROM correlation_heads h
        JOIN correlation_chain_revisions r USING (site_id,chain_id,revision_digest,manifest_id)
        JOIN correlation_input_groups g ON g.site_id=r.site_id AND g.manifest_id=r.manifest_id
            AND g.group_id=r.anchor_group_id AND g.group_revision=r.anchor_group_revision
        WHERE h.site_id=%s AND h.manifest_id=%s AND r.result->>'is_candidate'='true'
          AND g.score IS NOT NULL
        ORDER BY h.chain_id
        """,
        (site_id, manifest_id),
    ).fetchall()
    catalog = load_catalog(subject="chain")
    for chain_id, revision in candidates:
        pin = ChainPin(chain_id, revision, manifest_id)
        enqueue_job(
            conn,
            site_id=site_id,
            kind=DEMO_PREPARE_KIND if synthetic else PREPARE_KIND,
            subject=pin.key(catalog.digest),
            payload={
                "chain_id": chain_id,
                "revision": revision,
                "manifest_id": str(manifest_id),
                "catalog": catalog.model_dump(mode="json"),
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
    synthetic = job.kind == DEMO_PREPARE_KIND
    if payload["synthetic"] is not synthetic:
        raise ValueError("assessment preparation is outside its runtime")
    if "chain_id" in payload:
        _prepare_chain(conn, job, now, catalog)
        return
    group_id = str(payload["group_id"])
    revision = str(payload["revision"])
    version = str(payload["computation_version"])
    digest = str(payload["input_digest"])
    if job.subject != prepare_key(group_id, revision, version, digest, catalog.digest):
        raise ValueError("assessment preparation does not bind the exact score")
    prior = conn.execute(
        "SELECT 1 FROM group_assessment_requests WHERE site_id=%s AND group_id=%s "
        "AND group_revision=%s AND computation_version=%s AND input_digest=%s "
        "AND catalog_digest=%s AND chain_id IS NULL",
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
    _freeze_request(conn, job, now, catalog, pack, revision, str(payload["selection"]))


def _prepare_chain(
    conn: psycopg.Connection[Any], job: Job, now: datetime, catalog: AssessmentCatalog
) -> None:
    payload = job.payload
    pin = ChainPin(
        str(payload["chain_id"]), str(payload["revision"]), UUID(str(payload["manifest_id"]))
    )
    if job.subject != pin.key(catalog.digest):
        raise ValueError("assessment preparation does not bind the exact chain")
    prior = conn.execute(
        "SELECT 1 FROM group_assessment_requests WHERE site_id=%s AND chain_id=%s "
        "AND chain_revision=%s AND chain_manifest_id=%s AND catalog_digest=%s",
        (job.site_id, pin.chain_id, pin.revision, pin.manifest_id, catalog.digest),
    ).fetchone()
    if prior is None:
        pack, group_revision = build_chain_pack(conn, site_id=job.site_id, pin=pin)
        _freeze_request(conn, job, now, catalog, pack, group_revision, "chain_candidate", pin)


def _freeze_request(
    conn: psycopg.Connection[Any],
    job: Job,
    now: datetime,
    catalog: AssessmentCatalog,
    pack: EvidencePack,
    group_revision: str,
    selection: str,
    pin: ChainPin | None = None,
) -> None:
    prompt = build_prompt(pack, catalog)
    prompt_digest = sha256(prompt).hexdigest()
    request_id = sha256_hex([job.site_id, job.subject, pack.digest, prompt_digest])
    synthetic = job.kind == DEMO_PREPARE_KIND
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
           prompt, job_id, selection, synthetic, created_at, chain_id, chain_revision,
           chain_manifest_id)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        (
            job.site_id,
            request_id,
            pack.group_id,
            group_revision,
            pack.score.computation_version,
            pack.score.input_digest,
            pack.digest,
            prompt_digest,
            catalog.digest,
            catalog.version,
            Jsonb(catalog.model_dump(mode="json")),
            Jsonb(pack.as_dict()),
            prompt,
            job_id,
            selection,
            synthetic,
            now,
            pin.chain_id if pin else None,
            pin.revision if pin else None,
            pin.manifest_id if pin else None,
        ),
    )
