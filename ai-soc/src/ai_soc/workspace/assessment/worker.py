"""Run bounded assessment calls with durable admission and fenced publication."""

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from time import monotonic
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from ai_soc.contracts.canonical import canonical_bytes
from ai_soc.workspace.assessment.catalog import AssessmentCatalog
from ai_soc.workspace.assessment.pack import EvidencePack
from ai_soc.workspace.assessment.scheduling import (
    ASSESS_KIND,
    DEMO_ASSESS_KIND,
    AssessmentPreparation,
)
from ai_soc.workspace.assessment.validation import Outcome, output_schema, validate_assessment
from ai_soc.workspace.db import site_transaction
from ai_soc.workspace.jobs import (
    Job,
    LeaseLost,
    claim_job,
    complete_job,
    fail_job,
    lock_live_job,
)
from ai_soc.workspace.model.provider import (
    AssessmentProvider,
    ProviderInvalidResponse,
    ProviderResult,
    ProviderUnavailable,
)
from ai_soc.workspace.worker import run_once

LEASE = timedelta(seconds=60)


@contextmanager
def _slot(conn: psycopg.Connection[Any], site_id: str, concurrency: int) -> Iterator[bool]:
    for index in range(concurrency):
        key = int.from_bytes(
            sha256(canonical_bytes(["group-assessment-slot", site_id, index])).digest()[:8],
            "big",
            signed=True,
        )
        row = conn.execute("SELECT pg_try_advisory_lock(%s::bigint)", (key,)).fetchone()
        if row is not None and row[0]:
            try:
                yield True
            finally:
                conn.execute("SELECT pg_advisory_unlock(%s::bigint)", (key,))
            return
    yield False


def _outcome(
    conn: psycopg.Connection[Any],
    job: Job,
    *,
    attempt: int,
    outcome: Outcome,
    result: ProviderResult | None,
    elapsed_ms: int | None,
    now: datetime,
) -> None:
    conn.execute(
        """
        INSERT INTO group_assessment_outcomes
          (site_id, request_id, attempt, status, outcome, input_tokens, output_tokens,
           latency_ms, finished_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        (
            job.site_id,
            job.subject,
            attempt,
            outcome.status,
            Jsonb(outcome.model_dump(mode="json")),
            result.input_tokens if result else None,
            result.output_tokens if result else None,
            result.latency_ms if result else elapsed_ms,
            now,
        ),
    )


def _run_claim(
    conn: psycopg.Connection[Any],
    *,
    worker_id: str,
    site_id: str,
    provider: AssessmentProvider,
    synthetic: bool,
    clock: Callable[[], datetime],
) -> tuple[bool, bool]:
    """Return whether a job was consumed and whether it used this run's call budget."""
    sites = frozenset({site_id})
    kind = DEMO_ASSESS_KIND if synthetic else ASSESS_KIND
    with site_transaction(conn, site_id, sites):
        switch = conn.execute(
            "SELECT enabled FROM group_assessment_sites WHERE site_id=%s FOR SHARE",
            (site_id,),
        ).fetchone()
        if not switch or not switch[0]:
            return False, False
        job = claim_job(
            conn,
            worker_id=worker_id,
            site_id=site_id,
            authorized_sites=sites,
            kind=kind,
            job_kinds=frozenset({kind}),
            now=clock(),
            lease=LEASE,
        )
        conn.execute(
            """
            INSERT INTO group_assessment_outcomes
              (site_id,request_id,attempt,status,outcome,finished_at)
            SELECT r.site_id,r.request_id,a.attempt,'provider_unavailable',%s,%s
            FROM group_assessment_requests r
            JOIN group_assessment_attempts a USING (site_id,request_id)
            JOIN jobs j USING (site_id,job_id)
            WHERE r.site_id=%s AND r.synthetic=%s AND j.state='dead'
              AND NOT EXISTS (
                  SELECT 1 FROM group_assessment_outcomes o
                  WHERE (o.site_id,o.request_id)=(r.site_id,r.request_id)
              )
            ON CONFLICT (site_id,request_id) DO NOTHING
            """,
            (
                Jsonb(
                    Outcome(status="provider_unavailable", reason="attempt_interrupted").model_dump(
                        mode="json"
                    )
                ),
                clock(),
                site_id,
                synthetic,
            ),
        )
    if job is None:
        return False, False

    reserved = False
    try:
        with site_transaction(conn, site_id, sites):
            lock_live_job(conn, job=job, worker_id=worker_id, now=clock())
            row = conn.execute(
                """
                SELECT r.prompt,r.prompt_digest,r.catalog,r.catalog_digest,
                       r.evidence_pack,r.pack_digest,a.attempt,o.status,s.total
                FROM group_assessment_requests r
                JOIN scores s USING
                  (site_id,group_id,group_revision,computation_version,input_digest)
                LEFT JOIN group_assessment_attempts a USING (site_id,request_id)
                LEFT JOIN group_assessment_outcomes o USING (site_id,request_id)
                WHERE r.site_id=%s AND r.request_id=%s AND r.job_id=%s AND r.synthetic=%s
                """,
                (site_id, job.subject, job.job_id, synthetic),
            ).fetchone()
            if row is None:
                raise LookupError("assessment request is unavailable in this runtime")
            if row[6] is not None:
                if row[7] is None:
                    _outcome(
                        conn,
                        job,
                        attempt=int(row[6]),
                        outcome=Outcome(
                            status="provider_unavailable", reason="attempt_interrupted"
                        ),
                        result=None,
                        elapsed_ms=None,
                        now=clock(),
                    )
                complete_job(
                    conn,
                    job_id=job.job_id,
                    worker_id=worker_id,
                    lease_token=job.lease_token,
                    now=clock(),
                )
                return True, False

            prompt = bytes(row[0])
            catalog = AssessmentCatalog.model_validate_json(canonical_bytes(row[2]))
            pack = EvidencePack.from_dict(row[4])
            score = float(row[8])
            if (sha256(prompt).hexdigest(), catalog.digest, pack.digest) != (
                row[1],
                row[3],
                row[5],
            ):
                raise ValueError("assessment input differs from its frozen request")
            schema = output_schema(catalog)
            conn.execute(
                """
                INSERT INTO group_assessment_attempts
                  (site_id,request_id,attempt,lease_token,provider,model,started_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    site_id,
                    job.subject,
                    job.attempts,
                    job.lease_token,
                    provider.provider_id,
                    provider.model_id,
                    clock(),
                ),
            )
        reserved = True
        started = monotonic()
        result: ProviderResult | None = None
        try:
            result = provider.complete(prompt, schema)
            outcome = validate_assessment(result.raw_json, pack, catalog, score=score)
        except ProviderUnavailable as exc:
            outcome = Outcome(status="provider_unavailable", reason=exc.reason)
        except ProviderInvalidResponse as exc:
            outcome = Outcome(status="invalid_response", reason=exc.reason)
        duration = int((monotonic() - started) * 1000)
        with site_transaction(conn, site_id, sites):
            lock_live_job(conn, job=job, worker_id=worker_id, now=clock())
            _outcome(
                conn,
                job,
                attempt=job.attempts,
                outcome=outcome,
                result=result,
                elapsed_ms=duration,
                now=clock(),
            )
            complete_job(
                conn,
                job_id=job.job_id,
                worker_id=worker_id,
                lease_token=job.lease_token,
                now=clock(),
            )
    except LeaseLost:
        pass
    except Exception as exc:
        try:
            with site_transaction(conn, site_id, sites):
                fail_job(
                    conn,
                    job_id=job.job_id,
                    worker_id=worker_id,
                    lease_token=job.lease_token,
                    now=clock(),
                    error=type(exc).__name__,
                )
        except LeaseLost:
            pass
    return True, reserved


def drain_assessments(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    worker_id: str,
    provider: AssessmentProvider | None,
    enabled: bool,
    max_calls: int,
    concurrency: int,
    synthetic: bool = False,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> int:
    """Defer unclaimed work when disabled, saturated, or out of this run's budget."""
    if not conn.autocommit or not 1 <= concurrency <= 8 or not 1 <= max_calls <= 1000:
        raise ValueError("invalid assessment worker bounds")
    with site_transaction(conn, site_id, frozenset({site_id})):
        conn.execute(
            "INSERT INTO group_assessment_sites(site_id,enabled) VALUES (%s,%s) "
            "ON CONFLICT (site_id) DO UPDATE SET enabled=EXCLUDED.enabled "
            "WHERE group_assessment_sites.enabled IS DISTINCT FROM EXCLUDED.enabled",
            (site_id, enabled and provider is not None),
        )
    if not enabled or provider is None:
        return 0

    preparation = AssessmentPreparation(synthetic=synthetic)
    prepared = 0
    while prepared < max_calls:
        count = run_once(
            conn,
            worker_id=worker_id,
            site_ids=frozenset({site_id}),
            handler=preparation,
            batch_size=1,
            clock=clock,
        )
        if not count:
            break
        prepared += count

    calls = 0
    for _ in range(max_calls + 5):
        if calls >= max_calls:
            break
        with _slot(conn, site_id, concurrency) as available:
            if not available:
                break
            consumed, charged = _run_claim(
                conn,
                worker_id=worker_id,
                site_id=site_id,
                provider=provider,
                synthetic=synthetic,
                clock=clock,
            )
        if not consumed:
            break
        calls += int(charged)
    return calls
