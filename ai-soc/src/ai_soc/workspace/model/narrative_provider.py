"""Portable incident narrative execution through the workspace provider port."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, cast
from uuid import UUID, uuid4

import psycopg

from ai_soc.workspace.audit_outbox import record_audit
from ai_soc.workspace.db import site_transaction
from ai_soc.workspace.jobs import Job, LeaseLost, heartbeat_job
from ai_soc.workspace.model.bundle import supported_provider_execution
from ai_soc.workspace.model.cli_provider import TokenUsage
from ai_soc.workspace.model.narrate import (
    Generation,
    authorize_provider_call,
    finish_call,
    load_generation,
)
from ai_soc.workspace.model.provider import (
    AssessmentProvider,
    ProviderInvalidResponse,
    ProviderResult,
    ProviderUnavailable,
)
from ai_soc.workspace.model.schemas import ValidatedNarrative
from ai_soc.workspace.model.validation import validate_incident_narrative
from ai_soc.workspace.worker import LEASE

ConnectionFactory = Callable[[], psycopg.Connection[Any]]


@dataclass(frozen=True, slots=True)
class ProviderNarrativeProvenance:
    provider_id: str
    model_id: str
    request_sha256: str
    schema_sha256: str


@dataclass(frozen=True, slots=True)
class ProviderNarrativeResult:
    narrative: ValidatedNarrative
    usage: TokenUsage
    provenance: ProviderNarrativeProvenance


@contextmanager
def _transaction(
    conn: psycopg.Connection[Any], site_id: str, sites: frozenset[str]
) -> Iterator[None]:
    with site_transaction(conn, site_id, sites):
        conn.execute("SET LOCAL lock_timeout = '2s'")
        conn.execute("SET LOCAL statement_timeout = '5s'")
        yield


def _clock() -> datetime:
    return datetime.now(UTC)


def _recover_interrupted(conn: psycopg.Connection[Any], *, site_id: str, now: datetime) -> int:
    rows = conn.execute(
        "SELECT c.call_id,c.generation_id,c.job_id,c.producing_attempt,"
        "c.producing_lease_token FROM narrative_calls c "
        "JOIN jobs j ON (j.site_id,j.job_id)=(c.site_id,c.job_id) "
        "LEFT JOIN narrative_outcomes o ON (o.site_id,o.call_id)=(c.site_id,c.call_id) "
        "WHERE c.site_id=%s AND c.execution_path='provider' AND o.call_id IS NULL "
        "AND j.state='running' AND j.locked_until<=%s ORDER BY j.job_id FOR UPDATE OF j",
        (site_id, now),
    ).fetchall()
    for call_id, generation_id, job_id, attempt, token in rows:
        conn.execute(
            "INSERT INTO narrative_outcomes(site_id,call_id,generation_id,status,"
            "error_code,provenance,finished_at) VALUES "
            "(%s,%s,%s,'abandoned_unknown','abandoned_unknown','{}',%s)",
            (site_id, call_id, generation_id, now),
        )
        conn.execute(
            "UPDATE jobs SET state=CASE WHEN attempts>=5 THEN 'dead' ELSE 'queued' END,"
            "run_after=%s,locked_by=NULL,locked_until=NULL,lease_token=NULL,"
            "last_error='abandoned_unknown' WHERE site_id=%s AND job_id=%s "
            "AND attempts=%s AND lease_token=%s",
            (now, site_id, job_id, attempt, token),
        )
        record_audit(
            conn,
            site_id=site_id,
            kind="narrative.abandoned",
            actor_key=None,
            payload={"call_id": str(call_id), "attempt": int(attempt), "usage": "unknown"},
        )
    return len(rows)


def _claim(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    worker_id: str,
    provider: AssessmentProvider,
    now: datetime,
) -> tuple[Job, Generation] | None:
    rows = conn.execute(
        "SELECT j.job_id,j.kind,j.subject,j.payload,j.attempts FROM jobs j "
        "JOIN narrative_generations g ON (g.site_id,g.narrate_job_id)=(j.site_id,j.job_id) "
        "WHERE j.site_id=%s AND j.kind='narrate' AND j.state='queued' "
        "AND j.attempts<5 AND j.run_after<=%s ORDER BY j.run_after,j.job_id "
        "FOR UPDATE OF j SKIP LOCKED",
        (site_id, now),
    ).fetchall()
    for job_id, kind, subject, payload, attempts in rows:
        generation = load_generation(
            conn, site_id=site_id, generation_id=UUID(str(payload["generation_id"]))
        )
        if not supported_provider_execution(
            generation.execution,
            provider_id=provider.provider_id,
            model_id=provider.model_id,
        ):
            continue
        token = uuid4()
        until = now + LEASE
        conn.execute(
            "UPDATE jobs SET state='running',attempts=attempts+1,locked_by=%s,"
            "locked_until=%s,lease_token=%s WHERE site_id=%s AND job_id=%s",
            (worker_id, until, token, site_id, job_id),
        )
        return (
            Job(
                int(job_id),
                site_id,
                str(kind),
                str(subject),
                dict(payload),
                int(attempts) + 1,
                token,
                until,
            ),
            generation,
        )
    return None


def _heartbeat(
    connect: ConnectionFactory,
    *,
    sites: frozenset[str],
    worker_id: str,
    job: Job,
    stop: threading.Event,
    lost: threading.Event,
) -> None:
    while not stop.wait(10.0):
        try:
            with connect() as conn, _transaction(conn, job.site_id, sites):
                heartbeat_job(
                    conn,
                    job_id=job.job_id,
                    worker_id=worker_id,
                    lease_token=job.lease_token,
                    now=_clock(),
                    lease=LEASE,
                )
        except Exception:
            lost.set()
            return


def _provider_result(
    provider: AssessmentProvider, generation: Generation
) -> tuple[ProviderNarrativeResult | None, str | None, TokenUsage, int]:
    schema_value = json.loads(generation.execution.schema)
    if not isinstance(schema_value, dict):
        raise ValueError("invalid_frozen_narrative_schema")
    schema = cast(Mapping[str, object], schema_value)
    started = time.monotonic()
    response: ProviderResult | None = None
    error_code: str | None = None
    try:
        response = provider.complete(generation.execution.prompt, schema)
        narrative = validate_incident_narrative(
            response.raw_json,
            expected_site_id=generation.site_id,
            expected_incident_id=generation.incident_id,
            expected_revision_id=generation.incident_revision_id,
            pack=generation.pack,
        )
        if narrative.status == "invalid_structure":
            error_code = "invalid_structured_output"
            result = None
        else:
            result = ProviderNarrativeResult(
                narrative,
                TokenUsage(response.input_tokens, None, response.output_tokens),
                ProviderNarrativeProvenance(
                    provider.provider_id,
                    provider.model_id,
                    sha256(generation.execution.prompt).hexdigest(),
                    sha256(generation.execution.schema).hexdigest(),
                ),
            )
    except ProviderUnavailable as exc:
        result = None
        error_code = {
            "timeout": "timeout",
            "transport": "upstream_transport_failed",
            "rate_limit": "rate_limited",
        }.get(exc.reason, f"provider_{exc.reason}")
    except ProviderInvalidResponse:
        result = None
        error_code = "invalid_structured_output"
    elapsed_ms = min(2_147_483_647, int((time.monotonic() - started) * 1000))
    usage = (
        TokenUsage(response.input_tokens, None, response.output_tokens)
        if response is not None
        else TokenUsage(None, None, None)
    )
    return result, error_code, usage, elapsed_ms


def run_provider_narrative_once(
    conn: psycopg.Connection[Any],
    *,
    site_ids: frozenset[str],
    worker_id: str,
    provider: AssessmentProvider,
    connect: ConnectionFactory | None = None,
) -> int:
    """Run at most one provider-bound narrative call, with durable reservation and fencing."""
    if connect is None:
        dsn = conn.info.dsn

        def default_connect() -> psycopg.Connection[Any]:
            return psycopg.connect(dsn)

        connect = default_connect
    claimed: tuple[Job, Generation] | None = None
    call_id: UUID | None = None
    for site_id in sorted(site_ids):
        with _transaction(conn, site_id, site_ids):
            _recover_interrupted(conn, site_id=site_id, now=_clock())
        # Commit the recovered outcome and closed lease before claiming the next attempt.
        with _transaction(conn, site_id, site_ids):
            claimed = _claim(
                conn,
                site_id=site_id,
                worker_id=worker_id,
                provider=provider,
                now=_clock(),
            )
            if claimed is not None:
                job, generation = claimed
                call_id = authorize_provider_call(
                    conn,
                    job=job,
                    worker_id=worker_id,
                    generation=generation,
                    provider_id=provider.provider_id,
                    model_id=provider.model_id,
                    now=_clock(),
                )
                break
    if claimed is None:
        return 0
    assert call_id is not None
    job, generation = claimed
    stop = threading.Event()
    lost = threading.Event()
    heartbeat = threading.Thread(
        target=_heartbeat,
        kwargs={
            "connect": connect,
            "sites": site_ids,
            "worker_id": worker_id,
            "job": job,
            "stop": stop,
            "lost": lost,
        },
        daemon=True,
    )
    heartbeat.start()
    try:
        result, error_code, usage, elapsed_ms = _provider_result(provider, generation)
        if lost.is_set():
            return 1
        for attempt in range(3):
            try:
                with _transaction(conn, job.site_id, site_ids):
                    finish_call(
                        conn,
                        job=job,
                        worker_id=worker_id,
                        call_id=call_id,
                        generation=generation,
                        now=_clock(),
                        result=result,
                        error_code=error_code,
                        usage=usage,
                        elapsed_ms=elapsed_ms,
                    )
                return 1
            except LeaseLost:
                return 1
            except psycopg.Error:
                if attempt == 2 or lost.wait(0.1 * (attempt + 1)):
                    raise
        return 1
    finally:
        stop.set()
        heartbeat.join(timeout=15)
