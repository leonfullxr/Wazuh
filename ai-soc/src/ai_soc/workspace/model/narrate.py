"""Short, fenced PostgreSQL transactions for automatic incident narratives."""

from __future__ import annotations

import fcntl
import os
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from ai_soc.workspace.audit_outbox import record_audit
from ai_soc.workspace.db import require_site_transaction
from ai_soc.workspace.jobs import Job, LeaseLost, complete_job, enqueue_job, fail_job, lock_live_job
from ai_soc.workspace.model.bundle import (
    FrozenExecution,
    freeze_execution,
    rehydrate_pack,
    sha256,
    supported_execution,
)
from ai_soc.workspace.model.cli_profile import CodexProfile
from ai_soc.workspace.model.cli_provider import (
    UNKNOWN_USAGE,
    GenerationProvenance,
    GenerationResult,
    TokenUsage,
)
from ai_soc.workspace.model.pack import build_incident_pack
from ai_soc.workspace.model.schemas import FrozenIncidentPack

TRANSIENT_ERRORS = frozenset(
    {
        "timeout",
        "upstream_timeout",
        "upstream_transport_failed",
        "upstream_server_error",
        "rate_limited",
        "process_start_failed",
        "temporary_storage_unavailable",
    }
)


@dataclass(frozen=True, slots=True)
class Generation:
    site_id: str
    generation_id: UUID
    incident_id: UUID
    incident_revision_id: UUID
    revision_seq: int
    narrate_job_id: int
    generation_digest: str
    pack: FrozenIncidentPack
    execution: FrozenExecution


def load_generation(
    conn: psycopg.Connection[Any], *, site_id: str, generation_id: UUID
) -> Generation:
    require_site_transaction(conn, site_id)
    with conn.cursor(row_factory=dict_row) as cursor:
        cursor.execute(
            "SELECT * FROM narrative_generations WHERE site_id=%s AND generation_id=%s",
            (site_id, generation_id),
        )
        row = cursor.fetchone()
    if row is None:
        raise ValueError("unknown_generation")
    pack = rehydrate_pack(bytes(row["pack_bytes"]), str(row["pack_digest"]))
    if (
        pack.site_id != site_id
        or pack.incident_id != row["incident_id"]
        or pack.incident_revision_id != row["incident_revision_id"]
        or pack.revision_seq != row["revision_seq"]
    ):
        raise ValueError("frozen_pack_identity_mismatch")
    execution = FrozenExecution(
        bytes(row["prompt_bytes"]),
        bytes(row["schema_bytes"]),
        bytes(row["instructions_bytes"]),
        bytes(row["catalog_bytes"]),
        cast(dict[str, Any], row["execution_bundle"]),
    )
    if (
        execution.digest(pack.content_digest) != row["generation_digest"]
        or sha256(execution.prompt) != row["prompt_sha256"]
    ):
        raise ValueError("generation_digest_mismatch")
    return Generation(
        site_id,
        row["generation_id"],
        row["incident_id"],
        row["incident_revision_id"],
        int(row["revision_seq"]),
        int(row["narrate_job_id"]),
        str(row["generation_digest"]),
        pack,
        execution,
    )


def prepare_narrative(
    conn: psycopg.Connection[Any], *, job: Job, now: datetime, profile: CodexProfile | None = None
) -> UUID:
    """Freeze one exact revision and atomically enqueue/target its immutable request."""
    require_site_transaction(conn, job.site_id)
    if job.kind != "prepare_narrative":
        raise ValueError("unsupported_preparation_job")
    incident_id = UUID(str(job.payload["incident_id"]))
    revision_id = UUID(str(job.payload["incident_revision_id"]))
    if job.subject != str(revision_id) or type(job.payload.get("revision_seq")) is not int:
        raise ValueError("preparation_identity_mismatch")
    pack = build_incident_pack(
        conn, site_id=job.site_id, incident_id=incident_id, incident_revision_id=revision_id
    )
    if pack.revision_seq != job.payload["revision_seq"]:
        raise ValueError("preparation_revision_mismatch")
    execution = freeze_execution(pack, profile or CodexProfile())
    digest = execution.digest(pack.content_digest)
    prior = conn.execute(
        "SELECT generation_id FROM narrative_generations WHERE site_id=%s AND generation_digest=%s",
        (job.site_id, digest),
    ).fetchone()
    if prior is not None:
        generation_id = cast(UUID, prior[0])
    else:
        generation_id = uuid4()
        narrate_job_id = enqueue_job(
            conn,
            site_id=job.site_id,
            kind="narrate",
            subject=digest,
            payload={"generation_id": str(generation_id)},
        )
        conn.execute(
            "INSERT INTO narrative_generations(site_id,generation_id,incident_id,"
            "incident_revision_id,revision_seq,preparation_job_id,preparation_attempt,"
            "preparation_lease_token,narrate_job_id,pack_bytes,"
            "pack_digest,prompt_bytes,prompt_sha256,schema_bytes,instructions_bytes,catalog_bytes,"
            "execution_bundle,generation_digest,created_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                job.site_id,
                generation_id,
                incident_id,
                revision_id,
                pack.revision_seq,
                job.job_id,
                job.attempts,
                job.lease_token,
                narrate_job_id,
                pack.canonical_bytes(),
                pack.content_digest,
                execution.prompt,
                sha256(execution.prompt),
                execution.schema,
                execution.instructions,
                execution.catalog,
                Jsonb(execution.material),
                digest,
                now,
            ),
        )
    # Serialize target selection with evidence mutations, with no work-column write permission.
    incident = conn.execute(
        "SELECT evidence_head FROM incidents WHERE site_id=%s AND incident_id=%s FOR UPDATE",
        (job.site_id, incident_id),
    ).fetchone()
    if incident is not None and incident[0] == revision_id:
        conn.execute(
            "INSERT INTO incident_narrative_heads(site_id,incident_id,incident_revision_id,"
            "desired_generation_id,published_call_id,updated_at) VALUES (%s,%s,%s,%s,NULL,%s) "
            "ON CONFLICT(site_id,incident_id) DO UPDATE SET "
            "incident_revision_id=EXCLUDED.incident_revision_id,"
            "desired_generation_id=EXCLUDED.desired_generation_id,"
            "published_call_id=CASE WHEN incident_narrative_heads.desired_generation_id="
            "EXCLUDED.desired_generation_id THEN incident_narrative_heads.published_call_id "
            "ELSE NULL END,updated_at=EXCLUDED.updated_at",
            (job.site_id, incident_id, revision_id, generation_id, now),
        )
    record_audit(
        conn,
        site_id=job.site_id,
        kind="narrative.prepared",
        actor_key=None,
        payload={
            "generation_id": str(generation_id),
            "generation_digest": digest,
            "incident_revision_id": str(revision_id),
        },
    )
    return generation_id


class NarrativePreparationHandler:
    job_kinds = frozenset({"prepare_narrative"})

    def __init__(self, profile: CodexProfile | None = None):
        self.profile = profile or CodexProfile()

    def __call__(self, conn: psycopg.Connection[Any], jobs: tuple[Job, ...], now: datetime) -> None:
        if len(jobs) != 1:
            raise ValueError("narrative_preparation_requires_single_job")
        prepare_narrative(conn, job=jobs[0], now=now, profile=self.profile)


def authorize_call(
    conn: psycopg.Connection[Any],
    *,
    job: Job,
    worker_id: str,
    generation: Generation,
    host_id: str,
    runtime_id: str,
    boot_id: str,
    guardian_pid: int,
    guardian_start: str,
    now: datetime,
) -> UUID:
    lock_live_job(conn, job=job, worker_id=worker_id, now=now)
    if (
        job.kind != "narrate"
        or generation.narrate_job_id != job.job_id
        or job.subject != generation.generation_digest
        or job.payload != {"generation_id": str(generation.generation_id)}
    ):
        raise ValueError("narrative_request_identity_mismatch")
    call_id = uuid4()
    conn.execute(
        "INSERT INTO narrative_calls(site_id,call_id,generation_id,job_id,producing_attempt,"
        "producing_lease_token,worker_id,host_id,runtime_id,boot_id,guardian_pid,guardian_start,"
        "slot,authorized_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0,%s)",
        (
            job.site_id,
            call_id,
            generation.generation_id,
            job.job_id,
            job.attempts,
            job.lease_token,
            worker_id,
            host_id,
            runtime_id,
            boot_id,
            guardian_pid,
            guardian_start,
            now,
        ),
    )
    record_audit(
        conn,
        site_id=job.site_id,
        kind="narrative.authorized",
        actor_key=None,
        payload={
            "call_id": str(call_id),
            "generation_id": str(generation.generation_id),
            "attempt": job.attempts,
        },
    )
    return call_id


def finish_call(
    conn: psycopg.Connection[Any],
    *,
    job: Job,
    worker_id: str,
    call_id: UUID,
    generation: Generation,
    now: datetime,
    result: GenerationResult | None = None,
    error_code: str | None = None,
    usage: TokenUsage = UNKNOWN_USAGE,
    provenance: GenerationProvenance | None = None,
    elapsed_ms: int = 0,
) -> bool:
    """Retain one safe receipt; publish only against the current evidence/desired fence."""
    lock_live_job(conn, job=job, worker_id=worker_id, now=now)
    call = conn.execute(
        "SELECT 1 FROM narrative_calls WHERE site_id=%s AND call_id=%s "
        "AND generation_id=%s AND job_id=%s AND producing_attempt=%s "
        "AND producing_lease_token=%s AND worker_id=%s",
        (
            job.site_id,
            call_id,
            generation.generation_id,
            job.job_id,
            job.attempts,
            job.lease_token,
            worker_id,
        ),
    ).fetchone()
    if call is None:
        raise LeaseLost("call authorization does not match live attempt")
    if (result is None) == (error_code is None):
        raise ValueError("outcome_requires_result_or_error")
    if result is not None:
        if result.narrative.status not in {"validated", "all_removed"}:
            raise ValueError("unsafe_narrative_outcome")
        if result.narrative.pack_digest != generation.pack.content_digest:
            raise ValueError("outcome_pack_mismatch")
        status = result.narrative.status
        usage, provenance = result.usage, result.provenance
        narrative: dict[str, Any] | None = result.narrative.model_dump(mode="json")
    else:
        status, narrative = "unavailable", None
    conn.execute(
        "INSERT INTO narrative_outcomes(site_id,call_id,generation_id,status,error_code,narrative,"
        "input_tokens,cached_input_tokens,output_tokens,provenance,elapsed_ms,finished_at) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (
            job.site_id,
            call_id,
            generation.generation_id,
            status,
            error_code,
            None if narrative is None else Jsonb(narrative),
            usage.input_tokens,
            usage.cached_input_tokens,
            usage.output_tokens,
            Jsonb({} if provenance is None else asdict(provenance)),
            elapsed_ms,
            now,
        ),
    )
    incident = conn.execute(
        "SELECT evidence_head FROM incidents WHERE site_id=%s AND incident_id=%s FOR UPDATE",
        (job.site_id, generation.incident_id),
    ).fetchone()
    published = False
    if (
        result is not None
        and status == "validated"
        and incident is not None
        and incident[0] == generation.incident_revision_id
    ):
        update = conn.execute(
            "UPDATE incident_narrative_heads SET published_call_id=%s,"
            "updated_at=%s WHERE site_id=%s AND incident_id=%s "
            "AND incident_revision_id=%s AND desired_generation_id=%s",
            (
                call_id,
                now,
                job.site_id,
                generation.incident_id,
                generation.incident_revision_id,
                generation.generation_id,
            ),
        )
        published = update.rowcount == 1
    record_audit(
        conn,
        site_id=job.site_id,
        kind="narrative.finished",
        actor_key=None,
        payload={
            "call_id": str(call_id),
            "status": status,
            "error_code": error_code,
            "published": published,
        },
    )
    # A fresh clock fences effects after any wait for the incident lock.
    final_now = conn.execute("SELECT clock_timestamp()").fetchone()
    assert final_now is not None
    if result is not None:
        complete_job(
            conn,
            job_id=job.job_id,
            worker_id=worker_id,
            lease_token=job.lease_token,
            now=cast(datetime, final_now[0]),
        )
    else:
        fail_job(
            conn,
            job_id=job.job_id,
            worker_id=worker_id,
            lease_token=job.lease_token,
            now=cast(datetime, final_now[0]),
            error=error_code or "provider_unavailable",
            retryable=error_code in TRANSIENT_ERRORS,
        )
    return published


def recover_abandoned_calls(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    host_id: str,
    runtime_id: str,
    slot_fd: int,
    now: datetime,
) -> int:
    """Caller must hold this registered host's physical slot before entering."""
    require_site_transaction(conn, site_id)
    if host_id != sha256(Path("/etc/machine-id").read_bytes().strip()):
        raise PermissionError("recovery_requires_local_host")
    binding = conn.execute(
        "SELECT slot_directory FROM narrative_runtime_bindings WHERE site_id=%s "
        "AND host_id=%s AND runtime_id=%s",
        (site_id, host_id, runtime_id),
    ).fetchone()
    if binding is None:
        raise PermissionError("recovery_requires_registered_host")
    actual = os.fstat(slot_fd)
    expected = (Path(str(binding[0])) / "slot-0.lock").stat()
    if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
        raise PermissionError("recovery_slot_identity_mismatch")
    fcntl.flock(slot_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    rows = conn.execute(
        "SELECT c.call_id,c.generation_id,c.job_id,c.producing_attempt,c.producing_lease_token "
        "FROM narrative_calls c JOIN jobs j ON (j.site_id,j.job_id)=(c.site_id,c.job_id) "
        "LEFT JOIN narrative_outcomes o ON (o.site_id,o.call_id)=(c.site_id,c.call_id) "
        "WHERE c.site_id=%s AND c.host_id=%s AND c.runtime_id=%s AND o.call_id IS NULL "
        "AND j.state='running' AND j.locked_until<=%s ORDER BY j.job_id FOR UPDATE OF j",
        (site_id, host_id, runtime_id, now),
    ).fetchall()
    for call_id, generation_id, job_id, attempt, token in rows:
        conn.execute(
            "INSERT INTO narrative_outcomes(site_id,call_id,generation_id,status,"
            "error_code,provenance,finished_at) "
            "VALUES (%s,%s,%s,'abandoned_unknown','abandoned_unknown','{}',%s)",
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


def supported_generation(generation: Generation, profile: CodexProfile) -> bool:
    return supported_execution(generation.execution, profile)
