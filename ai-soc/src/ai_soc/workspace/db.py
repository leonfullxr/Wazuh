"""Transaction helpers for tenant-scoped workspace queries."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import psycopg
from psycopg.pq import TransactionStatus

RUNTIME_TABLES = (
    "sites",
    "checkpoints",
    "pipeline_runs",
    "jobs",
    "audit_outbox",
    "alert_sources",
    "alert_registry",
    "alert_mutations",
    "alerts",
    "alert_hourly",
    "entities",
    "alert_entities",
    "alert_reconciliation",
    "subject_registry",
    "groups",
    "group_revisions",
    "group_members",
    "group_heads",
    "enrichments",
    "score_manifests",
    "scores",
    "score_job_outputs",
    "work_items",
    "work_history",
    "dispositions",
    "workspace_idempotency",
    "asset_tags",
    "asset_tag_history",
    "correlation_source_projections",
    "correlation_manifests",
    "correlation_input_groups",
    "correlation_input_members",
    "correlation_edges",
    "correlation_chains",
    "correlation_chain_revisions",
    "correlation_stage_evidence",
    "correlation_heads",
    "correlation_decisions",
    "correlation_decision_history",
    "correlation_publication_intents",
    "correlation_requests",
    "incidents",
    "incident_membership_intervals",
    "incident_evidence_revisions",
    "incident_revision_members",
    "incident_history",
    "incident_comments",
    "incident_dispositions",
    "narrative_runtime_bindings",
    "narrative_generations",
    "narrative_calls",
    "narrative_outcomes",
    "incident_narrative_heads",
)
RUNTIME_SEQUENCES = (
    "jobs_job_id_seq",
    "alert_mutations_mutation_id_seq",
    "entities_entity_id_seq",
    "correlation_publication_intents_intent_seq_seq",
)


def _validate_runtime_role(conn: psycopg.Connection[Any]) -> None:
    with conn.cursor() as cursor:
        cursor.execute(
            """
            SELECT r.rolsuper, r.rolbypassrls, r.rolcreatedb, r.rolcreaterole, r.rolreplication,
                   EXISTS (SELECT 1 FROM pg_auth_members AS m WHERE m.member = r.oid),
                   has_database_privilege(r.oid, current_database(), 'CREATE'),
                   EXISTS (
                       SELECT 1 FROM pg_namespace AS n
                       WHERE n.nspname = ANY(current_schemas(true))
                         AND has_schema_privilege(r.oid, n.oid, 'CREATE')
                   ),
                   EXISTS (
                       SELECT 1 FROM pg_database AS d WHERE d.datname = current_database()
                         AND d.datdba = r.oid
                   ),
                   EXISTS (
                       SELECT 1 FROM pg_type AS t WHERE t.typowner = r.oid
                   ),
                   EXISTS (
                       SELECT 1
                       FROM pg_class AS c
                       JOIN pg_namespace AS n ON n.oid = c.relnamespace
                       WHERE n.nspname = 'public'
                         AND c.relname = ANY(%s)
                         AND c.relowner = r.oid
                   )
                   ,EXISTS (
                       SELECT 1 FROM pg_namespace AS n
                       WHERE n.nspname = ANY(current_schemas(true)) AND n.nspowner = r.oid
                   )
                   ,EXISTS (
                       SELECT 1 FROM pg_proc AS p
                       JOIN pg_namespace AS n ON n.oid = p.pronamespace
                       WHERE p.prosecdef
                         AND n.nspname NOT IN ('pg_catalog', 'information_schema')
                         AND has_schema_privilege(r.oid, n.oid, 'USAGE')
                         AND has_function_privilege(r.oid, p.oid, 'EXECUTE')
                   )
                   ,EXISTS (
                       SELECT 1 FROM pg_class AS c
                       JOIN pg_namespace AS n ON n.oid = c.relnamespace
                       WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
                             AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
                         AND NOT (n.nspname = 'public' AND c.relname = ANY(%s))
                         AND (
                             has_table_privilege(r.oid, c.oid, 'SELECT')
                             OR has_table_privilege(r.oid, c.oid, 'INSERT')
                             OR has_table_privilege(r.oid, c.oid, 'UPDATE')
                             OR has_table_privilege(r.oid, c.oid, 'DELETE')
                             OR has_table_privilege(r.oid, c.oid, 'TRUNCATE')
                             OR has_table_privilege(r.oid, c.oid, 'REFERENCES')
                             OR has_table_privilege(r.oid, c.oid, 'TRIGGER')
                         )
                   )
                   ,EXISTS (
                       SELECT 1 FROM pg_class AS c
                       JOIN pg_namespace AS n ON n.oid = c.relnamespace
                       WHERE c.relkind = 'S'
                         AND NOT (n.nspname = 'public' AND c.relname = ANY(%s))
                         AND (has_sequence_privilege(r.oid, c.oid, 'USAGE')
                              OR has_sequence_privilege(r.oid, c.oid, 'SELECT')
                              OR has_sequence_privilege(r.oid, c.oid, 'UPDATE'))
                   )
                   ,current_schemas(false) <> ARRAY['public']::name[]
                   ,EXISTS (
                       SELECT 1 FROM pg_class AS c
                       JOIN pg_namespace AS n ON n.oid = c.relnamespace
                       WHERE n.nspname = 'public' AND c.relname = ANY(%s)
                         AND (has_table_privilege(r.oid, c.oid, 'TRUNCATE')
                              OR has_table_privilege(r.oid, c.oid, 'REFERENCES')
                              OR has_table_privilege(r.oid, c.oid, 'TRIGGER')
                              OR (c.relname = 'audit_outbox'
                                  AND has_table_privilege(r.oid, c.oid, 'DELETE')))
                   )
            FROM pg_roles AS r
            WHERE r.rolname = current_user
            """,
            (
                list(RUNTIME_TABLES),
                list(RUNTIME_TABLES),
                list(RUNTIME_SEQUENCES),
                list(RUNTIME_TABLES),
            ),
        )
        row = cursor.fetchone()
    if row is None or any(bool(value) for value in row):
        raise PermissionError(
            "workspace queries require a clean, non-escalating runtime role and public search path"
        )


def require_site_transaction(conn: psycopg.Connection[Any], site_id: str) -> None:
    """Reject idle, mismatched and unknown tenants before domain reads or writes."""
    if conn.info.transaction_status is TransactionStatus.IDLE:
        raise PermissionError("correlation operation requires an active site transaction")
    row = conn.execute(
        "SELECT current_setting('app.site_id', true), "
        "EXISTS (SELECT 1 FROM sites WHERE site_id=%s)",
        (site_id,),
    ).fetchone()
    if row is None or row[0] != site_id or not row[1]:
        raise PermissionError("correlation operation requires an active known site transaction")


@contextmanager
def site_transaction(
    conn: psycopg.Connection[Any],
    site_id: str,
    authorized_sites: frozenset[str],
    *,
    readonly: bool = False,
    repeatable_read: bool = False,
) -> Iterator[psycopg.Connection[Any]]:
    """Run a transaction with one authorized site in transaction-local RLS context."""
    if not site_id or site_id not in authorized_sites:
        raise PermissionError("site is not authorized")
    if conn.info.transaction_status is TransactionStatus.IDLE:
        previous_site: str | None = None
    else:
        with conn.cursor() as cursor:
            cursor.execute("SELECT current_setting('app.site_id', true)")
            row = cursor.fetchone()
        previous_site = None if row is None else row[0]
        if previous_site not in (None, "", site_id):
            raise RuntimeError("nested site transactions cannot change the active site")
    with conn.transaction():
        if readonly or repeatable_read:
            mode = "READ ONLY" if readonly else "READ WRITE"
            isolation = "REPEATABLE READ" if repeatable_read else "READ COMMITTED"
            conn.execute(f"SET TRANSACTION ISOLATION LEVEL {isolation} {mode}")
        _validate_runtime_role(conn)
        with conn.cursor() as cursor:
            cursor.execute("SELECT current_setting('app.site_id', true)")
            row = cursor.fetchone()
        previous = None if row is None else row[0]
        conn.execute("SELECT set_config('app.site_id', %s, true)", (site_id,))
        yield conn
        conn.execute("SELECT set_config('app.site_id', %s, true)", (previous or "",))
