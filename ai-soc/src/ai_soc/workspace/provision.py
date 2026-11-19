"""Provision a restricted workspace runtime role on an existing connection."""

from typing import Any

import psycopg
from psycopg import sql

from ai_soc.workspace.db import RUNTIME_SEQUENCES, RUNTIME_TABLES

TABLES = RUNTIME_TABLES


class ProvisioningError(RuntimeError):
    """The existing role cannot be safely reused as the workspace runtime role."""


def _assert_existing_role_is_safe(conn: psycopg.Connection[Any], role: str) -> None:
    with conn.cursor() as cursor:
        cursor.execute(
            """
            SELECT
                r.rolsuper OR r.rolbypassrls OR r.rolcreatedb OR
                    r.rolcreaterole OR r.rolreplication,
                EXISTS (SELECT 1 FROM pg_auth_members AS m WHERE m.member = r.oid),
                EXISTS (SELECT 1 FROM pg_database AS d WHERE d.datdba = r.oid),
                EXISTS (SELECT 1 FROM pg_namespace AS n WHERE n.nspowner = r.oid),
                EXISTS (SELECT 1 FROM pg_class AS c WHERE c.relowner = r.oid),
                EXISTS (SELECT 1 FROM pg_proc AS p WHERE p.proowner = r.oid),
                EXISTS (SELECT 1 FROM pg_type AS t WHERE t.typowner = r.oid),
                has_database_privilege(r.oid, current_database(), 'CREATE'),
                EXISTS (
                    SELECT 1 FROM pg_namespace AS n
                    WHERE has_schema_privilege(r.oid, n.oid, 'CREATE')
                ),
                EXISTS (
                    SELECT 1 FROM pg_class AS c
                    JOIN pg_namespace AS n ON n.oid = c.relnamespace
                    WHERE c.relkind = 'S'
                      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
                      AND NOT (n.nspname = 'public' AND c.relname = ANY(%s))
                      AND (has_sequence_privilege(r.oid, c.oid, 'USAGE')
                           OR has_sequence_privilege(r.oid, c.oid, 'SELECT')
                           OR has_sequence_privilege(r.oid, c.oid, 'UPDATE'))
                ),
                EXISTS (
                    SELECT 1 FROM pg_proc AS p
                    JOIN pg_namespace AS n ON n.oid = p.pronamespace
                    WHERE p.prosecdef
                      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
                      AND has_schema_privilege(r.oid, n.oid, 'USAGE')
                      AND has_function_privilege(r.oid, p.oid, 'EXECUTE')
                ),
                EXISTS (
                    SELECT 1
                    FROM pg_class AS c
                    JOIN pg_namespace AS n ON n.oid = c.relnamespace
                    WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
                      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
                      AND (
                          has_table_privilege(r.oid, c.oid, 'SELECT')
                          OR has_table_privilege(r.oid, c.oid, 'INSERT')
                          OR has_table_privilege(r.oid, c.oid, 'UPDATE')
                          OR has_table_privilege(r.oid, c.oid, 'DELETE')
                          OR has_table_privilege(r.oid, c.oid, 'TRUNCATE')
                          OR has_table_privilege(r.oid, c.oid, 'REFERENCES')
                          OR has_table_privilege(r.oid, c.oid, 'TRIGGER')
                      )
                      AND NOT (
                          n.nspname = 'public'
                          AND ((c.relname = ANY(%s)
                                AND NOT (has_table_privilege(r.oid, c.oid, 'TRUNCATE')
                                         OR has_table_privilege(r.oid, c.oid, 'REFERENCES')
                                         OR has_table_privilege(r.oid, c.oid, 'TRIGGER')))
                               OR (c.relname = 'audit_outbox'
                                   AND NOT (has_table_privilege(r.oid, c.oid, 'DELETE')
                                            OR has_table_privilege(r.oid, c.oid, 'TRUNCATE')
                                            OR has_table_privilege(r.oid, c.oid, 'REFERENCES')
                                            OR has_table_privilege(r.oid, c.oid, 'TRIGGER'))))
                      )
                )
            FROM pg_roles AS r
            WHERE r.rolname = %s
            """,
            (list(RUNTIME_SEQUENCES), [table for table in TABLES if table != "audit_outbox"], role),
        )
        row = cursor.fetchone()
    if row is None:
        return
    names = (
        "elevated role attributes",
        "role memberships",
        "database ownership",
        "schema ownership",
        "relation ownership",
        "function ownership",
        "type ownership",
        "database CREATE privilege",
        "schema CREATE privilege",
        "unrelated sequence privileges",
        "reachable SECURITY DEFINER functions",
        "unrelated relation privileges",
    )
    unsafe = [name for name, present in zip(names, row, strict=True) if bool(present)]
    if unsafe:
        raise ProvisioningError(f"existing role has unsafe privileges: {', '.join(unsafe)}")


def provision_runtime_role(conn: psycopg.Connection[Any], *, role: str, password: str) -> None:
    """Provision the role within the caller-owned transaction."""
    conn.execute("SELECT pg_advisory_xact_lock(%s)", (0x4159534F43524F4C,))
    with conn.cursor() as cursor:
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,))
        exists = cursor.fetchone() is not None
    if not exists:
        conn.execute(sql.SQL("CREATE ROLE {} LOGIN").format(sql.Identifier(role)))
    else:
        _assert_existing_role_is_safe(conn, role)
    conn.execute(
        sql.SQL(
            "ALTER ROLE {} WITH LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "NOREPLICATION NOBYPASSRLS PASSWORD {}"
        ).format(sql.Identifier(role), sql.Literal(password))
    )
    conn.execute(sql.SQL("ALTER ROLE {} SET search_path TO public").format(sql.Identifier(role)))
    conn.execute(
        sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
            sql.Identifier(conn.info.dbname or "ai_soc_workspace"),
            sql.Identifier(role),
        )
    )
    conn.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(role)))
    for table in TABLES:
        privileges = (
            "SELECT, INSERT, UPDATE"
            if table == "audit_outbox"
            else "SELECT, INSERT, UPDATE, DELETE"
        )
        conn.execute(
            sql.SQL("GRANT {} ON TABLE {} TO {}").format(
                sql.SQL(privileges), sql.Identifier(table), sql.Identifier(role)
            )
        )
    for sequence in RUNTIME_SEQUENCES:
        conn.execute(
            sql.SQL("GRANT USAGE, SELECT, UPDATE ON SEQUENCE {} TO {}").format(
                sql.Identifier(sequence), sql.Identifier(role)
            )
        )
