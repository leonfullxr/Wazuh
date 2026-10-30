"""Explicit-site SQL queries used only inside the workspace API repository."""

from __future__ import annotations

import ipaddress
import sys
from collections.abc import Mapping
from datetime import datetime
from typing import Any, cast

import psycopg
from psycopg import sql
from psycopg.rows import dict_row

from ai_soc.workspace.db import site_transaction


def _score_intent_job_id_sql(
    score_alias: str,
    *,
    completed_before_cutoff: bool = False,
    completed_before_now: bool = False,
) -> str:
    """Return the latest known completion for this exact recorded producer key."""
    history_bound = "AND j.completed_at <= %s " if completed_before_cutoff else ""
    current_bound = "AND j.completed_at <= statement_timestamp() " if completed_before_now else ""
    return (
        "COALESCE((SELECT max(j.job_id) FROM score_job_outputs o "
        "JOIN jobs j ON (j.site_id, j.job_id) = (o.site_id, o.job_id) "
        f"WHERE o.site_id = {score_alias}.site_id "
        f"AND o.group_id = {score_alias}.group_id "
        f"AND o.group_revision = {score_alias}.group_revision "
        f"AND o.computation_version = {score_alias}.computation_version "
        f"AND o.input_digest = {score_alias}.input_digest "
        "AND j.state = 'done' AND j.completed_at IS NOT NULL "
        f"{history_bound}{current_bound}), 0)"
    )


def _known_frozen_cutoff_sql(expression: str) -> str:
    return (
        f"CASE WHEN {expression} ~ '(Z|[+-][0-9]{{2}}:[0-9]{{2}})$' "
        f"AND pg_input_is_valid({expression}, 'timestamp with time zone') "
        f"THEN ({expression})::timestamptz END"
    )


class WorkspaceRepository:
    def __init__(self, conn: psycopg.Connection[Any], site_id: str) -> None:
        self.conn = conn
        self.site_id = site_id
        self._site_context: Any | None = None

    @classmethod
    def connect(cls, dsn: str, site_id: str) -> WorkspaceRepository:
        conn = cast(
            psycopg.Connection[Any],
            psycopg.connect(dsn),
        )
        repository = cls(conn, site_id)
        repository._site_context = site_transaction(conn, site_id, frozenset({site_id}))
        try:
            repository._site_context.__enter__()
        except Exception:
            conn.close()
            raise
        return repository

    def close(self) -> None:
        # Called from route finally blocks: preserve their exception so failed
        # domain operations roll back and successful writes await COMMIT.
        error_info = sys.exc_info()
        try:
            if self._site_context is not None:
                self._site_context.__exit__(*error_info)
        except Exception:
            if error_info[1] is None:
                raise
        finally:
            self.conn.close()

    def site(self) -> dict[str, Any] | None:
        return self._one(
            "SELECT site_id, label, wazuh_version, health, health_detail, updated_at "
            "FROM sites WHERE site_id = %s",
            (self.site_id,),
        )

    def list_alerts(
        self,
        *,
        start: datetime,
        end: datetime,
        filters: Mapping[str, object],
        sort: str,
        limit: int,
        after: tuple[datetime, str] | None,
    ) -> list[dict[str, Any]]:
        where = [
            "a.site_id = %s",
            "a.event_ts >= %s",
            "a.event_ts < %s",
            "a.normalized IS NOT NULL",
        ]
        params: list[Any] = [self.site_id, start, end]
        if filters.get("rule_id") is not None:
            where.append("a.normalized->>'rule_id' = %s")
            params.append(filters["rule_id"])
        if filters.get("min_level") is not None:
            where.append("(a.normalized->>'rule_level')::integer >= %s")
            params.append(filters["min_level"])
        if filters.get("max_level") is not None:
            where.append("(a.normalized->>'rule_level')::integer <= %s")
            params.append(filters["max_level"])
        if filters.get("agent_id") is not None:
            where.append("a.normalized->>'agent_id' = %s")
            params.append(filters["agent_id"])
        if filters.get("tactic") is not None:
            where.append("a.normalized->'mitre_tactics' ? %s")
            params.append(filters["tactic"])
        if filters.get("entity") is not None:
            kind = filters.get("entity_kind")
            value = filters.get("entity")
            if not isinstance(kind, str) or not isinstance(value, str):
                raise ValueError("cursor entity filter is invalid")
            where.append(
                "EXISTS (SELECT 1 FROM alert_entities ae "
                "JOIN entities e USING (site_id, entity_id) "
                "WHERE ae.site_id = a.site_id AND ae.alert_key = a.alert_key "
                "AND ae.event_ts = a.event_ts AND e.kind = %s AND e.value_norm = %s)"
            )
            params.extend(
                (
                    kind,
                    _query_entity_value(kind, value),
                )
            )
        op = "<" if sort == "event_ts_desc" else ">"
        if after is not None:
            where.append(f"(a.event_ts, a.alert_key) {op} (%s, %s)")
            params.extend(after)
        direction = "DESC" if sort == "event_ts_desc" else "ASC"
        params.append(limit)
        return self._all(
            "SELECT a.alert_key, a.event_ts, a.normalized FROM alerts a WHERE "
            + " AND ".join(where)
            + f" ORDER BY a.event_ts {direction}, a.alert_key {direction} LIMIT %s",
            tuple(params),
        )

    def alert(self, alert_key: str) -> dict[str, Any] | None:
        return self._one(
            "SELECT a.alert_key, a.event_ts, a.normalized, a.raw, a.normalize_gaps, "
            "a.mapping_profile, a.ingested_at FROM alerts a "
            "WHERE a.site_id = %s AND a.alert_key = %s AND a.normalized IS NOT NULL",
            (self.site_id, alert_key),
        )

    def alert_registry_state(self, alert_key: str) -> str | None:
        row = self._one(
            "SELECT CASE WHEN a.alert_key IS NULL THEN 'expired' "
            "WHEN a.normalized_at IS NULL THEN 'pending' ELSE 'retained' END AS state "
            "FROM alert_registry r LEFT JOIN alerts a "
            "ON (a.site_id, a.alert_key, a.event_ts) = "
            "(r.site_id, r.alert_key, r.original_event_ts) "
            "WHERE r.site_id = %s AND r.alert_key = %s",
            (self.site_id, alert_key),
        )
        return None if row is None else str(row["state"])

    def entities_for_alert(self, alert_key: str, event_ts: datetime) -> list[dict[str, Any]]:
        return self._all(
            "SELECT e.kind, e.value_norm, ae.role, e.first_seen, e.last_seen "
            "FROM alert_entities ae JOIN entities e USING (site_id, entity_id) "
            "WHERE ae.site_id = %s AND ae.alert_key = %s AND ae.event_ts = %s "
            "ORDER BY e.kind, e.value_norm, ae.role",
            (self.site_id, alert_key, event_ts),
        )

    def context(
        self, alert_key: str, start: datetime, end: datetime, limit: int
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        alert = self.alert(alert_key)
        if alert is None:
            return [], []
        rows = self._all(
            "SELECT DISTINCT a.alert_key, a.event_ts, a.normalized FROM alerts a "
            "JOIN alert_entities ae ON ae.site_id = a.site_id "
            "AND ae.alert_key = a.alert_key AND ae.event_ts = a.event_ts "
            "JOIN alert_entities target ON target.site_id = ae.site_id "
            "AND target.entity_id = ae.entity_id "
            "WHERE a.site_id = %s AND target.alert_key = %s AND target.event_ts = %s "
            "AND a.event_ts >= %s AND a.event_ts < %s AND a.normalized IS NOT NULL "
            "ORDER BY a.event_ts DESC, a.alert_key DESC LIMIT %s",
            (self.site_id, alert_key, alert["event_ts"], start, end, limit),
        )
        entities = self.entities_for_alert(alert_key, alert["event_ts"])
        return rows, entities

    def overview(self, start: datetime, end: datetime, now: datetime) -> dict[str, Any]:
        totals = self._one(
            "SELECT count(*) AS alerts FROM alerts WHERE site_id = %s AND event_ts >= %s "
            "AND event_ts < %s AND normalized IS NOT NULL",
            (self.site_id, start, end),
        ) or {"alerts": 0}
        # Aggregate raw rows in the requested range; this correctly clips partial edge hours.
        hourly = self._all(
            "SELECT date_trunc('hour', event_ts AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS hour, "
            "CASE WHEN (normalized->>'rule_level')::int BETWEEN 0 AND 6 THEN '0-6' "
            "WHEN (normalized->>'rule_level')::int BETWEEN 7 AND 9 THEN '7-9' "
            "WHEN (normalized->>'rule_level')::int BETWEEN 10 AND 12 THEN '10-12' "
            "WHEN (normalized->>'rule_level')::int BETWEEN 13 AND 15 THEN '13-15' "
            "ELSE 'unknown' END AS level_band, "
            "count(*)::int AS count FROM alerts WHERE site_id = %s "
            "AND event_ts >= %s AND event_ts < %s "
            "AND normalized IS NOT NULL GROUP BY 1, 2 ORDER BY 1, 2",
            (self.site_id, start, end),
        )

        def top(expr: str) -> list[dict[str, Any]]:
            return self._all(
                f"SELECT {expr} AS key, count(*)::int AS count FROM alerts WHERE site_id = %s "
                "AND event_ts >= %s AND event_ts < %s AND normalized IS NOT NULL "
                f"AND COALESCE({expr}, '') <> '' GROUP BY 1 ORDER BY count DESC, key LIMIT 10",
                (self.site_id, start, end),
            )

        rules = top("normalized->>'rule_id'")
        agents = self._all(
            "SELECT normalized->>'agent_id' AS key, "
            "max(normalized->>'agent_name') AS label, count(*)::int AS count "
            "FROM alerts WHERE site_id = %s AND event_ts >= %s AND event_ts < %s "
            "AND normalized IS NOT NULL AND COALESCE(normalized->>'agent_id', '') <> '' "
            "GROUP BY normalized->>'agent_id' ORDER BY count DESC, key LIMIT 10",
            (self.site_id, start, end),
        )
        tactics = self._all(
            "SELECT tactic AS key, count(*)::int AS count FROM alerts, "
            "LATERAL jsonb_array_elements_text(normalized->'mitre_tactics') tactic "
            "WHERE site_id = %s AND event_ts >= %s AND event_ts < %s AND normalized IS NOT NULL "
            "GROUP BY tactic ORDER BY count DESC, tactic LIMIT 10",
            (self.site_id, start, end),
        )
        ips = top("normalized->>'src_ip'")
        users = top("COALESCE(normalized->>'src_user', normalized->>'dst_user')")
        checkpoint = self._one(
            "SELECT min(checkpoint_ts) AS checkpoint_at, min(updated_at) AS oldest_updated_at, "
            "count(*)::int AS source_count FROM checkpoints WHERE site_id = %s",
            (self.site_id,),
        )
        success = self._one(
            "SELECT max(finished_at) AS last_success_at FROM pipeline_runs WHERE site_id = %s "
            "AND kind = 'poll' AND outcome = 'ok'",
            (self.site_id,),
        )
        mismatch = self._reconciliation_summary(now)
        return {
            "totals": totals,
            "hourly": hourly,
            "rules": rules,
            "agents": agents,
            "tactics": tactics,
            "ips": ips,
            "users": users,
            "checkpoint": checkpoint,
            "success": success,
            "mismatch": mismatch,
        }

    def health(self, now: datetime) -> dict[str, Any]:
        checkpoint = self._one(
            "SELECT min(checkpoint_ts) AS at, min(updated_at) AS oldest_updated_at, "
            "count(*)::int AS source_count FROM checkpoints WHERE site_id = %s",
            (self.site_id,),
        )
        run = self._one(
            "SELECT run_id, kind, started_at, finished_at, outcome, error_code, pipeline_version, "
            "read_count, inserted_count, duplicate_count, window_from, window_to "
            "FROM pipeline_runs WHERE site_id = %s "
            "AND kind = 'poll' AND outcome = 'ok' AND finished_at IS NOT NULL "
            "ORDER BY finished_at DESC, run_id DESC LIMIT 1",
            (self.site_id,),
        )
        last = self._one(
            "SELECT max(finished_at) AS at FROM pipeline_runs "
            "WHERE site_id = %s AND kind = 'poll' AND outcome = 'ok'",
            (self.site_id,),
        )
        reconciliation = self._reconciliation_summary(now)
        normalized = (
            self._one(
                "SELECT count(*)::int AS normalized FROM alert_registry r JOIN alerts a "
                "ON (a.site_id, a.alert_key, a.event_ts) = "
                "(r.site_id, r.alert_key, r.original_event_ts) "
                "WHERE r.site_id = %s AND a.normalized_at IS NOT NULL "
                "AND r.original_event_ts >= %s AND r.original_event_ts < %s",
                (self.site_id, run["window_from"], run["window_to"]),
            )
            if run and run["window_from"] and run["window_to"]
            else {"normalized": 0}
        )
        return {
            "checkpoint": checkpoint,
            "run": run,
            "last": last,
            "reconciliation": reconciliation,
            "normalized": int((normalized or {}).get("normalized", 0)),
        }

    def queue_rows(
        self,
        *,
        filters: Mapping[str, object],
        sort: str,
        limit: int,
        after: tuple[Any, ...] | None,
    ) -> list[dict[str, Any]]:
        where = ["gh.site_id = %s"]
        params: list[Any] = [self.site_id]
        if filters.get("from") is not None:
            value = filters["from"]
            if not isinstance(value, str | datetime):
                raise ValueError("cursor start time is invalid")
            where.append("gr.first_ts >= %s")
            params.append(datetime.fromisoformat(value) if isinstance(value, str) else value)
        if filters.get("to") is not None:
            value = filters["to"]
            if not isinstance(value, str | datetime):
                raise ValueError("cursor end time is invalid")
            where.append("gr.first_ts < %s")
            params.append(datetime.fromisoformat(value) if isinstance(value, str) else value)
        if filters.get("min_score") is not None:
            where.append("coalesce(s.total, 0) >= %s")
            params.append(filters["min_score"])
        if filters.get("max_score") is not None:
            where.append("coalesce(s.total, 0) <= %s")
            params.append(filters["max_score"])
        if filters.get("status"):
            where.append("w.status = ANY(%s)")
            params.append(filters["status"])
        if filters.get("owner_key") is not None:
            where.append("w.owner_key = %s")
            params.append(filters["owner_key"])
        elif filters.get("unassigned"):
            where.append("w.owner_key IS NULL")
        if filters.get("rule_id") is not None:
            where.append("gr.rule_id = %s")
            params.append(filters["rule_id"])
        if filters.get("entity") is not None:
            kind, entity_value = filters.get("entity_kind"), filters.get("entity")
            if not isinstance(kind, str) or not isinstance(entity_value, str):
                raise ValueError("cursor entity filter is invalid")
            where.append("gr.primary_entity = %s")
            canonical_value = _query_entity_value(kind, entity_value)
            params.append(f"{kind}:{canonical_value}")
        if after is not None:
            if sort == "priority_desc":
                where.append(
                    "(coalesce(s.total, 0) < %s OR "
                    "(coalesce(s.total, 0) = %s AND gh.group_id > %s))"
                )
                params.extend((after[0], after[0], after[1]))
            elif sort == "last_ts_desc":
                where.append("(gr.last_ts < %s OR (gr.last_ts = %s AND gh.group_id > %s))")
                params.extend((after[0], after[0], after[1]))
            else:
                where.append("(gr.first_ts, gh.group_id) > (%s, %s)")
                params.extend(after)
        order = {
            "priority_desc": "coalesce(s.total, 0) DESC, gh.group_id ASC",
            "last_ts_desc": "gr.last_ts DESC, gh.group_id ASC",
            "first_ts_asc": "gr.first_ts ASC, gh.group_id ASC",
        }[sort]
        params.append(limit)
        return self._all(
            "SELECT gh.group_id, gh.current_revision AS revision, gr.title, gr.alert_count, "
            "gr.first_ts, gr.last_ts, gr.rule_id, gr.primary_entity, gr.pipeline_version, "
            "pe.first_seen AS primary_first_seen, pe.last_seen AS primary_last_seen, "
            "s.total, s.computation_version, s.input_digest, s.components, "
            "w.status, w.owner_key, w.updated_at, d.disposition_id, d.label, d.reason_code, "
            "d.note, d.actor_key, d.at AS disposition_at, d.propagate_to_members "
            "FROM group_heads gh JOIN group_revisions gr ON (gr.site_id, gr.group_id, gr.revision) "
            "= (gh.site_id, gh.group_id, gh.current_revision) "
            "JOIN work_items w ON (w.site_id, w.group_id) = (gh.site_id, gh.group_id) "
            "LEFT JOIN entities pe ON pe.site_id = gh.site_id "
            "AND pe.kind = split_part(gr.primary_entity, ':', 1) "
            "AND pe.value_norm = substring(gr.primary_entity from "
            "length(split_part(gr.primary_entity, ':', 1)) + 2) "
            "LEFT JOIN LATERAL (SELECT sx.*, "
            + _score_intent_job_id_sql("sx", completed_before_now=True)
            + " AS intent_job_id FROM scores sx JOIN score_manifests sm "
            "USING (site_id, group_id, group_revision, computation_version, input_digest) "
            "WHERE sx.site_id = gh.site_id "
            "AND sx.group_id = gh.group_id AND sx.group_revision = gh.current_revision "
            "AND sx.computed_at <= statement_timestamp() "
            "AND "
            + _known_frozen_cutoff_sql("sm.manifest->>'as_of'")
            + " <= statement_timestamp() AND "
            + _score_intent_job_id_sql("sx", completed_before_now=True)
            + " > 0 "
            "ORDER BY "
            + _known_frozen_cutoff_sql("sm.manifest->>'as_of'")
            + " DESC, intent_job_id DESC, "
            "sx.computed_at DESC, "
            "sx.computation_version DESC, sx.input_digest DESC LIMIT 1) s ON true "
            "LEFT JOIN LATERAL (SELECT * FROM dispositions dx WHERE dx.site_id = gh.site_id "
            "AND dx.group_id = gh.group_id ORDER BY dx.at DESC, dx.disposition_id DESC "
            "LIMIT 1) d ON true "
            "WHERE " + " AND ".join(where) + f" ORDER BY {order} LIMIT %s",
            tuple(params),
        )

    def group_detail(self, group_id: str) -> dict[str, Any] | None:
        rows = self._all(
            "SELECT gh.group_id, gh.current_revision AS revision, gr.title, gr.alert_count, "
            "gr.first_ts, gr.last_ts, gr.rule_id, gr.primary_entity, gr.pipeline_version, "
            "pe.first_seen AS primary_first_seen, pe.last_seen AS primary_last_seen, "
            "s.total, s.computation_version, s.input_digest, s.components, "
            "w.status, w.owner_key, w.updated_at, d.disposition_id, d.label, d.reason_code, "
            "d.note, d.actor_key, d.at AS disposition_at, d.propagate_to_members "
            "FROM group_heads gh JOIN group_revisions gr ON (gr.site_id, gr.group_id, gr.revision) "
            "= (gh.site_id, gh.group_id, gh.current_revision) "
            "JOIN work_items w ON (w.site_id, w.group_id) = (gh.site_id, gh.group_id) "
            "LEFT JOIN entities pe ON pe.site_id = gh.site_id "
            "AND pe.kind = split_part(gr.primary_entity, ':', 1) "
            "AND pe.value_norm = substring(gr.primary_entity from "
            "length(split_part(gr.primary_entity, ':', 1)) + 2) "
            "LEFT JOIN LATERAL (SELECT sx.*, "
            + _score_intent_job_id_sql("sx", completed_before_now=True)
            + " AS intent_job_id FROM scores sx JOIN score_manifests sm "
            "USING (site_id, group_id, group_revision, computation_version, input_digest) "
            "WHERE sx.site_id = gh.site_id "
            "AND sx.group_id = gh.group_id AND sx.group_revision = gh.current_revision "
            "AND sx.computed_at <= statement_timestamp() "
            "AND "
            + _known_frozen_cutoff_sql("sm.manifest->>'as_of'")
            + " <= statement_timestamp() AND "
            + _score_intent_job_id_sql("sx", completed_before_now=True)
            + " > 0 "
            "ORDER BY "
            + _known_frozen_cutoff_sql("sm.manifest->>'as_of'")
            + " DESC, intent_job_id DESC, "
            "sx.computed_at DESC, "
            "sx.computation_version DESC, sx.input_digest DESC LIMIT 1) s ON true "
            "LEFT JOIN LATERAL (SELECT * FROM dispositions dx WHERE dx.site_id = gh.site_id "
            "AND dx.group_id = gh.group_id ORDER BY dx.at DESC, dx.disposition_id DESC "
            "LIMIT 1) d ON true "
            "WHERE gh.site_id = %s AND gh.group_id = %s",
            (self.site_id, group_id),
        )
        return rows[0] if rows else None

    def group_members(
        self, group_id: str, limit: int, after: tuple[datetime, str] | None
    ) -> list[dict[str, Any]]:
        params: list[Any] = [self.site_id, group_id]
        keyset = ""
        if after is not None:
            keyset = "AND (event_ts, alert_key) > (%s, %s) "
            params.extend(after)
        params.extend((self.site_id, group_id, limit))
        return self._all(
            "SELECT alert_key, event_ts, normalized_snapshot AS normalized "
            "FROM group_members WHERE site_id = %s AND group_id = %s "
            + keyset
            + "AND group_revision = (SELECT current_revision FROM group_heads "
            "WHERE site_id = %s AND group_id = %s) "
            "ORDER BY event_ts, alert_key LIMIT %s",
            tuple(params),
        )

    def group_extras(self, group_id: str) -> dict[str, list[dict[str, Any]]]:
        revision = self._one(
            "SELECT current_revision FROM group_heads WHERE site_id = %s AND group_id = %s",
            (self.site_id, group_id),
        )
        if revision is None:
            return {"enrichments": [], "history": []}
        current_revision = revision["current_revision"]
        enrichments = self._all(
            "SELECT enrichment_id::text AS enrichment_id, source, source_version, value, "
            "fetched_at, expires_at "
            "FROM enrichments WHERE site_id = %s AND group_id = %s AND group_revision = %s "
            "ORDER BY source, fetched_at DESC, enrichment_id",
            (self.site_id, group_id, current_revision),
        )
        history = self._all(
            "SELECT at, actor_key, action, before_value AS before, after_value AS after "
            "FROM work_history WHERE site_id = %s AND group_id = %s ORDER BY at, history_id",
            (self.site_id, group_id),
        )
        return {"enrichments": enrichments, "history": history}

    def list_asset_tags(
        self, *, kind: str | None, query: str | None, limit: int, after: tuple[Any, ...] | None
    ) -> list[dict[str, Any]]:
        where = [
            "e.site_id = %s",
            "e.kind = 'host'",
            "(t.entity_id IS NOT NULL OR EXISTS (SELECT 1 FROM alerts a "
            "WHERE a.site_id = e.site_id AND a.normalized_at IS NOT NULL "
            "AND lower(a.normalized->>'agent_id') = e.value_norm))",
        ]
        params: list[Any] = [self.site_id]
        if kind is not None:
            where.append("e.kind = %s")
            params.append(kind)
        if query is not None:
            where.append("e.value_norm ILIKE %s")
            params.append("%" + query.replace("%", "\\%").replace("_", "\\_") + "%")
        if after is not None:
            where.append("(e.kind, e.value_norm, e.entity_id) > (%s, %s, %s)")
            params.extend(after)
        params.append(limit)
        return self._all(
            "SELECT e.entity_id, e.kind, e.value_norm, coalesce(t.criticality,0) AS criticality, "
            "coalesce(t.tags,ARRAY[]::text[]) AS tags, t.set_by, t.set_at "
            "FROM entities e LEFT JOIN LATERAL (SELECT * FROM asset_tags latest "
            "WHERE latest.site_id=e.site_id AND latest.entity_id=e.entity_id "
            "ORDER BY latest.revision DESC LIMIT 1) t ON true "
            "WHERE " + " AND ".join(where) + " ORDER BY e.kind, e.value_norm, e.entity_id LIMIT %s",
            tuple(params),
        )

    def entity_identity(self, entity_id: int) -> dict[str, Any] | None:
        return self._one(
            "SELECT kind, value_norm FROM entities WHERE site_id = %s AND entity_id = %s",
            (self.site_id, entity_id),
        )

    def alert_volume(self, *, from_: datetime, to: datetime, bucket: str) -> list[dict[str, Any]]:
        return self._all(
            "SELECT date_trunc(%s, event_ts AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS hour, "
            "CASE WHEN (normalized->>'rule_level')::int BETWEEN 0 AND 6 THEN '0-6' "
            "WHEN (normalized->>'rule_level')::int BETWEEN 7 AND 9 THEN '7-9' "
            "WHEN (normalized->>'rule_level')::int BETWEEN 10 AND 12 THEN '10-12' "
            "WHEN (normalized->>'rule_level')::int BETWEEN 13 AND 15 THEN '13-15' "
            "ELSE 'unknown' END AS band, count(*)::int AS count FROM alerts "
            "WHERE site_id = %s AND event_ts >= %s AND event_ts < %s "
            "AND normalized IS NOT NULL GROUP BY 1,2 ORDER BY 1,2",
            (bucket, self.site_id, from_, to),
        )

    def precision_at_k(
        self,
        from_: datetime,
        to: datetime,
        now: datetime,
        *,
        rule_id: str | None,
    ) -> list[dict[str, Any]]:
        return self._all(
            "WITH current_revisions AS (SELECT DISTINCT ON (gr.group_id) gr.group_id, "
            "gr.revision, gr.rule_id, gr.first_ts FROM group_revisions gr "
            "WHERE gr.site_id = %s AND gr.created_at <= %s "
            "ORDER BY gr.group_id, gr.created_at DESC, gr.revision DESC), "
            "current_groups AS (SELECT group_id, revision, rule_id FROM current_revisions "
            "WHERE first_ts >= %s AND first_ts < %s "
            "AND (%s::text IS NULL OR rule_id = %s::text)), "
            "score_candidates AS (SELECT s.group_id, s.total, "
            + _score_intent_job_id_sql("s", completed_before_cutoff=True, completed_before_now=True)
            + " AS intent_job_id, (sm.manifest->>'as_of')::timestamptz AS frozen_as_of, "
            "s.computed_at, s.computation_version, s.input_digest "
            "FROM current_groups g JOIN scores s ON s.site_id = %s "
            "AND s.group_id = g.group_id AND s.group_revision = g.revision "
            "JOIN score_manifests sm ON "
            "(sm.site_id, sm.group_id, sm.group_revision, sm.computation_version, sm.input_digest) "
            "= (s.site_id, s.group_id, s.group_revision, s.computation_version, s.input_digest) "
            "WHERE s.computed_at <= %s AND "
            + _known_frozen_cutoff_sql("sm.manifest->>'as_of'")
            + " <= %s AND s.computed_at <= statement_timestamp() AND "
            + _known_frozen_cutoff_sql("sm.manifest->>'as_of'")
            + " <= statement_timestamp()), "
            "ranked AS (SELECT DISTINCT ON (candidate.group_id) candidate.group_id, "
            "candidate.total, candidate.intent_job_id FROM score_candidates candidate "
            "WHERE candidate.intent_job_id > 0 "
            "ORDER BY candidate.group_id, candidate.frozen_as_of DESC, "
            "candidate.intent_job_id DESC, candidate.computed_at DESC, "
            "candidate.computation_version DESC, candidate.input_digest DESC), "
            "labels AS (SELECT DISTINCT ON (d.group_id) d.group_id, d.label FROM dispositions d "
            "WHERE d.site_id = %s AND d.at <= %s ORDER BY d.group_id, d.at DESC, "
            "d.disposition_id DESC), "
            "ordered AS (SELECT r.group_id, l.label, row_number() OVER "
            "(ORDER BY r.total DESC, r.group_id) AS rank "
            "FROM ranked r LEFT JOIN labels l USING (group_id)) "
            "SELECT k.k, count(*) FILTER "
            "(WHERE o.label IN ('true_positive','benign_true_positive'))::int AS relevant, "
            "count(*) FILTER (WHERE o.label IS NOT NULL AND o.label <> 'undetermined')::int "
            "AS labelled "
            "FROM (VALUES (1),(5),(10),(20)) AS k(k) LEFT JOIN ordered o ON o.rank <= k.k "
            "GROUP BY k.k ORDER BY k.k",
            (
                self.site_id,
                to,
                from_,
                to,
                rule_id,
                rule_id,
                to,
                self.site_id,
                to,
                to,
                self.site_id,
                to,
            ),
        )

    def _reconciliation_summary(self, now: datetime) -> dict[str, Any]:
        return self._one(
            "WITH latest AS (SELECT DISTINCT ON (r.site_id, r.index_pattern, r.hour) "
            "r.index_pattern, r.hour, r.alarm, r.checked_at FROM alert_reconciliation r "
            "JOIN pipeline_runs p ON (p.site_id, p.run_id) = (r.site_id, r.run_id) "
            "WHERE r.site_id = %s AND p.finished_at IS NOT NULL AND p.outcome IN ('ok','partial') "
            "AND r.hour >= date_trunc('hour', %s - interval '48 hours') "
            "AND r.hour < date_trunc('hour', %s) "
            "ORDER BY r.site_id, r.index_pattern, r.hour, p.finished_at DESC, p.run_id DESC) "
            "SELECT count(*)::int AS checked, count(*) FILTER (WHERE alarm)::int AS mismatched, "
            "max(checked_at) AS last_checked FROM latest",
            (self.site_id, now, now),
        ) or {"checked": 0, "mismatched": 0, "last_checked": None}

    def _one(self, query: str, params: tuple[Any, ...]) -> dict[str, Any] | None:
        with self.conn.cursor(row_factory=dict_row) as cursor:
            cursor.execute(sql.SQL(cast(Any, query)), params)
            row = cursor.fetchone()
        return row

    def _all(self, query: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        with self.conn.cursor(row_factory=dict_row) as cursor:
            cursor.execute(sql.SQL(cast(Any, query)), params)
            return list(cursor.fetchall())


def _query_entity_value(kind: str, value: str) -> str:
    normalized = _canonical_entity_value(kind, value)
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError:
            # Match the normalizer's preserved value when the input is not an IP.
            return normalized
    return normalized


def _canonical_entity_value(kind: str, value: str) -> str:
    if kind in {"host", "user", "process", "file", "hash", "rule_group"}:
        return value.casefold()
    if kind == "cve":
        return value.upper()
    return value
