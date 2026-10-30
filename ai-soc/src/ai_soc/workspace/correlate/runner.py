"""Frozen-input construction and lease-bound deterministic correlation execution."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import UUID

import psycopg

from ai_soc.workspace.correlate.chains import evaluate_chain, load_chain_rule, parse_chain_rule
from ai_soc.workspace.correlate.edges import build_edges
from ai_soc.workspace.correlate.models import (
    ChainRule,
    CorrelationGroup,
    CorrelationInput,
    CorrelationObservation,
)
from ai_soc.workspace.correlate.repository import (
    enqueue_correlation,
    freeze_manifest,
    load_manifest,
    persist_results,
)
from ai_soc.workspace.correlate.scheduling import correlation_savepoint, identity
from ai_soc.workspace.correlate.sources import project_retained_sources
from ai_soc.workspace.db import require_site_transaction
from ai_soc.workspace.jobs import Job
from ai_soc.workspace.triage.score_selection import select_score_references

ROOT = Path(__file__).resolve().parents[4]
RULE_PATH = ROOT / "content/workspace/chains/linux.ssh_bruteforce_to_persistence.yaml"
MAX_GROUPS = 512
MAX_OBSERVATIONS = 100_000
HASH_PATTERN = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")


def correlation_code_identity() -> str:
    digest = hashlib.sha256()
    base = Path(__file__).parent
    dependencies = (
        *base.glob("*.py"),
        base.parent / "triage/score_selection.py",
        base.parent / "api/repository.py",
    )
    for path in sorted(dependencies):
        digest.update(path.relative_to(base.parent).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


CORRELATION_JOB_KINDS = frozenset({"prepare_correlation", "correlate_window"})
ANCHOR_COVERAGE = "full-before-rule-window; recent-anchor-results-are-partial"


def build_correlation_config(*, rule: ChainRule, code_identity: str) -> dict[str, str]:
    """Retain the exact policy bytes with the supported evaluator and live intake."""
    if rule.source_yaml is None:
        raise ValueError("correlation configuration requires retained policy bytes")
    config = {
        "rule_digest": rule.content_digest,
        "rule_source_yaml": rule.source_yaml,
        "code_identity": code_identity,
        "intake_hours": "12",
        "classifier_window_seconds": str(rule.window_seconds),
        "anchor_coverage": ANCHOR_COVERAGE,
    }
    rule_from_config(config)
    return config


def rule_from_config(config: object, *, supported_code: str | None = None) -> ChainRule:
    if not isinstance(config, dict):
        raise ValueError("correlation configuration must retain an exact policy")
    values = cast(dict[str, object], config)
    source = values.get("rule_source_yaml")
    if not isinstance(source, str):
        raise ValueError("correlation configuration requires rule_source_yaml")
    rule = parse_chain_rule(source.encode("utf-8"))
    if (
        values.get("rule_digest") != rule.content_digest
        or values.get("intake_hours") != "12"
        or values.get("classifier_window_seconds") != str(rule.window_seconds)
        or values.get("anchor_coverage") != ANCHOR_COVERAGE
    ):
        raise ValueError("correlation configuration differs from its retained policy or intake")
    code = values.get("code_identity")
    if not isinstance(code, str) or not code or len(code) > 256:
        raise ValueError("correlation configuration requires a code identity")
    if supported_code is not None and code != supported_code:
        raise ValueError("pinned correlation code identity is unavailable")
    return rule


@correlation_savepoint
def build_frozen_inputs(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    start: datetime,
    end: datetime,
    as_of: datetime,
    computation_version: str,
) -> CorrelationInput:
    """Pin bounded current head revisions and every retained member in a half-open window."""
    require_site_transaction(conn, site_id)
    for value, label in ((start, "start"), (end, "end"), (as_of, "as_of")):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(f"{label} must be timezone-aware")
    if not start < end <= as_of or end - start > timedelta(hours=48):
        raise ValueError(
            "correlation window must be nonempty, at most 48 hours, and no later than as_of"
        )
    heads = conn.execute(
        """SELECT gh.group_id, gh.current_revision
           FROM group_heads gh JOIN group_revisions gr
             ON (gr.site_id, gr.group_id, gr.revision) =
                (gh.site_id, gh.group_id, gh.current_revision)
           WHERE gh.site_id=%s AND gr.first_ts < %s AND gr.last_ts >= %s
           ORDER BY gh.group_id LIMIT %s""",
        (site_id, end, start, MAX_GROUPS + 1),
    ).fetchall()
    if len(heads) > MAX_GROUPS:
        raise ValueError("correlation input group cap exceeded")
    pinned = {str(group): str(revision) for group, revision in heads}
    if not pinned:
        return CorrelationInput(
            site_id=site_id,
            window_start=start,
            window_end=end,
            as_of=as_of,
            computation_version=computation_version,
            groups=(),
            observations=(),
        )
    rows = conn.execute(
        """SELECT gm.group_id, gm.group_revision, gm.alert_key, gm.event_ts,
                  gm.source_hash, gm.normalized_snapshot
           FROM group_members gm
           WHERE gm.site_id=%s AND (gm.group_id, gm.group_revision) IN (
               SELECT key, value FROM jsonb_each_text(%s::jsonb)
           ) AND gm.event_ts >= %s AND gm.event_ts < %s
           ORDER BY gm.group_id, gm.alert_key LIMIT %s""",
        (site_id, json.dumps(pinned), start, end, MAX_OBSERVATIONS + 1),
    ).fetchall()
    if len(rows) > MAX_OBSERVATIONS:
        raise ValueError("correlation input observation cap exceeded")
    if not rows:
        return CorrelationInput(
            site_id=site_id,
            window_start=start,
            window_end=end,
            as_of=as_of,
            computation_version=computation_version,
            groups=(),
            observations=(),
        )

    references = select_score_references(
        conn, site_id=site_id, group_revisions=tuple(sorted(pinned.items())), as_of=as_of
    )
    scores = {
        pin: (reference.total, reference.computation_version, reference.input_digest)
        for pin, reference in references.items()
    }
    fim_keys = tuple(
        str(row[2]) for row in rows if str(row[5].get("rule_id")) in {"550", "553", "554"}
    )
    projections = (
        project_retained_sources(
            conn, site_id=site_id, alert_keys=fim_keys, extraction_version="syscheck-v1"
        )
        if fim_keys
        else {}
    )

    members_by_group: dict[str, list[CorrelationObservation]] = {}
    groups: list[CorrelationGroup] = []
    group_by_id = {str(group): str(revision) for group, revision in heads}
    for group_id, revision, alert_key, event_ts, source_hash, raw_snapshot in rows:
        group_id, revision, alert_key = str(group_id), str(revision), str(alert_key)
        snapshot = cast(dict[str, Any], raw_snapshot)
        refs_value = snapshot.get("_entity_refs", ())
        refs = cast(list[object], refs_value) if isinstance(refs_value, list) else []
        hash_values: list[str] = []
        for ref in refs:
            if not isinstance(ref, dict):
                continue
            entity_ref = cast(dict[str, object], ref)
            value = entity_ref.get("value")
            if entity_ref.get("kind") == "hash":
                if not isinstance(value, str) or not HASH_PATTERN.fullmatch(value):
                    raise ValueError(
                        "retained file hash is malformed; correlation input is unavailable"
                    )
                hash_values.append(value)
        hashes = tuple(sorted(set(hash_values)))
        file_path = file_event = None
        if str(snapshot.get("rule_id")) in {"550", "553", "554"}:
            projection = projections[alert_key]
            file_path, file_event = projection.path, projection.event
        observation = CorrelationObservation(
            site_id=site_id,
            group_id=group_id,
            group_revision=revision,
            alert_key=alert_key,
            source_hash=str(source_hash),
            event_ts=event_ts,
            rule_id=_text(snapshot.get("rule_id")),
            decoder=_text(snapshot.get("decoder")),
            agent_id=_text(snapshot.get("agent_id")),
            src_ip=_text(snapshot.get("src_ip")),
            dst_ip=_text(snapshot.get("dst_ip")),
            src_user=_text(snapshot.get("src_user")),
            dst_user=_text(snapshot.get("dst_user")),
            rule_groups=tuple(sorted(snapshot.get("rule_groups") or ())),
            mitre_tactics=tuple(sorted(snapshot.get("mitre_tactics") or ())),
            file_path=file_path,
            file_event=file_event,
            hashes=hashes,
        )
        members_by_group.setdefault(group_id, []).append(observation)
    for group_id, revision in sorted(group_by_id.items()):
        members = members_by_group.get(group_id)
        if not members:
            continue
        selected = scores.get((group_id, revision))
        groups.append(
            CorrelationGroup(
                site_id=site_id,
                group_id=group_id,
                revision=revision,
                score=None if selected is None else selected[0],
                computation_version=None if selected is None else selected[1],
                input_digest=None if selected is None else selected[2],
            )
        )
    observations = tuple(
        sorted(
            (item for members in members_by_group.values() for item in members),
            key=lambda item: item.alert_key,
        )
    )
    return CorrelationInput(
        site_id=site_id,
        window_start=start,
        window_end=end,
        as_of=as_of,
        computation_version=computation_version,
        groups=tuple(groups),
        observations=observations,
    )


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


class CorrelationHandler:
    """Execute frozen correlation jobs using policy and code loaded before claims."""

    job_kinds = CORRELATION_JOB_KINDS

    def __init__(self, *, rule_path: Path = RULE_PATH) -> None:
        self.rule = load_chain_rule(rule_path)
        self.code_identity = correlation_code_identity()

    def preclaim_with_connection(self, conn: psycopg.Connection[Any], job: Job) -> None:
        require_site_transaction(conn, job.site_id)
        if job.kind == "prepare_correlation":
            config = job.payload.get("config")
            if type(job.payload.get("generation")) is not int or identity(
                config
            ) != job.payload.get("config_identity"):
                raise ValueError("preparation job has invalid immutable pins")
            rule_from_config(config, supported_code=self.code_identity)
        elif job.kind == "correlate_window":
            manifest_value = job.payload.get("manifest_id")
            intent_value = job.payload.get("intent_id")
            if not isinstance(manifest_value, str) or not isinstance(intent_value, str):
                raise ValueError("correlation job has invalid immutable pins")
            if job.subject != intent_value:
                raise ValueError("correlation job subject differs from its publication intent")
            try:
                manifest_id = UUID(manifest_value)
                UUID(intent_value)
            except ValueError as exc:
                raise ValueError("correlation job has invalid UUID pins") from exc
            row = conn.execute(
                "SELECT rule_digest, computation_version FROM correlation_manifests "
                "WHERE site_id=%s AND manifest_id=%s",
                (job.site_id, manifest_id),
            ).fetchone()
            if row is None or str(row[1]) != self.code_identity:
                raise ValueError("correlation job policy or code identity is unavailable")

    def __call__(self, conn: psycopg.Connection[Any], jobs: tuple[Job, ...], now: datetime) -> None:
        for job in jobs:
            if job.kind == "correlate_window":
                manifest_id = UUID(_required(job.payload, "manifest_id"))
                intent_id = UUID(_required(job.payload, "intent_id"))
                inputs, rule = load_manifest(conn, siteid=job.site_id, manifestid=manifest_id)
                if inputs.computation_version != self.code_identity:
                    raise ValueError(
                        "pinned correlation policy or code identity does not match worker"
                    )
                edges = build_edges(inputs)
                chains = evaluate_chain(rule, inputs)
                persist_results(
                    conn,
                    siteid=job.site_id,
                    manifestid=manifest_id,
                    intentid=intent_id,
                    edges=edges,
                    chains=chains,
                    now=now,
                )
            elif job.kind == "prepare_correlation":
                self._prepare(conn, job, now)
            else:
                raise ValueError(f"unsupported correlation job kind: {job.kind}")

    def _prepare(self, conn: psycopg.Connection[Any], job: Job, now: datetime) -> None:
        from ai_soc.workspace.correlate.scheduling import prepare_request

        prepare_request(conn, job=job, now=now, code_identity=self.code_identity)


def _required(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"job payload requires {key}")
    return value


def coverage(inputs: CorrelationInput, rule: ChainRule) -> dict[str, object]:
    last_anchor = inputs.window_end - timedelta(seconds=rule.window_seconds)
    complete = last_anchor > inputs.window_start
    return {
        "scope": "selected_current_heads",
        "intake_start": inputs.window_start,
        "intake_end_exclusive": inputs.window_end,
        "fully_observed_anchor_start": inputs.window_start if complete else None,
        "fully_observed_anchor_end_exclusive": last_anchor if complete else None,
        "complete_anchors": complete,
        "recent_anchor_results": "partial",
        "absence_scope": "selected_current_heads_only; absent chains are not expired",
        "classifier_window_seconds": rule.window_seconds,
        "caps": {"groups": MAX_GROUPS, "observations": MAX_OBSERVATIONS, "hours": 48},
        "truncated": False,
        "unavailable_score_groups": sum(group.score is None for group in inputs.groups),
        "unavailable_file_sources": sum(
            observation.rule_id in {"550", "553", "554"} and observation.file_path is None
            for observation in inputs.observations
        ),
        "omissions": ["unselected historical revisions", "members outside the half-open intake"],
    }


def runtime_status(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    now: datetime,
    code_identity: str,
) -> dict[str, object]:
    from ai_soc.workspace.correlate.scheduling import request_snapshot

    require_site_transaction(conn, site_id)
    row = conn.execute(
        """SELECT count(*) FILTER (WHERE state='queued' AND run_after<=%s
                    OR state='running' AND locked_until<=%s),
                  count(*) FILTER (WHERE state='queued' AND run_after>%s),
                  count(*) FILTER (WHERE state='running' AND locked_until>%s),
                  count(*) FILTER (WHERE state='dead'),
                  count(*) FILTER (WHERE state IN ('queued','running') AND
                      kind='prepare_correlation' AND
                      payload->'config'->>'code_identity' IS DISTINCT FROM %s)
           FROM jobs WHERE site_id=%s AND kind=ANY(%s)""",
        (now, now, now, now, code_identity, site_id, sorted(CORRELATION_JOB_KINDS)),
    ).fetchone()
    assert row is not None
    counts = dict(
        zip(("due", "deferred", "running", "dead", "blocked"), map(int, row), strict=True)
    )
    request = request_snapshot(conn, site_id=site_id)
    if request is not None:
        active = conn.execute(
            "SELECT state FROM jobs WHERE site_id=%s AND job_id=%s",
            (site_id, request["active_prepare_job_id"]),
        ).fetchone()
        request["active_job_state"] = None if active is None else str(active[0])
        if request["pending"] and (active is None or str(active[0]) in {"dead", "done"}):
            counts["blocked"] += 1
    return {"correlation": request, **counts}


def _outstanding(status: dict[str, object]) -> bool:
    request = status.get("correlation")
    pending = isinstance(request, dict) and bool(cast(dict[str, object], request).get("pending"))
    return pending or any(
        status.get(key) for key in ("due", "deferred", "running", "dead", "blocked")
    )


def main() -> int:
    from ai_soc.workspace.correlate.scheduling import recover_request
    from ai_soc.workspace.db import site_transaction
    from ai_soc.workspace.runtime import PipelineRuntime, load_pipeline_config
    from ai_soc.workspace.worker import run_once

    parser = argparse.ArgumentParser(description="Run bounded durable workspace correlation")
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--status", action="store_true")
    modes.add_argument(
        "--recover", action="store_true", help="restart a terminal pending preparation"
    )
    modes.add_argument(
        "--freeze", action="store_true", help="freeze and enqueue an explicit historical window"
    )
    modes.add_argument(
        "--drain",
        action="store_true",
        help="process only ready prepare/correlate jobs, bounded by --max-jobs",
    )
    parser.add_argument("--max-jobs", type=int, default=100_000, help="bound --drain claims")
    parser.add_argument("--site", required=True)
    parser.add_argument("--from", dest="window_start")
    parser.add_argument("--to", dest="window_end")
    parser.add_argument("--as-of")
    parser.add_argument("--evidence", type=Path, help="write mode-600 JSON evidence")
    parser.add_argument("--batch-size", type=int, default=1)
    args = parser.parse_args()
    if not 1 <= args.max_jobs <= 100_000:
        parser.error("--max-jobs must be in 1..100000")
    if not 1 <= args.batch_size <= 100:
        parser.error("--batch-size must be in 1..100")
    explicit = (args.window_start, args.window_end, args.as_of)
    if args.freeze and any(value is None for value in explicit):
        parser.error("--freeze requires --from, --to and --as-of")
    if not args.freeze and any(value is not None for value in explicit):
        parser.error("--from, --to and --as-of are only valid with --freeze")
    source = os.environ.get("WS_WORKER_CONFIG")
    if not source:
        parser.error("WS_WORKER_CONFIG must reference an explicit authorized site configuration")
    config = load_pipeline_config(Path(source))
    authorized = frozenset(site.site_id for site in config.sites)
    if args.site not in authorized:
        parser.error("--site is not authorized by WS_WORKER_CONFIG")
    if (
        not args.status
        and not next(site for site in config.sites if site.site_id == args.site).correlation_enabled
    ):
        parser.error("site must opt in with correlation_enabled=true")
    site_ids = frozenset({args.site})
    worker_id = os.environ.get("WS_WORKER_ID", "workspace-correlator")
    results: dict[str, object]
    exit_code = 0
    correlation = CorrelationHandler()
    with PipelineRuntime(config) as runtime, runtime.connect() as conn:
        if args.status:
            with site_transaction(conn, args.site, site_ids):
                status = runtime_status(
                    conn,
                    site_id=args.site,
                    now=datetime.now(UTC),
                    code_identity=correlation.code_identity,
                )
                results = {"site_id": args.site, **status}
                exit_code = int(_outstanding(status))
        elif args.recover:
            with site_transaction(conn, args.site, site_ids):
                generation = recover_request(conn, site_id=args.site, now=datetime.now(UTC))
            results = {"site_id": args.site, "recovery_generation": generation}
        elif args.freeze:
            start = _datetime(args.window_start, "--from")
            end = _datetime(args.window_end, "--to")
            as_of = _datetime(args.as_of, "--as-of")
            now = datetime.now(UTC)
            if as_of > now:
                parser.error("--as-of must not be in the future")
            with site_transaction(conn, args.site, site_ids):
                rule = correlation.rule
                inputs = build_frozen_inputs(
                    conn,
                    site_id=args.site,
                    start=start,
                    end=end,
                    as_of=as_of,
                    computation_version=correlation.code_identity,
                )
                manifest = freeze_manifest(conn, inputs=inputs, rule=rule, now=now)
                job_id = enqueue_correlation(conn, manifestid=manifest, siteid=args.site, now=now)
            results = {
                "site_id": args.site,
                "manifest_id": str(manifest),
                "job_id": job_id,
                "window_start": start.isoformat(),
                "window_end": end.isoformat(),
                "as_of": as_of.isoformat(),
                "groups": len(inputs.groups),
                "observations": len(inputs.observations),
                "coverage": coverage(inputs, rule),
                "rule_digest": rule.content_digest,
                "code_identity": correlation.code_identity,
            }
        else:
            limit = args.max_jobs
            handled = 0
            error: str | None = None
            while handled < limit:
                try:
                    count = run_once(
                        conn,
                        worker_id=worker_id,
                        site_ids=site_ids,
                        handler=correlation,
                        batch_size=min(args.batch_size, limit - handled),
                        job_kinds=CORRELATION_JOB_KINDS,
                    )
                except (ValueError, LookupError, PermissionError) as exc:
                    error = str(exc)
                    break
                handled += count
                if not count:
                    break
            with site_transaction(conn, args.site, site_ids):
                status = runtime_status(
                    conn,
                    site_id=args.site,
                    now=datetime.now(UTC),
                    code_identity=correlation.code_identity,
                )
            results = {"site_id": args.site, "processed": handled, **status}
            if error is not None:
                results["error"] = error
            exit_code = int(error is not None or _outstanding(status))
    _emit(results, args.evidence)
    return exit_code


def _datetime(value: str, option: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SystemExit(f"{option} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SystemExit(f"{option} must include a timezone")
    return parsed.astimezone(UTC)


def _emit(value: dict[str, object], destination: Path | None) -> None:
    def utc_timestamp(item: object) -> str:
        if isinstance(item, datetime) and item.tzinfo is not None:
            return item.astimezone(UTC).isoformat()
        raise TypeError(f"unsupported JSON value: {type(item).__name__}")

    rendered = json.dumps(value, sort_keys=True, separators=(",", ":"), default=utc_timestamp)
    if destination is None:
        print(rendered)
        return
    import stat

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(destination, flags, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(rendered + "\n")
    if stat.S_IMODE(destination.stat().st_mode) != 0o600:
        raise PermissionError("evidence file must have mode 600")


if __name__ == "__main__":
    sys.exit(main())
