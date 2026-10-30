"""Bounded deterministic normalization, grouping, enrichment and score handlers."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

import psycopg

from ai_soc.workspace.context import load_site_context
from ai_soc.workspace.correlate.runner import CorrelationHandler, build_correlation_config
from ai_soc.workspace.correlate.scheduling import request_correlation
from ai_soc.workspace.jobs import Job
from ai_soc.workspace.normalize.models import load_profile
from ai_soc.workspace.normalize.repository import normalize_batch
from ai_soc.workspace.runtime import PipelineConfig
from ai_soc.workspace.triage.enrich import ContextAdapter, enrich_group, score_group_snapshot
from ai_soc.workspace.triage.repository import group_batch
from ai_soc.workspace.triage.score import SCORE_VERSION, load_weights
from ai_soc.workspace.triage.score_outputs import record_score_output

PIPELINE_VERSION = "workspace.deterministic.m2.v1"
ROOT = Path(__file__).resolve().parents[3]
WEIGHTS_PATH = ROOT / "content/workspace/scoring/weights.yaml"


def _payload_text(job: Job, name: str) -> str:
    value = job.payload.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"job payload requires {name}")
    return value


class PipelineHandler:
    job_kinds = frozenset(
        {
            "workspace_ping",
            "normalize_alert",
            "enrich_group",
            "rescore_group",
            "prepare_correlation",
            "correlate_window",
        }
    )

    def __init__(self, config: PipelineConfig) -> None:
        self.correlation = CorrelationHandler()
        self.correlation_code_identity = self.correlation.code_identity
        self.correlation_config = build_correlation_config(
            rule=self.correlation.rule, code_identity=self.correlation_code_identity
        )
        self.correlation_enabled = {site.site_id: site.correlation_enabled for site in config.sites}
        self.profiles = {site.site_id: load_profile(site.wazuh_version) for site in config.sites}
        self.wazuh_versions = {site.site_id: site.wazuh_version for site in config.sites}
        self.context_adapters: dict[str, dict[str, dict[str, ContextAdapter]]] = {}
        self.context_revisions: dict[str, str] = {}
        for site in config.sites:
            active_adapters, active_digest = load_site_context(site.site_id, site.context_sources)
            bundles = {active_digest: active_adapters}
            for historical_sources in site.context_history:
                historical_adapters, historical_digest = load_site_context(
                    site.site_id, historical_sources
                )
                bundles.setdefault(historical_digest, historical_adapters)
            self.context_adapters[site.site_id] = bundles
            self.context_revisions[site.site_id] = active_digest
        self.pipeline_versions = {
            site_id: f"{PIPELINE_VERSION}+ctx:{context_sha256}"
            for site_id, context_sha256 in self.context_revisions.items()
        }
        self.weights = load_weights(WEIGHTS_PATH)
        self.content_hash = hashlib.sha256(WEIGHTS_PATH.read_bytes()).hexdigest()
        digest = hashlib.sha256()
        for path in sorted(Path(__file__).parent.rglob("*.py")):
            digest.update(str(path.relative_to(Path(__file__).parent)).encode())
            digest.update(b"\0")
            digest.update(path.read_bytes())
            digest.update(b"\0")
        self.code_hash = digest.hexdigest()
        self.computation_version = f"{SCORE_VERSION}:{self.code_hash}"

    def __call__(self, conn: psycopg.Connection[Any], jobs: tuple[Job, ...], now: datetime) -> None:
        cohorts: dict[str, list[str]] = defaultdict(list)
        for job in jobs:
            if job.kind == "normalize_alert":
                profile = self.profiles[job.site_id]
                if _payload_text(job, "mapping_profile") != profile.profile_id:
                    raise ValueError("normalization profile differs from frozen job")
                key = _payload_text(job, "alert_key")
                if key != job.subject:
                    raise ValueError("normalization subject differs from payload")
                cohorts[job.site_id].append(key)
            elif job.kind in {"enrich_group", "rescore_group"}:
                self._score(conn, job, now)
            elif job.kind in {"prepare_correlation", "correlate_window"}:
                self.correlation(conn, (job,), now)
            elif job.kind != "workspace_ping":
                raise ValueError(f"unsupported job kind: {job.kind}")
        for site_id, keys in cohorts.items():
            counts = normalize_batch(
                conn,
                site_id=site_id,
                alert_keys=tuple(keys),
                profile=self.profiles[site_id],
                now=now,
            )
            if counts.normalized + counts.already_normalized != len(set(keys)):
                raise LookupError("normalization job evidence is missing or expired")
            # This method merges the retained current-head membership and enqueues
            # pinned enrichment work in the same transaction as normalization.
            group_batch(
                conn,
                site_id=site_id,
                alert_keys=keys,
                pipeline_version=self.pipeline_versions[site_id],
                now=now,
            )

    def preclaim(self, job: Job) -> None:
        """Reject unresolved pinned inputs before the queue attempt is committed."""
        if job.kind not in {"enrich_group", "rescore_group"}:
            return
        pipeline_version = job.payload.get("pipeline_version")
        if not isinstance(pipeline_version, str) or "+ctx:" not in pipeline_version:
            return
        prefix, context_revision = pipeline_version.rsplit("+ctx:", 1)
        if prefix != PIPELINE_VERSION or context_revision not in self.context_adapters[job.site_id]:
            raise ValueError(
                "job context bundle is not present in the preloaded site context history"
            )

    def preclaim_with_connection(self, conn: psycopg.Connection[Any], job: Job) -> None:
        self.preclaim(job)
        if job.kind in self.correlation.job_kinds:
            self.correlation.preclaim_with_connection(conn, job)

    def _score(self, conn: psycopg.Connection[Any], job: Job, now: datetime) -> None:
        computation = _payload_text(job, "computation_version")
        if computation != SCORE_VERSION:
            raise ValueError("worker cannot replay an unsupported score computation")
        cutoff = datetime.fromisoformat(_payload_text(job, "as_of"))
        if cutoff.tzinfo is None or cutoff.utcoffset() is None or cutoff > now:
            raise ValueError("enrichment cutoff must be an explicit past instant")
        pipeline_version = job.payload.get("pipeline_version")
        if isinstance(pipeline_version, str) and "+ctx:" in pipeline_version:
            prefix, context_revision = pipeline_version.rsplit("+ctx:", 1)
            if prefix != PIPELINE_VERSION:
                raise ValueError("worker cannot resolve the pipeline version pinned by this job")
            adapters = self.context_adapters[job.site_id][context_revision]
        else:
            # Pre-context jobs and explicit test/manual jobs remain unavailable for
            # offline providers instead of silently binding to current local files.
            adapters = None
            context_revision = None
        snapshot = enrich_group(
            conn,
            site_id=job.site_id,
            group_id=_payload_text(job, "group_id"),
            group_revision=_payload_text(job, "group_revision"),
            as_of=cutoff,
            adapters=adapters,
            context_revision=context_revision,
            now=now,
        )
        result = score_group_snapshot(
            conn,
            snapshot=snapshot,
            weights=self.weights,
            computation_version=self.computation_version,
            wazuh_version=self.wazuh_versions[job.site_id],
            code_hash=self.code_hash,
            content_hash=self.content_hash,
            now=now,
        )
        record_score_output(conn, job=job, result=result)
        request_correlation(
            conn,
            site_id=job.site_id,
            enabled=self.correlation_enabled[job.site_id],
            config=self.correlation_config,
            now=now,
        )
