# Operate the analyst workspace

The analyst workspace stores alerts in PostgreSQL 16 and reads Wazuh through a dedicated read-only identity. The deterministic pipeline handles ingestion, grouping, scoring, correlation, and analyst actions. An optional dedicated model process can generate labelled incident narratives. Those narratives do not affect ranking, workflow, or group membership.

Run workspace commands from a source checkout. Workspace content assets are not included in the service wheel. The service image includes the browser application and backend modules, but it does not configure a workspace database, cursor secret, API, or worker processes. Workspace packaging and production deployment have not been qualified.

## Prepare the database

The local workspace uses a private PostgreSQL 16 container. Compose binds it only to `127.0.0.1`. Each checkout gets a stable Compose project, and Docker allocates a free host port when `WS_PG_PORT` is empty. Set `WS_PG_PORT` in `.env.workspace` only when you need a fixed local port.

Run these commands from the repository root:

```sh
make ws-db-up
make ws-migrate
make ws-provision-role
```

`ws-db-up` creates a random local Postgres owner password in `.secrets/workspace-pg-password` with mode `0600`. It waits for database health and saves the connection settings in `build/workspace-db.env` with mode `0600`. The migration runner uses the owner connection.

`ws-provision-role` creates or resets the restricted `workspace_app` login. It stores the password in `.secrets/workspace-app-password` and adds `WS_APP_DATABASE_URL` to the private runtime file. Runtime services and workers use this role. Migrations never create login roles or contain credentials.

`workspace_app` is `NOSUPERUSER`, `NOBYPASSRLS`, and `NOINHERIT`. It owns no workspace table. The `site_transaction` boundary rejects owner and bypass roles, requires the requested site in the caller's explicit authorization set, and sets one transaction-local `app.site_id` value. Row-level security uses that value and fails closed when it is absent. `schema_migrations` is global migration infrastructure and is not site-scoped.

The migration runner applies and records each SQL migration in its own transaction. A session advisory lock serializes migration runners. The runner stores SHA-256 checksums and rejects edits to applied files. Versions 0005 and 0009 are reserved. Migration 0006 enables and forces site row-level security. Migrations 0030 through 0032 add exact score producers, durable narrative storage, and retained event ordering. Migrations move only forward, and the runner rejects missing applied history.

Preserve a pre-migration backup and the prior application artifact before database changes. Restore the backup into another database and verify it before you switch a protected runtime reference. Applied migration checksums are immutable. Owner maintenance applies migrations because runtime roles cannot perform DDL.

The queue keys idempotency by `(site_id, kind, subject)`. Workers claim jobs with `FOR UPDATE SKIP LOCKED`. A fresh fencing token and expiry guard each heartbeat and state transition. Claims count toward the five-attempt limit, including reclaimed expired leases. The worker supports deterministic normalization, grouping, enrichment, score jobs, and `workspace_ping`. A bounded drain exits after it processes ready work. Delayed retries and dead jobs remain explicit.

Stop the local database with `make ws-db-down`. The named volume remains so the schema and data persist. To remove the volume, use the Compose project reported by `scripts/workspace/db.py` and its `down --volumes` option.

## Configure the Wazuh source

Set `WS_WORKER_CONFIG` to a protected JSON configuration with this shape:

```json
{
  "schema_version": 1,
  "database_env_file": "/run/secrets/workspace-database.env",
  "sites": [{
    "site_id": "lab",
    "label": "Lab",
    "wazuh_version": "4.14.7",
    "indexer_url": "https://indexer.example.test:9200",
    "ca_file": "/run/secrets/indexer-ca.pem",
    "credential_file": "/run/secrets/workspace-source.json",
    "index_pattern": "wazuh-alerts-*",
    "expected_roles": ["dedicated_workspace_reader"],
    "full_visibility_attestation": "operator-approved-v1",
    "context_sources": {},
    "context_history": []
  }]
}
```

The credential file contains `username` and `password`. Never expose this file to the browser. Verify the installed Wazuh release, the trusted CA, the exact source roles, and the full visibility attestation before you connect. Unsupported mapping releases fail closed. The 4.14.7 mapping keeps its original profile identifier so existing normalized records remain reproducible. Its captured-field qualification covers only the tested release and fields.

Register each configured site through the maintenance connection. Then create daily partitions for the required event dates. Supply `WS_DATABASE_URL` to the maintenance process through a protected runtime loader:

```sh
make ws-partitions WS_ARGS="--from 2026-10-21 --to 2026-10-24"
```

The date range is half-open. The restricted runtime cannot create partitions. A missing date fails instead of granting DDL privileges to the runtime.

## Configure offline score context

`context_sources` is optional and defaults to empty. An empty configuration leaves vulnerability, Known Exploited Vulnerabilities, and GeoIP inputs unavailable. Configure each source independently. Snapshot paths must be absolute, and a lowercase SHA-256 must pin each complete snapshot file.

The worker verifies these bounded local files when `PipelineHandler` starts, before it claims work. It never refreshes context over the network or reads source files inside a job transaction.

### Vulnerability snapshots

A vulnerability snapshot is a strict version 1 document. It contains `site_id`, `source_id`, `source_version`, `captured_at`, required `expires_at`, provenance, and per-agent rows. Provenance records these fields:

- `kind: "wazuh_read_only_export"`
- `index_pattern: "wazuh-states-vulnerabilities-*"`
- `query_sha256`
- `export_sha256`
- whether the export is complete

The configured snapshot SHA pins the complete JSON file. `export_sha256` identifies the upstream export and is not a self-reference to the JSON file. Each agent row contains `agent_id`, `complete`, and `vulnerabilities`. Each vulnerability has a canonical CVE and one of these severity values: `Critical`, `High`, `Medium`, or `Low`.

Only an explicit complete row with no vulnerabilities counts as measured zero. Missing or incomplete rows, an unknown severity, a future capture, or an expired snapshot remain unavailable. High or Critical findings set the normalized vulnerability signal. The worker does not accept precomputed operator scores.

### GeoIP snapshots

A GeoIP snapshot uses the same site, source, version, capture, and expiry fields. It also records its offline database version and completeness. Address rows contain canonical public IP addresses, a normalized `score_value` from the offline provider, and classification details.

GeoIP context is unavailable if any public address from a group is missing. The worker ignores private addresses. The runtime does not support network lookups or database downloads.

### Known Exploited Vulnerabilities content

Known Exploited Vulnerabilities configuration points to an approved content-pack directory, its pack SHA-256, the matching `BuildProvenance`, and a source ID. The runtime uses the content-pack verifier and its freshness policy. It does not accept a raw JSON file or an operator-supplied approval timestamp.

This scoring also requires a complete as-of vulnerability inventory for every group agent. A synthetic fixture pack is suitable for tests but does not qualify as a live source.

### Context history and retention

For vulnerability and GeoIP data, the frozen cutoff must satisfy `captured_at <= as_of < expires_at`. Jobs and immutable enrichment evidence include a context bundle SHA. If the bundle changes while a group revision stays the same, the pipeline creates a new job identity and retains the previous evidence.

List old bundles under `context_history` when pending jobs still refer to them. The worker verifies and preloads every current and historical file before it claims work. If a queued job refers to a bundle that is not configured, the worker rolls back the claim before it commits the attempt. Keep historical source files until no pending job needs them.

Old jobs that do not pin a context bundle keep their unavailable-provider behavior.

The score manifest points to immutable enrichment rows. These rows retain source IDs, SHA-256 digests, and provenance. Replay reads the database evidence and does not reopen mutable source files.

Current detail, queue, and quality views select the score from the newest completed durable enrichment or rescore intent for the same `as_of` cutoff, group revision, asset revision, computation, and context bundle. Ordinary enrichment jobs use the asset revision from their score manifest. Asset-tag rescore jobs use their explicit revision.

Each completed job records `completed_at`. Historical quality queries restrict intent completion by the query's `to` time. Older jobs without a completion time retain their deterministic timestamp fallback. A late retry can finish without replacing a newer context decision or appearing in an earlier quality window.

Keep completed enrichment and rescore jobs for at least as long as their score manifests and evidence. Job history determines score authority. Before you delete jobs, preserve an equivalent immutable intent ledger.

## Ingest and process alerts

With `WS_WORKER_CONFIG` set to the protected configuration path, run:

```sh
make ws-poll WS_ARGS="--site lab --reconcile"
make ws-worker WS_ARGS="--drain --batch-size 100 --max-jobs 100000"
```

The first poll covers a bounded fixed window. Later polls use the durable completion checkpoint and overlap. Each traversal drains all pages. The batch bound does not truncate the window.

`ws-poll --watch` polls at intervals. Schedule worker drains alongside the poller. A successful drain does not provide a continuously running worker supervisor. Check the reported outstanding and dead counts, including delayed retries.

The batch size limits homogeneous normalization and other short-job cohorts. Enrichment and rescoring jobs are claimed one at a time when ready to execute. Large retained memberships must not age other score leases in a prefetched batch. Each score keeps its own atomic effects and completion transaction.

The lease remains 60 seconds. A job that exceeds the lease rolls back under the expiry fence. Monitor individual job cost and dead jobs before you increase workload size. This policy does not establish a capacity guarantee.

Use `ws-backfill` with explicit `--site`, `--from`, and `--to` values for older data after you prepare the partitions. Reconciliation can discover and enqueue late missing alerts. Drain the worker before you expect normalization gates to pass. The system retains source mutations as conflicts and never overwrites them. Registry identity remains after raw retention, so rediscovery cannot restore expired payloads.

## Correlate alerts

The normal workspace worker handles deterministic ingestion, scoring, and correlation. It excludes model jobs. Keep its Wazuh credential read-only and its full-site visibility attestation current.

Run `make ws-correlate WS_ARGS="--help"` to see the bounded historical correlation and frozen replay commands. Generic tactic progression remains disabled.

## Run the dedicated model process

Provision a distinct model role through an owner connection:

```sh
make ws-model-provision WS_ARGS="--config /protected/model.json --role workspace_model"
```

The command grants the narrow role and creates it as `NOLOGIN` if the role is absent. Configure login through protected operator tooling. Never use an owner DSN for normal model execution. Run the same command without `--role` to register the site, host, runtime, and shared slot directory. Keep all sites and checkouts on the host in the same protected slot domain.

Set `WS_MODEL_DATABASE_URL` through a protected runtime loader. Do not print it or commit credentials. The configuration includes `site_ids`, a `host_id` from `local_host_id()`, `runtime_id`, an absolute `slot_directory`, and an optional `worker_id`. The runtime binding is immutable. Investigate an unexpected host or directory change before you continue.

Use these commands to operate the model process:

- `make ws-model-status WS_ARGS="--config /protected/model.json"` reports queued, deferred, running, dead, and blocked counts. It also reports held capacity and observed executable availability. It does not probe an account.
- `make ws-model-prepare WS_ARGS="--config /protected/model.json"` freezes pending evidence without inference.
- `make ws-model-drain WS_ARGS="--config /protected/model.json --max-jobs 100"` performs one bounded drain.
- `make ws-model-watch WS_ARGS="--config /protected/model.json --poll-seconds 5 --max-jobs 100"` drains new incident evidence and waits between cycles.

Account controls govern spend. The workspace does not impose a daily budget. The model process never promotes an incident automatically.

Run `ws-model-watch` under an operator-owned supervisor with restart-on-failure and protected logs. Stop that supervisor's specific process. Do not kill unrelated CLI sessions. A scheduler can exit while a guardian finishes its bounded call. The physical slot remains held until cost-bearing descendants exit. Another scheduler cannot treat lease expiry as a capacity release.

Status distinguishes held capacity from deferred work. A restart uses the same binding and reconciles abandoned attempts before it admits new calls.

## Recover model work

Unsupported or unavailable pinned execution bundles block before attempts. Restore the matching installed bundle to continue. Configuration changes do not rewrite frozen requests.

Account limits, invalid output, and unsupported tool attempts terminate as unavailable. Classified transport, timeout, rate, and server failures retry at most five attempts. Do not reset attempt counters or bypass account controls. Preparation and model dead letters remain visible for operator investigation. Creating an evidence revision is an analyst action and is not an automatic repair.

A crash after inference but before receipt persistence can lose usage or result evidence and permit a later external re-execution. External exactly-once execution is unavailable. Unknown token usage stays null, while recorded zero stays zero.

Narrative GET requests are read-only and never generate output. Current views require current evidence and the exact desired published result. Historical revision requests are explicit. Field checks restrict factual selections. Every narrative remains labelled `Unvalidated AI summary` and has no ranking, workflow, or membership authority. Investigate creates an editable question and requires normal question submission.

## Deliver audit events

The caller inserts audit records in the same transaction as the state change. The relay locks one site-scoped pending row and sends its stable event ID with the stored site, kind, actor, payload, and creation time. It marks the event sent only after the sink acknowledges it.

Failed sends record a bounded error class and attempt time. They retry with capped exponential backoff. Delivery is at least once, so the sink must deduplicate by event ID. `oldest_pending_age_seconds` reports the pending age for the site.

Deliver committed events to an existing HTTPS SQS queue with `ws-audit-relay --queue-url`. To qualify local durable delivery, use a private spool:

```sh
make ws-audit-relay WS_ARGS="--site lab --spool build/workspace-audit"
```

The relay acknowledges an event only after SQS acknowledgement or a successful file and directory sync. Retries preserve event IDs and bytes. Immutable event envelopes cannot be edited after commit. The shared archive consumer stores `workspace.1` envelopes before it deletes queue messages.

A local spool and SDK tests do not qualify a live AWS queue or archive deployment. Monitor pending, oldest, and dead audit records. Require acknowledgements from the configured destination.

## Qualify a deployment

The browser build and backend modules require explicit integration with a restricted database provider and cursor secret. Validate source identity, source visibility, normalization completeness, retained evidence, database permissions, replay, score quality, process recovery, audit delivery, and browser behavior before analysts rely on the workspace.

The workspace has not been qualified for production deployment.
