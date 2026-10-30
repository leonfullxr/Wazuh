# Run the deterministic alert workspace

The workspace stores alerts in PostgreSQL 16 and reads Wazuh with a dedicated read-only identity. It requires full visibility for the selected site. Grouping, scoring and analyst actions are deterministic; workspace AI output is unavailable at this stage.

## Prepare the database and source

Run `make ws-db-up`, `make ws-migrate` and `make ws-provision-role` from the repository root. The private settings file is `build/workspace-db.env`. Runtime processes use its restricted application connection; migrations and partition maintenance use the separate owner connection. Preserve mode `0600` on credential/configuration files.

Provide `WS_WORKER_CONFIG` as the path to a protected JSON configuration with this shape:

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

The credential file contains `username` and `password`; it is never a browser configuration. Verify the installed release, trusted CA, exact source roles and full visibility attestation before connecting. Unsupported mapping releases fail closed. The 4.14.7 mapping retains its original profile identifier so existing normalized records remain reproducible; its captured-field qualification is limited to the tested release and fields.

Register each configured site using the maintenance connection, then create daily partitions for the required event dates. With `WS_DATABASE_URL` supplied securely to that maintenance process:

```sh
make ws-partitions WS_ARGS="--from 2026-10-21 --to 2026-10-24"
```

The date range is half-open. The restricted runtime cannot create partitions. A missing date fails visibly rather than granting runtime DDL privileges.

## Optional offline score context

`context_sources` is optional and defaults to empty, which leaves vulnerability, KEV and GeoIP inputs unavailable. Each source can be configured independently. Snapshot paths must be absolute and their lowercase SHA-256 must pin the complete snapshot file. The worker reads and verifies these bounded local files when `PipelineHandler` starts, before it claims work; it never refreshes context over the network or reads source files inside a job transaction.

The vulnerability snapshot is a strict version-1 document with `site_id`, `source_id`, `source_version`, `captured_at`, required `expires_at`, provenance and per-agent rows. Provenance records `kind: "wazuh_read_only_export"`, `index_pattern: "wazuh-states-vulnerabilities-*"`, `query_sha256`, `export_sha256` and whether the export is complete. The configured snapshot SHA pins the full JSON file; `export_sha256` independently identifies the upstream export and is not a self-reference to the JSON file. Each agent row has `agent_id`, `complete` and `vulnerabilities`, each containing a canonical CVE and severity (`Critical`, `High`, `Medium` or `Low`). Only an explicit complete row with no vulnerabilities counts as measured zero. Missing or incomplete rows, unknown severity, a future capture or an expired snapshot remain unavailable. High or Critical findings set the existing normalized vulnerability signal; the worker does not accept precomputed operator scores.

The GeoIP snapshot uses the same site/source/version/capture/expiry fields and records its offline database version and completeness. Its address rows contain canonical public IPs, a normalized `score_value` from the offline provider, and classification details. The context is unavailable if any public address from the group is missing. Private addresses are ignored. No network lookup or runtime database download is supported.

KEV configuration points to an already approved content-pack directory, its pack SHA-256, the matching `BuildProvenance`, and a source ID. The runtime uses the existing content-pack verifier and KEV index/freshness policy; it does not accept a raw KEV JSON file or an operator-supplied approval timestamp. KEV scoring also needs a complete as-of vulnerability inventory for every group agent. A synthetic fixture pack is useful for tests only and does not qualify as a live KEV source.

For vulnerability and GeoIP, the frozen cutoff must satisfy `captured_at <= as_of < expires_at`. A context bundle SHA is included in jobs created by the pipeline and in immutable enrichment evidence. If a bundle changes while a group revision stays the same, the pipeline creates a new job identity and retains the old evidence. To finish jobs pinned to older bundles after a restart, list those bundles under `context_history`; the worker verifies and preloads every current and historical file before it claims work. If a queued job's bundle is not present there, its claim is rolled back before the attempt is committed. Keep historical source files until no pending job needs them. Old unpinned jobs keep their unavailable-provider behavior. The score manifest points to immutable enrichment rows that retain input source IDs, SHA-256 digests and provenance, so replay reads database evidence and does not reopen mutable source files.

For an equal `as_of` cutoff, current detail, queue and quality views select the score from the newest completed durable enrichment/rescore intent matching that exact group revision, asset revision, computation and context bundle. Ordinary enrichment jobs do not carry an asset revision, so their match uses the immutable asset revision recorded in that job's score manifest; asset-tag rescore jobs carry and must match their explicit revision. Each completed job records `completed_at`; historical quality queries bound intent completion by their `to` time. Older completed jobs without a recorded completion time do not acquire inferred authority; their scores retain the deterministic timestamp fallback. This lets a late retry finish and remain replayable without displacing a newer context decision or leaking a later completion into an earlier quality window. Keep completed enrichment/rescore jobs for at least as long as their score manifests and evidence; job history is part of the deterministic score-selection record, and purging it would change authority ordering or prevent a later context bundle from becoming current. If retention is introduced, preserve an equivalent immutable intent ledger before deleting jobs.

## Ingest and process

With `WS_WORKER_CONFIG` set to the protected configuration path:

```sh
make ws-poll WS_ARGS="--site lab --reconcile"
make ws-worker WS_ARGS="--drain --batch-size 100 --max-jobs 100000"
```

The first poll covers a bounded fixed window. Later polls use the durable completion checkpoint and overlap. Each traversal drains all pages; the batch bound does not truncate the window. `ws-poll --watch` polls periodically. Schedule worker drains alongside it; a successful drain is not a continuously running worker supervisor. Check the reported outstanding/dead counts, including delayed retries.

The batch size bounds homogeneous normalization or other short-job cohorts. Enrichment and rescoring jobs are claimed singly when ready to execute; large retained memberships must not age other score leases in a prefetched batch. Each score keeps its own atomic effects/completion transaction. The lease remains 60 seconds, and a single job that exceeds it still rolls back under the expiry fence. Monitor individual job cost and dead jobs before expanding workload size; this policy is not a capacity guarantee.

Use `ws-backfill` with explicit `--site`, `--from` and `--to` for older data, after preparing its partitions. Reconciliation can discover and enqueue late missing alerts; drain the worker before expecting normalization gates to pass. Source mutations are retained as conflicts, never overwritten. Registry identity remains after raw retention, and rediscovery cannot resurrect expired payloads.

## Deployment and audit delivery

The workspace browser build and backend modules require explicit integration with a restricted database provider and cursor secret. The existing service image does not serve this workspace; deployment and live identity qualification remain separate work. Validate source visibility, normalization completeness, replay and score quality before relying on the workflow.

Deliver committed audit events to an existing HTTPS SQS queue with `ws-audit-relay --queue-url`, or explicitly qualify local durable delivery with a private spool:

```sh
make ws-audit-relay WS_ARGS="--site lab --spool build/workspace-audit"
```

The relay acknowledges only after SQS acknowledgement or successful file and directory sync. Retries preserve event IDs and bytes; immutable event envelopes cannot be edited after commit. The shared archive consumer conditionally persists `workspace.1` envelopes before queue deletion. A local spool and SDK tests do not qualify a live AWS queue/archive deployment.
