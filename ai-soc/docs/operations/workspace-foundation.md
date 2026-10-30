# Workspace database foundation

Run these workspace commands from a source checkout. Workspace content assets are not included in the service wheel, and workspace packaging and deployment have not been qualified.

The workspace uses a private local PostgreSQL 16 container. Compose binds it only to `127.0.0.1`; each checkout gets a stable, distinct Compose project and Docker allocates a free host port when `WS_PG_PORT` is empty. Set `WS_PG_PORT` in `.env.workspace` only when a fixed local port is useful.

Run:

```sh
make ws-db-up
make ws-migrate
make ws-provision-role
```

The first command creates a random local Postgres owner password in `.secrets/workspace-pg-password` with mode `0600`, waits for database health, and saves connection settings in ignored `build/workspace-db.env` with mode `0600`. The migration runner uses that owner connection. `ws-provision-role` creates or resets the restricted `workspace_app` login, stores its password in `.secrets/workspace-app-password`, and adds `WS_APP_DATABASE_URL` to the private runtime file. Runtime services and workers use that role. Migrations never create login roles or contain credentials.

`workspace_app` is `NOSUPERUSER`, `NOBYPASSRLS`, and `NOINHERIT`. It owns no workspace table. The `site_transaction` boundary rejects owner and bypass roles, requires the requested site in the caller's explicit authorization set, and sets the single transaction-local `app.site_id` value. RLS uses that value and fails closed when it is absent. `schema_migrations` is global migration infrastructure and is not site-scoped.

Each SQL migration is applied and recorded in its own transaction. A session advisory lock serializes migration runners, and the runner stores SHA-256 checksums to reject edits to already applied files. Versions 0005 (role provisioning) and 0009 are intentionally reserved; 0006 enables and forces site RLS. Migrations only move forward, and missing applied history is rejected.

The queue keys idempotency by `(site_id, kind, subject)`. Workers claim jobs with `FOR UPDATE SKIP LOCKED`; a fresh fencing token and expiry guard each heartbeat and state transition. Claims count toward the five-attempt ceiling, including reclaimed expired leases. The worker supports deterministic normalization, grouping, enrichment and score jobs, as well as `workspace_ping`. A bounded drain exits after ready work is processed; delayed retry/dead counts remain explicit.

Audit records are inserted in the caller's state-change transaction. The relay locks one site-scoped pending row and sends its stable event id with the stored site, kind, actor, payload, and creation time. It marks the event sent only after an explicit sink acknowledgement. Failed sends record a bounded error class and attempt time, then retry with capped exponential backoff; delivery is at least once, so the sink must deduplicate by event id. `oldest_pending_age_seconds` exposes the site-scoped pending age for monitoring.

Deployment qualification requires independently reviewed evidence and tools appropriate to the configured environment.

Stop the local service with `make ws-db-down`. The named volume remains so the local schema and data persist. To remove that volume, use the Compose project shown by `scripts/workspace/db.py` and its `down --volumes` option deliberately.
