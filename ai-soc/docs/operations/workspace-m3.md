# Local M3 workspace operation

Use a separate qualified Postgres database and protected configuration. Migrations0030–0032 add exact score producers, durable narrative storage and retained event ordering. Owner maintenance applies migrations; runtime roles cannot perform DDL. Preserve pre-migration backups and the prior application artifact. Restore into another database and verify it before switching protected runtime references. Applied migration checksums are immutable.

The normal workspace worker handles deterministic ingestion, scoring and correlation. It excludes both model job kinds. Keep its Wazuh credential read-only and its full-site visibility attestation current. `make ws-correlate WS_ARGS="--help"` documents bounded historical correlation and frozen replay commands. Generic tactic progression remains disabled.

## Dedicated model process

Provision a distinct model role using an owner connection. `make ws-model-provision WS_ARGS="--config /protected/model.json --role workspace_model"` grants the narrow role and creates it NOLOGIN if absent. Configure login separately through protected operator tooling; never use an owner DSN for normal model execution. Run the same command without `--role` to explicitly register the site/host/runtime/shared slot directory. Keep all sites and checkouts on that host in the same protected slot domain.

`WS_MODEL_DATABASE_URL` supplies the dedicated connection. Do not print it or commit credentials. Configuration includes site_ids, host_id from `local_host_id()`, runtime_id, absolute slot_directory and optional worker_id. The runtime binding is immutable; unexpected host/directory changes require an explicit operator investigation.

- `make ws-model-status WS_ARGS="--config /protected/model.json"` reports queued/deferred/running/dead/blocked counts, held capacity and observed executable availability. It does not probe an account.
- `make ws-model-prepare WS_ARGS="--config /protected/model.json"` freezes pending evidence without inference.
- `make ws-model-drain WS_ARGS="--config /protected/model.json --max-jobs 100"` performs one bounded drain.
- `make ws-model-watch WS_ARGS="--config /protected/model.json --poll-seconds 5 --max-jobs 100"` automatically drains new incident evidence and waits between cycles. Account controls govern spend; there is no workspace daily budget. No incident is automatically promoted.

Run watch under an operator-owned supervisor with restart-on-failure and protected logs. Stop that supervisor's specific process; never kill unrelated CLI sessions. A scheduler can exit while a guardian finishes its bounded call. The physical slot remains held until cost-bearing descendants exit; another scheduler cannot infer that lease expiry releases capacity. Status distinguishes held capacity from deferred work. Restart uses the same binding and reconciles abandoned attempts before admitting new calls.

## Failures and retained evidence

Unsupported or unavailable pinned execution bundles block before attempts. Restore the matching installed bundle to continue; changing configuration never silently rewrites frozen requests. Account limits, invalid output and unsupported tool attempts terminate unavailable. Classified transport/timeout/rate/server failures retry at most five attempts. Do not reset attempt counters or circumvent account controls. Preparation and model dead letters remain visible for operator investigation; creating a new evidence revision is an analyst action, not a hidden repair loop.

A crash after inference but before receipt persistence can lose usage/result evidence and permit later external reexecution. External exactly-once is unavailable. Unknown token usage stays null; recorded zero stays zero. Audit envelopes are committed with effects and delivered by the existing durable relay. Monitor pending/oldest/dead audit records and require actual destination acknowledgements; local spool evidence does not qualify cloud delivery.

Narrative GET is read-only and never generates. Current views require current evidence and the exact desired published result. Historical revision requests are explicit. Field checks limit factual selections; every narrative remains labelled Unvalidated AI summary and has no ranking, workflow or membership authority. Investigate creates an editable question and requires normal question submission.

Deployment requires independent validation of source identity, retained evidence, database permissions, process recovery and browser behavior. The workspace has not been qualified for production deployment.
