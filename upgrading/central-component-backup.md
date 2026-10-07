# Central component backup: configuration and cold logs

A file-level backup splits into two independent tracks: a small point-in-time tarball of configuration, and a continuous incremental copy of compressed alert and archive logs to cold storage. This runbook gives the item lists, the ordering that keeps manager downtime short, and the failure modes seen in production. Reference scripts live in [scripts/central-backup](../scripts/central-backup/README.md).

> Applies to self-hosted Wazuh (single node or manager cluster on VMs or bare metal) where the manager writes `/var/ossec/logs/alerts` and `/var/ossec/logs/archives` locally and a separate backup host is reachable over SSH. Indexer snapshots and site failover are separate concerns (see [Related](#related)).

## Table of Contents

- [Two-track model](#two-track-model)
- [What to back up](#what-to-back-up)
- [What this does not cover](#what-this-does-not-cover)
- [Configuration backup design](#configuration-backup-design)
- [Log sync design](#log-sync-design)
- [Retention](#retention)
- [Failure modes and fixes](#failure-modes-and-fixes)
- [Restore](#restore)
- [Verification](#verification)
- [Related](#related)

## Two-track model

| Track | Content | Frequency | Manager stop |
|---|---|---|---|
| **Configuration** | Manager, indexer, and dashboard config files (small) | Daily or after each config change | Yes, briefly, only to copy queue DB files consistently |
| **Logs** | Finalized `*.json.gz` and `*.log.gz` under `alerts/` and `archives/` (large, growing) | Daily, at a different time than the config track | No, compressed files are already rotated and stable |

The tracks use different tools on purpose. Configuration fits in one tarball and needs a consistent DB copy. Logs are too large to re-tar every day, so they sync incrementally with rsync and a sent-files record.

## What to back up

The authoritative per-component lists live in [Pre-upgrade checklist](pre-upgrade-checklist.md#backups). The condensed set below is what the reference script covers. Append site-specific custom paths after checking each one exists on the node.

- **Manager:** `/var/ossec/api/configuration`, `/var/ossec/etc` (includes `client.keys`, `ossec.conf`, custom rules, decoders, `shared/` group config, `lists/`), queue state (`agents-timestamp`, `rids/`, `fts/`), `stats/`, `var/multigroups/`, plus `/etc/filebeat/`, `/etc/postfix/`, custom `integrations/`, `wodles/`, and `active-response/bin/` entries.
- **Queue DBs (stopped manager only):** `/var/ossec/queue/db` and `/var/ossec/var/db/global.db`. These two require the short stop/start window.
- **Indexer:** `/etc/wazuh-indexer/certs/`, `opensearch.yml`, `jvm.options`, `opensearch.keystore`, `opensearch-security/`.
- **Dashboard:** `/etc/wazuh-dashboard/certs/`, `opensearch_dashboards.yml`, `opensearch_dashboards.keystore`, `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml`.
- **Logs:** compressed files only, `*.json.gz` and `*.log.gz`, under `/var/ossec/logs/alerts` and `/var/ossec/logs/archives`. Active uncompressed `.log` and `.json` files are still being written and are picked up on a later run after rotation.

> Missing paths are normal on nodes that do not run every component. Log each skip and continue. Only fail the run when nothing at all was collected, or when the remote transfer itself fails.

## What this does not cover

- **Indexed events.** Rebuild them from the cold logs if needed. For index lifecycle and snapshot repositories, see [S3 Snapshot Repository with MinIO](../indexer/snapshots-minio.md). Snapshots record incremental index state and are not a substitute for a VM-level backup.
- **Dashboards and visualizations.** Export them manually from Management, Saved Objects. They cannot be scripted reliably into the tarball.
- **Indexer users and roles.** Stored in indices. Extract them with `securityadmin.sh` (`-r` retrieve mode) against the indexer IP from `opensearch.yml`, and store the output alongside the tarball.
- **OS-level extras.** Systemd unit overrides, crontabs, and proxy files used during install. Copy them into the tarball as reference, but reapply them by hand on restore instead of overwriting newer defaults.

## Configuration backup design

The order matters more than the tool flags:

1. Validate the remote path is writable over SSH.
2. Stop `wazuh-manager` and record the start time.
3. Tar only the paths that exist.
4. Start `wazuh-manager` immediately and record the downtime.
5. Measure the tarball size, copy it with `scp`, enforce the remote count retention, then write and email the HTML report.

Design notes:

- **Lock:** a lock file in `/tmp` makes overlapping cron runs exit early.
- **Cron environment:** use full binary paths (`/sbin/sendmail`, `/usr/bin/sshpass`, `/bin/tar`, `/usr/bin/du`, `/usr/bin/df`, `/usr/bin/awk`, `/usr/bin/tee`). Interactive shells find these on `PATH`, cron often does not.
- **FIPS hosts:** add the compliant key-exchange override to SSH and SCP when `/proc/sys/crypto/fips_enabled` reports `1`. Keep the cipher set aligned with local policy.
- **No prompts:** never call `read` for a restore confirmation inside a cron script. Gate auto-restore behind an `AUTO_RESTORE` variable that defaults to `no`.
- **Email:** pipe through `sendmail -t` with `MIME-Version: 1.0` and `Content-Type: text/html` headers. Without those headers the report arrives as raw markup.

```bash
./wazuh_config_backup.sh --selftest
REMOTE_HOST=192.0.2.10 REMOTE_USER=backup REMOTE_PASS='secret' \
  ./wazuh_config_backup.sh
```

## Log sync design

The log script scans both log trees, skips anything already recorded in the sent log, and rsyncs the remainder with `--files-from`:

- **Compressed only:** the `find` filter matches `*.json.gz` and `*.log.gz`. This is what makes a no-stop copy safe.
- **Fingerprint:** each sent file is recorded as `absolute-path:mtime`. Path alone is not enough because rotation reuses names, and mtime alone is not enough across directories.
- **Size capture:** file sizes for the email report are read before rsync runs, because `--remove-source-files` may delete the source right after a successful transfer.
- **Destinations:**
  - `RESTORE=yes` writes back to the original paths on the remote host (`/var/ossec/logs/alerts`, `/var/ossec/logs/archives`). Use this only when the remote host is a staged restore target.
  - `RESTORE=no` writes under a staging base such as `/backup/wazuh-logs/alerts` and `/backup/wazuh-logs/archives`.
- **Source removal:** `REMOVE=yes` adds `--remove-source-files` so the manager disk stays bounded. `REMOVE=no` keeps sources for local search.
- **Statuses:** every run emails one of three statuses. `SUCCESS` means files moved, `NO FILES FOUND` means nothing new was pending (the normal steady state after catch-up), `FAILED` means SSH or rsync failed and nothing was marked as sent.

```bash
./wazuh_log_sync.sh --selftest
./wazuh_log_sync.sh --remote-host 192.0.2.10 --remote-user backup \
  --restore no --remove no
```

> If logs for a date range never arrive but the script reports success, check whether the remote files were deleted or the remote path was changed after a first sync. The local sent log still considers those files delivered, so later runs skip them. Truncating the sent log forces a full rescan on the next run.

## Retention

Keep two independent policies, one for the manager and one for the cold host:

```bash
# Manager hot logs older than one year (adjust to local policy)
0 0 * * * find /var/ossec/logs/alerts/ -type f -mtime +365 -exec rm -f {} \;
0 0 * * * find /var/ossec/logs/archives/ -type f -mtime +365 -exec rm -f {} \;

# Cold host copies older than 100 days
45 3 * * * find /backup/wazuh-logs/alerts/ -type f -mtime +100 -exec rm -f {} \;
45 3 * * * find /backup/wazuh-logs/archives/ -type f -mtime +100 -exec rm -f {} \;
```

For config tarballs the reference script keeps the newest `RETENTION_COUNT` archives (default `3`) with `ls -1t` plus `tail`, and lists what it deleted in the email report. Once cold copies exist, align filesystem cleanup with [Alert and archive retention](../scripts/policy-deletion/README.md).

## Failure modes and fixes

| Symptom | Cause | Fix |
|---|---|---|
| **Manager down for an hour or more during backup** | A `tar -tzf` integrity listing loop ran while the manager was still stopped | Restart the manager right after the tarball is written, run any verification after the restart |
| **Email arrives as raw HTML markup** | Report piped to mail without MIME headers | Send with `MIME-Version: 1.0` and `Content-Type: text/html` via `sendmail -t` |
| **Script works by hand, fails from cron** | Bare binary names or missing env under cron | Use full paths for every binary, set required variables in the crontab or an env file |
| **SSH fails with a key-exchange error against an older peer** | Peer offers only legacy KEX algorithms | Add the matching `-o KexAlgorithms` override, scoped to that host, and review cipher policy |
| **Every run reports FAILED over one missing path** | A hardcoded path does not exist on that node role | Check existence per item, skip with a warning, fail only when nothing was collected or the transfer failed |
| **A date range never arrives, script reports success** | Stale sent-log entries after remote deletion or a remote path change | Truncate the sent log and rerun to force a rescan, then verify the remote destination matches the `RESTORE` setting |
| **Remote disk fills despite retention** | Retention counted an empty `ls` or ran only on success path | Count with `sed` filtered empty lines, run retention only after a confirmed transfer, include deletions in the report |

## Restore

1. Install the same Wazuh version on the target host first.
2. Copy customizations from the tarball, not whole default files. Merging an old `ossec.conf` over newer defaults can reintroduce removed options.
3. Restore ownership (`root:wazuh`) and service permissions, then restart the manager.
4. Recreate indexer users and roles from the `securityadmin.sh` output, re-register any snapshot repository, and import dashboard objects manually.
5. Rebuild recent indices from the cold logs if the outage window needs searching.

Practice this on an isolated VM before relying on it. A VM-level snapshot remains the fastest recovery path; this file backup is the slower but portable second layer.

## Verification

- Both reference scripts pass `--selftest` (ordering, compressed-only filter, sent-log, MIME header).
- A manual config run emails `SUCCESS` with a nonzero tarball size and the remote host shows one new `backup_*.tar.gz`.
- A manual log run emails `SUCCESS` on first catch-up and `NO FILES FOUND` on immediate rerun.
- Manager downtime in the config report is seconds or low minutes, not hours.
- A trial restore on a lab host starts all services and a test agent enrolls into the correct group.

## Related

- [Reference scripts](../scripts/central-backup/README.md) - usage, variables, cron lines, deliberate simplifications
- [Pre-upgrade checklist](pre-upgrade-checklist.md#backups) - authoritative per-component path lists
- [Disaster recovery](disaster-recovery.md) - active/passive site failover and failback, which file backups alone do not provide
- [S3 Snapshot Repository with MinIO](../indexer/snapshots-minio.md) - indexer snapshot repositories and space reclamation
- [Alert and archive retention](../scripts/policy-deletion/README.md) - filesystem and indexer cleanup once cold copies exist
- [Postfix email delivery](../troubleshooting/server/postfix-email.md) - diagnosing relay failures when reports never arrive
- [Creating a backup](https://documentation.wazuh.com/current/user-manual/manager/backup.html) - official central components procedure
- [Restoring Wazuh from backup](https://documentation.wazuh.com/current/user-manual/manager/restore-backup.html) - official restore procedure
