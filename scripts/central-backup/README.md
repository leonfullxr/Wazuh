# Central component backup scripts

Two cron-friendly scripts that split a Wazuh backup into independent tracks.
For the full runbook, including what to back up, what to leave out, restore
steps, and failure modes, see
[central-component-backup.md](../../upgrading/central-component-backup.md).

- **Configuration track** - `wazuh_config_backup.sh` takes a point-in-time
  tarball of manager, indexer, and dashboard configuration, copies it to a
  remote host with `scp`, keeps the newest `RETENTION_COUNT` archives there,
  and emails an HTML report.
- **Log track** - `wazuh_log_sync.sh` incrementally syncs only finalized
  compressed logs (`*.json.gz`, `*.log.gz`) from
  `/var/ossec/logs/alerts` and `/var/ossec/logs/archives` with rsync, records
  what was sent in a fingerprint file, and emails an HTML report with one of
  three statuses: `SUCCESS`, `NO FILES FOUND`, or `FAILED`.

## Usage

1. Copy both scripts to the manager (for example `/opt/wazuh-backup/`) and
   make them executable:

   ```bash
   chmod +x wazuh_config_backup.sh wazuh_log_sync.sh
   ```

2. Verify the structure without touching the network:

   ```bash
   ./wazuh_config_backup.sh --selftest
   ./wazuh_log_sync.sh --selftest
   ```

3. Set the remote destination. Environment variables or CLI flags both work:

   ```bash
   REMOTE_HOST=192.0.2.10 REMOTE_USER=backup REMOTE_PASS='secret' \
     ./wazuh_config_backup.sh
   ./wazuh_log_sync.sh --remote-host 192.0.2.10 --remote-user backup \
     --restore no --remove no
   ```

4. Schedule them at different times so they do not contend on the network:

   ```
   0 1 * * * /opt/wazuh-backup/wazuh_config_backup.sh >/dev/null 2>&1
   30 1 * * * /opt/wazuh-backup/wazuh_log_sync.sh >/dev/null 2>&1
   ```

## Configuration

| Variable | Meaning |
|---|---|
| **REMOTE_HOST, REMOTE_USER, REMOTE_PASS** | Backup host reachable over SSH, with write access to the destination path |
| **REMOTE_BACKUP_PATH** | Destination directory for config tarballs (default `/backup/wazuh-backup`) |
| **STAGING_DIR** | Destination base for log sync when `RESTORE=no` (default `/backup/wazuh-logs`) |
| **RETENTION_COUNT** | How many config tarballs to keep on the remote host (default `3`) |
| **RESTORE** | `yes` writes logs back to their original paths on the remote host, `no` writes to `STAGING_DIR` |
| **REMOVE** | `yes` deletes each source log after a successful rsync, `no` keeps it |
| **EMAIL_TO, EMAIL_FROM** | Report sender and recipient (requires `sendmail`) |
| **AUTO_RESTORE** | Config track only: `yes` extracts the tarball on the remote host, default `no` |

Prefer passing secrets through the environment or a restricted env file
rather than editing them into the script. Keep `AUTO_RESTORE=no` unless a
dedicated restore host is the explicit target.

## Deliberate simplifications

- **Item lists are minimal.** They cover the paths that exist on a standard
  deployment. Append site-specific custom paths (custom active-response
  binaries, CDB lists, integrations, wodles) after verifying each one exists.
- **No tar integrity gate inside the stopped window.** The reference script
  restarts the manager immediately after the tarball is written. A
  `tar -tzf` listing loop on a large archive held the manager stopped for a
  long time in production; run any verification after the restart.
- **Password SSH via sshpass.** The scripts use `sshpass` to stay close to
  the field-tested version. For long-lived use, prefer key-based SSH and
  remove the password variables.
- **FIPS handling is minimal.** Only the key-exchange override needed for
  legacy peers is included. Harden the cipher selection for the local policy
  before production use.

## Related

- [Central component backup](../../upgrading/central-component-backup.md) -
  the full runbook: ordering, retention, email, failure modes, restore
- [Pre-upgrade checklist](../../upgrading/pre-upgrade-checklist.md#backups) -
  authoritative per-component path lists
- [Disaster recovery](../../upgrading/disaster-recovery.md) - site failover,
  which needs more than file backups
- [Alert and archive retention](../policy-deletion/README.md) - filesystem
  and indexer cleanup once cold copies exist
