# Mount Permissions: Running Wazuh under a noexec /var

Hardening baselines (CIS and similar) often mount `/var` with the `noexec` option. Wazuh installs its binaries under `/var/ossec/bin`, so this breaks the agent (and the manager, which lives in the same tree).

## Table of Contents

- [Impact](#impact)
- [Solution: mount /var/ossec with exec](#solution-mount-varossec-with-exec)
- [Summary](#summary)

## Impact

If `/var` is (re)mounted `noexec`, **the Wazuh agent stops working immediately**: the kernel blocks execution of the binaries and libraries under `/var/ossec/bin`, the service fails to start, and future upgrades will fail as well.

## Solution: mount /var/ossec with exec

Comply with the hardening policy on `/var` while carving out `/var/ossec` as a separate mount point with `exec` permissions, overriding the parent restriction.

1. Stop the agent:

   ```bash
   systemctl stop wazuh-agent
   ```

2. Make `/var/ossec` its own mount point:

   - **Option A (recommended):** with free space or LVM available, create a dedicated logical volume/partition and mount it at `/var/ossec`.
   - **Option B (workaround):** bind-mount the directory onto itself with the `exec` flag.

3. Persist it in `/etc/fstab` so the mount survives reboots (adjust the device or source path as needed):

   ```
   # Bind-mount workaround: remount /var/ossec over itself with exec
   /var/ossec  /var/ossec  none  defaults,bind,exec  0 0
   ```

4. Apply the mount:

   ```bash
   mount -a
   # or specifically:
   mount -o remount,exec /var/ossec
   ```

5. Start the agent:

   ```bash
   systemctl start wazuh-agent
   ```

Verify with `findmnt /var/ossec` — the options column must include `exec` (i.e. must not show `noexec`).

## Summary

A `noexec` parent `/var` is fatal for Wazuh. The clean fix is a dedicated `exec` mount at `/var/ossec` — either a real volume or a self bind mount — persisted in `/etc/fstab`. The same technique applies on manager nodes, and is closely related to moving Wazuh data onto a new disk (see the indexer/storage guides in [`../../indexer/`](../../indexer/)).
