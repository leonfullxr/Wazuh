# Disk Management

Disk-full events are the most common Wazuh Indexer emergency: once a data
node crosses the [disk watermarks](shard-management.md#disk-watermarks),
shards stop allocating and indices are eventually forced read-only, which
means **alerts stop being indexed**. This guide covers finding where the
space went, freeing it quickly, and moving or expanding storage properly.

Long-term, the real fix is a [retention policy](ilm-retention.md) sized to
your ingestion rate — everything below buys you time or capacity.

## Table of Contents

- [Finding where the space went](#finding-where-the-space-went)
- [Quick wins to free space](#quick-wins-to-free-space)
- [Moving indexer data to a new disk](#moving-indexer-data-to-a-new-disk)
- [Expanding into a new partition on the same disk](#expanding-into-a-new-partition-on-the-same-disk)
- [Moving manager archives to a new disk](#moving-manager-archives-to-a-new-disk)
- [After recovery](#after-recovery)

## Finding where the space went

Start by sizing the big directories:

```bash
du -sh /var/log/* | sort -hr | head
du -sh /var/* | sort -hr | head
```

### When `df` and `du` disagree

`df -h` reports blocks used by the **filesystem**; `du -sh DIR` only sums
what is reachable under that **one directory**. If `df` shows far more usage
than `du` can account for, something on that filesystem is holding space that
`du` cannot see. Checklist, in order of likelihood:

1. **Compare the right things.**

   ```bash
   df -hT /path/to/DIR                      # which filesystem is DIR on?
   sudo du -xhd1 /mount/point | sort -h     # top-level dirs, no crossing mounts
   ```

2. **Deleted-but-still-open files** (the classic cause — a process holds a
   file descriptor to a log that was rotated/deleted; counts in `df`, not in
   `du`):

   ```bash
   sudo lsof -nP +L1 | sort -k7 -hr | head
   sudo lsof -nP | grep '(deleted)' | sort -k7 -hr | head
   ```

   Fix by restarting the owning process, or truncate in place via
   `:> /proc/<PID>/fd/<FD>`. Common culprits: application logs, rotated
   logs, `journald`, Docker container logs.

3. **Filesystem snapshots / CoW subvolumes** — `du` does not see snapshot
   data, `df` does:

   ```bash
   sudo btrfs subvolume list -s /mount/point   # btrfs
   sudo zfs list -t snapshot -o name,used,refer | sort -k2 -h   # zfs
   ```

4. **ext4 reserved blocks** (typically 5% reserved for root):

   ```bash
   findmnt -no SOURCE /mount/point
   sudo tune2fs -l /dev/XXX | grep -E 'Block size|Reserved block (count|percentage)'
   ```

5. **systemd-journald and Docker**:

   ```bash
   journalctl --disk-usage
   sudo du -sh /var/lib/docker/* | sort -h
   docker system df -v
   sudo ls -lh /var/lib/docker/containers/*/*-json.log
   ```

6. **Inode exhaustion** — lots of tiny files can exhaust inodes while bytes
   look fine. Note `du -i` shows inode counts, **not** sizes:

   ```bash
   df -i /mount/point
   sudo du -ai --max-depth=1 /path/to/DIR | sort -n
   ```

7. **Nested mounts / bind mounts** inside the directory:

   ```bash
   findmnt -R /path/to/DIR
   sudo du -xsh /path/to/DIR    # -x: stay on one filesystem
   ```

In practice, the most common real-world fixes are: restart the process
holding a deleted log, vacuum journald, prune Docker, or adjust the ext4
reserved-block percentage.

## Quick wins to free space

When the indexer node is at the flood-stage watermark and you need headroom
*now*:

- **Vacuum the systemd journal** — archived journals routinely accumulate
  gigabytes:

  ```bash
  journalctl --disk-usage
  sudo journalctl --vacuum-size=2048M
  ```

- **Temporarily lower the ext4 root reserve** (default 5% — on a large data
  partition that is a lot of space):

  ```bash
  sudo tune2fs -m 1 /dev/<data-partition>
  ```

  Treat this as an emergency measure and **revert it** once real capacity is
  restored.

- **Delete the oldest indices** (irreversible — snapshot first if you must
  keep them):

  ```
  DELETE wazuh-alerts-4.x-<oldest-date>
  ```

- If none of that is enough, grow the LVM volume if there is free extent
  space, or move the data path to a bigger disk (next sections).

## Moving indexer data to a new disk

The primary remedy when the data partition is genuinely full. Uses a bind
mount so the indexer keeps seeing `/var/lib/wazuh-indexer`. **In a cluster,
do one node at a time** and let the cluster return to green in between.

```bash
# 1. Disable replica reallocation, flush, and stop services
curl -X PUT "https://<INDEXER_IP>:9200/_cluster/settings" -u <USERNAME> -k \
  -H 'Content-Type: application/json' -d'
{
  "persistent": { "cluster.routing.allocation.enable": "primaries" }
}'
curl -X POST "https://<INDEXER_IP>:9200/_flush" -u <USERNAME> -k
sudo systemctl stop wazuh-indexer
sudo systemctl stop filebeat        # on manager nodes shipping to this indexer

# 2. Create the new location (on the new, larger disk)
sudo mkdir -p /data/wazuh-indexer

# 3. Move the data
sudo mv /var/lib/wazuh-indexer/* /data/wazuh-indexer/

# 4. Verify
sudo ls -lah /data/wazuh-indexer/      # should show the data
sudo ls -lah /var/lib/wazuh-indexer/   # should be empty

# 5. Fix ownership and permissions
sudo chown -R wazuh-indexer:wazuh-indexer /data/wazuh-indexer
sudo chmod 750 /data/wazuh-indexer

# 6. Bind-mount the new location over the old path, persistently
echo "/data/wazuh-indexer /var/lib/wazuh-indexer none defaults,bind 0 0" \
  | sudo tee -a /etc/fstab

# 7. Point path.data at the new location in /etc/wazuh-indexer/opensearch.yml
#    path.data: /data/wazuh-indexer

# 8. Update the heap dump path in /etc/wazuh-indexer/jvm.options
#    -XX:HeapDumpPath=/data/wazuh-indexer

# 9. Reload systemd and mount
sudo systemctl daemon-reload
sudo mount -a

# 10. Verify the mount
df -h | grep wazuh-indexer
mount | grep wazuh-indexer
sudo ls -lah /var/lib/wazuh-indexer/   # shows data again through the bind mount

# 11. Start the indexer, confirm the node rejoined, re-enable allocation
sudo systemctl enable --now wazuh-indexer
curl -k -u <USERNAME> "https://<INDEXER_IP>:9200/_cat/nodes?v"
curl -X PUT "https://<INDEXER_IP>:9200/_cluster/settings" -u <USERNAME> -k \
  -H 'Content-Type: application/json' -d'
{
  "persistent": { "cluster.routing.allocation.enable": "all" }
}'
```

Do not forget step 11 — a cluster left with `allocation.enable: primaries`
will accumulate [unassigned replica shards](shard-management.md#allocation-is-disabled).

## Expanding into a new partition on the same disk

A common scenario on VMs: the hypervisor disk was grown, and the extra space
must become the indexer's data volume. Generic procedure (adapt device names
— here the new partition ends up as `/dev/sda7`):

```bash
# 0. Stop the stack and snapshot the VM first
sudo systemctl stop filebeat
sudo systemctl stop wazuh-dashboard
sudo systemctl stop wazuh-indexer

# 1. Create and format the new partition in the freed space
parted /dev/sda print free
parted /dev/sda mkpart primary ext4 <START> <END>
lsblk -fm
mkfs.ext4 /dev/sda7

# 2. Copy the data across (preserving permissions, one filesystem)
mkdir -p /mnt/wazuh-indexer
mount /dev/sda7 /mnt/wazuh-indexer
rsync -apvx /var/lib/wazuh-indexer/ /mnt/wazuh-indexer/
du -sh /var/lib/wazuh-indexer /mnt/wazuh-indexer   # sanity-check sizes match

# 3. Swap the new partition into place
mv /var/lib/wazuh-indexer /var/lib/wazuh-indexer.bck
mkdir -p /var/lib/wazuh-indexer
chown wazuh-indexer:wazuh-indexer /var/lib/wazuh-indexer
chmod 750 /var/lib/wazuh-indexer
umount /mnt/wazuh-indexer

# 4. Mount persistently by UUID, then restart the stack
blkid -s UUID -o value /dev/sda7
echo "UUID=<UUID> /var/lib/wazuh-indexer ext4 defaults 0 2" | sudo tee -a /etc/fstab
sudo mount -a
sudo systemctl start wazuh-indexer wazuh-dashboard filebeat
```

Once the cluster is green and data is confirmed intact, remove
`/var/lib/wazuh-indexer.bck` to actually reclaim the old space. If the
environment uses LVM, simply growing the logical volume and filesystem
(`lvextend` + `resize2fs`/`xfs_growfs`) is a simpler alternative.

## Moving manager archives to a new disk

Wazuh manager archives (`/var/ossec/logs/archives/`) grow fast when event
archiving is enabled and often fill the manager's disk. Same bind-mount
approach — one node at a time:

```bash
# 1. Stop services
sudo systemctl stop wazuh-manager
sudo systemctl stop filebeat

# 2. Create the new location and move the archives
sudo mkdir -p /data/wazuh-archives
sudo mv /var/ossec/logs/archives/* /data/wazuh-archives/

# 3. Permissions
sudo chown -R wazuh:wazuh /data/wazuh-archives
sudo chmod 750 /data/wazuh-archives

# 4. Bind mount
echo "/data/wazuh-archives /var/ossec/logs/archives none defaults,bind 0 0" \
  | sudo tee -a /etc/fstab
sudo systemctl daemon-reload
sudo mount -a

# 5. Verify and restart
mount | grep wazuh-archives
sudo systemctl enable --now wazuh-manager
sudo systemctl enable --now filebeat
sudo tail -f /var/ossec/logs/ossec.log   # confirm events are processing
```

## After recovery

- Keep Filebeat **stopped** on the managers until the indexer's data
  partition is back under the low watermark; consider disabling archives
  ingestion in Filebeat if you do not need it. When Filebeat restarts it will
  ship its backlog, causing an ingestion surge — make sure there is headroom.
- If indices were forced read-only by the flood-stage watermark, the block is
  released automatically once disk drops below the high watermark (on
  current versions); on older versions clear it manually:

  ```
  PUT wazuh-alerts-*/_settings
  { "index.blocks.read_only_allow_delete": null }
  ```

- Revert temporary measures (`tune2fs -m 5`, watermark overrides).
- Configure or resize the [ISM retention policy](ilm-retention.md) so this
  does not recur.
