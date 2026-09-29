# S3 Snapshot Repository with MinIO

The Wazuh Indexer stores snapshots in any S3-compatible object store, and
MinIO is the usual self-hosted choice. This guide adds the credentials to the
indexer keystore and registers the repository. It also explains why bucket
usage does not fall when snapshots are deleted. That second part is why most
people open this page: snapshot retention frees space in the cluster and
appears to free nothing in MinIO.

> Applies to a self-hosted Wazuh Indexer (OpenSearch) with a reachable MinIO
> server. Run the commands on every indexer node unless noted otherwise.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Procedure](#procedure)
  - [1. Add the credentials to the keystore](#1-add-the-credentials-to-the-keystore)
  - [2. Reload secure settings and register the repository](#2-reload-secure-settings-and-register-the-repository)
  - [3. Take a first snapshot](#3-take-a-first-snapshot)
- [Why MinIO disk usage does not fall](#why-minio-disk-usage-does-not-fall)
- [Audit the bucket with the MinIO client](#audit-the-bucket-with-the-minio-client)
- [Reclaim the space with a lifecycle rule](#reclaim-the-space-with-a-lifecycle-rule)
- [Verification](#verification)
- [Related](#related)

## Prerequisites

- A MinIO server reachable from every indexer node on the S3 API port, `9000`
  by default.
- An S3 access key pair for a dedicated MinIO user. Do not reuse the console
  administrator account for snapshots.
- A bucket, for example `wazuh`.
- Indexer API credentials with permission to manage cluster settings.
- The `repository-s3` plugin. If registration fails with an unknown
  repository type, install it and restart the indexer:

  ```bash
  sudo /usr/share/wazuh-indexer/bin/opensearch-plugin install repository-s3
  sudo systemctl restart wazuh-indexer
  ```

## Procedure

### 1. Add the credentials to the keystore

The keystore is the only supported location for these values. Run both
commands on every indexer node and paste the key when prompted:

```bash
/usr/share/wazuh-indexer/bin/opensearch-keystore add s3.client.default.access_key
/usr/share/wazuh-indexer/bin/opensearch-keystore add s3.client.default.secret_key
```

If you ran the commands as root, the file owner changes and the service can
no longer read the keystore at startup. Restore the ownership and the
permissions:

```bash
sudo chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/opensearch.keystore
sudo chmod 660 /etc/wazuh-indexer/opensearch.keystore
```

> Do not write the secret key into `opensearch.yml`, a systemd unit, or a
> script in the repository. All three end up in version control or in a world
> readable file sooner or later.

### 2. Reload secure settings and register the repository

Reloading makes the cluster pick up the new keystore values without a
restart:

```bash
curl -k -u "<INDEXER_USERNAME>:<INDEXER_PASSWORD>" \
  -X POST "https://<INDEXER_IP>:9200/_nodes/reload_secure_settings"
```

Then register the repository:

```bash
curl -k -u "<INDEXER_USERNAME>:<INDEXER_PASSWORD>" \
  -X PUT "https://<INDEXER_IP>:9200/_snapshot/wazuh?pretty" \
  -H "Content-Type: application/json" -d '{
  "type": "s3",
  "settings": {
    "bucket": "wazuh",
    "endpoint": "http://<MINIO_IP>:9000",
    "protocol": "http",
    "region": "us-east-1",
    "path_style_access": true
  }
}'
```

Read the repository back to confirm:

```bash
curl -k -u "<INDEXER_USERNAME>:<INDEXER_PASSWORD>" \
  "https://<INDEXER_IP>:9200/_snapshot/wazuh?pretty"
```

| Setting | Why it is there |
|---|---|
| `endpoint` and `protocol` | MinIO listens on plain HTTP on port `9000` in most labs. Terminate TLS in front of it for production and change `protocol` to `https` |
| `region` | The S3 client rejects an empty region. Any value works with MinIO, and `us-east-1` is the convention |
| `path_style_access` | MinIO uses path-style addresses. Without it the client tries virtual-host style and fails on a bare IP address |

### 3. Take a first snapshot

```bash
curl -k -u "<INDEXER_USERNAME>:<INDEXER_PASSWORD>" \
  -X PUT "https://<INDEXER_IP>:9200/_snapshot/wazuh/snapshot-0001?wait_for_completion=false"
```

Check the progress and the list of stored snapshots:

```bash
curl -k -u "<INDEXER_USERNAME>:<INDEXER_PASSWORD>" \
  "https://<INDEXER_IP>:9200/_snapshot/wazuh/_status?pretty"
curl -k -u "<INDEXER_USERNAME>:<INDEXER_PASSWORD>" \
  "https://<INDEXER_IP>:9200/_cat/snapshots/wazuh?v"
```

The bucket must now contain objects. If it does not, read the indexer log at
`/var/log/wazuh-indexer/*.log` before going further.

## Why MinIO disk usage does not fall

Snapshot retention and cleanup jobs remove old snapshots from the cluster,
and the cluster reports the deletions as successful. The physical disk usage
on the MinIO server does not fall.

The root cause is bucket versioning. When versioning is enabled on the
bucket, deleting an object does not remove its data. MinIO writes a delete
marker, which hides the object from normal listings, and keeps every earlier
version on disk. The indexer sees the snapshot as gone. The object versions
are still there and still consume space.

Two details make this confusing in practice:

- MinIO consoles and `mc` often show the logical size of the current
  versions, so the bucket looks empty while the disk is not.
- The lifecycle scanner runs on its own schedule, so reclaimed space appears
  later than the deletion itself.

## Audit the bucket with the MinIO client

List every version, including the hidden ones:

```bash
mc ls --versions --recursive local/wazuh/
```

Output of that shape:

```text
[2026-07-15 11:24:02 UTC]      0B STANDARD v3 DEL index-1
[2026-07-15 11:15:30 UTC]      0B STANDARD v2 DEL index-1
[2026-07-10 09:02:11 UTC]     84MB STANDARD null v1 PUT index-1
[2026-07-15 11:24:02 UTC]      0B STANDARD v2 DEL metadata-snapshot
[2026-07-10 09:02:10 UTC]     15MB STANDARD null v1 PUT metadata-snapshot
```

The `DEL` rows are delete markers. The older `PUT` rows are the versions
that hold the space. This is the evidence that separates a failed deletion
from a deferred one.

Also confirm from the cluster side that the snapshot really is gone:

```bash
curl -k -u "<INDEXER_USERNAME>:<INDEXER_PASSWORD>" \
  "https://<INDEXER_IP>:9200/_snapshot/wazuh/_all?pretty"
```

## Reclaim the space with a lifecycle rule

A lifecycle rule on the bucket removes both the markers and the versions
they hide.

In the MinIO Console, open **Buckets**, select the `wazuh` bucket, open
**Lifecycle Rules**, and add a rule with these settings:

| Setting | Value |
|---|---|
| Rule name | `purge-deleted-snapshots` |
| Scope | All objects in the bucket |
| Expired object delete markers | Enabled |
| Noncurrent version expiration | Expire noncurrent versions after 1 day |

The sequence after the rule is in place:

1. The indexer deletes a snapshot during its cleanup job.
2. MinIO writes a delete marker for each object of that snapshot.
3. The lifecycle scanner removes the noncurrent version behind the marker
   during the next run.
4. Physical space returns to the pool.

Two alternatives, with their trade-offs:

- **Disable versioning on the bucket.** Deletes free space immediately and
  no lifecycle rule is needed. You also lose the protection that keeps an
  accidental overwrite or delete from destroying the repository.
- **Keep versioning and add the rule.** Deletes stay recoverable for the
  configured day, and space returns on the lifecycle schedule. This is the
  safer default for a backup target.

The rule does not touch current versions, so snapshots that the cluster
still lists are safe.

## Verification

1. Delete an old snapshot through the cluster API or the dashboard:

   ```bash
   curl -k -u "<INDEXER_USERNAME>:<INDEXER_PASSWORD>" \
     -X DELETE "https://<INDEXER_IP>:9200/_snapshot/wazuh/snapshot-0001"
   ```

2. Run `mc ls --versions --recursive local/wazuh/` again. The `DEL` markers
   for that snapshot are present.
3. Wait for the lifecycle scan to run. With noncurrent versions set to one
   day, allow up to about a day before judging the result.
4. Run the same `mc ls` command. The `PUT` versions behind those markers are
   gone.
5. Compare `mc admin info local/` before and after. The usage figure falls
   only after step 4.
6. Confirm that a new snapshot still completes. Restore one snapshot into a
   test indexer and check that the data is intact.

## Related

- [Indexer hub](README.md) - quick reference and diagnostic commands
- [Disk management](disk-management.md) - finding space on the indexer nodes
  themselves
- [ISM retention](ilm-retention.md) - how long snapshots are worth keeping
- [Cluster topology](cluster-topology.md) - snapshot strategy for HA clusters
- [Wazuh: Migrating Wazuh indices](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/migrating-wazuh-indices.html)
- [OpenSearch: Register snapshot repository](https://docs.opensearch.org/latest/install-and-configure/opensearch/snapshots/index/)
