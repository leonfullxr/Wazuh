# Reindexing Wazuh Indices

Some changes cannot be applied to a live index: fixing a field mapping
conflict, or applying a new
[primary shard count](shard-management.md#increasing-the-number-of-primary-shards)
to historical indices. In both cases you update the **index template** first
and then copy the data into a fresh index with `_reindex`.

## Table of Contents

- [Step 1: Name the destination index carefully](#step-1-name-the-destination-index-carefully)
- [Step 2: Pre-tune the destination index](#step-2-pre-tune-the-destination-index)
- [Step 3: Run the optimized reindex](#step-3-run-the-optimized-reindex)
- [Step 4: Post-reindex cleanup](#step-4-post-reindex-cleanup)
- [Alternative: re-ingesting archived logs with Filebeat](#alternative-re-ingesting-archived-logs-with-filebeat)

## Step 1: Name the destination index carefully

Templates apply **by index name pattern**. After updating the template (e.g.
changing a field mapping from `keyword` to `long`), the destination index
must match the template's pattern — usually `wazuh-alerts-4.x-*`. If you
reindex into a name like `backup-2023`, the template will not apply and the
indexer will dynamically map the field right back to the wrong type.

The pragmatic convention: append `-reindexed` to the original name.

- Old index: `wazuh-alerts-4.x-2023.10.01`
- New index: `wazuh-alerts-4.x-2023.10.01-reindexed`

Because the Wazuh dashboards query with the wildcard pattern
`wazuh-alerts-*`, the `-reindexed` index is picked up automatically — no
saved objects need touching.

## Step 2: Pre-tune the destination index

Create the destination with heavy-write settings so the copy is not throttled
by refreshes, replication and synchronous translog writes:

```
PUT /wazuh-alerts-4.x-2023.10.01-reindexed
{
  "settings": {
    "index.number_of_replicas": 0,
    "index.refresh_interval": "-1",
    "index.translog.durability": "async"
  }
}
```

Because the name matches `wazuh-alerts-4.x-*`, the index inherits the
corrected mappings (and shard count) from the updated template at creation
time.

## Step 3: Run the optimized reindex

Use `slices=auto` to parallelize across shards/cores and a larger batch size:

```
POST /_reindex?slices=auto&wait_for_completion=false
{
  "source": {
    "index": "wazuh-alerts-4.x-2023.10.01",
    "size": 5000
  },
  "dest": {
    "index": "wazuh-alerts-4.x-2023.10.01-reindexed"
  }
}
```

`wait_for_completion=false` returns a **task ID** immediately so the console
does not time out on large indices. Track progress with:

```
GET /_tasks/<task_id>
```

## Step 4: Post-reindex cleanup

Restore standard settings so the new index is searchable and redundant again:

```
PUT /wazuh-alerts-4.x-2023.10.01-reindexed/_settings
{
  "index.number_of_replicas": 1,
  "index.refresh_interval": "1s",
  "index.translog.durability": "request"
}
```

Verify the document counts match between source and destination
(`GET _cat/indices/wazuh-alerts-4.x-2023.10.01*?v`), then delete the old
index:

```
DELETE /wazuh-alerts-4.x-2023.10.01
```

Repeat per historical index. Weigh the effort against simply letting
[retention](ilm-retention.md) age the old indices out — reindexing months of
daily indices is expensive.

## Alternative: re-ingesting archived logs with Filebeat

If instead of copying between indices you are making Filebeat on the Wazuh
manager re-read archived logs (`alerts.json`) and ship them fresh to the
indexer, tune Filebeat's output in `/etc/filebeat/filebeat.yml` so the
backfill is not bottlenecked by the defaults:

```yaml
output.elasticsearch:
  hosts: ["https://<INDEXER_IP>:9200"]
  # ... auth settings ...
  worker: 4            # parallel output workers
  bulk_max_size: 2048  # events per bulk request
```

Then restart Filebeat:

```bash
systemctl restart filebeat
```

Revert to the defaults after the backfill — permanently oversized bulk
requests increase memory pressure on both Filebeat and the indexer.
