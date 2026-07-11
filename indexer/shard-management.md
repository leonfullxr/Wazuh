# Shard Management

Shard sizing and allocation are the single biggest lever on Wazuh Indexer
performance and stability. This guide covers sizing rules, how to change the
shard count, and how to diagnose and fix red/yellow cluster states and
unassigned shards.

## Table of Contents

- [Sizing guidelines](#sizing-guidelines)
- [Worked example: resizing oversized shards](#worked-example-resizing-oversized-shards)
- [Increasing the number of primary shards](#increasing-the-number-of-primary-shards)
- [Monitoring shard count](#monitoring-shard-count)
- [Cluster health: red and yellow states](#cluster-health-red-and-yellow-states)
- [Diagnosing unassigned shards](#diagnosing-unassigned-shards)
- [Disk watermarks](#disk-watermarks)
- [Manually rerouting shards](#manually-rerouting-shards)
- [References](#references)

## Sizing guidelines

There are trade-offs in both directions. More shards means more cluster-state
and heap overhead just to maintain them; larger shards take longer to move
when the cluster rebalances or recovers. Querying many small shards is faster
per shard but adds per-query overhead; fewer larger shards can be faster
overall. As a starting point for time-based data such as Wazuh alerts:

- **Aim for an average shard size of 20-40 GB**, and keep shards **under
  50 GB**. Oversized shards cause increased memory and CPU usage on data
  nodes, longer query response times, slow recovery and rebalancing, and
  performance bottlenecks during ingestion.
- **Avoid the "gazillion shards" problem.** The number of shards a node can
  hold is proportional to its heap. As a rule of thumb, keep it **below 20
  shards per GB of JVM heap** on each node.
- **Low-volume environments (under ~100 GB/day per index):** the opposite
  problem. Daily indices produce many tiny shards. Consider merging several
  days into one index (weekly/monthly rollover, or reindexing old daily
  indices together) to reduce index count. Perform merges during low-activity
  windows to avoid disturbing ingestion.

References: [Wazuh indexer tuning — shards and replicas](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-tuning.html#shards-and-replicas),
[Elastic — Size your shards](https://www.elastic.co/docs/deploy-manage/production-guidance/optimize-performance/size-shards).

## Worked example: resizing oversized shards

A common failure mode in large environments: `wazuh-alerts` daily indices
ingest ~1.5 TB/day with the default-ish 12 primary shards, producing shards of
roughly **150 GB each** — three times the recommended maximum. The fix is to
raise the primary shard count so shards land in the target range:

- 1.5 TB / 36 shards ≈ **41.6 GB per shard** — within the recommended limit.
- With 12 data nodes, 36 shards distribute evenly at 3 primaries per node.

After the change, expect improvements only gradually: old oversized indices
remain until [retention policies](ilm-retention.md) delete them (or you
[reindex](reindexing.md) them). During that window, monitor indexing speed,
search latency, node resource utilization and overall cluster health. If
problems persist after old indices have aged out, the indexing architecture
itself (index rotation scheme, node count, heap sizing) needs a redesign.

## Increasing the number of primary shards

The shard count for **new** indices is set in the Filebeat-managed index
template on the Wazuh manager:

1. SSH into the Wazuh manager and back up the template:

   ```bash
   cd /etc/filebeat
   cp wazuh-template.json wazuh-template.json.bak
   ```

2. Edit `wazuh-template.json` and change the shard count, e.g.:

   ```json
   "index.number_of_shards": 36
   ```

3. Upload the template and restart Filebeat:

   ```bash
   filebeat setup --index-management
   systemctl restart filebeat
   ```

The new setting takes effect **from the next daily index onward** — the
current day's index was already created with the old settings, which live in
the indexer itself. To apply the new shard count to existing indices you must
[reindex them](reindexing.md); the number of primary shards cannot be changed
on a live index.

## Monitoring shard count

Each node can hold a limited number of shards
(`cluster.max_shards_per_node`, default 1000). Approaching the limit blocks
new index creation — which for Wazuh means alerts stop being indexed at
midnight when the next daily index is due.

You can create an OpenSearch Alerting monitor that fires when the active
shard count reaches ~85% of your cluster-wide maximum. Use a query against
`_cluster/health` (or a cluster metrics monitor) with a trigger condition
such as:

```
ctx.results[0].active_shards > 1000
```

Adjust the threshold to 85% of `max_shards_per_node * number_of_data_nodes`.

## Cluster health: red and yellow states

```
GET _cluster/health
```

| Status | Meaning | Impact |
|---|---|---|
| green | All primary and replica shards assigned | Normal |
| yellow | All primaries assigned, one or more replicas unassigned | Data intact, no redundancy on affected indices |
| red | At least one primary shard unassigned | Data in that shard is unavailable; writes to it fail |

Common causes and fixes:

- **Yellow on a single-node cluster** — replicas can never be assigned
  because a replica may not live on the same node as its primary. Set
  replicas to 0; see [Replicas](replicas.md).
- **Yellow on `.opendistro-*` system indices** — same root cause; these
  indices default to 1 replica. See [Replicas](replicas.md) for settings,
  templates, and an ISM policy that fixes this permanently.
- **Red after a node loss or disk-full event** — diagnose with the allocation
  explain API below; free disk first if watermarks are the cause.

## Diagnosing unassigned shards

List unassigned shards and their reason:

```bash
curl -k -u <USERNAME>:<PASSWORD> \
  "https://<INDEXER_IP>:9200/_cat/shards?h=index,shard,prirep,state,unassigned.reason" \
  | grep UNASSIGNED
```

Ask the cluster *why* it will not allocate a shard — this is the single most
useful API for shard problems:

```bash
curl -k -u <USERNAME>:<PASSWORD> \
  "https://<INDEXER_IP>:9200/_cluster/allocation/explain?pretty"
```

Wider context (Dev Tools console):

```
GET _cluster/stats
GET _cat/shards?v=true&h=index,shard,prirep,state,node,unassigned.reason&s=state
GET _cat/nodes?v&h=name,heap.percent,ram.percent,ram.max,load_1m
GET _nodes/stats/os,process,jvm
GET _nodes/stats/fs
GET _cat/recovery?v&active_only=true

# Effective settings of an index / the cluster
GET <index-name>/_settings?flat_settings=true&include_defaults=true
GET _cluster/settings?flat_settings=true&include_defaults=true
```

### Allocation is disabled

If `allocation/explain` reports that no allocations are allowed, shard
allocation was disabled (typically for maintenance — e.g. the
[move-data-to-a-new-disk procedure](disk-management.md#moving-indexer-data-to-a-new-disk)
sets it to `primaries`) and never re-enabled:

```
PUT _cluster/settings
{
  "persistent": {
    "cluster.routing.allocation.enable": "all"
  }
}
```

Also check for a per-index allocation block:

```
PUT <index>/_settings
{ "index.routing.allocation.disable_allocation": false }
```

## Disk watermarks

The most frequent cause of unassigned shards. Once a node's disk usage
crosses the **low watermark** (default **85%** used), the cluster stops
assigning new shards to it. At the high watermark (default 90%) it actively
relocates shards away, and at the flood stage (default 95%) indices with a
shard on that node are forced read-only.

Check disk usage and shard distribution per node:

```bash
curl -k -u <USERNAME>:<PASSWORD> "https://<INDEXER_IP>:9200/_cat/allocation?v"
```

**Fix the disk first** — see [Disk management](disk-management.md). If your
nodes have large disks (multiple TB), the default 85% may be unnecessarily
conservative — 15% of a 5 TB disk is a lot of headroom. You can raise it:

```
PUT _cluster/settings
{
  "transient": {
    "cluster.routing.allocation.disk.watermark.low": "90%"
  }
}
```

Use `persistent` instead of `transient` (or the configuration file) to
survive restarts. Important subtlety from the
[official documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/disk-allocator.html):
**percentage values refer to *used* disk space, while byte values refer to
*free* disk space.**

## Manually rerouting shards

For explicit control over shard placement, use the cluster reroute API.
Move a shard between nodes:

```
POST _cluster/reroute
{
  "commands": [
    {
      "move": {
        "index": "<index-name>",
        "shard": 0,
        "from_node": "<node-1>",
        "to_node": "<node-2>"
      }
    }
  ]
}
```

As a **last resort** for a red index whose primary shard data is genuinely
lost (e.g. the node's disk is gone), you can allocate an empty primary. This
**permanently discards whatever data was in that shard**:

```
POST _cluster/reroute
{
  "commands": [
    {
      "allocate_empty_primary": {
        "index": "<index-name>",
        "shard": <shard-number>,
        "node": "<node-name>",
        "accept_data_loss": true
      }
    }
  ]
}
```

Only use this after `allocation/explain` confirms no node holds a copy of the
shard, and prefer restoring from a snapshot if one exists.

## References

- [Wazuh indexer tuning](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-tuning.html)
- [Elastic — Size your shards](https://www.elastic.co/docs/deploy-manage/production-guidance/optimize-performance/size-shards)
- [Elastic — How many shards should I have in my Elasticsearch cluster?](https://www.elastic.co/blog/how-many-shards-should-i-have-in-my-elasticsearch-cluster)
- [Elastic — Cluster reroute API](https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-reroute.html)
- [Elastic — Disk-based shard allocation](https://www.elastic.co/guide/en/elasticsearch/reference/current/disk-allocator.html)
