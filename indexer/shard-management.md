# Shard Management

Shard sizing and allocation are the single biggest lever on Wazuh Indexer
performance and stability. This guide covers sizing rules, how to change the
shard count, and how to diagnose and fix red/yellow cluster states and
unassigned shards.

## Table of Contents

- [Sizing guidelines](#sizing-guidelines)
- [Worked example: resizing oversized shards](#worked-example-resizing-oversized-shards)
- [Worked example: planning shard count for retention and many sources](#worked-example-planning-shard-count-for-retention-and-many-sources)
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

- Aim for an average shard size of 20-40 GB, and keep shards under
  50 GB. Oversized shards cause increased memory and CPU usage on data
  nodes, longer query response times, slow recovery and rebalancing, and
  performance bottlenecks during ingestion.
- **Avoid the "gazillion shards" problem.** As a conservative planning
  ceiling, keep the total of primary and replica shards below 20 per GB of
  JVM heap on each data node. This is a legacy operational rule of thumb,
  not an OpenSearch hard limit; benchmark the OpenSearch version bundled with
  Wazuh and monitor heap pressure, cluster-manager latency, and recovery time.
- **Low-volume environments:** if a daily primary shard remains far below the
  target range, daily indices create unnecessary cluster-state and heap
  overhead. Consider a longer index period or a tested size/age rollover
  design. Do not raise `cluster.max_shards_per_node` to compensate for
  oversharding.

Measure the current distribution before changing the template:

```http
GET _cat/indices/wazuh-alerts-*?v&h=index,pri,rep,docs.count,pri.store.size&s=index:desc
GET _cat/shards/wazuh-alerts-*?v&h=index,shard,prirep,state,store,node&s=store:desc
GET _cat/nodes?v&h=name,heap.max,heap.percent,disk.used_percent,node.role
```

Calculate both budgets:

```text
estimated primaries = ceil(expected primary bytes per index / target shard bytes)
total shards = primary shards * (1 + number_of_replicas)
```

Prefer a primary count that distributes evenly across the data nodes without
creating tiny shards. Re-evaluate after changing ingestion volume, node count,
heap size, replica count, or index period.

References: [Wazuh indexer tuning - shards and replicas](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-tuning.html#shards-and-replicas),
[Elastic - Size your shards](https://www.elastic.co/docs/deploy-manage/production-guidance/optimize-performance/size-shards).

## Worked example: resizing oversized shards

A common failure mode in large environments: `wazuh-alerts` daily indices
ingest about 1.5 TB/day with 12 primary shards, producing shards of roughly
125 GB each. Compare candidate counts before changing the template:

- 1.5 TB / 36 shards is about 42 GB per shard and distributes as three
  primaries per node on a 12-node cluster.
- 1.5 TB / 48 shards is about 31 GB per shard and distributes as four
  primaries per node.

Both are below 50 GB, but 48 is inside the initial target range at the cost of
more shard overhead. Benchmark ingestion, search, and recovery on the actual
hardware rather than choosing from arithmetic alone.

After the change, expect improvements only gradually: old oversized indices
remain until [retention policies](ilm-retention.md) delete them (or you
[reindex](reindexing.md) them). During that window, monitor indexing speed,
search latency, node resource utilization and overall cluster health. If
problems persist after old indices have aged out, the indexing architecture
itself (index rotation scheme, node count, heap sizing) needs a redesign.

## Worked example: planning shard count for retention and many sources

Shard *size* (above) is only half of capacity planning; the other half is the shard *count* you accumulate over the retention window, especially when you split events into many index prefixes (per site, per tenant, per source, as in [alert separation](index-separation.md)). Each extra prefix is another daily index, so shard count grows with sources x retention, not just data volume.

Index cadence sets the baseline:

- Alerts and archives (if enabled) roll daily.
- Monitoring and statistics roll weekly.
- Every index costs `primary shards x (1 + number_of_replicas)` shards.

Worked example: 11 alert index prefixes, one primary shard each, 90-day retention (~13 weeks):

| Config | Shards/day (alerts) | Shards/week (+2 stats & monitoring) | ~90 days (+~20 base) | Indexer nodes (~1000 shards each) |
|---|---|---|---|---|
| 1 primary **+ 1 replica** | 22 | 156 | ~2048 | **3** (fits, with headroom) |
| 1 primary, **0 replicas** | 11 | 79 | ~1047 | 1 only by raising the limit -> **3 recommended** |

Takeaways:

- **Dropping replicas roughly halves both shard count and disk usage** - reasonable when HA is not required, at the cost of no redundancy (a lost node loses its primaries until it is restored).
- **Never run exactly two indexer nodes.** Use 1 (lab / no HA) or 3+ (production); two nodes cannot form a reliable quorum.
- More prefixes = faster shard accumulation, which caps how long retention/ILM can extend before you must add indexer nodes. If the number of sources will grow, plan the node count with it, or weigh [separate clusters](index-separation.md#single-cluster-with-logical-separation-vs-separate-clusters).
- Watch the *other* limit too: many small per-source daily indices can leave each shard far below the [20-40 GB target](#sizing-guidelines) (oversharding). For low-volume sources prefer a longer index period or a size/age rollover over daily indices, and do not just raise `cluster.max_shards_per_node` to paper over it.

## Increasing the number of primary shards

The shard count for new indices comes from an index template. Use a
higher-order custom template so a Filebeat setup or upgrade does not silently
replace the setting:

1. Download the template that matches the installed Wazuh version:

   ```bash
   WAZUH_VERSION="<WAZUH_VERSION>"
   curl -fsSL \
     "https://raw.githubusercontent.com/wazuh/wazuh/v${WAZUH_VERSION}/extensions/elasticsearch/7.x/wazuh-template.json" \
     -o w-indexer-template.json
   ```

2. Edit `w-indexer-template.json`. Set `order` to `1` and change the shard
   and replica settings:

   ```json
   {
     "order": 1,
     "index_patterns": [
       "wazuh-alerts-4.x-*",
       "wazuh-archives-4.x-*"
     ],
     "settings": {
       "index.number_of_shards": 48,
       "index.number_of_replicas": 1
     }
   }
   ```

   Preserve the mappings and remaining settings from the downloaded template;
   the shortened object above shows only the fields to review.

3. Load the template through the Wazuh Indexer API:

   ```bash
   curl -fsS -k -u <INDEXER_USERNAME>:<INDEXER_PASSWORD> \
     -X PUT "https://<INDEXER_IP>:9200/_template/wazuh-custom" \
     -H "Content-Type: application/json" \
     --data-binary @w-indexer-template.json
   ```

4. Verify the effective custom template before waiting for the next index:

   ```bash
   curl -fsS -k -u <INDEXER_USERNAME>:<INDEXER_PASSWORD> \
     "https://<INDEXER_IP>:9200/_template/wazuh-custom?pretty&filter_path=wazuh-custom.order,wazuh-custom.index_patterns,wazuh-custom.settings"
   ```

The new setting takes effect from the next daily index onward: the
current day's index was already created with the old settings, which live in
the indexer itself. To apply the new shard count to existing indices you must
[reindex them](reindexing.md); the number of primary shards cannot be changed
on a live index.

## Monitoring shard count

Each node can hold a limited number of shards
(`cluster.max_shards_per_node`, default 1000). Approaching the limit blocks
new index creation, which for Wazuh means alerts stop being indexed at
midnight when the next daily index is due.

You can create an OpenSearch Alerting monitor that fires when the active
shard count reaches ~85% of your cluster-wide maximum. Use a query against
`_cluster/health` (or a cluster metrics monitor) with a trigger condition
such as:

```javascript
ctx.results[0].active_shards > 1000
```

Adjust the threshold to 85% of `max_shards_per_node * number_of_data_nodes`.

## Cluster health: red and yellow states

```http
GET _cluster/health
```

| Status | Meaning | Impact |
|---|---|---|
| green | All primary and replica shards assigned | Normal |
| yellow | All primaries assigned, one or more replicas unassigned | Data intact, no redundancy on affected indices |
| red | At least one primary shard unassigned | Data in that shard is unavailable; writes to it fail |

Common causes and fixes:

- **Yellow on a single-node cluster** - replicas can never be assigned
  because a replica may not live on the same node as its primary. Set
  replicas to 0; see [Replicas](replicas.md).
- **Yellow on `.opendistro-*` system indices** - same root cause; these
  indices default to 1 replica. See [Replicas](replicas.md) for settings,
  templates, and an ISM policy that fixes this permanently.
- **Red after a node loss or disk-full event** - diagnose with the allocation
  explain API below; free disk first if watermarks are the cause.

## Diagnosing unassigned shards

List unassigned shards and their reason:

```bash
curl -k -u <USERNAME>:<PASSWORD> \
  "https://<INDEXER_IP>:9200/_cat/shards?h=index,shard,prirep,state,unassigned.reason" \
  | grep UNASSIGNED
```

Ask the cluster *why* it will not allocate a shard: this is the single most
useful API for shard problems:

```bash
curl -k -u <USERNAME>:<PASSWORD> \
  "https://<INDEXER_IP>:9200/_cluster/allocation/explain?pretty"
```

Wider context (Dev Tools console):

```http
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
allocation was disabled (typically for maintenance, e.g. the
[move-data-to-a-new-disk procedure](disk-management.md#moving-indexer-data-to-a-new-disk)
sets it to `primaries`) and never re-enabled:

```http
PUT _cluster/settings
{
  "persistent": {
    "cluster.routing.allocation.enable": "all"
  }
}
```

Also check for a per-index allocation block:

```http
PUT <index>/_settings
{ "index.routing.allocation.disable_allocation": false }
```

## Disk watermarks

The most frequent cause of unassigned shards. Once a node's disk usage
crosses the low watermark (default 85% used), the cluster stops
assigning new shards to it. At the high watermark (default 90%) it actively
relocates shards away, and at the flood stage (default 95%) indices with a
shard on that node are forced read-only.

Check disk usage and shard distribution per node:

```bash
curl -k -u <USERNAME>:<PASSWORD> "https://<INDEXER_IP>:9200/_cat/allocation?v"
```

Fix the disk first: see [Disk management](disk-management.md). If your
nodes have large disks (multiple TB), the default 85% may be unnecessarily
conservative: 15% of a 5 TB disk is a lot of headroom. You can raise it:

```http
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
percentage values refer to *used* disk space, while byte values refer to
*free* disk space.

## Manually rerouting shards

For explicit control over shard placement, use the cluster reroute API.
Move a shard between nodes:

```http
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

As a last resort for a red index whose primary shard data is genuinely
lost (e.g. the node's disk is gone), you can allocate an empty primary. This
permanently discards whatever data was in that shard:

```http
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
- [OpenSearch - Tuning for indexing speed](https://docs.opensearch.org/latest/tuning-your-cluster/performance/)
- [OpenSearch - Cluster shard limits](https://docs.opensearch.org/latest/install-and-configure/configuring-opensearch/cluster-settings/)
- [Elastic - Size your shards](https://www.elastic.co/docs/deploy-manage/production-guidance/optimize-performance/size-shards)
- [Elastic - How many shards should I have in my Elasticsearch cluster?](https://www.elastic.co/blog/how-many-shards-should-i-have-in-my-elasticsearch-cluster)
- [Elastic - Cluster reroute API](https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-reroute.html)
- [Elastic - Disk-based shard allocation](https://www.elastic.co/guide/en/elasticsearch/reference/current/disk-allocator.html)
