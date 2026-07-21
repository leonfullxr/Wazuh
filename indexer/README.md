# Wazuh Indexer (OpenSearch) - Operations, Tuning and Troubleshooting

This section is for administrators who operate the Wazuh Indexer in
single-node, clustered, or multi-site deployments. It covers capacity
planning, shard and replica design, retention, storage recovery, ingest
pipeline customization, and cluster troubleshooting.

The Wazuh Indexer is based on OpenSearch. Use the Wazuh-specific defaults and
paths in these guides first, then validate changes against the OpenSearch
version bundled with your Wazuh release. Procedures that apply only to legacy
Elasticsearch-based deployments are marked explicitly.

## Table of Contents

- [How the indexer stores Wazuh data](#how-the-indexer-stores-wazuh-data)
- [Sizing and optimization baseline](#sizing-and-optimization-baseline)
- [Quick reference](#quick-reference)
- [Advanced operations](#advanced-operations)
- [Quick diagnostic commands](#quick-diagnostic-commands)

## How the indexer stores Wazuh data

Understanding the write path makes most indexer problems much easier to reason
about:

1. The Wazuh **manager** generates alerts (`/var/ossec/logs/alerts/alerts.json`)
   and, optionally, archives of every received event.
2. **Filebeat**, running on each manager node, ships those documents to the
   indexer. Two Filebeat artifacts control how data lands:
   - `/etc/filebeat/wazuh-template.json` - the **index template**: mappings,
     number of primary shards and replicas for new indices.
   - `/usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json` - the
     **ingest pipeline**: runs inside the indexer at index time and handles
     timestamp parsing, GeoIP enrichment and daily index naming.
3. The indexer creates **one index per day** per data type:

   | Index pattern | Contents |
   |---|---|
   | `wazuh-alerts-4.x-yyyy.MM.dd` | Alerts (events that matched a rule above the logging threshold) |
   | `wazuh-archives-4.x-yyyy.MM.dd` | All events, if archiving is enabled |
   | `wazuh-monitoring-*` | Agent status snapshots |
   | `wazuh-statistics-*` | Manager performance statistics |
   | `.opendistro-*` / `.opensearch-*` | Internal plugin indices (alerting, ISM history, ...) |
   | `.kibana*` | Dashboard saved objects |

4. Each index is split into **primary shards** (configurable in the template)
   and **replica shards** (copies for redundancy). Shard count and size drive
   most of the cluster's performance and stability characteristics - see
   [Shard management](shard-management.md).

Because indices are created daily, template or pipeline changes only affect
**indices created after the change**. Historical indices keep their old
settings until you [reindex](reindexing.md) them or they age out via
[retention policies](ilm-retention.md).

## Sizing and optimization baseline

Treat these values as starting points, not hard limits. Measure the actual
indexing rate, search latency, recovery time, heap pressure, and disk
headroom before and after a change.

| Decision | Production baseline |
|---|---|
| Primary shard size | Aim for roughly **20-40 GB** for time-series indices and normally keep shards below **50 GB** so recovery and relocation remain manageable. Very small deployments may need a longer index period to avoid many tiny shards. |
| Primary shard count | Start with a multiple of the number of data nodes so primaries distribute evenly, then choose enough primaries to keep the expected index size in the target range. Change the template before the next index is created. |
| Shards per heap | Use **fewer than 20 primary plus replica shards per GB of JVM heap** as a conservative planning ceiling. This is a legacy rule of thumb, not an OpenSearch limit; benchmark the bundled OpenSearch version and also monitor the hard `cluster.max_shards_per_node` budget. |
| Replicas | Use `0` on a single-node deployment because a replica cannot share a node with its primary. Use at least `1` in HA clusters, with enough nodes and disk capacity to place it. Include replicas in shard and storage calculations. |
| Retention and rollover | Use OpenSearch **ISM** for Wazuh Indexer deployments. Apply retention before adding capacity. The stock daily indices are usually sufficient; consider size/age rollover only when daily indices consistently produce shards outside the target range, and test alias/template behavior before production rollout. |
| Heap and disk | Set equal JVM minimum and maximum heap values, normally around half of system RAM, and prevent swapping. Keep enough free disk for shard relocation; do not plan steady-state operation near the low watermark. |

Estimate the primary count for a daily index as:

```text
primary shards = ceil(expected primary data per index / target shard size)
```

Round that result to a practical multiple of the data-node count where doing
so does not create undersized shards. For example, 1.5 TB/day divided by a
40 GB target is about 38 primaries; a 12-node cluster might test 36 or 48
primaries and select between them using ingestion and recovery benchmarks.
See [Shard management](shard-management.md) for the procedure and its
operational safeguards.

For low-volume environments, daily indices can create hundreds of tiny
shards. Prefer a longer index period or a tested rollover design instead of
raising `cluster.max_shards_per_node`. For high-volume environments, change
the template before oversized shards accumulate and allow old indices to age
out through [ISM retention](ilm-retention.md), or
[reindex](reindexing.md) only when the migration cost is justified.

## Quick reference

| Symptom or task | Start here |
|---|---|
| Cluster is red or yellow | [Shard management: cluster health](shard-management.md#cluster-health-red-and-yellow-states) |
| Shards are unassigned | [Shard management: allocation diagnosis](shard-management.md#diagnosing-unassigned-shards) |
| Single-node cluster remains yellow | [Replica management](replicas.md) |
| Shards exceed 40-50 GB or recovery is slow | [Shard sizing and template changes](shard-management.md#sizing-guidelines) |
| New indices fail at rollover or midnight | [Shard-count monitoring](shard-management.md#monitoring-shard-count) and [disk management](disk-management.md) |
| Disk watermark or read-only indices | [Disk management](disk-management.md) |
| Define or verify retention | [ISM / ILM retention](ilm-retention.md) |
| Apply a new mapping or shard count to old data | [Reindexing](reindexing.md) |
| Route selected alerts to another index | [Index separation](index-separation.md) |
| Change the timestamp embedded in `full_log` | [Ingest pipeline customization](ingest-pipeline-customization.md) |
| Reset or recover indexer credentials | [Password reset and recovery](../troubleshooting/passwords-recovery.md) |
| Record indexer authentication and authorization activity | [Security audit logs](security-audit-logs.md) |

## Advanced operations

| Guide | When to use it |
|---|---|
| [Cross-cluster search](cross-cluster-search.md) | Query remote Wazuh indexer clusters from a central SOC |
| [GeoIP enrichment](geoip.md) | Refresh GeoLite2 data or perform index-time geographic enrichment |
| [Internal users auditing](auditing.md) | Review built-in indexer accounts and harden role mappings |
| [Security audit logs](security-audit-logs.md) | Record and retain authentication, authorization, TLS, and security-configuration events |
| [Index separation](index-separation.md) | Give selected event classes distinct access control or retention |
| [Reindexing](reindexing.md) | Repair mappings or migrate historical indices to a new shard design |

## Quick diagnostic commands

Run these from the Wazuh Dashboard Dev Tools console
(**Indexer management > Dev Tools**) or with `curl` against
`https://<INDEXER_IP>:9200`:

```http
GET _cluster/health
GET _cluster/allocation/explain
GET _cat/nodes?v&h=name,heap.percent,ram.percent,disk.used_percent,load_1m
GET _cat/indices?v&s=store.size:desc
GET _cat/shards?v&h=index,shard,prirep,state,node,unassigned.reason&s=state
GET _cat/allocation?v
```

Equivalent with curl:

```bash
curl -k -u <USERNAME>:<PASSWORD> "https://<INDEXER_IP>:9200/_cluster/health?pretty"
```

If the cluster is not green, start with
[Shard management - cluster health](shard-management.md#cluster-health-red-and-yellow-states).
If indices go read-only or shards will not allocate, it is almost always disk:
see [Disk management](disk-management.md).
