# Wazuh Indexer (OpenSearch) — Operations, Tuning and Troubleshooting

Field-tested guides for operating the Wazuh Indexer: shard sizing, retention,
disk management, ingest pipeline customization and cluster troubleshooting.
Everything here applies to the Wazuh Indexer (an OpenSearch distribution);
where a procedure differs for legacy Elasticsearch-based Wazuh deployments,
it is called out explicitly.

## Table of Contents

- [How the indexer stores Wazuh data](#how-the-indexer-stores-wazuh-data)
- [Guides](#guides)
- [Quick diagnostic commands](#quick-diagnostic-commands)

## How the indexer stores Wazuh data

Understanding the write path makes most indexer problems much easier to reason
about:

1. The Wazuh **manager** generates alerts (`/var/ossec/logs/alerts/alerts.json`)
   and, optionally, archives of every received event.
2. **Filebeat**, running on each manager node, ships those documents to the
   indexer. Two Filebeat artifacts control how data lands:
   - `/etc/filebeat/wazuh-template.json` — the **index template**: mappings,
     number of primary shards and replicas for new indices.
   - `/usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json` — the
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
   most of the cluster's performance and stability characteristics — see
   [Shard management](shard-management.md).

Because indices are created daily, template or pipeline changes only affect
**indices created after the change**. Historical indices keep their old
settings until you [reindex](reindexing.md) them or they age out via
[retention policies](ilm-retention.md).

## Guides

| Guide | What it covers |
|---|---|
| [Shard management](shard-management.md) | Shard sizing rules, increasing primary shards, red/yellow cluster health, unassigned shards, disk watermarks |
| [ILM / ISM retention](ilm-retention.md) | Index lifecycle policies, automated deletion, switching policies safely |
| [Disk management](disk-management.md) | Diagnosing disk usage (`df` vs `du`), freeing space, moving data to a new disk or partition |
| [Reindexing](reindexing.md) | Optimized `_reindex` procedure for mapping fixes and shard-count changes |
| [Index separation](index-separation.md) | Routing alerts into dedicated indices by rule group |
| [Replicas](replicas.md) | Replica settings for single-node clusters and `.opendistro-*` system indices |
| [GeoIP](geoip.md) | How GeoIP enrichment works, updating GeoLite2 databases, country-based alert filtering |
| [Cross-cluster search](cross-cluster-search.md) | Searching remote Wazuh indexer clusters from a central cluster |
| [Internal users auditing](auditing.md) | Purpose and criticality of the built-in service accounts and roles |
| [Miscellaneous operations](misc-operations.md) | Local timezone in `full_log`, recovering indexer credentials |

## Quick diagnostic commands

Run these from the Wazuh Dashboard Dev Tools console
(**Indexer management > Dev Tools**) or with `curl` against
`https://<INDEXER_IP>:9200`:

```
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
[Shard management — cluster health](shard-management.md#cluster-health-red-and-yellow-states).
If indices go read-only or shards will not allocate, it is almost always disk:
see [Disk management](disk-management.md).
