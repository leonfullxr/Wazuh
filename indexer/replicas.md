# Replica Management

Replica shards provide redundancy - but a replica can never be allocated on
the same node as its primary. On a **single-node** deployment (the default
Wazuh all-in-one install), every index created with 1 replica leaves an
unassigned replica shard behind, and the cluster sits permanently
[yellow](shard-management.md#cluster-health-red-and-yellow-states).

Wazuh's own template creates `wazuh-*` indices with 0 replicas on
all-in-one installs, but the **`.opendistro-*` system indices** (alerting,
ISM history, ...) are created by OpenSearch plugins with their own defaults
and are the usual culprit behind a stubbornly yellow single-node cluster.

## Table of Contents

- [Fix existing indices](#fix-existing-indices)
- [Fix indices created in the future](#fix-indices-created-in-the-future)
- [ISM policy: fix it permanently](#ism-policy-fix-it-permanently)
- [Node count, quorum, and fault tolerance](#node-count-quorum-and-fault-tolerance)
- [Notes for multi-node clusters](#notes-for-multi-node-clusters)

## Fix existing indices

Set replicas to 0 on the offending indices. From Dev Tools:

```http
PUT wazuh-monitoring*/_settings
{ "index": { "number_of_replicas": 0 } }
```

For the `.opendistro-*` system indices, also disable `auto_expand_replicas`
- otherwise the plugin re-expands the replica count as nodes join:

```http
PUT .opendistro-*/_settings
{
  "index": {
    "number_of_replicas": 0,
    "auto_expand_replicas": false
  }
}
```

Equivalent with curl and the admin certificate:

```bash
curl -k -XPUT "https://<INDEXER_IP>:9200/.opendistro-*/_settings" \
  -H 'Content-Type: application/json' \
  --cert /etc/wazuh-indexer/certs/admin.pem \
  --key /etc/wazuh-indexer/certs/admin-key.pem \
  -u <USERNAME> \
  -d '{ "index": { "number_of_replicas": 0, "auto_expand_replicas": false } }'
```

## Fix indices created in the future

Settings changes only affect existing indices. The plugins keep creating new
ones, and alerting history indices roll over frequently. Install index
templates so new system indices are created with 0 replicas:

```http
PUT _index_template/opendistro_alerting_alerts
{
  "index_patterns": [".opendistro-alerting-alerts*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0
    }
  }
}
```

```http
PUT _index_template/ism_history_indices
{
  "index_patterns": [".opendistro-ism-managed-index-history-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0
    }
  }
}
```

The ISM plugin history indices also honor a dedicated cluster setting. Set it
too:

```http
PUT .opendistro-ism-managed-index-history-*/_settings
{
  "index.number_of_replicas": 0,
  "index.auto_expand_replicas": false
}

PUT _cluster/settings
{
  "persistent": {
    "opendistro": {
      "index_state_management": {
        "history": { "number_of_replicas": "0" }
      }
    }
  }
}
```

## ISM policy: fix it permanently

Templates cover the common cases, but an [ISM](ilm-retention.md) policy is a
belt-and-braces approach that force-sets replicas to 0 on every new
`.opendistro-*` index as soon as it is created:

<details>
<summary>Click to expand the ISM policy</summary>

```http
PUT _plugins/_ism/policies/set_opendistro_replica_to_0
{
  "policy": {
    "policy_id": "Opendistro replica to 0",
    "description": "Set replica count for .opendistro-* indices to 0",
    "default_state": "index_created",
    "states": [
      {
        "name": "index_created",
        "actions": [],
        "transitions": [
          {
            "state_name": "replica_0",
            "conditions": { "min_index_age": "0ms" }
          }
        ]
      },
      {
        "name": "replica_0",
        "actions": [
          {
            "retry": {
              "count": 3,
              "backoff": "exponential",
              "delay": "1m"
            },
            "replica_count": { "number_of_replicas": 0 }
          }
        ],
        "transitions": []
      }
    ],
    "ism_template": [
      {
        "index_patterns": [".opendistro-*"],
        "priority": 1
      }
    ]
  }
}
```

</details>

The `ism_template` block auto-attaches the policy to newly created matching
indices. The `retry` block handles transient failures.

## Node count, quorum, and fault tolerance

A replica count and a node count constrain each other. Set them together.

**Replicas decide how many copies exist.** `number_of_replicas + 1` is the
number of copies of each shard, and a replica never shares a node with its
primary. The cluster needs at least that many data nodes to place them all.

**Node count decides whether the cluster stays available.** The
cluster-manager-eligible nodes elect a cluster manager by majority vote. Below a
majority the cluster serves nothing, even with every shard intact on disk.

The cluster survives the smaller of the two limits:

| Nodes | Replicas | Data survives | Quorum survives | Effective tolerance |
|---|---|---|---|---|
| 2 | 1 | 1 | 0 | **0** |
| 3 | 1 | 1 | 1 | **1** |
| 3 | 2 | 2 | 1 | **1**, and permanently yellow after one loss |
| 4 | 2 | 2 | 1 | **1** |
| 5 | 2 | 2 | 2 | **2** |

Two rules follow, and they answer most replica questions:

- **Use 3 nodes with 1 replica, or 5 nodes with 2 replicas.** Other pairings
  spend hardware on a limit that something else already caps.
- **Never set more replicas than `data_nodes - 1`.** The extra copies cannot be
  placed, and the cluster stays yellow until you add nodes or lower the count.

So "can I run 2 replicas on a 4-node cluster?" resolves as follows. The cluster
places the data correctly and still fails after two node losses, because two
survivors cannot form a majority of four. Pair 2 replicas with 5 nodes.

For the voting rules behind the quorum column, the fault-tolerance table for
every node count, and the procedures to add or remove a node safely, see
[Indexer cluster topology](cluster-topology.md).

## Notes for multi-node clusters

- On multi-node clusters, **keep at least 1 replica** on `wazuh-alerts-*`:
  losing a node without replicas means a red cluster and lost data. Replicas
  are configured alongside shards in `/etc/filebeat/wazuh-template.json` -
  see [Increasing shards](shard-management.md#increasing-the-number-of-primary-shards).
- Replicas double the disk footprint and the cluster-wide shard count. Count
  them in the [shard-per-heap budget](shard-management.md#sizing-guidelines)
  and in [disk capacity planning](disk-management.md).
- Reference: [OpenSearch alerting settings](https://docs.opensearch.org/docs/latest/observing-your-data/alerting/settings/).
- Node count, voting, and role specialization: [Indexer cluster topology](cluster-topology.md).
- Planning a new deployment: [Sizing a Wazuh deployment](../upgrading/sizing.md).
