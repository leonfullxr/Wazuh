# Replica Management

Replica shards provide redundancy, but a replica can never be allocated on
the same node as its primary. On a single-node deployment (the default
Wazuh all-in-one install), every index created with 1 replica leaves an
unassigned replica shard behind, and the cluster sits permanently
[yellow](shard-management.md#cluster-health-red-and-yellow-states).

Wazuh's own template creates `wazuh-*` indices with 0 replicas on
all-in-one installs, but the `.opendistro-*` system indices (alerting,
ISM history, ...) are created by OpenSearch plugins with their own defaults
and are the usual culprit behind a stubbornly yellow single-node cluster.

## Table of Contents

- [Fix existing indices](#fix-existing-indices)
- [Fix indices created in the future](#fix-indices-created-in-the-future)
- [ISM policy: fix it permanently](#ism-policy-fix-it-permanently)
- [Notes for multi-node clusters](#notes-for-multi-node-clusters)

## Fix existing indices

Set replicas to 0 on the offending indices. From Dev Tools:

```http
PUT wazuh-monitoring*/_settings
{ "index": { "number_of_replicas": 0 } }
```

For the `.opendistro-*` system indices, also disable `auto_expand_replicas`,
since otherwise the plugin re-expands the replica count as nodes join:

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

Settings changes only affect existing indices; the plugins keep creating new
ones (alerting history indices roll over frequently). Install index templates
so new system indices are born with 0 replicas:

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

The ISM plugin's history indices additionally honor a dedicated cluster
setting; set it too:

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
indices; the `retry` block handles transient failures.

## Notes for multi-node clusters

- On multi-node clusters, keep at least 1 replica on `wazuh-alerts-*`:
  losing a node without replicas means a red cluster and lost data. Replicas
  are configured alongside shards in `/etc/filebeat/wazuh-template.json`;
  see [Increasing shards](shard-management.md#increasing-the-number-of-primary-shards).
- Replicas double the disk footprint and cluster-wide shard count; factor
  them into the [shard-per-heap budget](shard-management.md#sizing-guidelines)
  and [disk capacity planning](disk-management.md).
- Reference: [OpenSearch alerting settings](https://docs.opensearch.org/docs/latest/observing-your-data/alerting/settings/).
