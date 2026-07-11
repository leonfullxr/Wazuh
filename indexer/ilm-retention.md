# Index Lifecycle and Retention (ISM / ILM)

Wazuh creates one alerts index per day, forever, unless something deletes
them. Lifecycle policies automate retention: they act on indices as they age
(reduce replicas, close, delete) without manual intervention. This is the
primary tool for keeping [disk usage](disk-management.md) under control.

Terminology matters here:

- **ISM (Index State Management)** - the OpenSearch plugin shipped with the
  **Wazuh Indexer**. This is what you should use.
- **ILM (Index Lifecycle Management)** - the Elasticsearch equivalent, only
  relevant for legacy Wazuh deployments backed by Elasticsearch/ODFE.

## Table of Contents

- [ISM on the Wazuh Indexer](#ism-on-the-wazuh-indexer)
  - [Choose retention, rollover, or both](#choose-retention-rollover-or-both)
  - [Example: delete alerts after 90 days](#example-delete-alerts-after-90-days)
  - [Policy mechanics worth knowing](#policy-mechanics-worth-knowing)
- [ILM on legacy Elasticsearch deployments](#ilm-on-legacy-elasticsearch-deployments)
  - [Check and control the ILM service](#check-and-control-the-ilm-service)
  - [Switching lifecycle policies safely](#switching-lifecycle-policies-safely)
- [References](#references)

## ISM on the Wazuh Indexer

ISM policies are managed via `_plugins/_ism/policies/` or from the dashboard
under **Indexer management > Index Management > State management policies**.

A policy defines *states* and *transitions*: an index enters the default
state when the policy attaches, and moves between states when conditions
(usually `min_index_age`) are met, executing the actions of each state.

### Choose retention, rollover, or both

Use the smallest policy that solves the operational problem:

| Need | Design |
|---|---|
| Enforce a fixed retention period | Attach a delete policy to the stock daily `wazuh-alerts-*` indices. This is the normal starting point. |
| Daily shards are consistently too small | Use a longer index period or a rollover design so each index accumulates enough data before rotation. |
| Daily shards exceed the target size before the day ends | Use more primary shards, or test size-based rollover if ingestion varies too much for a fixed shard count. |
| Move older data to warm nodes | Add an allocation state before deletion and configure node attributes plus allocation awareness first. |

Rollover is not a drop-in replacement for Wazuh's date-named indices. It
requires a write alias and a correctly numbered bootstrap index, and the
Filebeat pipeline must write through that alias. Validate dashboard patterns,
templates, restore procedures, and upgrades in a non-production environment.
Do not combine a custom rollover design with the stock daily
`date_index_name` behavior without verifying which mechanism owns index
creation.

For current supported examples, see
[Wazuh index lifecycle management](https://documentation.wazuh.com/current/user-manual/wazuh-indexer-cluster/index-lifecycle-management.html)
and [OpenSearch rollover](https://docs.opensearch.org/latest/im-plugin/ism/policies/#rollover).
Use `min_primary_shard_size`, age, or document-count conditions based on the
measured workload; avoid total-index-size conditions when shards are uneven.

### Example: delete alerts after 90 days

```http
PUT _plugins/_ism/policies/wazuh_alerts_retention
{
  "policy": {
    "description": "Delete wazuh-alerts indices older than 90 days",
    "default_state": "hot",
    "states": [
      {
        "name": "hot",
        "actions": [],
        "transitions": [
          {
            "state_name": "delete",
            "conditions": { "min_index_age": "90d" }
          }
        ]
      },
      {
        "name": "delete",
        "actions": [
          {
            "retry": { "count": 3, "backoff": "exponential", "delay": "1h" },
            "delete": {}
          }
        ],
        "transitions": []
      }
    ],
    "ism_template": [
      {
        "index_patterns": ["wazuh-alerts-*"],
        "priority": 1
      }
    ]
  }
}
```

Key points:

- The `ism_template` block auto-attaches the policy to **newly created**
  indices matching the patterns. Existing indices must be attached manually:
  dashboard **Index Management > Indices > select indices > Apply policy**,
  or via `POST _plugins/_ism/add/<index-pattern>` with the policy ID.
- The `retry` block prevents a transient failure (e.g. a red cluster during
  the delete) from permanently stalling the managed index.
- ISM evaluates policies on a cycle (every 5 minutes by default), so
  transitions are not instantaneous.
- Use separate policies when alerts and archives have different legal or
  operational retention. Do not include `wazuh-archives-*` in this example
  unless 90 days is also the approved archive retention.
- For a real-world policy that manages replicas on system indices, see
  [Replicas - ISM policy](replicas.md#ism-policy-fix-it-permanently).

Check what ISM is doing to your indices:

```http
GET _plugins/_ism/explain/wazuh-alerts-*
```

### Policy mechanics worth knowing

- Retention should be sized against ingestion rate and disk capacity: daily
  primary data plus replicas, multiplied by retention days, must stay well
  below the
  [disk watermarks](shard-management.md#disk-watermarks) on your data nodes.
- After [increasing shard counts](shard-management.md#increasing-the-number-of-primary-shards)
  or other template changes, the cluster only fully converges once ISM has
  deleted the old-format indices - plan the observation window accordingly.
- Snapshot before delete if you have compliance requirements; deletion via
  ISM is not recoverable.

## ILM on legacy Elasticsearch deployments

Only applicable if your stack still runs Elasticsearch (Wazuh 4.x with ODFE
or older Elastic-based deployments).

### Check and control the ILM service

```http
GET _ilm/status
```

Normal operation returns:

```json
{ "operation_mode": "RUNNING" }
```

If ILM was stopped (e.g. for maintenance), resume it and it continues
executing policies from where it left off:

```http
POST _ilm/start
```

### Switching lifecycle policies safely

Assigning a new policy on top of an old one can make phase execution
**silently fail**. Always remove the existing policy first:

1. Remove the current policy (target a data stream or alias to cover all its
   indices):

   ```http
   POST <index-or-alias>/_ilm/remove
   ```

2. **Check the index state before proceeding.** Policy removal strips all ILM
   metadata regardless of what the index was doing at that moment. For
   example, the `forcemerge` action temporarily closes an index before
   reopening it - removing the policy mid-forcemerge can leave the index
   **closed indefinitely**. Verify and repair:

   ```http
   GET <index-or-alias>

   # Re-open any index left closed
   POST <index-or-alias>/_open
   ```

3. Assign the new policy:

   ```http
   PUT <index-or-alias>/_settings
   {
     "index": {
       "lifecycle": { "name": "new-lifecycle-policy" }
     }
   }
   ```

## References

- [OpenSearch - Index State Management](https://docs.opensearch.org/docs/latest/im-plugin/ism/index/)
- [OpenSearch - ISM policies](https://docs.opensearch.org/docs/latest/im-plugin/ism/policies/)
- [Elastic - Configure a lifecycle policy / switch policies](https://www.elastic.co/docs/manage-data/lifecycle/index-lifecycle-management/configure-lifecycle-policy#switch-lifecycle-policies)
- [Elastic - Start and stop ILM](https://www.elastic.co/docs/manage-data/lifecycle/index-lifecycle-management/start-stop-index-lifecycle-management)
