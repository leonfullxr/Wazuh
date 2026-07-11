# Index Lifecycle and Retention (ISM / ILM)

Wazuh creates one alerts index per day, forever, unless something deletes
them. Lifecycle policies automate retention: they act on indices as they age
(reduce replicas, close, delete) without manual intervention. This is the
primary tool for keeping [disk usage](disk-management.md) under control.

Terminology matters here:

- **ISM (Index State Management)** — the OpenSearch plugin shipped with the
  **Wazuh Indexer**. This is what you should use.
- **ILM (Index Lifecycle Management)** — the Elasticsearch equivalent, only
  relevant for legacy Wazuh deployments backed by Elasticsearch/ODFE.

## Table of Contents

- [ISM on the Wazuh Indexer](#ism-on-the-wazuh-indexer)
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

### Example: delete alerts after 90 days

```
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
        "index_patterns": ["wazuh-alerts-*", "wazuh-archives-*"],
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
- For a real-world policy that manages replicas on system indices, see
  [Replicas — ISM policy](replicas.md#ism-policy-fix-it-permanently).

Check what ISM is doing to your indices:

```
GET _plugins/_ism/explain/wazuh-alerts-*
```

### Policy mechanics worth knowing

- Retention should be sized against ingestion rate and disk capacity: daily
  index size x retention days must stay well below the
  [disk watermarks](shard-management.md#disk-watermarks) on your data nodes.
- After [increasing shard counts](shard-management.md#increasing-the-number-of-primary-shards)
  or other template changes, the cluster only fully converges once ISM has
  deleted the old-format indices — plan the observation window accordingly.
- Snapshot before delete if you have compliance requirements; deletion via
  ISM is not recoverable.

## ILM on legacy Elasticsearch deployments

Only applicable if your stack still runs Elasticsearch (Wazuh 4.x with ODFE
or older Elastic-based deployments).

### Check and control the ILM service

```
GET _ilm/status
```

Normal operation returns:

```json
{ "operation_mode": "RUNNING" }
```

If ILM was stopped (e.g. for maintenance), resume it and it continues
executing policies from where it left off:

```
POST _ilm/start
```

### Switching lifecycle policies safely

Assigning a new policy on top of an old one can make phase execution
**silently fail**. Always remove the existing policy first:

1. Remove the current policy (target a data stream or alias to cover all its
   indices):

   ```
   POST <index-or-alias>/_ilm/remove
   ```

2. **Check the index state before proceeding.** Policy removal strips all ILM
   metadata regardless of what the index was doing at that moment. For
   example, the `forcemerge` action temporarily closes an index before
   reopening it — removing the policy mid-forcemerge can leave the index
   **closed indefinitely**. Verify and repair:

   ```
   GET <index-or-alias>

   # Re-open any index left closed
   POST <index-or-alias>/_open
   ```

3. Assign the new policy:

   ```
   PUT <index-or-alias>/_settings
   {
     "index": {
       "lifecycle": { "name": "new-lifecycle-policy" }
     }
   }
   ```

## References

- [OpenSearch — Index State Management](https://docs.opensearch.org/docs/latest/im-plugin/ism/index/)
- [OpenSearch — ISM policies](https://docs.opensearch.org/docs/latest/im-plugin/ism/policies/)
- [Elastic — Configure a lifecycle policy / switch policies](https://www.elastic.co/docs/manage-data/lifecycle/index-lifecycle-management/configure-lifecycle-policy#switch-lifecycle-policies)
- [Elastic — Start and stop ILM](https://www.elastic.co/docs/manage-data/lifecycle/index-lifecycle-management/start-stop-index-lifecycle-management)
