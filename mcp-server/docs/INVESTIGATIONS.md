# Read-only investigations

The investigation pilot is off unless `WAZUH_INVESTIGATIONS_FILE` names an operator-owned JSON file and `WAZUH_INVESTIGATION_KEYS` supplies a comma-separated Fernet key ring. The first key encrypts new evidence references; all keys decrypt references. Generate keys securely (for example, `python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'`), place them in a secret manager, and distribute the same ring to every replica. Retain retiring keys for at least 15 minutes. Missing or invalid configuration fails startup. Never put keys in the JSON file.

Example configuration, with field values that must be validated against the deployment:

```json
{
  "tie_breaker": "event.id",
  "tie_breaker_verified": true,
  "saved": {
    "saved_investigation_failed_logins": {"version": "1", "rule_groups": ["authentication_failed"]},
    "saved_investigation_privilege_changes": {"version": "1", "rule_groups": ["privilege_escalation"]}
  }
}
```

## Qualify a cluster before enabling investigations

Run the preflight with the same Indexer reader, CA bundle and cluster configuration that the MCP server uses. From an installed wheel, run `wazuh-mcp-preflight --cluster default --tie-breaker event.id`. From the `mcp-server/` Compose directory, run:

```sh
docker compose exec wazuh-mcp python -m wazuh_mcp.preflight_cli --cluster default --tie-breaker event.id
```

Use `--cluster default` for the environment-configured connection. To test a named connection, set `WAZUH_CLUSTERS_FILE` to the server’s cluster file and use `--cluster prod-eu` (or omit the option to follow the file’s default). If using the implicit `./config/clusters.json`, run from the server’s working directory. Run it for each direct cluster available to the pilot group. The command only opens a temporary read-only search context. It releases the scroll when it receives a scroll ID. If the first response is interrupted before the ID arrives, the Indexer expires the context after one minute.

The scan checks the mappings of the open, visible `wazuh-alerts-*` indices and reads every matching alert in one scroll snapshot. It checks the field's source shape, verifies one indexed sort value per alert, and detects duplicates across rollover boundaries. It exercises the timeline sort, reads index UUIDs and tests evidence retrieval in each index. The reader needs access to index mappings and settings, search and scroll (including release), and document GET. Use the intended reader even if an administrator account is available. On Wazuh Indexer 4.14.5 the command passed with index-level `read`, `indices:admin/mappings/get` and `indices:monitor/settings/get` limited to the fixture indices, plus cluster-level `indices:data/read/scroll/clear` to release the reader’s scroll. Removing the clear permission made the result inconclusive.

| Exit | JSON status | Operator action |
| --- | --- | --- |
| 0 | `pass` | Record the field, cluster, reader and run time. Set `tie_breaker_verified` only after every cluster in scope passes. |
| 1 | `fail` | Correct the reported data or mapping violation and rerun. Changing a mapping alone does not backfill existing alerts. |
| 2 | `inconclusive` | Keep investigations disabled. Check permissions, connectivity, index rollover and scan budgets before retrying. |

The output includes `reason`, `indices_checked` and `documents_checked`. For a resolved connection, check the `target` object against the intended cluster, Indexer endpoint and tie-breaker before accepting a pass. The default limits are 30 seconds, 10,000 documents, 100 scroll pages (including the final empty page), 200 documents per page, and 10,000,000 response bytes. The maximum page size is 10,000. If the exact match count exceeds the document limit, the check stops on the first page. Use `--help` for individual overrides. For large clusters, schedule the check during a quiet period. Allow memory for one sort value per visible document when raising the limits.

Choose a single-valued keyword or integral field with doc values and a directly readable source path. An index with no visible document for an evidence read, an unsupported mapping, changing index topology or interrupted scan cannot pass. `event.id` is an example field and must be verified on your deployment. A pass covers the visible snapshot under the tested reader. Repeat after rollover, reader or mapping changes, and monitor incoming alerts for the same invariant.

## Pilot configuration

For a one-group rollout, use a dedicated pilot instance and grant the analyst group read access to the qualified cluster. The cluster policy applies to all tools on that instance. Sign in as an analyst, open a timeline event and retrieve its evidence. Then sign in as an identity outside the group and verify that the same reference yields no event data. [Cluster policy configuration](CLUSTER_POLICY.md)

The pilot rejects cross-cluster search configurations; connect directly to each cluster. `WAZUH_TOOLSETS`, `WAZUH_DISABLED_TOOLS`, and `WAZUH_TOOL_PROFILE` apply to the registered names, which belong to the analysis toolset. Definitions are loaded at startup and may contain only reviewed rule-group filters and a version. Changes require a restart. Each saved tool's description names that definition's version and rule groups, and states that `from` and `to` are required.

`investigate_agent_timeline` selects the most recent 1–50 alerts in an absolute window no longer than 24 hours, displaying the selected page oldest first. If omitted, the interval is the preceding hour and the limit is 50. `sources.alerts` distinguishes complete, partial and unavailable searches and reports the exact match count when known. Agent status is a current observation, not an event in the historical interval. Saved investigations require explicit endpoints and return their version and normalized filters. Input query syntax and arbitrary fields are not accepted.

The investigation reader needs search and document-read access on its allowed alert indices, plus the index-scoped `indices:monitor/settings/get` permission to bind evidence to the index UUID. A read-only account with search alone can find alerts but cannot issue verifiable references. The Manager reader needs `agent:read` on the requested agents.

Evidence references expire after 15 minutes. `get_investigation_evidence` rechecks the current principal and cluster grant and verifies the index identity and projected content. Expired, inaccessible, remapped, recreated or changed records return an unavailable result. References are encrypted and are not transferable to another principal or cluster. Keep clocks synchronized across replicas. Indexer searches and the status observation share a ten-second deadline; individual backend replies are capped at 2 MB and compressed responses are refused. Whole events are omitted when the output budget is reached. Both `structuredContent` and standalone JSON in the text content carry the same sanitized result, so replies consume roughly twice the encoded object size. The largest response and real backend mappings must be qualified before enabling this pilot in production.


## Client qualification

The optional [official client smoke runner](../evals/mcp-app-client/README.md) connects over loopback using the official TypeScript MCP SDK and Apps AppBridge. It checks the negotiated protocol, resource discovery, JSON and structured output equivalence, viewer handshake and a drill-down on a synthetic alert. It starts no live response actions. The desktop host and real Wazuh deployment used in production should still be qualified separately.
