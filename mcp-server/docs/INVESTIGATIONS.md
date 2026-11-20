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

Enable only after verifying the tie-breaker field is sortable and unique across all alert indices, including rollover indices, for the supported Indexer mappings. `event.id` is an illustration, not a claim about Wazuh mappings. If this cannot be demonstrated, do not enable the pilot. The pilot rejects cross-cluster search configurations; connect directly to each cluster. `WAZUH_TOOLSETS`, `WAZUH_DISABLED_TOOLS`, and `WAZUH_TOOL_PROFILE` apply to the registered names, which belong to the analysis toolset. Definitions are loaded at startup and may contain only reviewed rule-group filters and a version. Changes require a restart.

`investigate_agent_timeline` selects the most recent 1–50 alerts in an absolute window no longer than 24 hours, displaying the selected page oldest first. If omitted, the interval is the preceding hour and the limit is 50. `sources.alerts` distinguishes complete, partial and unavailable searches and reports the exact match count when known. Agent status is a current observation, not an event in the historical interval. Saved investigations require explicit endpoints and return their version and normalized filters. Input query syntax and arbitrary fields are not accepted.

Evidence references expire after 15 minutes. `get_investigation_evidence` rechecks the current principal and cluster grant and verifies the index identity and projected content. Expired, inaccessible, remapped, recreated or changed records return an unavailable result. References are encrypted and are not transferable to another principal or cluster. Keep clocks synchronized across replicas. Indexer searches and the status observation share a ten-second deadline; individual backend replies are capped at 2 MB and compressed responses are refused. Whole events are omitted when the output budget is reached. Both `structuredContent` and standalone JSON in the text content carry the same sanitized result, so replies consume roughly twice the encoded object size. The largest response and real backend mappings must be qualified before enabling this pilot in production.


## Client qualification

The optional [official client smoke runner](../evals/mcp-app-client/README.md) connects over loopback using the official TypeScript MCP SDK and Apps AppBridge. It checks the negotiated protocol, resource discovery, JSON and structured output equivalence, viewer handshake and a drill-down on a synthetic alert. It starts no live response actions. The desktop host and real Wazuh deployment used in production should still be qualified separately.
