# Cluster access policy

Set `WAZUH_CLUSTER_POLICY_FILE` to a JSON file to restrict access by API key or verified identity-provider group. If the variable is absent, existing deployment behavior is preserved. A configured empty, unreadable, malformed, or invalid file prevents startup. Cross-cluster search is not supported with a policy; configure direct cluster connections instead.

```json
{
  "rules": [
    {"identity": {"type": "api_key", "id": "key-id"}, "cluster": "staging", "allow": ["wazuh:read", "wazuh:write"]},
    {"identity": {"type": "idp_group", "issuer": "https://identity.example", "id": "analysts"}, "cluster": "production", "allow": ["wazuh:read"]},
    {"identity": {"type": "idp_group", "issuer": "https://identity.example", "id": "suspended"}, "cluster": "production", "deny": ["wazuh:read", "wazuh:write"]}
  ]
}
```

The `id` of an API key is its server key ID, not the secret. Group and issuer values are case-sensitive verified IdP claims. Matching grants are combined, then explicit denials win. Permissions are also limited by current token and key scopes. A group grant expires 15 minutes after verified login; the user must authenticate again. A missing grant denies access, including to the default cluster. Add explicit rules when adding a cluster. The server reads and validates one immutable snapshot at startup; restart to change policy. Client cache freshness is zero when policy is enabled, and each dispatch and evidence lookup rechecks the current policy.
