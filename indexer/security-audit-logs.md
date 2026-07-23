<!-- Support: WS-38338, WS-36711, WS-37030 -->

# Wazuh Indexer Security Audit Logs

OpenSearch Security audit logs record authentication, authorization, TLS, and
security-configuration activity against the Wazuh Indexer. Enable them when
access to indexed data must be attributable for incident response or
compliance.

Audit logging can add substantial indexing volume and stores evidence on the
same cluster by default. Define scope, access control, retention, and an
external copy before enabling every category in production.

## Prerequisites

- Administrative access to every indexer node and the Security REST API.
- A healthy cluster with enough disk and shard capacity for the expected
  audit volume.
- A backup of `/etc/wazuh-indexer/opensearch-security/` and the active
  security configuration.
- An approved list of events, ignored service accounts, and retention period.

The endpoint prefix can be `/_plugins/_security/` or the older
`/_opendistro/_security/` depending on the OpenSearch version bundled with
Wazuh. Test `GET <PREFIX>/api/audit/config` before changing anything.

## Procedure

### 1. Configure the storage backend

Add these static settings to `/etc/wazuh-indexer/opensearch.yml` on every
indexer node:

```yaml
plugins.security.audit.type: internal_opensearch
plugins.security.audit.config.index: "'security-audit-'YYYY.MM.dd"
```

`internal_opensearch` writes audit events back into the current cluster. For
stronger tamper separation, evaluate `external_opensearch`, a data stream, or
another supported storage type instead.

Restart one indexer at a time and wait for the cluster to recover before
continuing:

```bash
sudo systemctl restart wazuh-indexer
sudo journalctl -u wazuh-indexer --since "5 minutes ago" --no-pager
```

```http
GET _cluster/health
GET _cat/nodes?v
```

### 2. Configure audit scope

In Wazuh Dashboard, open Indexer management > Security > Audit logs and
enable audit logging. Start with REST auditing and high-value failure events;
enable transport auditing only if the additional volume is required.

Recommended initial posture:

- Keep request-body logging disabled. Bodies can contain queries, event data,
  credentials, or personal information.
- Keep sensitive-header exclusion enabled.
- Ignore only known service accounts whose successful traffic would
  overwhelm useful records; continue logging their failures and security
  changes where the bundled plugin permits.
- Leave `AUTHENTICATED` and `GRANTED_PRIVILEGES` disabled initially if
  successful requests create excessive volume.
- Keep `FAILED_LOGIN`, `MISSING_PRIVILEGES`, `SSL_EXCEPTION`,
  `BAD_HEADERS`, and security-index modification attempts visible.

Export or capture the current audit configuration before using the REST API:

```http
GET _plugins/_security/api/audit/config
```

Example scoped configuration for a current OpenSearch Security API:

```http
PUT _plugins/_security/api/audit/config
{
  "enabled": true,
  "audit": {
    "ignore_users": [
      "kibanaserver"
    ],
    "ignore_requests": [],
    "disabled_rest_categories": [
      "AUTHENTICATED",
      "GRANTED_PRIVILEGES"
    ],
    "disabled_transport_categories": [
      "AUTHENTICATED",
      "GRANTED_PRIVILEGES"
    ],
    "log_request_body": false,
    "resolve_indices": true,
    "resolve_bulk_requests": false,
    "exclude_sensitive_headers": true,
    "enable_transport": false,
    "enable_rest": true
  }
}
```

If that payload is rejected, use the dashboard editor or the schema returned
by `GET` for the installed version. Do not copy a configuration between
different Wazuh/OpenSearch releases without comparing their schemas.

### 3. Create a dashboard data view

Create a data view/index pattern for:

```text
security-audit-*
```

Select `@timestamp` if it is available as the time field. Restrict read access
to security administrators and auditors; audit documents expose usernames,
source addresses, requested indices, and privilege decisions.

### 4. Add retention

Create a dedicated ISM policy for `security-audit-*`. Do not silently add the
pattern to the Wazuh alert policy because audit evidence may have a different
legal retention requirement.

Estimate storage from measured daily audit volume and replica count, then
verify policy attachment:

```http
GET _plugins/_ism/explain/security-audit-*
GET _cat/indices/security-audit-*?v&s=index
```

See [ISM retention](ilm-retention.md) for policy mechanics.

## Verification

1. Perform one controlled failed login to the indexer API from a test source.
2. Perform one request with an account that lacks the requested privilege.
3. Confirm the audit index exists:

   ```http
   GET _cat/indices/security-audit-*?v
   ```

4. Search recent categories:

   ```http
   GET security-audit-*/_search
   {
     "size": 20,
     "sort": [
       {
         "@timestamp": "desc"
       }
     ],
     "query": {
       "range": {
         "@timestamp": {
           "gte": "now-15m"
         }
       }
     }
   }
   ```

5. Verify the event identifies the source, effective user, request, category,
   and outcome without exposing authorization headers or passwords.
6. Measure daily index growth, shard count, and indexing latency for several
   days before expanding the categories.

## Troubleshooting

| Symptom | Check |
|---|---|
| Audit UI enabled but no index appears | `plugins.security.audit.type` on every node, rolling restart, indexer logs |
| REST API path returns 404 | Try the prefix used by the bundled plugin and inspect the installed OpenSearch version |
| Configuration changes disappear | Dynamic audit config was not saved through the Security API, or nodes have inconsistent static settings |
| Audit indices grow rapidly | Successful request categories, transport auditing, request-body/bulk resolution, ignored service accounts |
| Dashboard user cannot read audit data | Data-view permissions and index role mapping for `security-audit-*` |
| Cluster pressure increases | Reduce categories, shorten retention, change replicas, or send audit logs to an external backend |

## See also

- [Built-in internal users](auditing.md)
- [Indexer optimization hub](README.md)
- [OpenSearch audit logs](https://docs.opensearch.org/latest/security/audit-logs/index/)
- [OpenSearch audit storage types](https://docs.opensearch.org/latest/security/audit-logs/storage-types/)
