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

Add these static settings to `/etc/wazuh-indexer/opensearch.yml` on **every**
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

In Wazuh Dashboard, open **Indexer management > Security > Audit logs** and
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

## Reading console user activity

With auditing on, the audit index answers the accountability questions about
console use. It shows which user signed in and from where. It shows which
API calls the session made, and which settings that user changed. The trail
records requests that reach the indexer and the dashboard. It does not
record a click-by-click history of the UI.

Two places to read it:

- **Security > Audit logs** in the dashboard shows the status, the active
  configuration, and the recent categories.
- **Discover**, with a data view over the audit index, shows the raw events.
  They are filterable and exportable for an audit pack.

The index name follows `plugins.security.audit.config.index`, and it differs
between installations. `security-audit-*` is what this guide configures,
while `security-auditlog-*` appears on other setups. Confirm the name before
you create the data view:

```http
GET _cat/indices/security-audit*?v&s=index
```

### Question to field

| Question | Filter and fields |
|---|---|
| Who signed in, and when | `audit_category: AUTHENTICATED`, plus `audit_request_effective_user` and `@timestamp` |
| Who failed to sign in | `audit_category: FAILED_LOGIN`. The field `audit_request_effective_user` holds the name the client sent |
| Which endpoint a user called | `audit_rest_request_path` and `audit_rest_request_method` |
| Which user was denied | `audit_category: MISSING_PRIVILEGES`, plus `audit_request_privilege` |
| Which user accessed a resource successfully | `audit_category: GRANTED_PRIVILEGES`, plus `audit_request_privilege` |
| Which cluster or index setting changed | `CLUSTER_SETTINGS_CHANGED` or `INDEX_SETTINGS_CHANGED`. The `audit_settings_changes` array holds the setting, the old and new value, the operation, and the scope |
| Which security objects changed | The security-configuration category. Its name differs by release, so read the values from `audit_category` in your own data |
| Whether the caller used the admin TLS certificate | `audit_request_effective_user_is_admin`, which is true only when the caller presented the admin certificate |

`audit_request_initiating_user` is logged when it differs from the effective
user, which covers impersonation.

### Mistyped sign-ins look like extra accounts

`FAILED_LOGIN` stores the username string exactly as the client sent it. One
typo therefore creates a second apparent account with its own timestamps and
source addresses. Restrict any report on real accounts to successful
authentication:

```http
GET security-audit-*/_search
{
  "size": 0,
  "query": {
    "term": { "audit_category": "AUTHENTICATED" }
  },
  "aggs": {
    "users": {
      "terms": {
        "field": "audit_request_effective_user.keyword",
        "size": 50
      }
    }
  }
}
```

If the aggregation reports that the field is not aggregatable, check the
mapping with `GET security-audit-*/_mapping/field/audit_request_effective_user`
and use the sub-field name the index actually has.

### What the trail does not cover

| Change | Attributed? | Where it is recorded |
|---|---|---|
| Index or cluster settings through the API | Yes | Audit index, with old and new values |
| Internal users, roles, and role mappings | Yes | Audit index, security-configuration category |
| Rules, decoders, and `ossec.conf` written on the manager | No | [FIM](../fim/README.md) detects the file change. The user behind it needs whodata, which a containerized manager cannot provide ([details](../fim/containers.md#whodata-attribution-is-not-available-inside-a-container)) |
| Navigation and page views inside the UI | No | Not recorded |

For manager configuration, pair FIM with a change process that carries
attribution of its own. Managing rules, decoders, and configuration in a
repository gives who, what, and when through commit history, and the FIM
alert confirms when the change reached the manager.

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
| One account appears under several usernames | `FAILED_LOGIN` records the name the client sent, typos included. Aggregate on `AUTHENTICATED` only |
| Cluster pressure increases | Reduce categories, shorten retention, change replicas, or send audit logs to an external backend |

## See also

- [Built-in internal users](auditing.md)
- [FIM in containerized environments](../fim/containers.md) - why file changes on the manager carry no user attribution in a pod
- [Indexer optimization hub](README.md)
- [OpenSearch audit logs](https://docs.opensearch.org/latest/security/audit-logs/index/)
- [OpenSearch audit storage types](https://docs.opensearch.org/latest/security/audit-logs/storage-types/)
