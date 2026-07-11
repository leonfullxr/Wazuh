# Auditing the Built-in Internal Users

Security reviews of a Wazuh deployment regularly flag the indexer's default
accounts and ask which can be removed. Short answer: they are **service
accounts and roles of the OpenSearch Security plugin**, not end-user logins.
Most should be kept and restricted rather than deleted - several are
load-bearing, and removing the wrong one takes the dashboard or alert
ingestion down.

They are defined in
`/etc/wazuh-indexer/opensearch-security/internal_users.yml` and managed with
`securityadmin.sh` or the dashboard security UI. See
[OpenSearch - security configuration YAML files](https://docs.opensearch.org/latest/security/configuration/yaml/).

## Account-by-account breakdown

### admin

The cluster superuser. Used for low-level administrative tasks against the
security REST API (role management, mappings, certificates, applying
configuration via `securityadmin.sh`) and general backend administration.

**Do not delete.** It is the only account that can recover control of the
cluster if the security configuration locks you out. Day-to-day operational
use can and should be restricted - reserve it for emergency and maintenance
procedures.

### kibanaserver

The service account the **Wazuh Dashboard backend** uses to authenticate
against the indexer and persist UI state: the `.kibana*` indices, saved
objects, visualizations, dashboards and tenant configuration. Declared in
`/etc/wazuh-dashboard/opensearch_dashboards.yml`.

**Deleting it breaks the dashboard**: the console can no longer log in to the
indexer or load the UI.

### logstash

A service account intended for ingestion processes (Logstash, Filebeat with
direct output, external agents) that need write access to cluster indices.
Historically used by Filebeat on the Wazuh manager to ship alerts to the
indexer.

**Verify before touching it.** If your ingestion pipelines authenticate with
this account, removing it stops alert indexing. If Filebeat uses a dedicated
account with the `filebeat` role instead, `logstash` may be inactive - but it
is conventionally kept as a template account for ingestion integrations.
Check what credentials Filebeat actually uses (`filebeat keystore list`,
`filebeat test output`) before deciding.

### snapshotrestore

Mapped to the role with snapshot privileges (`cluster:admin/snapshot/*`,
`indices:admin/*`). Used by automated backup jobs or manual restore
operations.

Not essential for online cluster operation, but required for the snapshot
functionality - **recommended to keep**.

### anomalyadmin

Tied to the OpenSearch **Anomaly Detection** plugin; part of the Security
plugin's predefined catalog. As of Wazuh 4.14.0 the Anomaly Detection module
is enabled by default. Removing the account does not affect the Wazuh core
*provided* the Anomaly Detection module has been explicitly disabled.

### readall / kibanaro (roles)

Predefined **read-only roles**, not accounts. `readall` grants read access to
all indices at the backend level; `kibanaro` allows read-only consumption
through the dashboard. They exist to map audit, monitoring or query users
without write privileges.

**No risk if unmapped to real users** - and they are exactly what you want
for least-privilege and segregation-of-duties mappings, so keep them.

## Summary table

| Account / role | Safe to delete? | Consequence of removal |
|---|---|---|
| `admin` | No | Lose the only guaranteed recovery path into the cluster |
| `kibanaserver` | No | Dashboard cannot authenticate; UI down |
| `logstash` | Only after verifying ingestion does not use it | Alert indexing stops if in use |
| `snapshotrestore` | Discouraged | Snapshot/restore functionality breaks |
| `anomalyadmin` | Yes, if Anomaly Detection is disabled | Anomaly Detection plugin loses its service account |
| `readall`, `kibanaro` | Keep (harmless) | Lose convenient read-only role mappings |

## Hardening recommendations

- Change every default password with the `wazuh-passwords-tool.sh` (see
  [password reset and recovery](../troubleshooting/passwords-recovery.md)
  for the keystore side effects on Filebeat and the dashboard).
- Restrict `admin` to break-glass procedures; create named administrator
  accounts mapped to appropriate roles for routine work.
- Map human read-only consumers (auditors, NOC screens) to `readall` /
  `kibanaro` instead of granting broader roles.
- Audit `internal_users.yml` and the role mappings after upgrades - new
  plugin service accounts (like `anomalyadmin`) can appear as features are
  enabled by default.

## See also

- [Indexer security audit logs](security-audit-logs.md) - record authentication,
  authorization, TLS, and security-configuration activity.
- [Password reset and recovery](../troubleshooting/passwords-recovery.md)
