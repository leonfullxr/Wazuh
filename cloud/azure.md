# Azure Log Ingestion (azure-logs wodle + ms-graph module)

## Table of Contents
- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Minimal Configuration Examples](#minimal-configuration-examples)
- [Common Pitfalls](#common-pitfalls)
- [Workaround: Indexer Mapping Conflicts](#workaround-indexer-mapping-conflicts)
- [References](#references)

## Introduction

Wazuh integrates with Microsoft Azure through two components:

1. **`azure-logs` wodle** -- a Python module (`/var/ossec/wodles/azure/azure-logs`, runs on the manager or a Linux agent) with three sub-integrations:
   - **`<log_analytics>`** -- runs KQL queries against a Log Analytics workspace via the Log Analytics API (Azure Monitor / Activity logs, any table in the workspace).
   - **`<graph>`** -- pulls Microsoft Entra ID (Azure AD) logs via the Microsoft Graph API (e.g. `auditLogs/directoryAudits`, `auditLogs/signIns`).
   - **`<storage>`** -- reads log blobs from an Azure Storage account container (e.g. diagnostics exported to blob storage).
2. **`ms-graph` module** -- a native `modulesd` module (Wazuh >= 4.6, configured as `<ms-graph>` in `ossec.conf`) that polls the Microsoft Graph Security API: Defender / Microsoft 365 Defender alerts and incidents (`security` to `alerts_v2`, `incidents`), Entra ID Protection (`identityProtection` to `riskDetections`), Intune device management, and more.

Official docs: [Using Wazuh to monitor Microsoft Azure](https://documentation.wazuh.com/current/cloud-security/azure/index.html) and [ms-graph module reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/ms-graph-module.html)

## Prerequisites

- **App registration** in Microsoft Entra ID: note the tenant (directory) ID and application (client) ID, and create a client secret.
- **API permissions** (Application type) granted with admin consent:
  - Log Analytics: `Data.Read` on the Log Analytics API; the app also needs a Reader role on the workspace.
  - Graph wodle: `AuditLog.Read.All`, `Directory.Read.All` on Microsoft Graph.
  - ms-graph module: `SecurityEvents.Read.All` / `SecurityAlert.Read.All`, `SecurityIncident.Read.All`, `IdentityRiskEvent.Read.All`, depending on the resources queried.
- The storage sub-integration instead uses the storage account name and an access key (no app registration required).
- Credentials for the wodle should go in an `auth_path` file (`application_id` / `application_key` lines) rather than inline in `ossec.conf`.

## Minimal Configuration Examples

Log Analytics via the wodle:

```xml
<wodle name="azure-logs">
  <disabled>no</disabled>
  <interval>1d</interval>
  <run_on_start>yes</run_on_start>
  <log_analytics>
    <auth_path>/var/ossec/wodles/azure_credentials</auth_path>
    <tenantdomain>yourtenant.onmicrosoft.com</tenantdomain>
    <request>
      <tag>azure-activity</tag>
      <query>AzureActivity</query>
      <workspace>WORKSPACE_ID</workspace>
      <time_offset>1d</time_offset>
    </request>
  </log_analytics>
</wodle>
```

Defender / Entra alerts via the ms-graph module:

```xml
<ms-graph>
  <enabled>yes</enabled>
  <only_future_events>yes</only_future_events>
  <interval>5m</interval>
  <version>v1.0</version>
  <api_auth>
    <client_id>APP_CLIENT_ID</client_id>
    <tenant_id>TENANT_ID</tenant_id>
    <secret_value>CLIENT_SECRET</secret_value>
    <api_type>global</api_type>
  </api_auth>
  <resource>
    <name>security</name>
    <relationship>alerts_v2</relationship>
  </resource>
</ms-graph>
```

## Common Pitfalls

- **Mapping conflicts in the indexer.** Azure events sometimes ship `data.properties` as an object and sometimes as a plain string, so documents get rejected with `mapper_parsing_exception`. See the [workaround below](#workaround-indexer-mapping-conflicts).
- **Client secret expiry.** Secrets expire (6-24 months by default); the wodle then fails authentication silently until you check `ossec.log`. Track renewal dates.
- **Missing admin consent** results in HTTP 403 on every request even though the permissions look configured in the portal.
- **State/offsets.** `time_offset` (wodle) and `only_future_events` (ms-graph) only apply to the first execution; afterwards the modules resume from their stored state under `/var/ossec/wodles/azure/` -- clear it to re-ingest.
- **Storage `content_type`** must match the blob format (`json_file`, `json_inline`, `plain`), otherwise events are mangled or skipped.
- **Proxy/egress issues** are common when the manager runs containerized: confirm the container can actually reach `login.microsoftonline.com` and `graph.microsoft.com` through your proxy before blaming the module.
- **Debugging.** Set `wazuh_modules.debug=2` in `local_internal_options.conf`, or run `/var/ossec/wodles/azure/azure-logs` manually with the same arguments as your configuration.

## Workaround: Indexer Mapping Conflicts

If you forward events through Logstash, the following filter moves the string variant of `data.properties` to a separate field so both shapes can be indexed:

```ruby
filter {
  ruby {
    code => "
      if event.get('[data][properties]').is_a? String
        event.set('[data][properties_string]', event.get('[data][properties]'))
        event.remove('[data][properties]')
      end
    "
  }
}
```

## References

- [Using Wazuh to monitor Microsoft Azure](https://documentation.wazuh.com/current/cloud-security/azure/index.html)
- [ms-graph module reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/ms-graph-module.html)
- [AWS log ingestion](aws.md)
- [Google Cloud Pub/Sub ingestion](gcp-pubsub.md)
