# Collecting Jira Audit Exports

Jira audit API responses wrap records in a `records` array. Wazuh's JSON log
collector expects one JSON object per line, so this integration normalizes a
downloaded response to NDJSON and applies focused rules to the resulting
records.

This guide covers normalization and Wazuh ingestion. Automate the Jira API
download separately using the current Atlassian authentication, pagination,
and rate-limit documentation. Never store an API token in this repository.

## Prerequisites

- A Jira audit export shaped as
  `{"offset":0,"limit":1000,"records":[...]}`.
- `jq` on the host that normalizes the export.
- A Wazuh agent on that host, with read access to the output directory.
- An approved list of Jira audit actions and severities.

Audit records can contain account IDs, project names, IP addresses, and object
details. Restrict file permissions and dashboard access accordingly.

## Procedure

1. Install the normalizer:

   ```bash
   sudo install -o root -g wazuh -m 750 jira-format_json.sh \
     /usr/local/sbin/jira-format-json
   sudo install -d -o root -g wazuh -m 750 /var/log/atlassian/jira
   ```

2. Normalize one downloaded response to a uniquely named NDJSON file:

   ```bash
   sudo /usr/local/sbin/jira-format-json \
     /var/lib/atlassian/jira-audit-2026-07-10T120000Z.json \
     /var/log/atlassian/jira/jira-audit-2026-07-10T120000Z.ndjson
   sudo chown root:wazuh \
     /var/log/atlassian/jira/jira-audit-2026-07-10T120000Z.ndjson
   ```

   The script validates every element with `jq -e` and publishes the output
   atomically so Wazuh does not read a partial file.

3. Configure the local Wazuh agent:

   ```xml
   <localfile>
     <location>/var/log/atlassian/jira/*.ndjson</location>
     <log_format>json</log_format>
     <only-future-events>yes</only-future-events>
   </localfile>
   ```

4. Install [`jira_rules.xml`](jira_rules.xml) on every manager:

   ```bash
   sudo install -o wazuh -g wazuh -m 640 jira_rules.xml \
     /var/ossec/etc/rules/jira_audit_rules.xml
   sudo /var/ossec/bin/wazuh-analysisd -t
   sudo systemctl restart wazuh-manager
   sudo systemctl restart wazuh-agent
   ```

## Verification

Validate the conversion:

```bash
jq -e -c . /var/log/atlassian/jira/*.ndjson >/dev/null
wc -l /var/log/atlassian/jira/*.ndjson
```

Paste one sanitized line into `/var/ossec/bin/wazuh-logtest`. Phase 2 should
select the JSON decoder and phase 3 should match the intended Jira rule.

In the dashboard, verify `summary`, `category`, `objectItem`, actor fields,
rule ID, and timestamp. Compare the source record count to the number
collected, accounting for rules that intentionally remain below alert level.

## Operations

- Implement API pagination; a single response may not contain the full audit
  interval.
- Keep a cursor or interval checkpoint to avoid gaps and duplicate downloads.
- Write a new timestamped NDJSON file per successful fetch and rotate files
  after Wazuh has consumed them.
- Review `jira_rules.xml` when Atlassian changes summary/category text.
- Do not alert on every administrative record. Assign high levels only to
  actions that require response in your environment.

## See also

- [Confluence audit exports](../confluence/README.md)
- [Generic webhook delivery](../../webhook/README.md)
- [Wazuh JSON log collection](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/log-data-configuration.html)
