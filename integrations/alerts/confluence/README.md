# Collecting Confluence Audit Exports

Confluence audit API responses wrap events in a `results` array. This
integration converts a downloaded response to newline-delimited JSON (NDJSON)
so a Wazuh agent can collect each audit record independently.

The procedure covers normalization and Wazuh ingestion, not the vendor API
client. Automate downloads with the current Atlassian authentication,
pagination, and rate-limit guidance, and keep credentials outside scripts and
the repository.

## Prerequisites

- A Confluence audit response shaped as `{"results":[...],"start":0,...}`.
- `jq` on the normalization host.
- A Wazuh agent with read access to the output directory.
- An approved audit-event and severity policy.

Confluence records can contain user names, account identifiers, source
addresses, page/space names, and permission changes. Treat the output as
security-sensitive.

## Procedure

1. Install the normalizer and create a protected output directory:

   ```bash
   sudo install -o root -g wazuh -m 750 confluence-format_json.sh \
     /usr/local/sbin/confluence-format-json
   sudo install -d -o root -g wazuh -m 750 /var/log/atlassian/confluence
   ```

2. Normalize one API response:

   ```bash
   sudo /usr/local/sbin/confluence-format-json \
     /var/lib/atlassian/confluence-audit-2026-07-10T120000Z.json \
     /var/log/atlassian/confluence/confluence-audit-2026-07-10T120000Z.ndjson
   sudo chown root:wazuh \
     /var/log/atlassian/confluence/confluence-audit-2026-07-10T120000Z.ndjson
   ```

   The script validates every record and atomically renames the complete
   output into place.

3. Configure the local Wazuh agent:

   ```xml
   <localfile>
     <location>/var/log/atlassian/confluence/*.ndjson</location>
     <log_format>json</log_format>
     <only-future-events>yes</only-future-events>
   </localfile>
   ```

4. Install [`confluence_rules.xml`](confluence_rules.xml) on every manager:

   ```bash
   sudo install -o wazuh -g wazuh -m 640 confluence_rules.xml \
     /var/ossec/etc/rules/confluence_audit_rules.xml
   sudo /var/ossec/bin/wazuh-analysisd -t
   sudo systemctl restart wazuh-manager
   sudo systemctl restart wazuh-agent
   ```

## Verification

```bash
jq -e -c . /var/log/atlassian/confluence/*.ndjson >/dev/null
wc -l /var/log/atlassian/confluence/*.ndjson
```

Paste one sanitized line into `/var/ossec/bin/wazuh-logtest`. Confirm the JSON
decoder extracts nested fields and the intended Confluence rule matches.

In the dashboard, verify actor, source address, `summary`, `category`,
`affectedObject`, `associatedObjects`, rule ID, and timestamp. Compare source
and output record counts before relying on the pipeline.

## Operations

- Fetch every page and maintain a durable interval/cursor checkpoint.
- Write a timestamped file only after a complete successful API response.
- Rotate consumed NDJSON files based on audit volume and retention.
- Review rule field paths and text when Atlassian changes the response schema.
- Rules matching `sysAdmin` or `superAdmin` activity should add context, not
  automatically imply malicious behavior.

## See also

- [Jira audit exports](../jira/README.md)
- [Generic webhook delivery](../../webhook/README.md)
- [Wazuh JSON log collection](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/log-data-configuration.html)
