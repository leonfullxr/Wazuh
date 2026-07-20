# Extracting structured data from Windows eventchannel messages

The decoder for Windows eventchannel logs is built into the Wazuh manager's
source code, so you cannot modify it or write a custom decoder for this log
type. When the value you need lives inside the free-text or XML `message` of an
event, the alternative is a custom **integratord** script: it fires on alerts
matching a rule ID, parses the `message` block, and re-injects the structured
JSON into the manager's analysis queue, where a second rule turns it into a
clean alert with the values as first-class fields.

This folder ships **two parsers** for the two common message shapes - pick the
one that matches your source. For **JSON** logs use
[`../custom-json`](../custom-json) instead (a different input format, a
different script):

| Script | Message shape | Example source | Writes |
|---|---|---|---|
| `custom-windows` | `key: value` free text | Antivirus (Symantec, ...) scan results | `win.system.messages` |
| `custom-windows-xml` | embedded XML | ADFS audit events (EventID 1203 / 1210) | `win.system.parsed_fields` (default `UserId`, `IpAddress`) |

For the concept, the alternatives (and why they fall short), and the important
**scale caveat** (each re-injection roughly doubles the queue load for matched
events), see
[decoders/windows-eventchannel-fields.md](../../decoders/windows-eventchannel-fields.md).

## `custom-windows` - key/value messages

Extracts a configurable list of keys (scan type, detected risk, file, action
taken, counters, product/version metadata - edit `EXTRACT_KEYS` and
`METRIC_PATTERNS` at the top of the script) and replaces `win.system.message`
with a structured `win.system.messages` object. Leading free text before the
first key is kept under `Information`.

## `custom-windows-xml` - XML messages (ADFS)

Extracts the configured XML tags (edit `TAGS` at the top; default `UserId` and
`IpAddress`) from `win.system.message`, falling back to `win.eventdata.data`.
It HTML-unescapes the payload, parses it as XML, and **falls back to regex**
when the content is escaped or truncated (ADFS `win.eventdata.data` often is),
writing the results to `win.system.parsed_fields`. Note `<IpAddress>` can be a
comma-separated `client,forwarded` list.

Validate the parser without touching the manager:

```bash
python3 custom-windows-xml --selftest      # prints "selftest OK"
```

## Installation

Same steps for either script - substitute the name (`custom-windows` or
`custom-windows-xml`):

1. Copy it into the integrations directory and set ownership/permissions:

   ```bash
   cp custom-windows-xml /var/ossec/integrations/custom-windows-xml
   chmod 750 /var/ossec/integrations/custom-windows-xml
   chown root:wazuh /var/ossec/integrations/custom-windows-xml
   ```

2. Add an `<integration>` block to `/var/ossec/etc/ossec.conf` with the rule ID
   that matches the eventchannel logs to process (for ADFS, a rule on EventID
   1203 / 1210):

   ```xml
   <integration>
     <name>custom-windows-xml</name>
     <hook_url>NONE</hook_url>
     <api_key>NONE</api_key>
     <rule_id>RULE_ID</rule_id> <!-- Replace with the trigger rule ID -->
     <alert_format>json</alert_format>
   </integration>
   ```

3. Add a rule that alerts on the re-injected structured events (dashboard >
   **Server Management > Rules** > add a new rules file):

   ```xml
   <group name="windows,custom,">
     <rule id="100110" level="10">
       <decoded_as>json</decoded_as>
       <field name="integration">^custom-windows-xml$</field>
       <description>ADFS: user $(win.system.parsed_fields.UserId) from $(win.system.parsed_fields.IpAddress)</description>
       <options>no_full_log</options>
     </rule>
   </group>
   ```

4. Restart the Wazuh manager - on **every** node in a cluster; integrations and
   rules are not synchronized automatically.

## Debugging

Run the script manually against a saved alert JSON file with debug output
(written to `/var/ossec/logs/custom-windows*.log` and stdout):

```bash
/var/ossec/integrations/custom-windows-xml /tmp/sample_alert.json debug
```

Or set `integrator.debug=2` in `/var/ossec/etc/internal_options.conf`, restart,
and watch `/var/ossec/logs/ossec.log`.

## Related

- [decoders/windows-eventchannel-fields.md](../../decoders/windows-eventchannel-fields.md) - concept, alternatives, and the scale caveat
- [`../custom-json`](../custom-json) - the equivalent enrichment for **JSON** logs (a different input format, not the same script)
- [`../otlp-syslog-extraction`](../otlp-syslog-extraction) - a similar "unwrap the embedded payload" pattern for JSON-wrapped syslog
- [Integratord documentation](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)
