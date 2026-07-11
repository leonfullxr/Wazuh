# Extracting structured data from Windows eventchannel messages

The decoder for Windows eventchannel logs is built into the Wazuh manager's
source code, so you cannot modify it or write a custom decoder for this log
type. When the interesting data lives in the free-text `message` field of an
event (common with antivirus and other security products logging to the event
channel), the alternative is a custom **integratord** script: it fires on
alerts matching a rule ID, parses the `message` block into key/value pairs,
and re-injects the structured JSON into the manager's analysis queue, where a
custom rule turns it into a clean alert.

`custom-windows` extracts a configurable list of keys (scan type, detected
risk, file, action taken, counters, product/version metadata, etc. - edit
`EXTRACT_KEYS` and `METRIC_PATTERNS` at the top to match your event source)
and replaces `win.system.message` with a structured `win.system.messages`
object. Any leading free text before the first key is kept under
`Information`.

## Installation

1. SSH to the Wazuh manager and copy the script into the integrations
   directory:

   ```bash
   cp custom-windows /var/ossec/integrations/custom-windows
   chmod 750 /var/ossec/integrations/custom-windows
   chown root:wazuh /var/ossec/integrations/custom-windows
   ```

2. Add an `<integration>` block to `/var/ossec/etc/ossec.conf`, replacing
   `RULE_ID` with the rule ID that matches the eventchannel logs you want to
   process:

   ```xml
   <integration>
     <name>custom-windows</name>
     <hook_url>NONE</hook_url>
     <api_key>NONE</api_key>
     <rule_id>RULE_ID</rule_id> <!-- Replace with actual rule ID -->
     <alert_format>json</alert_format>
   </integration>
   ```

3. Create a rule that alerts on the re-injected structured events
   (dashboard > **Server Management > Rules** > add a new rules file):

   ```xml
   <group name="windows,custom,">
     <rule id="100011" level="10">
       <decoded_as>json</decoded_as>
       <field name="integration">^custom-windows$</field>
       <description>Windows custom decoded logs.</description>
       <options>no_full_log</options>
     </rule>
   </group>
   ```

4. Restart the Wazuh manager.

## Debugging

Run the script manually against a saved alert JSON file with debug output:

```bash
/var/ossec/integrations/custom-windows /tmp/sample_alert.json debug
```

## Related

- [Integratord documentation](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)
- [`../otlp-syslog-extraction`](../otlp-syslog-extraction) - a similar
  "unwrap the embedded payload" pattern for JSON-wrapped syslog.
