# Overview

`custom-swift_extractor.py` is a script designed to run on a Wazuh manager. It listens for JSON-formatted alerts (triggered via a custom rule), extracts additional fields from the alert payload, enriches the JSON, and forwards the result to the Wazuh analysis daemon (`analysisd`) via a UNIX datagram socket. The goal is to make fields like the initiating user’s principal name, IP address, and target resource group display names visible in subsequent alerts.

The idea is to have a wodle that executes this script when a custom rule gets triggered, and then the content of the custom rule gets ingested into the script for its extraction.

Note: this script has been modified based on Azure Graph logs. The fields can be modifief accordingly to specific client/log requirements.

## Installation

1. **Copy the script**  
   Place the file in `/var/ossec/integrations/`:  
   ```bash
   cp custom-swift_extractor.py /var/ossec/integrations/
   ```

2. **Set ownership & permissions**

   ```bash
   chown root:wazuh /var/ossec/integrations/custom-swift_extractor.py
   chmod 750 /var/ossec/integrations/custom-swift_extractor.py
   ```

3. **Restart Wazuh manager**

   ```bash
   systemctl restart wazuh-manager
   ```

## Configuration

### 1. Add the integration wodle to `ossec.conf`

In the `<integrations>` block of `/var/ossec/etc/ossec.conf`, add:

```xml
<integration>
    <name>custom-swift_extractor.py</name>
    <rule_id>113006</rule_id>           <!-- Your trigger rule ID -->
    <alert_format>json</alert_format>
    <options>JSON</options>
</integration>
```

> **Note:** Ensure that `<name>` matches the script filename exactly.

### 2. Create custom rules

Create or edit a rules file, e.g. `/var/ossec/ruleset/local_rules.xml`:

```xml
<group name="azure,custom-json-enrichment">
  <!-- Trigger rule: catches incoming Azure log and runs the script -->
  <rule id="113006" level="3">
    <if_sid>87801</if_sid>                      <!-- Base Azure Log Analytics rule -->
    <field name="InitiatedBy">userPrincipalName</field> <!-- added for more precision -->
    <field name="InitiatedBy">ipAddress</field>  <!-- added for more precision -->
    <options>no_full_log</options>
    <description>Run JSON extractor to enrich Azure alert</description>
  </rule>

  <!-- Post-extraction rule: fires once script adds new fields -->
  <rule id="113007" level="3">
    <decoded_as>json</decoded_as>
    <if_sid>113006</if_sid>
    <field name="InitiatedBy_user_PrincipalName">\S+</field>
    <options>no_full_log</options>
    <description>
      Enriched alert: InitiatedBy_user_PrincipalName: $(InitiatedBy_user_PrincipalName),
      IP: $(InitiatedBy_user_ipAddress),
      TargetResources_userPrincipalName: $(TargetResources_userPrincipalName),
      GroupDisplayName new/old: $(TargetResources_GroupDisplayName_newValue)/$(TargetResources_GroupDisplayName_oldValue)
    </description>
  </rule>
</group>
```

Adjust rule IDs and `<if_sid>` values to suit your environment and avoid conflicts with other Azure rules (e.g., 87802, 87803…).

## Script Details & Workflow

### Logging setup

```python
logging.basicConfig(
    filename='/var/ossec/logs/swift_extractor.log',
    filemode='a',
    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
    level=logging.DEBUG
)
```

* **Log file**: `/var/ossec/logs/swift_extractor.log`
* **Log levels**: INFO, DEBUG, ERROR for troubleshooting

### Reading the alert payload

1. Reads the alert JSON file path from `sys.argv[1]`.
2. Loads it into `alert_json`, extracts `alert_json["data"]` as `alert_data`.
3. On failure, logs error and exits with code 1.

### Extracting `InitiatedBy` fields

1. Grabs `alert_data["InitiatedBy"]` (stringified JSON).
2. Parses into `initiated_by = json.loads(...)`.
3. If `initiated_by["user"]` exists, extracts:

   * `userPrincipalName` → `alert_data["InitiatedBy_user_PrincipalName"]`
   * `ipAddress` → `alert_data["InitiatedBy_user_ipAddress"]`

Otherwise logs a parse error.

### Extracting `TargetResources` fields

1. Reads `alert_data["TargetResources"]`, which may be a list or JSON-string.
2. Parses it into Python list `target_resources`.
3. From the **first** element:

   * `userPrincipalName` → `alert_data["TargetResources_userPrincipalName"]`
   * In `modifiedProperties`, finds `displayName == "Group.DisplayName"` and captures:

     * `newValue` → `alert_data["TargetResources_GroupDisplayName_newValue"]`
     * `oldValue` → `alert_data["TargetResources_GroupDisplayName_oldValue"]`

### Forwarding to analysisd

```python
sock = socket(AF_UNIX, SOCK_DGRAM)
sock.connect(SOCKET_ADDR)
message = "SWIFT:" + json.dumps(alert_data)
sock.send(message.encode())
sock.close()
logging.info("SWIFT log has been sent to the analysis queue.")
```

* **Socket path**: `…/queue/sockets/queue` (built relative to script’s parent directory).
* Prepends `"SWIFT:"` to the enriched JSON.
* Any send errors are logged and printed.

## Implications & Notes
* The script only runs for alerts matching your custom rule (e.g., 113006).
* It “duplicates” the alert as an enriched version (rule 113007). This would be the only downside...
