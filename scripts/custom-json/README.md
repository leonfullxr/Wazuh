Thought for 4 seconds


````markdown
# custom-swift_log_extractor README

## Overview

`custom-swift_log_extractor.py` is a Python3 script designed to run on a Wazuh manager. It listens for specific JSON-formatted Azure alerts (triggered via a custom rule), extracts additional fields from the alert payload, enriches the JSON, and forwards the result to the Wazuh analysis daemon (`analysisd`) via a UNIX datagram socket. The goal is to make fields like the initiating user’s principal name, IP address, and target resource group display names visible in subsequent alerts and in your SIEM.

---

## Table of Contents

1. [Prerequisites](#prerequisites)  
2. [Installation](#installation)  
3. [Configuration](#configuration)  
   - [1. Add integration to `ossec.conf`](#1-add-integration-to-ossecconf)  
   - [2. Place and secure the script](#2-place-and-secure-the-script)  
   - [3. Create custom rules](#3-create-custom-rules)  
4. [Script Details & Workflow](#script-details--workflow)  
   - [Logging setup](#logging-setup)  
   - [Reading the alert payload](#reading-the-alert-payload)  
   - [Extracting `InitiatedBy` fields](#extracting-initiatedby-fields)  
   - [Extracting `TargetResources` fields](#extracting-targetresources-fields)  
   - [Forwarding to analysisd](#forwarding-to-analysisd)  
5. [Usage](#usage)  
6. [Troubleshooting](#troubleshooting)  
7. [Implications & Notes](#implications--notes)  

---

## Prerequisites

- **Wazuh manager** with version supporting JSON integrations  
- **Python 3** installed on the manager  
- Write permissions under `/var/ossec/` for root or `wazuh` user  
- A rule ID (e.g., `113006`) reserved for triggering this integration  
- A UNIX datagram socket directory: `…/queue/sockets/queue`  

---

## Installation

1. **Copy the script**  
   Place the file in `/var/ossec/integrations/` (or your preferred integrations directory):  
   ```bash
   cp custom-swift_log_extractor.py /var/ossec/integrations/
````

2. **Set ownership & permissions**

   ```bash
   chown root:wazuh /var/ossec/integrations/custom-swift_log_extractor.py
   chmod 750 /var/ossec/integrations/custom-swift_log_extractor.py
   ```

3. **Restart Wazuh manager**

   ```bash
   systemctl restart wazuh-manager
   ```

---

## Configuration

### 1. Add integration to `ossec.conf`

In the `<integrations>` block of `/var/ossec/etc/ossec.conf`, add:

```xml
<integration>
    <name>custom-swift_log_extractor.py</name>
    <rule_id>113006</rule_id>           <!-- Your trigger rule ID -->
    <alert_format>json</alert_format>
    <options>JSON</options>
</integration>
```

> **Note:** Ensure that `<name>` matches the script filename exactly.

### 2. Place and secure the script

As above in Installation, confirm:

* Script path matches `<name>` in `ossec.conf`.
* Permissions allow Wazuh to execute the script.

### 3. Create custom rules

Create or edit a rules file, e.g. `/var/ossec/ruleset/local_rules.xml`:

```xml
<group name="azure,custom-json-enrichment">
  <!-- Trigger rule: catches incoming Azure log and runs the script -->
  <rule id="113006" level="3">
    <if_sid>87801</if_sid>                      <!-- Base Azure Log Analytics rule -->
    <field name="InitiatedBy">userPrincipalName</field>
    <field name="InitiatedBy">ipAddress</field>
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

---

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

---

## Usage

1. **Generate or receive** an Azure alert matching rule 87801 (or your base rule).
2. Wazuh rule 113006 fires, calls the extractor script.
3. Script enriches JSON, sends to `analysisd`.
4. Wazuh processes it as a new alert (rule 113007), now containing your extra fields.
5. Downstream tools (Filebeat, SIEM) will see the enriched JSON.

---

## Troubleshooting

* **No alerts with enriched fields**

  * Confirm `<integration><name>` matches script filename exactly.
  * Check `/var/ossec/logs/swift_extractor.log` for parse/send errors.
  * Verify your rule IDs and `if_sid` references in local rules.

* **Permission errors**

  * Ensure script is owned by `root:wazuh` with mode `750`.
  * Ensure `/var/ossec/queue/sockets/queue` is writable by Wazuh.

* **Duplicate naming**

  * The integration name in `ossec.conf` must match the actual Python script name.

---

## Implications & Notes

* **No impact on normal ingestion**

  * The script only runs for alerts matching your custom rule (e.g., 113006).
  * It “duplicates” the alert as an enriched version (rule 113007) without altering the original.

* **Performance**

  * Execution is per-alert. Ensure you scope the rule tightly to avoid high script invocation.

* **Adaptability**

  * To extract additional fields, extend the JSON parsing logic in the script before forwarding.
