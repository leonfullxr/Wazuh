# Active Response: blocking attacker IPs

Active Response (AR) runs a script on an endpoint or on the manager when an
alert matches a chosen rule/level, so detections can trigger an automatic
reaction (block an IP, disable an account, run a remediation command). Wazuh
ships out-of-the-box AR scripts, and you can add your own.

Two building blocks tie together in `ossec.conf`:

```xml
<command>
  <name>block-ip</name>              <!-- label used by the active-response block -->
  <executable>block-ip.py</executable> <!-- script under active-response/bin -->
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <disabled>no</disabled>
  <command>block-ip</command>
  <location>local</location>         <!-- where the script runs, see below -->
  <rules_id>100001</rules_id>        <!-- or <level>10</level> -->
  <timeout>600</timeout>             <!-- seconds; auto-undo after this -->
</active-response>
```

`<location>` controls where the response executes:

- `local` - on the agent that raised the alert (most common).
- `server` - on the Wazuh manager.
- `defined-agent` - on a specific agent (`<agent_id>001</agent_id>`).
- `all` - on every agent.

`<timeout>` with a timeout-capable command auto-reverses the action (for
example, unblocks the IP) after the given number of seconds.

## Recipe 1: block with the built-in `firewall-drop`

The out-of-the-box `firewall-drop` script blocks the attacker's source IP on
the local firewall of the endpoint that raised the alert (iptables /
firewalld on Linux, PF on macOS/BSD, netsh on Windows). No custom code needed:
just point it at the rules that identify the attack. Example wiring it to the
built-in Shellshock rules for a 10-minute block:

```xml
<!-- /var/ossec/etc/ossec.conf on the Wazuh manager -->
<ossec_config>
  <!-- firewall-drop is usually present by default -->
  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>       <!-- run on the attacked endpoint -->
    <rules_id>31168,31169</rules_id>  <!-- Shellshock rules -->
    <timeout>600</timeout>            <!-- auto-unblock after 10 minutes -->
  </active-response>
</ossec_config>
```

The same pattern works for SSH brute force, web attacks, or any rule that
carries a `srcip`. Test by triggering the rule and checking
`/var/ossec/logs/active-responses.log` on the endpoint for execution details.

## Recipe 2: maintain a CDB blocklist via an integration script

When you want a central, persistent list of attacker IPs (for example, to
feed a perimeter firewall, or to escalate on repeat offenders), use an
integration script instead of an AR command. It appends each attacker's source
IP to a [CDB list](https://documentation.wazuh.com/current/user-manual/ruleset/cdb-list.html),
and a companion rule raises a high-severity alert whenever a new event arrives
from an IP already on the list.

An integration is more reliable than an AR command for this: appending to a
shared list from the AR execution context behaves inconsistently across
versions, whereas the integration hook runs the script cleanly on every
matching alert.

[`cdb-blocklist-integration.py`](cdb-blocklist-integration.py) does exactly
this: see its header for behaviour and the docstrings for each step.

### Install

1. Copy the script into the manager's integrations directory and set
   ownership/permissions (repeat on every manager in a cluster):

   ```bash
   cp cdb-blocklist-integration.py /var/ossec/integrations/
   chown root:wazuh /var/ossec/integrations/cdb-blocklist-integration.py
   chmod 750       /var/ossec/integrations/cdb-blocklist-integration.py
   ```

2. Create the CDB source list the script appends to:

   ```bash
   cd /var/ossec/etc/lists
   touch blacklist-custom
   chown wazuh:wazuh blacklist-custom
   chmod 660 blacklist-custom
   ```

3. Register the list and add the integration in `/var/ossec/etc/ossec.conf`.
   Point `<rule_id>` at the rules whose source IPs you want to collect:

   ```xml
   <ruleset>
     <!-- ... -->
     <list>etc/lists/blacklist-custom</list>
   </ruleset>

   <integration>
     <name>cdb-blocklist-integration.py</name>
     <rule_id>100071,100072</rule_id>
     <alert_format>json</alert_format>
     <options>JSON</options>
   </integration>
   ```

4. Add rules: one (or more) that select the events to harvest IPs from, and
   one that fires when a source IP matches the list
   (`address_match_key` looks up the IP against the list keys):

   ```xml
   <group name="attack,">
     <!-- Collect IPs from these events (adjust if_sid to your sources). -->
     <rule id="100071" level="10">
       <if_sid>5715</if_sid>                    <!-- e.g. sshd accepted/auth -->
       <if_group>web|attack|attacks|sshd</if_group>
       <description>Source IP candidate for the blocklist.</description>
     </rule>
     <rule id="100072" level="10">
       <if_sid>BASE_RULE_ID</if_sid>            <!-- e.g. your firewall base rule -->
       <description>Source IP candidate (firewall logs).</description>
     </rule>

     <!-- Fire when an incoming IP is already on the blocklist. -->
     <rule id="100073" level="12">
       <if_sid>100071</if_sid>
       <list field="srcip" lookup="address_match_key">etc/lists/blacklist-custom</list>
       <description>Source IP found in the custom blocklist.</description>
     </rule>
   </group>
   ```

5. Restart the manager. Optionally create the script's log dir up front
   (it self-creates it, but this fixes ownership):

   ```bash
   mkdir -p /var/log/cdb-blocklist
   chown -R wazuh:wazuh /var/log/cdb-blocklist
   chmod 750 /var/log/cdb-blocklist
   ```

### Verify

Ingest a test log carrying a `srcip` that matches rule 100071/100072, then:

```bash
cat /var/ossec/etc/lists/blacklist-custom   # new "<ip>:" entry appears
tail /var/log/cdb-blocklist/cdb-blocklist.log
```

Send the same IP again and the log shows `Entry already present`, and rule
100073 fires at level 12.

## Gotchas

- **Permissions are the usual failure.** If the log shows
  `Permission denied: '.../blacklist-custom'`, the `wazuh` user cannot write
  the list: fix ownership (`chown wazuh:wazuh`) and mode (`660`). The
  integration script must be `750`, `root:wazuh`.
- **No `srcip` in the alert.** The script extracts `data.srcip`, then falls
  back to a `srcip=<ip>` token in `full_log`. Alerts with neither are logged
  and skipped: confirm the decoder actually extracts a source IP.
- **Pushing to a perimeter firewall.** To block on an edge device
  (Fortinet, Palo Alto, OPNsense, etc.) rather than the local host, have a
  custom script call the device API/CLI, or ship the blocklist file to a box
  the firewall reads (for example via key-based `scp` to a dedicated,
  least-privilege user) and run it with `<location>server</location>` or on a
  jump host.
- **Rule levels vs. loops.** A collection rule that also matches its own
  re-injected alerts can loop; keep the "found in list" rule (100073) at a
  distinct level and scope its `if_sid` narrowly.

## Related

- [`../eventchannel-extraction`](../eventchannel-extraction) - another
  integratord script pattern (parse and re-inject structured data).
- [`../email-alerting`](../email-alerting) - route the resulting high-severity
  alerts to the right recipients.
