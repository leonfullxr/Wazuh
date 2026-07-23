# Agent Flooding and Noisy Alerts

Runbook for `Agent buffer is full` warnings, dropped events at the agent, and - since it is almost always the real root cause - reducing noisy alert sources.

## Table of Contents

- [How the agent buffer works](#how-the-agent-buffer-works)
- [Triage questions](#triage-questions)
- [Step 1: Find the flooding source](#step-1-find-the-flooding-source)
  - [Most-triggered rules per agent](#most-triggered-rules-per-agent)
  - [Enable archives to see events that trigger no alert](#enable-archives-to-see-events-that-trigger-no-alert)
  - [Debug logging](#debug-logging)
- [Step 2: Reduce noise at the source](#step-2-reduce-noise-at-the-source)
  - [Exclude events at collection (agent side)](#exclude-events-at-collection-agent-side)
  - [Silence a rule (manager side)](#silence-a-rule-manager-side)
- [Step 3 (last resort): Increase the client buffer](#step-3-last-resort-increase-the-client-buffer)
- [Inspecting agent databases on the manager](#inspecting-agent-databases-on-the-manager)
- [Related guides](#related-guides)

## How the agent buffer works

The agent buffer is a purely **in-memory leaky-bucket queue** that smooths bursts of events toward the manager:

- Default capacity is **5,000 events**, drained at up to **500 events/second** ([anti-flooding mechanism](https://documentation.wazuh.com/current/user-manual/agent/agent-management/antiflooding.html)).
- At **90% occupancy** a warning alert is generated; at **100%** new events are silently **dropped**. The buffer never blocks or throttles the processes producing the events.
- It is **volatile**: an agent restart clears it, and buffered events are never persisted to disk.
- The buffer itself causes **no disk I/O**. Heavy disk activity on a monitored host comes from the monitored application itself, or from Wazuh modules (FIM, Logcollector) scanning rapidly changing files - not from the buffer.

Two practical consequences:

1. A buffer overflow **cannot** harm the monitored application (e.g. a database); it only loses telemetry.
2. Raising `queue_size` only increases RAM usage *when the queue fills* (roughly `queue_size x average event size`; events are typically a few hundred bytes to a few KB). It does not fix the flood - it postpones it.

A common failure mode: FIM (syscheck) configured over fast-changing data directories (database datafiles, log spools) floods the buffer with file-change events. Check the agent's `/var/ossec/logs/ossec.log` to see which module is active right before the buffer fills, and exclude those paths from monitoring.

## Triage questions

Before changing anything, establish:

- What does this agent monitor? Does it receive syslog from external devices?
- How many `<localfile>` entries does it have?
- Did the flooding start after adding a monitored product/service or changing configuration?

## Step 1: Find the flooding source

### Most-triggered rules per agent

Build a quick data-table visualization in the dashboard:

1. Go to **Explore -> Visualize -> Create visualization**.
2. Choose **Data Table** over the `wazuh-alerts-*` index pattern.
3. Add a bucket -> **Split rows** -> Aggregation **Terms** -> Field `rule.id` -> **Update**.
4. Add a filter: `agent.id` **is** `<AGENT_ID>`.

The result is the top alerting rules for that agent. Review whether they are actually needed - most floods are dominated by a handful of low-value rules.

### Enable archives to see events that trigger no alert

Not every incoming event triggers an alert, so alert data alone can miss the flood. Temporarily log everything the manager receives:

1. In the manager's `/var/ossec/etc/ossec.conf` set:

   ```xml
   <logall_json>yes</logall_json>
   ```

2. Restart the manager:

   ```bash
   systemctl restart wazuh-manager
   ```

3. Watch what arrives from the agent:

   ```bash
   tail -f /var/ossec/logs/archives/archives.json | grep -i '"id":"<AGENT_ID>"'
   ```

4. **When done, set `logall_json` back to `no` and restart the manager** - archives grow very fast and will fill the disk.

### Debug logging

To trace Windows event collection and logcollector behavior, on the affected component set in `/var/ossec/etc/local_internal_options.conf`:

```ini
windows.debug=2
logcollector.debug=2
```

Restart the service afterwards, and revert when finished.

## Step 2: Reduce noise at the source

Excluding events **at the agent** is always preferable to silencing them at the manager: it saves agent CPU, network throughput, and manager EPS all at once.

### Exclude events at collection (agent side)

**Windows event channel** - filter unwanted event IDs (or event ID + attribute combinations) with a `<query>`:

```xml
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
  <query>Event/System[EventID != 5152 and EventID != 4673] and
  (Event/System[EventID = 4673] and Event/EventData/Data[@Name="processName"] != "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe")</query>
</localfile>
```

This example drops all `5152` events, and drops `4673` only when generated by a specific process - so `4673` from anything else is still monitored. Deploy it via the centralized `agent.conf` of the relevant agent group to cover the whole fleet.

**Linux log files** - use `<exclude>` inside `<localfile>`:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/logs/*</location>
  <exclude>/var/logs/e*</exclude>
</localfile>
```

Reference: [`localfile` options](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html#exclude)

**FIM floods** - narrow or remove `<directories>` entries covering rapidly changing paths (database datafiles, spool directories).

### Silence a rule (manager side)

If the events must still reach the manager but the alert is worthless, overwrite the rule with level `0` (alerts are suppressed at level 0):

1. In the dashboard go to **Server Management -> Rules**, search for the rule ID (e.g. `60106`) and copy the original rule definition.
2. Open **Custom rules** -> `local_rules.xml`, paste the rule, set `level="0"` and add `overwrite="yes"`:

   ```xml
   <rule id="60106" level="0" overwrite="yes">
     <if_sid>60103</if_sid>
     <field name="win.system.eventID">^528$|^540$|^673$|^4624$|^4769$</field>
     <options>no_full_log</options>
     <description>Windows logon success.</description>
     <mitre>
       <id>T1078</id>
     </mitre>
     <group>authentication_success,gdpr_IV_32.2,gpg13_7.1,gpg13_7.2,hipaa_164.312.b,nist_800_53_AC.7,nist_800_53_AU.14,pci_dss_10.2.5,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
   </rule>
   ```

3. Restart the Wazuh manager for the change to take effect.

> Silencing at the manager still costs agent CPU, bandwidth, and analysisd throughput for every suppressed event. Use it only when the event is needed for other correlations, or when you cannot touch the agent configuration.

## Step 3 (last resort): Increase the client buffer

Only when the traffic is genuinely legitimate (you actually need all those events) should you enlarge the buffer, in the agent's `ossec.conf`:

```xml
<!-- Agent buffer options -->
<client_buffer>
  <disabled>no</disabled>
  <queue_size>10000</queue_size>
  <events_per_second>1000</events_per_second>
</client_buffer>
```

- Raise `events_per_second` gradually (steps of ~100, up to 1000) and observe whether the buffer-full alerts stop - higher rates increase agent and manager load.
- `queue_size` can go up to 100,000; memory cost is `queue_size x average event size` only while the queue is occupied.
- Restart the agent after each change.

Reference: [`client_buffer` options](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/client-buffer.html)

Raising the agent-side rate pushes the load to the manager - verify the manager can absorb it: see [../server/analysisd.md](../server/analysisd.md).

## Inspecting agent databases on the manager

Oversized per-agent databases on the manager can accompany chronic flooding:

```bash
# Number of registered agents
/var/ossec/bin/cluster_control -a | egrep -v "STATUS|^000" | wc -l
# Number of active agents
/var/ossec/bin/cluster_control -a | grep ' active ' | wc -l
# Number of agent DB files
ls -1 /var/ossec/queue/db/*.db | grep -v global | wc -l
# 20 biggest agent DBs
ls -lSh /var/ossec/queue/db/*.db | grep -v global | head -20
# global.db size
ls -lh /var/ossec/queue/db/global.*
# Total DB folder size
du -sh /var/ossec/queue/db/
# Uptime of analysisd (how long stats have been accumulating)
PIDme=$(pgrep -x wazuh-analysisd); ps -p $PIDme -o etime=
```

## Related guides

- [../server/analysisd.md](../server/analysisd.md) - confirm whether the manager itself drops events, measure EPS, and tune analysisd queues
- [disconnections.md](disconnections.md) - flooding can precede or cause agent disconnections
- [../../scripts/EPS/](../../scripts/EPS/) - real-time EPS measurement script
