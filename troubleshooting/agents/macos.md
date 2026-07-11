# macOS Agents

Working configuration for macOS agents: collecting security-relevant entries from the unified logging system (ULS), plus lightweight CPU/memory/disk/network health metrics using `full_command`.

Deploy the block below as centralized configuration (`agent.conf`) for a macOS agent group, or place the individual `<localfile>` entries in the agent's local `ossec.conf`.

## Table of Contents

- [Unified log collection](#unified-log-collection)
- [Health metrics via full_command](#health-metrics-via-full_command)
- [Full agent_config block](#full-agent_config-block)
- [Notes](#notes)

## Unified log collection

macOS agents read the unified logging system with `log_format` `macos`. Without a `<query>` the volume is unusable, so scope it to the processes you care about:

```xml
<localfile>
  <location>macos</location>
  <log_format>macos</log_format>
  <query type="trace,log,activity" level="info">(process == "sudo") or (process == "sessionlogoutd") or (process == "sshd") or (process == "tccd") or (message contains "SessionAgentNotificationCenter") or (process == "screensharingd") or (process == "securityd") or (process == "Terminal") or (process == "Siri") or (process == "mds") or (process == "kernel") or (process == "searchpartyuseragent") or (process == "imagent") or (process == "sharingd") or (process == "bluetoothd") or (process == "TouchBarServer") or (process == "powerd") or (process == "runningboardd") or (process == "audioaccessotyd") or (process == "gamepolicyd") or (process == "corebrightnessd")</query>
</localfile>
```

Trim the process list to your use case — `sudo`, `sshd`, `screensharingd`, `securityd`, and `tccd` cover most authentication/access monitoring needs.

Reference: [Monitoring macOS ULS events](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/monitoring-macos-uls-events.html)

## Health metrics via full_command

Each entry runs a shell one-liner every 30 seconds and forwards the output as an event. Percentages are emitted for easy alerting thresholds; raw metrics for dashboards.

<details>
<summary>Click to expand the individual metric collectors</summary>

```xml
<!-- CPU usage: percentage -->
<localfile>
  <log_format>full_command</log_format>
  <command>top -l 1 | grep 'CPU usage' | awk '{print ($3+$5)*100/($3+$5+$7)}'</command>
  <alias>CPU_health</alias>
  <out_format>$(timestamp) $(hostname) CPU_health: $(log)</out_format>
  <frequency>30</frequency>
</localfile>

<!-- Memory usage: percentage -->
<localfile>
  <log_format>full_command</log_format>
  <command>top -l 1 | grep PhysMem | awk '$NF=="unused."{print ($2*100)/($2+$(NF-1))}'</command>
  <alias>memory_health</alias>
  <out_format>$(timestamp) $(hostname) memory_health: $(log)</out_format>
  <frequency>30</frequency>
</localfile>

<!-- Disk usage: percentage -->
<localfile>
  <log_format>full_command</log_format>
  <command>df -h | awk '$NF=="/"{print $3*100/($3+$4)}'</command>
  <alias>disk_health</alias>
  <out_format>$(timestamp) $(hostname) disk_health: $(log)</out_format>
  <frequency>30</frequency>
</localfile>

<!-- CPU usage metrics (user, system, combined %, idle) -->
<localfile>
  <log_format>full_command</log_format>
  <command>top -l 1 | grep 'CPU usage' | awk '{print $3, $5, ($3+$5)*100/($3+$5+$7)"%", $7}'</command>
  <alias>cpu_metrics</alias>
  <out_format>$(timestamp) $(hostname) cpu_usage_check: $(log)</out_format>
  <frequency>30</frequency>
</localfile>

<!-- Load average metrics -->
<localfile>
  <log_format>full_command</log_format>
  <command>top -l 1 | grep 'Load Avg' | awk '{print $3, $4, $5}'</command>
  <alias>load_average_metrics</alias>
  <out_format>$(timestamp) $(hostname) load_average_check: $(log)</out_format>
  <frequency>30</frequency>
</localfile>

<!-- Memory metrics (used, unused) -->
<localfile>
  <log_format>full_command</log_format>
  <command>top -l 1 | grep PhysMem | awk '$NF=="unused."{print $2,$(NF-1)}'</command>
  <alias>memory_metrics</alias>
  <out_format>$(timestamp) $(hostname) memory_check: $(log)</out_format>
  <frequency>30</frequency>
</localfile>

<!-- Disk metrics (size, used, available, total) -->
<localfile>
  <log_format>full_command</log_format>
  <command>df -h | awk '$NF=="/"{print $2,$3,$4,$3+$4"Gi"}'</command>
  <alias>disk_metrics</alias>
  <out_format>$(timestamp) $(hostname) disk_check: $(log)</out_format>
  <frequency>30</frequency>
</localfile>

<!-- Network metrics (packets in / out) -->
<localfile>
  <log_format>full_command</log_format>
  <command>top -l 1 | grep Networks | awk '$NF=="out."{print $3,$5}'</command>
  <alias>network_metrics</alias>
  <out_format>$(timestamp) $(hostname) network_check: $(log)</out_format>
  <frequency>30</frequency>
</localfile>
```

</details>

## Full agent_config block

<details>
<summary>Click to expand the complete agent.conf snippet (ULS query + all metrics)</summary>

```xml
<agent_config>
  <localfile>
    <location>macos</location>
    <log_format>macos</log_format>
    <query type="trace,log,activity" level="info">(process == "sudo") or (process == "sessionlogoutd") or (process == "sshd") or (process == "tccd") or (message contains "SessionAgentNotificationCenter") or (process == "screensharingd") or (process == "securityd") or (process == "Terminal") or (process == "Siri") or (process == "mds") or (process == "kernel") or (process == "searchpartyuseragent") or (process == "imagent") or (process == "sharingd") or (process == "bluetoothd") or (process == "TouchBarServer") or (process == "powerd") or (process == "runningboardd") or (process == "audioaccessotyd") or (process == "gamepolicyd") or (process == "corebrightnessd")</query>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>top -l 1 | grep 'CPU usage' | awk '{print ($3+$5)*100/($3+$5+$7)}'</command>
    <alias>CPU_health</alias>
    <out_format>$(timestamp) $(hostname) CPU_health: $(log)</out_format>
    <frequency>30</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>top -l 1 | grep PhysMem | awk '$NF=="unused."{print ($2*100)/($2+$(NF-1))}'</command>
    <alias>memory_health</alias>
    <out_format>$(timestamp) $(hostname) memory_health: $(log)</out_format>
    <frequency>30</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>df -h | awk '$NF=="/"{print $3*100/($3+$4)}'</command>
    <alias>disk_health</alias>
    <out_format>$(timestamp) $(hostname) disk_health: $(log)</out_format>
    <frequency>30</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>top -l 1 | grep 'CPU usage' | awk '{print $3, $5, ($3+$5)*100/($3+$5+$7)"%", $7}'</command>
    <alias>cpu_metrics</alias>
    <out_format>$(timestamp) $(hostname) cpu_usage_check: $(log)</out_format>
    <frequency>30</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>top -l 1 | grep 'Load Avg' | awk '{print $3, $4, $5}'</command>
    <alias>load_average_metrics</alias>
    <out_format>$(timestamp) $(hostname) load_average_check: $(log)</out_format>
    <frequency>30</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>top -l 1 | grep PhysMem | awk '$NF=="unused."{print $2,$(NF-1)}'</command>
    <alias>memory_metrics</alias>
    <out_format>$(timestamp) $(hostname) memory_check: $(log)</out_format>
    <frequency>30</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>df -h | awk '$NF=="/"{print $2,$3,$4,$3+$4"Gi"}'</command>
    <alias>disk_metrics</alias>
    <out_format>$(timestamp) $(hostname) disk_check: $(log)</out_format>
    <frequency>30</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>top -l 1 | grep Networks | awk '$NF=="out."{print $3,$5}'</command>
    <alias>network_metrics</alias>
    <out_format>$(timestamp) $(hostname) network_check: $(log)</out_format>
    <frequency>30</frequency>
  </localfile>
</agent_config>
```

</details>

## Notes

- `full_command` requires `logcollector.remote_commands=1` in the agent's `local_internal_options.conf` when pushed via centralized configuration — see the [remote commands reference](https://documentation.wazuh.com/current/user-manual/reference/internal-options.html).
- Each metric arrives as a plain log line prefixed by its alias (e.g. `CPU_health:`); write custom rules matching those aliases to alert on thresholds or feed dashboards.
- A 30-second frequency across eight collectors is noticeable event volume per agent; raise `<frequency>` for large fleets.

## Related guides

- [flooding.md](flooding.md) — keep an eye on event volume added by frequent `full_command` collectors
- macOS agent installation and control paths differ from Linux: the agent lives under `/Library/Ossec/` and is managed with `/Library/Ossec/bin/wazuh-control`
