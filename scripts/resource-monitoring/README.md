# Disk / memory / CPU monitoring with Wazuh

Turn host resource metrics (CPU, memory, disk, load average, network) into
Wazuh alerts, with threshold rules for high usage. Based on the official blog
posts for [Linux](https://wazuh.com/blog/monitoring-linux-resource-usage-with-wazuh/)
and [Windows](https://wazuh.com/blog/monitoring-windows-resources-with-performance-counters/).

To roll this out to many endpoints at once, use
[centralized configuration (`agent.conf`)](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html).
Note that remote commands are disabled by default for security reasons; when
distributing command-based config centrally, enable them on each agent in
`/var/ossec/etc/local_internal_options.conf`:

```
wazuh_command.remote_commands=1
```

## Linux endpoints

### 1. Agent configuration

Add these `<localfile>` blocks to the agent's `/var/ossec/etc/ossec.conf`
(inside `<ossec_config>`). Each command runs every 5 minutes:

```xml
<!-- CPU, memory, disk metric -->
<localfile>
   <log_format>full_command</log_format>
   <command>echo $(top -bn1 | grep Cpu | awk '{print $2+$4+$6+$12+$14+$16}' ; free -m | awk 'NR==2{printf "%.2f\t\t\n", $3*100/$2 }' ; df -h | awk '$NF=="/"{print $5}'|sed 's/%//g')</command>
   <alias>general_health_metrics</alias>
   <out_format>$(timestamp) $(hostname) general_health_check: $(log)</out_format>
   <frequency>300</frequency>
</localfile>

<!-- load average metrics -->
<localfile>
   <log_format>full_command</log_format>
   <command>uptime | grep load | awk '{print $(NF-2),$(NF-1),$NF}' | sed 's/\,\([0-9]\{1,2\}\)/.\1/g'</command>
   <alias>load_average_metrics</alias>
   <out_format>$(timestamp) $(hostname) load_average_check: $(log)</out_format>
   <frequency>300</frequency>
</localfile>

<!-- memory metrics -->
<localfile>
   <log_format>full_command</log_format>
   <command>free --bytes| awk 'NR==2{print $3,$7}'</command>
   <alias>memory_metrics</alias>
   <out_format>$(timestamp) $(hostname) memory_check: $(log)</out_format>
   <frequency>300</frequency>
</localfile>

<!-- disk metrics -->
<localfile>
   <log_format>full_command</log_format>
   <command>df -B1 | awk '$NF=="/"{print $3,$4}'</command>
   <alias>disk_metrics</alias>
   <out_format>$(timestamp) $(hostname) disk_check: $(log)</out_format>
   <frequency>300</frequency>
</localfile>
```

Restart the agent:

```bash
sudo systemctl restart wazuh-agent
```

### 2. Manager configuration

- **Decoders**: dashboard > Server Management > Decoders > create a new
  decoder file with the contents of [`linux_metrics_decoders.xml`](linux_metrics_decoders.xml).
- **Rules**: dashboard > Server Management > Rules > create a new rule
  file with the contents of [`linux_metrics_rules.xml`](linux_metrics_rules.xml):

  | Rule ID | Fires when |
  |---|---|
  | 100054 | base rule: resource metrics event received |
  | 100055 | memory usage exceeds 80% (level 12) |
  | 100056 | CPU usage exceeds 80% (level 12) |
  | 100057 | disk usage exceeds 70% (level 12) |
  | 100058 | load average check (level 3) |
  | 100059 | memory metrics check (level 3) |
  | 100060 | disk metrics check (level 3) |

- Restart the Wazuh manager.

**Note:** if the dashboard shows the new fields (`data.cpu_usage_%`,
`data.memory_usage_%`, `data.disk_usage_%`, `data.1min_loadAverage`, etc.) as
unknown, go to Dashboard management > Index Patterns > wazuh-alerts-\* and
refresh the index pattern. The alerts then appear on the Discover page.

## Windows endpoints

### 1. Agent configuration

Windows metrics are collected with PowerShell `Get-Counter` via
[command wodles](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-command.html).
Add to the agent's `ossec.conf` inside `<ossec_config>`:

```xml
<!-- CPU Usage -->
<wodle name="command">
    <disabled>no</disabled>
    <tag>CPUUsage</tag>
    <command>Powershell -c "@{ winCounter = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples[0] } | ConvertTo-Json -compress"</command>
    <interval>5m</interval>
    <ignore_output>no</ignore_output>
    <run_on_start>yes</run_on_start>
    <timeout>0</timeout>
</wodle>
<!-- Memory Usage -->
<wodle name="command">
    <disabled>no</disabled>
    <tag>MEMUsage</tag>
    <command>Powershell -c "@{ winCounter = (Get-Counter '\Memory\Available MBytes').CounterSamples[0] } | ConvertTo-Json -compress"</command>
    <interval>5m</interval>
    <ignore_output>no</ignore_output>
    <run_on_start>yes</run_on_start>
    <timeout>0</timeout>
</wodle>
<!-- Network Received -->
<wodle name="command">
    <disabled>no</disabled>
    <tag>NetworkTrafficIn</tag>
    <command>Powershell -c "@{ winCounter = (Get-Counter '\Network Interface(*)\Bytes Received/sec').CounterSamples[0] } | ConvertTo-Json -compress"</command>
    <interval>5m</interval>
    <ignore_output>no</ignore_output>
    <run_on_start>yes</run_on_start>
    <timeout>0</timeout>
</wodle>
<!-- Network Sent -->
<wodle name="command">
    <disabled>no</disabled>
    <tag>NetworkTrafficOut</tag>
    <command>Powershell -c "@{ winCounter = (Get-Counter '\Network Interface(*)\Bytes Sent/sec').CounterSamples[0] } | ConvertTo-Json -compress"</command>
    <interval>5m</interval>
    <ignore_output>no</ignore_output>
    <run_on_start>yes</run_on_start>
    <timeout>0</timeout>
</wodle>
<!-- Disk Free -->
<wodle name="command">
    <disabled>no</disabled>
    <tag>DiskFree</tag>
    <command>Powershell -c "@{ winCounter = (Get-Counter '\LogicalDisk(*)\Free Megabytes').CounterSamples[0] } | ConvertTo-Json -compress"</command>
    <interval>5m</interval>
    <ignore_output>no</ignore_output>
    <run_on_start>yes</run_on_start>
    <timeout>0</timeout>
</wodle>
```

Restart the Windows agent (`NET START Wazuh` / restart the service).

### 2. Manager configuration

Create a new rule file with the contents of
[`windows_counter_rules.xml`](windows_counter_rules.xml):

| Rule ID | Fires when |
|---|---|
| 301000 | base rule: any winCounter command output (level 0) |
| 302000 | memory metric check |
| 302001 | available memory below 1 GB (level 5) |
| 302002 | available memory below 500 MB (level 7) |
| 302003 | disk free metric check |
| 302004 / 302005 | network traffic in / out check |
| 303000 | CPU metric check |
| 303001 / 303002 | CPU above 80% (level 5) / above 90% (level 7) |

For testing, you can temporarily raise rule 301000 from level 0 to 3+ to see
every counter sample as an alert.

Restart the manager:

```bash
sudo systemctl restart wazuh-manager
```

## Related

- [`../service-monitoring`](../service-monitoring) - alerting when the Wazuh
  services themselves go down.
