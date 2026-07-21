<!-- Support: WS-37876 -->

# Windows Registry Monitoring

This runbook is for administrators configuring or troubleshooting registry
File Integrity Monitoring (FIM) on Windows agents. Use it when expected key or
value changes do not alert, when 32/64-bit registry views differ, or when an
over-broad scope floods the agent.

## Prerequisites

- A Windows agent running with permission to read the target hive.
- A known agent configuration source: local `ossec.conf` or centralized
  `agent.conf`.
- A dedicated test key that can be created and removed safely.

Centralized configuration is merged with the local agent configuration.
Inspect the effective agent group and avoid defining the same registry path in
several profiles.

## Common issues

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| Registry changes not reported | Key/path not in `<registry>` block | Add the hive path to `ossec.conf` |
| Flood of registry events | Over-broad `<registry>` pattern | Narrow to specific keys; exclude volatile keys |
| Permission denied in agent log | Agent lacks read access to hive | Run agent with sufficient privileges; verify ACLs |
| No events after GPO change | Agent not restarted / config not merged | Confirm centralized `agent_config` applied; restart agent |

## Example registry monitoring config

```xml
<syscheck>
  <disabled>no</disabled>
  <registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</registry>
  <registry arch="both">HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services</registry>
  <registry arch="both">HKEY_LOCAL_MACHINE\Software\WazuhKBTest</registry>
</syscheck>
```

Use `arch="both"` for 32- and 64-bit view on x64 Windows.

For a noisy volatile subkey, use a narrow ignore instead of excluding the
whole parent:

```xml
<syscheck>
  <registry_ignore arch="both">HKEY_LOCAL_MACHINE\Software\Example\Volatile</registry_ignore>
</syscheck>
```

## Diagnostics

On the agent:

```powershell
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 100 | Select-String -Pattern "syscheck|registry"
```

On the manager, confirm alerts for the agent ID in **Threat Hunting** or via API.

## Verification procedure

1. Restart the agent after the effective configuration changes:

   ```powershell
   Restart-Service -Name WazuhSvc
   Get-Service -Name WazuhSvc
   ```

2. Confirm the agent log shows the registry path without configuration errors:

   ```powershell
   Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 200 |
     Select-String -Pattern "syscheck|registry|WazuhKBTest"
   ```

3. Create and modify a controlled value:

   ```powershell
   New-Item -Path "HKLM:\Software\WazuhKBTest" -Force
   New-ItemProperty -Path "HKLM:\Software\WazuhKBTest" `
     -Name "VerificationValue" -PropertyType String -Value "created" -Force
   Set-ItemProperty -Path "HKLM:\Software\WazuhKBTest" `
     -Name "VerificationValue" -Value "modified"
   ```

4. Wait for the configured FIM scan/realtime behavior. In the dashboard,
   filter by the agent and `syscheck.path` containing `WazuhKBTest`. Verify the
   alert distinguishes the created and modified values.
5. Remove the test key:

   ```powershell
   Remove-Item -Path "HKLM:\Software\WazuhKBTest" -Recurse -Force
   ```

If the PowerShell command succeeds but no event appears, check whether the
path was delivered through the expected agent group, whether the registry
view matches, and whether an ignore rule overrides it. If events arrive in
bursts, narrow the monitored paths before increasing the agent buffer.

## See also

- [Agent flooding](flooding.md) - registry scan bursts can fill the agent queue
- [Analysisd queue tuning](../server/analysisd.md)
