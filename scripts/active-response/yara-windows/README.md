# YARA active response: scan and delete malware on Windows

The official [Detecting malware using YARA integration](https://documentation.wazuh.com/current/proof-of-concept-guide/detect-malware-yara-integration.html)
proof of concept wires FIM to an active-response script that scans a new or
modified file with YARA and logs the verdict. It stops there: a positive match
produces an alert, but the file stays on disk. This guide replaces that script
with one that also removes the file, and covers the two things that break when
you naively bolt a delete onto the PoC version.

> Applies to Wazuh 4.x Windows agents with FIM realtime monitoring and
> `yara64.exe` already installed on the endpoint. The manager side is
> unchanged from the PoC apart from the optional deletion rules in
> [section 3](#3-manager-side-decoder-and-rules).

## Table of contents

- [Why the PoC script does not delete](#why-the-poc-script-does-not-delete)
- [Before you enable auto-delete](#before-you-enable-auto-delete)
- [Prerequisites](#prerequisites)
- [1. Back up the existing script](#1-back-up-the-existing-script)
- [2. Deploy the scripts](#2-deploy-the-scripts)
- [3. Manager-side decoder and rules](#3-manager-side-decoder-and-rules)
- [4. Manager-side active response configuration](#4-manager-side-active-response-configuration)
- [5. Agent-side FIM configuration](#5-agent-side-fim-configuration)
- [6. Restart both sides](#6-restart-both-sides)
- [7. Verify with EICAR](#7-verify-with-eicar)
- [What this script changes over the PoC version](#what-this-script-changes-over-the-poc-version)
- [Troubleshooting](#troubleshooting)
- [Related](#related)

## Why the PoC script does not delete

The PoC script's job ends at `Scan result:`. Adding a `Remove-Item` to it
fails intermittently for two reasons that only show up under real load:

- **The file is still being written.** FIM realtime fires on the first write,
  not on close. YARA then scans a partial file (missing the match) or the
  delete hits a sharing violation because the downloading process still holds
  the handle. Antivirus real-time scanning grabs the same handle at the same
  moment and widens the window.
- **The response hangs on STDIN.** `[Console]::In.ReadToEnd()` waits for the
  pipe to close. Wazuh `execd` writes one newline-terminated JSON line and
  keeps the pipe open, so `ReadToEnd()` never returns and the active response
  sits there until the agent restarts. Read exactly one line instead.

[`yara.ps1`](yara.ps1) handles both: it waits for the file size to hold steady
before scanning, then retries the delete while transient locks clear.

## Before you enable auto-delete

Deletion is not reversible and there is no `<timeout>` that undoes it. A YARA
false positive on this path is data loss, not a noisy alert.

- Scope `<rules_id>` to the narrowest set of FIM rules you actually want
  auto-remediated. A rule on a broad path plus a broad YARA ruleset will
  eventually delete something a user wanted.
- Run the setup in log-only mode first. Keep the PoC script in place, let it
  alert for a week, and read what it would have deleted.
- Prefer quarantine over deletion where the endpoint owner is not you. Swap
  the `Remove-Item` inside `Remove-FileWithRetry` for a `Move-Item` into a
  SYSTEM-only directory and you keep the same retry behaviour with a
  recoverable outcome.
- The script runs as `LocalSystem` (the agent service account), so it will
  happily delete files a user could not. Treat the YARA ruleset as production
  configuration and review changes to it.

## Prerequisites

On each Windows endpoint, confirm these exist before deploying anything:

| Path | Purpose |
|---|---|
| `C:\Program Files (x86)\ossec-agent\active-response\bin\yara\yara64.exe` | YARA binary |
| `C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\yara_rules.yar` | Compiled or source ruleset |
| `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log` | Written by the script (created on first run) |

PowerShell 5.1 (shipped with Windows) is enough. The paths above assume the
default 32-bit agent install; the script resolves the agent root from its own
location, so a 64-bit install under `C:\Program Files\ossec-agent` works with
no edits.

## 1. Back up the existing script

Keep the PoC script so you can roll back without re-downloading it:

```bat
cd "C:\Program Files (x86)\ossec-agent\active-response\bin"
mkdir backup
move yara.bat backup\yara.bat.old
```

## 2. Deploy the scripts

Copy both files into the active-response `bin` directory. They must stay
together: the `.bat` resolves the `.ps1` relative to itself.

| File | Destination |
|---|---|
| [`yara.bat`](yara.bat) | `C:\Program Files (x86)\ossec-agent\active-response\bin\yara.bat` |
| [`yara.ps1`](yara.ps1) | `C:\Program Files (x86)\ossec-agent\active-response\bin\yara.ps1` |

The `.bat` wrapper is required because `execd` on Windows only launches
`.exe`, `.cmd`, or `.bat`. It passes STDIN straight through to PowerShell.

Sanity-check the script's own logic before wiring it up. This runs offline and
needs neither a Wazuh agent nor YARA:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\yara.ps1 -SelfTest
```

It exercises the execd JSON parsing and the delete-with-retry path, and prints
`self-test passed` when everything holds.

## 3. Manager-side decoder and rules

> These are the standard decoder and rules from the official YARA PoC guide,
> reproduced here so this runbook stands alone. Skip ahead if you already
> deployed them.

`/var/ossec/etc/decoders/yara_decoders.xml`:

```xml
<decoder name="yara_decoder">
  <prematch>wazuh-yara:</prematch>
</decoder>

<decoder name="yara_decoder1">
  <parent>yara_decoder</parent>
  <regex>wazuh-yara: (\S+) - Scan result: (\S+) (\S+)</regex>
  <order>log_type, yara_rule, yara_scanned_file</order>
</decoder>
```

`/var/ossec/etc/rules/yara_rules.xml`:

```xml
<group name="syscheck,">
  <!-- FIM triggers. These IDs are what <rules_id> points at in section 4. -->
  <rule id="100010" level="7">
    <if_sid>550</if_sid>
    <field name="file" type="pcre2">(?i)C:\\Users.+Downloads</field>
    <description>File modified in the Downloads directory.</description>
  </rule>

  <rule id="100011" level="7">
    <if_sid>554</if_sid>
    <field name="file" type="pcre2">(?i)C:\\Users.+Downloads</field>
    <description>File added to the Downloads directory.</description>
  </rule>
</group>

<group name="yara,">
  <rule id="108000" level="0">
    <decoded_as>yara_decoder</decoded_as>
    <description>Yara grouping rule</description>
  </rule>

  <rule id="108001" level="12">
    <if_sid>108000</if_sid>
    <match>wazuh-yara: INFO - Scan result: </match>
    <description>File "$(yara_scanned_file)" is a positive match. Yara rule: $(yara_rule)</description>
  </rule>
</group>
```

Base rules 550 (file modified) and 554 (file added) are the built-in syscheck
events. `yara.ps1` logs the match line as `INFO - Scan result: <rule> <file>`
verbatim so `yara_decoder1` keeps matching.

**Optional: alert on the deletion itself.** Nothing in the PoC set fires when
the file is removed, so the removal is only visible in the endpoint log. These
two rules surface it. They are an addition to the PoC content, so validate
them in `wazuh-logtest` against a real log line before relying on them:

```xml
<group name="yara,">
  <rule id="108002" level="12">
    <if_sid>108000</if_sid>
    <match>wazuh-yara: INFO - Successfully deleted file: </match>
    <description>YARA active response removed a file that matched a rule.</description>
  </rule>

  <rule id="108003" level="12">
    <if_sid>108000</if_sid>
    <match>wazuh-yara: ERROR - Failed to delete file</match>
    <description>YARA active response could not remove a matched file.</description>
  </rule>
</group>
```

Rule 108003 is the one to alert on: a match that could not be removed means
malware is still on disk and needs a human.

## 4. Manager-side active response configuration

In `/var/ossec/etc/ossec.conf` on **every** manager node in the cluster:

```xml
<ossec_config>
  <command>
    <name>yara_windows</name>
    <executable>yara.bat</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>yara_windows</command>
    <location>local</location>
    <rules_id>100010,100011</rules_id>
  </active-response>
</ossec_config>
```

- `<timeout_allowed>no</timeout_allowed>` because a deletion cannot be
  reversed. There is nothing for a `<timeout>` to undo.
- `<location>local</location>` runs the script on the agent that raised the
  alert, which is the only place the file exists.
- `<rules_id>` must list FIM rules that carry `syscheck.path`. Point it at
  your own trigger rule IDs if they differ from 100010/100011.

## 5. Agent-side FIM configuration

The trigger rules only fire if FIM watches the directory in realtime. In the
Windows agent's `ossec.conf` (or the shared group configuration):

```xml
<syscheck>
  <directories realtime="yes" check_all="yes">C:\Users\*\Downloads</directories>
</syscheck>
```

Active response is enabled on Windows agents by default. If it was turned off,
re-enable it in the same file:

```xml
<active-response>
  <disabled>no</disabled>
</active-response>
```

## 6. Restart both sides

Manager:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
```

Windows agent:

```bat
net stop WazuhSvc
net start WazuhSvc
```

## 7. Verify with EICAR

Drop an [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/)
into the monitored `Downloads` folder. Exclude the folder from the endpoint's
antivirus first, or the AV removes the file before YARA sees it and you get
`ERROR - File not found`.

Then read
`C:\Program Files (x86)\ossec-agent\active-response\active-responses.log`:

```text
2026/07/20 13:46:32 wazuh-yara: ----------------------------------------------------
2026/07/20 13:46:32 wazuh-yara: File: [c:\users\<USER>\downloads\eicar.com]
2026/07/20 13:46:34 wazuh-yara: INFO - Scan result: SUSP_Just_EICAR_RID2C24 c:\users\<USER>\downloads\eicar.com
2026/07/20 13:46:34 wazuh-yara: INFO - Attempting to delete file...
2026/07/20 13:46:34 wazuh-yara: INFO - Successfully deleted file: c:\users\<USER>\downloads\eicar.com
```

A clean file logs `INFO - No malware detected.` and leaves the file alone.
Confirm the EICAR file is gone from the folder, and that rule 108001 (and
108002 if you added it) appears on the dashboard.

## What this script changes over the PoC version

| Change | Why |
|---|---|
| `ReadLine()` instead of `ReadToEnd()` on STDIN | `execd` does not close the pipe after writing the alert, so `ReadToEnd()` blocks forever |
| Agent root from `$PSScriptRoot` instead of `PROCESSOR_ARCHITECTURE` | The architecture check picks the wrong `Program Files` when agent and host bitness disagree |
| Wait for the file size to stabilize before scanning | FIM realtime fires on first write, so the file may still be downloading |
| Retry the delete up to 5 times, 1s apart | AV real-time scanning and the writing process hold transient handles |
| `-LiteralPath` everywhere | Filenames containing `[`, `]`, or `?` are otherwise treated as wildcards |
| Log YARA's own output when it exits with an error | A broken ruleset otherwise looks identical to a clean scan |
| Malformed JSON on STDIN logs a parse error instead of an exception | Makes the cause obvious in `active-responses.log` |
| `-SelfTest` switch | Validates parsing and delete logic offline before the script touches an endpoint |

## Troubleshooting

| Symptom in `active-responses.log` | Cause and fix |
|---|---|
| Nothing at all, no `wazuh-yara:` lines | The command never ran. Check `ossec.conf` `<rules_id>` matches the FIM rules that actually fired, and that `yara.bat` is in `active-response\bin` |
| The response starts and never finishes | The old script using `ReadToEnd()` is still in place. Confirm `yara.ps1` from this directory is deployed |
| `ERROR - No input received on STDIN.` | `yara.bat` was replaced by something that does not pass STDIN through, or the script was launched by hand |
| `ERROR - Could not parse syscheck.path from JSON.` | The triggering rule is not a syscheck rule. `<rules_id>` must point at FIM rules |
| `ERROR - File not found.` | Antivirus deleted the file first, or the user moved it. Exclude the test folder from AV when validating |
| `ERROR - yara64.exe not found at ...` | YARA is not installed at the expected path. See [Prerequisites](#prerequisites) |
| `ERROR - Failed to execute YARA (exit code 2)` with YARA output following | Rule syntax error or an unreadable rules file. Run `yara64.exe yara_rules.yar <file>` by hand |
| `WARNING - Delete attempt N failed: ...UnauthorizedAccessException` then success | Normal. A transient lock cleared on retry |
| `ERROR - Failed to delete file after 5 attempts` | A process holds the file open for the full retry window. Identify it with Handle or Process Explorer; consider raising `MaxRetries` |
| Alert 108001 fires but nothing on the dashboard confirms removal | Expected with the PoC ruleset. Add the optional deletion rules in [section 3](#3-manager-side-decoder-and-rules) |

## Related

- [`../README.md`](../README.md) - active response fundamentals, `<location>`
  semantics, and the CDB blocklist recipe.
- [`../../syscheck-email-notifications`](../../syscheck-email-notifications) -
  FIM rule patterns for the Windows Downloads folder and email routing for
  them.
- [`../../../troubleshooting/agents/windows-registry.md`](../../../troubleshooting/agents/windows-registry.md) -
  other Windows agent monitoring behaviour.
- [Detecting malware using YARA integration](https://documentation.wazuh.com/current/proof-of-concept-guide/detect-malware-yara-integration.html) -
  the upstream PoC this replaces the script half of.
- [Active response reference](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html) -
  official `<command>` and `<active-response>` documentation.
