# FIM on a Large Windows File Server

Two ways to audit file activity on a Windows file share. This guide covers the scale at which the first one stops working, and how to move to the second. The short version: Wazuh FIM `syscheck` monitors a defined set of files well, and a multi-terabyte share with over a million files is not that set.

> **Applies to:** Wazuh agent 4.x on Windows Server 2016 and later. The event
> IDs and access masks come from the Windows Security log and apply to any
> collector. The `syscheck` limits are specific to Wazuh.

## Table of Contents

- [Choose the approach before you configure anything](#choose-the-approach-before-you-configure-anything)
- [Approach 1: FIM syscheck with whodata](#approach-1-fim-syscheck-with-whodata)
  - [Deploy through an agent group](#deploy-through-an-agent-group)
  - [Required Windows audit policy](#required-windows-audit-policy)
  - [Roll out in phases](#roll-out-in-phases)
  - [Exclusions that matter on a file server](#exclusions-that-matter-on-a-file-server)
  - [The 260-character path limit](#the-260-character-path-limit)
- [The symptom: the inventory stops growing](#the-symptom-the-inventory-stops-growing)
- [Approach 2: Windows object access auditing](#approach-2-windows-object-access-auditing)
  - [Enable the audit policy](#enable-the-audit-policy)
  - [Add the SACL to the folder](#add-the-sacl-to-the-folder)
  - [Collect the Security channel](#collect-the-security-channel)
  - [Event 4660 may never appear](#event-4660-may-never-appear)
  - [Decode the access mask](#decode-the-access-mask)
- [Verify on the endpoint](#verify-on-the-endpoint)
- [Build the file activity dashboard](#build-the-file-activity-dashboard)
- [Detect ransomware and mass activity](#detect-ransomware-and-mass-activity)
- [Related](#related)

## Choose the approach before you configure anything

Both approaches answer "who touched this file, and when". They differ in what carries the load.

| | FIM syscheck with whodata | Windows object access auditing |
|---|---|---|
| What tracks the files | The Wazuh agent, in its own FIM database | Windows, through SACLs on the folder |
| Scale it suits | Thousands to low hundreds of thousands of files | Any size. Windows never enumerates the tree |
| Baseline scan | Yes. Every file is hashed and stored | None |
| Reports content changes | Yes, with `report_changes` | No |
| Reports read access | No | Yes |
| Alerts on file state | Added, modified, deleted, with before and after attributes | Access attempts, decoded from the access mask |
| Main cost | Agent CPU, RAM, and FIM database size | Security log volume |

Use file counts to decide. Below roughly 100,000 files in scope, use `syscheck`. Above roughly 1 million, go straight to object access auditing and do not spend a month tuning exclusions first. Between the two, pilot `syscheck` on one directory and measure.

The count that matters is files **in scope after exclusions**, not the size of the disk.

## Approach 1: FIM syscheck with whodata

`whodata` is what turns "this file changed" into "this user changed this file". It works through the same Windows audit subsystem as approach 2, so the audit policy below is a prerequisite for both.

### Deploy through an agent group

Push the configuration through a group rather than editing `ossec.conf` on each server. The agents pick it up without a manual restart.

1. In the dashboard, open **Agents management > Groups**.
2. Create a group, for example `windows-fileservers`, and assign the file server agents to it.
3. Edit the group `agent.conf`.

```xml
<agent_config>
  <syscheck>
    <directories check_all="yes" whodata="yes">D:\Finance</directories>
    <directories check_all="yes" whodata="yes">D:\Shared</directories>

    <ignore>D:\$RECYCLE.BIN</ignore>
    <ignore>D:\System Volume Information</ignore>
    <ignore>D:\Finance\DFSRPrivate</ignore>
    <ignore>D:\Shared\DFSRPrivate</ignore>

    <ignore type="sregex">.*\.tmp$|.*\.log$|.*\.bak$|.*\.lock$|.*\.swp$|.*\.db$|.*\.lnk$</ignore>

    <process_priority>19</process_priority>
  </syscheck>
</agent_config>
```

Three attributes decide the cost:

- `check_all="yes"` checks size, permissions, owner, hash, and modification time.
- `whodata="yes"` adds the user and the process behind each change.
- `report_changes="yes"` is **absent on purpose**. It copies every monitored file into a private directory to compute line-by-line differences. On a multi-terabyte share it fills the disk. Enable it only on a small set of text or configuration files.

`<process_priority>19</process_priority>` lowers the scan priority so the baseline scan competes less with the file-serving workload.

### Required Windows audit policy

`whodata` reads the Windows Security log. Without these policies it silently falls back or reports nothing.

| Policy path | Setting | State |
|---|---|---|
| Advanced Audit Policy Configuration > System Audit Policies > Object Access | Audit File System | Success, Failure |
| Advanced Audit Policy Configuration > System Audit Policies > Object Access | Audit Handle Manipulation | Success, Failure |

### Roll out in phases

Never enable the whole share at once. The baseline scan is the heaviest moment in the deployment.

1. Start with the **lowest-volume** directories in scope.
2. Watch for 48 hours:
   - CPU and RAM on the file server at peak hours.
   - The agent `ossec.log`, for queue-full warnings and whodata errors.
   - Event volume in the dashboard, against indexer capacity.
3. Add the next directory only after that window is clean.
4. Leave the highest-traffic directory for last. It is the one that decides whether this approach works at all.

### Exclusions that matter on a file server

Beyond the recycle bin and system volume information:

- **DFS Replication private folders.** `DFSRPrivate` under each replicated root is DFS-R staging. It changes constantly and means nothing for integrity monitoring. Exclude one per replicated directory.
- **Office temporary files.** Word and Excel create and delete lock and owner files on every open, which produces two FIM events per document view. Filter `~$*` along with the extension list. See [wazuh/wazuh#10677](https://github.com/wazuh/wazuh/issues/10677).
- **High-churn extensions.** `.tmp`, `.log`, `.bak`, `.lock`, `.swp`, `.db`, `.lnk` through one `sregex`.

Exclusions reduce event volume. They do not reduce the baseline scan, because the agent still walks the tree.

### The 260-character path limit

Windows applies a 260-character path limit unless the system opts out, and FIM does not monitor files whose full path exceeds it. Deep folder trees on a shared drive hit this regularly, and it fails quietly. See [wazuh/wazuh#11583](https://github.com/wazuh/wazuh/issues/11583).

Enable long path support on the server, then reboot:

```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" `
  -Name "LongPathsEnabled" -Value 1 -Type DWord
```

The Group Policy equivalent is **Computer Configuration > Administrative Templates > System > Filesystem > Enable Win32 long paths**.

This needs Windows Server 2016 or later, or Windows 10 build 1607 or later. The application must also opt in through its manifest. Treat the result as something to verify rather than assume, because a path that is still too long produces no error.

## The symptom: the inventory stops growing

This is how approach 1 fails at scale, and it is easy to misread as a configuration mistake.

The FIM inventory in the dashboard climbs and then stops at a round-looking number. The count stays flat across restarts and rescans. **No error appears in `ossec.log`**, and raising `<file_limit>` changes nothing. One investigated file server sat at roughly 59,000 files, and a second stalled at 100,000, against a share holding about 1.5 million files.

Before concluding that you have hit the ceiling, rule out the quiet causes:

- Paths longer than 260 characters, if long path support is not enabled.
- Files removed by an `<ignore>` rule that is broader than intended.
- A baseline scan that is still running. A first scan across millions of files takes hours, and the count grows slowly rather than stopping.

If the count is genuinely flat and the numbers above look familiar, stop tuning. `syscheck` is not the right instrument for this share. Move to approach 2.

> **Do not chase this with limits.** Raising `<file_limit>`, extending the
> directory count, and adding exclusions all leave the agent walking and hashing
> a tree of millions of files on every scan. The fix is to stop making the agent
> own the inventory.

## Approach 2: Windows object access auditing

Here Windows does the tracking. You place a SACL on the folder, Windows writes an event to the Security log for each matching access, and the agent forwards that log. The agent keeps no file inventory, so the size of the share stops mattering.

The trade is real: you get access events, including reads, and you lose the file-state comparison that `syscheck` provides. There is no "before and after" for a modified file, and no content diff.

### Enable the audit policy

Same two policies as [above](#required-windows-audit-policy). Set them through Group Policy for a domain, or `secpol.msc` for a standalone server. Confirm they applied:

```powershell
auditpol /get /subcategory:"File System"
```

### Add the SACL to the folder

The audit policy enables the mechanism. The SACL decides what Windows actually records. Without a SACL on the folder, the policy produces nothing.

1. Open the folder properties, then **Security > Advanced > Auditing**.
2. Add an entry. Set the principal to `Everyone`, the type to `All`, and apply it to this folder, subfolders, and files.
3. Select the permissions to audit. Start narrow. Auditing every read on a busy share produces very large volumes.

Apply the SACL to the specific shared directory, not to the volume root.

### Collect the Security channel

The agent forwards the Security channel through `localfile`:

```xml
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
</localfile>
```

> **Check your existing event ID filter.** Many deployments narrow the Security
> channel with a `<query>` to control volume. A filter that omits the object
> access IDs drops these events with no warning anywhere. If the events are
> present in Windows Event Viewer but absent from the dashboard, remove the
> filter, confirm the events arrive, then add the IDs back explicitly.

### Event 4660 may never appear

Documentation and most guides pair two event IDs for deletion:

| Event ID | Meaning |
|---|---|
| 4663 | An attempt was made to access an object |
| 4660 | An object was deleted |

On Windows Server 2025, file deletion tests produced **no 4660 at all**. The deletion appeared as **4663 with an access mask of `0x10000`**, which is the `DELETE` access right. That event carried the file name, the user, and the process.

Build deletion detection on **4663 with access mask `0x10000`**. Treat 4660 as a supplement where the platform emits it, not as the primary signal. A dashboard that keys deletion off 4660 alone can show zero deletions on a server that is deleting files all day.

### Decode the access mask

The access mask on 4663 is what turns one event ID into distinct activity types. These four cover the common cases:

| Access mask | Access right | Activity |
|---|---|---|
| `0x1` | ReadData, ListDirectory | File read, directory listed |
| `0x2` | WriteData, AddFile | File written, file created in a directory |
| `0x4` | AppendData, AddSubdirectory | Data appended, subdirectory created |
| `0x10000` | DELETE | File or directory deleted |

A single event can carry a combined mask, because a mask is a bit field. Match on the bit rather than on string equality where your query language allows it.

## Verify on the endpoint

Confirm Windows is generating the events before you debug the Wazuh side. Run this on the file server, and change the match string to a file you are about to touch:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663} |
  ForEach-Object {
    if ($_.Message -match 'Object Name:\s+(.+)') {
      $objectName = $matches[1]
      if ($objectName -like '*<FILENAME_FRAGMENT>*') {
        [PSCustomObject]@{
          TimeCreated = $_.TimeCreated
          ObjectName  = $objectName
          Accesses    = if ($_.Message -match 'Accesses:\s+(.+)') { $matches[1] }
        }
      }
    }
  }
```

The result splits the problem cleanly:

- **Events present here, absent in the dashboard.** The problem is collection. Check the `localfile` block and any event ID filter.
- **No events here.** The problem is Windows. Check the audit policy with `auditpol`, then check the SACL on the folder.

## Build the file activity dashboard

The dashboard the ticket asked for comes down to four visualizations plus two saved searches, all over the collected 4663 events.

Create one visualization per activity type, each filtered on event ID 4663 plus one access mask from the [decode table](#decode-the-access-mask). That gives read, write, append, and delete panels from a single event ID.

Then save two searches, which is what makes per-file history practical:

- **By user.** Filter on the subject user name field to answer "what did this account touch".
- **By object name.** Filter on the object name field to answer "who touched this file". This is the file-history search: enter a file name or a full path and read the events in time order.

Add the agent name and a time range as dashboard filters so the same panels serve every file server in the group.

## Detect ransomware and mass activity

Mass modification and mass deletion are volume signals, not new event types. Build them as frequency-based custom rules that fire when many FIM or object access events arrive from one agent inside a short window.

The building blocks:

- **Mass activity.** A custom rule with `frequency` and `timeframe` on top of the FIM rules for added, modified, and deleted files, grouped per agent.
- **Extension changes.** A rule matching known ransomware extensions in the file path field. This catches the rename-to-encrypted pattern that mass-modification counting can miss when the tool writes new files rather than modifying existing ones.

Tune the threshold against a measured baseline. A file server where a backup job legitimately rewrites 10,000 files each night needs a different threshold from a workstation share. See [custom rules](../rules/README.md).

## Related

- [FIM in containerized environments](containers.md) - what FIM can and cannot do per container deployment model
- [Windows registry monitoring](../troubleshooting/agents/windows-registry.md) - the registry half of Windows FIM
- [Agent flooding and noisy alerts](../troubleshooting/agents/flooding.md) - finding and silencing a noisy source after the rollout
- [Analysisd, EPS, and dropped events](../troubleshooting/server/analysisd.md) - what to check when the manager cannot absorb the new event volume
- [Custom rules](../rules/README.md) - writing the frequency-based rules above
- [Official FIM documentation](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity-monitoring/index.html)
