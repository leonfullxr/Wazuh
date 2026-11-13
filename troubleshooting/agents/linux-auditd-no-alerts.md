# Linux auditd Events Produce No Alerts

This runbook is for administrators who run auditd on Linux agents and see only the default execution alerts (Level 3 to 6) while commands from an attack simulation, or other suspicious activity, produce nothing at Level 7 or above. The detection chain has several links, each of which can break silently. Diagnose them in order: the first broken link explains the symptom, and fixing a later link does not help until the earlier ones work.

> Applies to Wazuh 4.x Linux agents with auditd. Paths follow Debian/Ubuntu layout; RHEL-family systems use the same files under the same names. Run the manager-side commands on the manager node (or the cluster node the agent reports to).

## Table of Contents

- [Symptom](#symptom)
- [How the detection chain works](#how-the-detection-chain-works)
- [Diagnose: find the broken link](#diagnose-find-the-broken-link)
- [Causes and fixes](#causes-and-fixes)
  - [1. The audit log is not collected](#1-the-audit-log-is-not-collected)
  - [2. The audit key is not in the audit-keys list](#2-the-audit-key-is-not-in-the-audit-keys-list)
  - [3. Audit filters skip service and root-context execution](#3-audit-filters-skip-service-and-root-context-execution)
  - [4. Shell builtins and file writes generate no execve](#4-shell-builtins-and-file-writes-generate-no-execve)
  - [5. FIM runs on a schedule, not in real time](#5-fim-runs-on-a-schedule-not-in-real-time)
  - [6. The same events are ingested twice](#6-the-same-events-are-ingested-twice)
  - [7. Auditing is silently disabled or overwritten](#7-auditing-is-silently-disabled-or-overwritten)
- [Writing Level 7+ detections](#writing-level-7-detections)
- [Tuning noisy automation](#tuning-noisy-automation)
- [Manager validation pitfalls](#manager-validation-pitfalls)
- [Related](#related)

## Symptom

- Default `audit_command` alerts (the auditd rules in the 80700 and 80780-80792 range, Level 3 to 6) appear for some commands, but a set of commands that clearly ran raises nothing.
- Custom Level 7+ rules, or a Level 7+ forwarding filter, deliver nothing even though the commands executed on the host.
- File changes under `/etc` or `/usr/bin` appear hours late, or without the user and process that made them.

> The default auditd rules are Level 3 to 6 by design. They supply execution telemetry, not detections. Level 7 and above comes from custom rules layered on top of them. A Level 7+ filter with only default rules will show very little from auditd.

## How the detection chain works

```
auditd (kernel rules, -k <key>)
  -> /var/log/audit/audit.log               (on the agent)
  -> logcollector, log_format audit         (on the agent)
  -> auditd decoder (audit.command, audit.auid, audit.exe, audit.key, ...)
  -> CDB list etc/lists/audit-keys          (on the manager: key -> category)
  -> rule 80792                             (parent of command-execution rules)
  -> custom rules                           (your Level 7+ detections)
```

Each arrow is a place where a record can be lost without any error message.

## Diagnose: find the broken link

Run the steps in order. Step 3 is the decisive test: it separates "the events never reached the manager" from "the events arrived and no rule matched".

1. **The kernel generates records for a new session.** Open a new SSH session (processes started in an existing shell are not audited after a rule change), run a test command, then:

   ```bash
   sudo ausearch -k <KEY> -ts recent | grep -c SYSCALL    # must be > 0
   ```

   Zero means the audit rules or the audit context are the problem. See [cause 7](#7-auditing-is-silently-disabled-or-overwritten).

2. **The agent reads the log.** The agent log should show logcollector opening the file:

   ```bash
   sudo grep -i 'audit.log' /var/ossec/logs/ossec.log | tail -2
   ```

   No match means the `<localfile>` block is missing. See [cause 1](#1-the-audit-log-is-not-collected).

3. **The manager receives the events.** Enable archiving temporarily (`<logall_json>yes</logall_json>` in the manager `ossec.conf`, then restart the manager), re-run the command, and search the archives:

   ```bash
   sudo grep '"audit"' /var/ossec/logs/archives/archives.json | tail -5
   ```

   Archives grow quickly. Disable `logall_json` once the test is done.

   - Events present in archives but no alert: the problem is on the manager (causes 2 and the custom rules).
   - Events absent from archives: the problem is on the agent (causes 1, 3, 4, 7).

4. **The key is mapped to a category.** On the manager:

   ```bash
   sudo grep -n '<KEY>' /var/ossec/etc/lists/audit-keys
   ```

   No line means cause 2.

5. **The parent rule fires.**

   ```bash
   sudo grep -c '"id":"80792"' /var/ossec/logs/alerts/alerts.json
   ```

   Zero while step 3 shows events means cause 2.

6. **Custom rules fire.** Aggregate by rule ID rather than reading the last page:

   ```bash
   sudo grep -oE '"id":"100[0-9]+"' /var/ossec/logs/alerts/alerts.json | sort | uniq -c
   ```

## Causes and fixes

### 1. The audit log is not collected

The journald source does not carry audit records when auditd is running. auditd owns the kernel audit netlink socket and writes its own file, so a `journald` `<localfile>` block sees none of it. Add an explicit file source to the agent `ossec.conf` (or the group `agent.conf`):

```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

`log_format audit` is required. It joins the multi-line audit records into one event before the auditd decoder runs. Reading the same file as `syslog` does not produce decoded `audit.*` fields.

### 2. The audit key is not in the audit-keys list

Rule 80792 fires only when the `key` of an audit record is listed in the CDB list `etc/lists/audit-keys` on the manager. That list ships with:

```
audit-wazuh-c:command
audit-wazuh-w:write
audit-wazuh-r:read
audit-wazuh-a:attribute
```

Records with any other key decode correctly, but nothing classifies them, so 80792 never fires. Choose one fix:

- **Use the standard keys in the agent rules (recommended).** Tag execve rules with `-k audit-wazuh-c` and watch rules with `-k audit-wazuh-w`. No manager-side change is needed.
- **Add your key to the list.** Append a `<key>:<category>` line to `/var/ossec/etc/lists/audit-keys` (for example `my_exec:command`), then restart the manager so the list is recompiled.

Do not keep a custom key in the agent rules without also adding it to the list.

### 3. Audit filters skip service and root-context execution

A rule such as this only records processes started from an interactive login session:

```
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1 -F key=...
```

Services, daemons, cron jobs, and any process started outside a login session carry an unset `auid` (`4294967295`), so the `auid!=-1` filter skips them. The command runs, but no record is written. Check the loaded rules with `sudo auditctl -l` and look for `auid` filters.

Add execve rules for root that do not filter on `auid`, alongside the user-session rules, for both the 64-bit and 32-bit syscall tables:

```
-a always,exit -F arch=b64 -S execve -F euid=0 -k audit-wazuh-c
-a always,exit -F arch=b32 -S execve -F euid=0 -k audit-wazuh-c
```

Covering only the 64-bit table leaves 32-bit binaries invisible. Root-context coverage is the broadest part of the rule set, so pair it with the exclusions described in [Tuning noisy automation](#tuning-noisy-automation).

### 4. Shell builtins and file writes generate no execve

Writing to a file with a shell builtin, such as `echo "..." >> /etc/some.conf`, does not start a new process, so there is no `execve` record to match. Use a watch rule on the file instead:

```
-w /etc/sysctl.conf -p wa -k audit-wazuh-w
-w /etc/ufw/sysctl.conf -p wa -k audit-wazuh-w
```

Watch rules feed the default write and attribute rules through the `audit-wazuh-w` key (see cause 2). Keep watch lists to the files you care about. Each watch adds kernel work on every access.

### 5. FIM runs on a schedule, not in real time

A `<syscheck>` block with `<frequency>43200</frequency>` and no `realtime` or `whodata` attribute reports a change only at the next scan, up to 12 hours later. Put the sensitive paths in real time:

```xml
<syscheck>
  <directories check_all="yes" realtime="yes">/etc/ufw,/etc/sysctl.d,/etc/cron.d</directories>
  <directories check_all="yes" whodata="yes">/etc/ssh</directories>
</syscheck>
```

`whodata` also records the user and process responsible for the change. It depends on the audit subsystem, so it only works on hosts where the audit rules from causes 2 to 4 are loaded. Scope real-time and whodata directories narrowly, because each watched directory adds monitoring load. Restart the agent after the change.

### 6. The same events are ingested twice

Symptom: the archives show the same message twice with different event IDs, once with `"location":"journald"` and once with a file location such as `/var/log/syslog` or `/var/log/auth.log`. Each duplicate is analyzed and alerted separately, which doubles the volume forwarded downstream. Wazuh does not deduplicate these.

Keep one source per message:

- On Ubuntu 24.04 with rsyslog active, keep the file-based sources and remove the `journald` `<localfile>` block.
- If journald is preferred, remove the `<localfile>` blocks for the files that duplicate it, and keep journald.

Never run both. Remember that centralized `agent.conf` blocks merge with the local `ossec.conf`, so check both for the same source. Verify afterwards:

```bash
sudo grep -c '"location":"journald"' /var/ossec/logs/archives/archives.json
```

### 7. Auditing is silently disabled or overwritten

These conditions produce no records and no error, while `auditctl -l` can look correct:

- **`-a task,never` in the base configuration.** Some distributions ship a performance default in `/etc/audit/rules.d/audit.rules` that contains `-D` followed by `-a task,never`. This rule is evaluated at process creation, and when it matches, the kernel allocates no audit context for the new task. The process produces no SYSCALL records even though the exit-list rules are loaded. `auditctl -l` prints the rule as `never,task`, so searching the files for that exact string finds nothing. Search for both spellings and remove the line:

  ```bash
  sudo auditctl -l | grep -E 'never,task|task,never'     # must print nothing
  grep -rn 'task' /etc/audit/rules.d/ /etc/audit/audit.rules
  ```

- **Changes apply only to new processes.** Open a new SSH session before testing.

- **`augenrules --load` reports "No change".** It skips the reload when the concatenated rules match the compiled file, so edits applied only to the compiled file are never loaded. Force a reload:

  ```bash
  sudo auditctl -D && sudo auditctl -R /etc/audit/audit.rules
  ```

- **Load order.** `augenrules` concatenates `rules.d` files in lexicographic order. A base file named `audit.rules` sorts after any numeric prefix, so a `-D` inside it wipes the rules loaded before it. Remove the `-D` from the base file, or give the base file its own numeric prefix so your custom file loads last.

- **Dropped events.** The default backlog of 64 is too small once execve auditing is on. Events are dropped without a log message. Set a larger buffer (`-b 8192` is a reasonable starting point) and watch the `lost` counter during the first days, particularly during simulations:

  ```bash
  sudo auditctl -s | grep -E 'lost|backlog'
  ```

## Writing Level 7+ detections

Build custom rules as children of rule 80792 with a CDB list lookup on `audit.command`. The list maps each command to a category, and `check_value` selects the category:

```xml
<group name="linux_use_cases,">
  <rule id="100500" level="7">
    <if_sid>80792</if_sid>
    <list field="audit.command" lookup="match_key_value" check_value="discovery">etc/lists/<LIST_NAME></list>
    <description>Linux Discovery: reconnaissance command $(audit.command) run by loginuid $(audit.auid)</description>
    <mitre>
      <id>T1082</id>
    </mitre>
    <group>audit_command,discovery,</group>
  </rule>
</group>
```

Practical rules:

- Keep custom rules in their own file with a reserved ID range, for example 100500-100599, and do not reuse an ID across files. Duplicate IDs stop the manager from starting.
- Declare the list in the manager `ossec.conf` inside the `<ruleset>` block, otherwise the rules load but ignore the list (`wazuh-analysisd -t` reports this as a warning):

  ```xml
  <ruleset>
    <list>etc/lists/<LIST_NAME></list>
  </ruleset>
  ```

- Use `audit.euid` (for example `<field name="audit.euid">^0$</field>`) to scope a rule to root execution.
- Group related rules into categories, and route the highest-severity categories to a separate queue downstream if the destination supports it. A Level 12 credential-access alert and a Level 7 discovery alert usually need different handling.
- CDB list files do not support comments. Every line is parsed as a `key:value` entry, so a commented line becomes a spurious entry. Keep list files data-only.

## Tuning noisy automation

Once detections are active, a scheduled monitoring job running under a user account can dominate the discovery category. The signature is a flat, repeating count per command (the same count for `who`, `df` and `sleep` in one window), while real operator activity sits at counts of one or two. Expected behavior, not a misconfiguration.

Identify the candidates by aggregation:

```bash
sudo ausearch -k audit-wazuh-c -ts recent | grep -oP 'comm="\K[^"]+' | sort | uniq -c | sort -rn | head -20
```

Then choose one approach:

- **Exclude at the source (preferred).** Add `never` rules before the rules they should bypass. Rules are evaluated in order, so the exclusion must come first:

  ```
  -a never,exit -F arch=b64 -S execve -F exe=/usr/bin/who
  -a never,exit -F arch=b64 -S execve -F exe=/usr/bin/df
  ```

- **Remove the entry from the CDB list.** The rules stay untouched, which makes this the safer change to hand to an analyst. Restart the manager after editing.

Review alerts by aggregation, not by reading the last page of `alerts.json`. A single noisy command can fill that page and hide everything else.

## Manager validation pitfalls

- **Dashboard rule editor.** Uploading rules through the web editor may return a generic `XML syntax error (1113)` with no location. That is a limitation of the editor's validation. Copy the file to `/var/ossec/etc/rules/` and validate on the manager:

  ```bash
  sudo /var/ossec/bin/wazuh-analysisd -t
  ```

  This checks XML syntax and rule semantics: unknown `if_sid` parents, undeclared CDB lists, duplicate IDs, and invalid rule options.

- **Stale compiled lists.** After editing a CDB list, restart the manager. If the new entries still do not match, delete the compiled `.cdb` file next to the list and restart again.

- **Restart, then test.** Rule and list changes take effect on restart. Re-run the same command in a new session and repeat the diagnosis steps from the start.

## Scope limits

auditd covers endpoint execution and file writes. It does not see network-only activity such as command-and-control beaconing over HTTP, which leaves no host-side record. Close those gaps with firewall or proxy logs, and with web server logs on hosts that serve applications.

## Related

- [Flooding and noisy alerts](flooding.md) - buffer behavior and silencing noisy rules
- [Analysisd, EPS, and dropped events](../server/analysisd.md) - confirm whether the manager itself drops events
- [File Integrity Monitoring](../../fim/README.md) - choosing realtime, scheduled, or whodata scans
