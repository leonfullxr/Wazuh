# Oracle Database Audit Events on Windows

Wazuh agents cannot read Oracle XML audit files. The value `xml` is not a
supported `log_format`, so a `<localfile>` block that points at the audit
directory collects nothing. This guide moves the audit trail to the Windows
Application event log. The agent then collects it through the event channel,
and one custom rule turns each record into an alert.

> Applies to Oracle Database on Windows with traditional or mixed-mode
> auditing, and to Wazuh 4.x Windows agents. It does not apply to a database
> built in pure Unified Auditing mode.

## Table of Contents

- [Why the XML files are not collected](#why-the-xml-files-are-not-collected)
- [Choose the audit target](#choose-the-audit-target)
- [Procedure](#procedure)
  - [1. Read the current setting](#1-read-the-current-setting)
  - [2. Send audit records to the event log](#2-send-audit-records-to-the-event-log)
  - [3. Collect the Application channel](#3-collect-the-application-channel)
  - [4. Add one rule](#4-add-one-rule)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)
- [Related](#related)

## Why the XML files are not collected

Wazuh `log_format` accepts values such as `eventchannel`, `eventlog`,
`syslog`, `json`, and `multi-line`. It has no `xml` value, and the agent has
no reader for the XML files that Oracle writes under `AUDIT_FILE_DEST`. The
files stay on disk and no event reaches the manager.

| Option | What it takes |
|---|---|
| Convert the XML files with a script | A scheduled job, plus handling for rotation, gaps, and duplicate records |
| Send audit records to the event log | One initialization parameter and a database restart |

This guide uses the event log. The records then travel through the same
collection path as every other Windows event.

## Choose the audit target

| Setting | Where Oracle writes records on Windows | How Wazuh reads them |
|---|---|---|
| `AUDIT_TRAIL=XML` | XML files under `AUDIT_FILE_DEST`, often `adump` | Not collectable without conversion |
| `AUDIT_TRAIL=OS` | Application event log | `eventchannel` block, which Windows agents monitor by default |
| `AUDIT_TRAIL=DB` | `SYS.AUD$` table | A query or a scheduled export, not agent collection |
| Unified Auditing | `UNIFIED_AUDIT_TRAIL` table, optionally the Windows Event Viewer through `UNIFIED_AUDIT_SYSTEMLOG` | A separate procedure |

> `AUDIT_TRAIL` is a static parameter. A change made with `SCOPE=SPFILE`
> takes effect only at the next instance restart. Plan a maintenance window.

## Procedure

### 1. Read the current setting

Connect to the instance as `SYSDBA`:

```sql
sqlplus / as sysdba
```

On a multitenant database, list the pluggable databases. Open the one that
is closed (replace `<PDB_NAME>` with your PDB name):

```sql
SELECT name, open_mode FROM v$pdbs;
ALTER PLUGGABLE DATABASE <PDB_NAME> OPEN;
```

Select the root container, where the parameter must be set, and read the
current value:

```sql
ALTER SESSION SET CONTAINER = CDB$ROOT;
SHOW PARAMETER audit_trail;
```

Skip the `ALTER SESSION` command on a non-CDB.

### 2. Send audit records to the event log

Set the audit trail to the operating system target:

```sql
ALTER SYSTEM SET AUDIT_TRAIL=OS SCOPE=SPFILE;
```

Enable auditing for the actions you need. Logons are the usual starting
point:

```sql
AUDIT CREATE SESSION;
```

Add more `AUDIT` statements for the privileges, objects, or actions in your
audit scope. Add `AUDIT_SYS_OPERATIONS` if records for top-level `SYS`
logons are also in scope.

Restart the instance and confirm the new value:

```sql
SHUTDOWN IMMEDIATE;
STARTUP;
SHOW PARAMETER audit_trail;
```

The value must now read `OS`. Open Event Viewer and go to **Windows Logs >
Application**. Confirm that an Oracle entry appears after a fresh database
logon. Oracle audit records on Windows reach this channel, and the source is
usually `Oracle` followed by the database name.

### 3. Collect the Application channel

Windows agents monitor the Application, Security, and System channels out of
the box. If the Application channel is already listed in
`C:\Program Files (x86)\ossec-agent\ossec.conf`, add nothing. A second block
for the same channel sends every event twice.

Add the block only when Application collection was removed:

```xml
<localfile>
  <location>Application</location>
  <log_format>eventchannel</log_format>
</localfile>
```

To limit the volume, keep only the Oracle events. Read the provider name from
Event Viewer first, then filter on it:

```xml
<localfile>
  <location>Application</location>
  <log_format>eventchannel</log_format>
  <query>Event/System[starts-with(Provider/@Name,'Oracle')]</query>
</localfile>
```

Delete the block that points at the audit directory. It can never collect
anything.

Restart the agent and confirm it is running:

```powershell
Restart-Service -Name WazuhSvc
Get-Service -Name WazuhSvc
```

Older agents register the service under the name `OssecSvc`.

### 4. Add one rule

Rule chains in the Windows ruleset start at `60000` and split by channel.
Pick the parent from the channel that the archived event reports:

| `win.system.channel` | Chain from | Note |
|---|---|---|
| `Application` | `60003`, or `60600` for information-level records | This is where `AUDIT_TRAIL=OS` writes on Windows |
| `Security` | `60001`, then `60103` for audit-success records | `60103` matches `severityValue` of `AUDIT_SUCCESS` or `success` |
| `System` | `60002` | Rare for database auditing |

Rule `60103` never matches an Application-channel event, because its parent
`60001` requires the channel to be `Security`. Confirm the channel in the
archived event before you choose a parent.

Add this rule to `/var/ossec/etc/rules/local_rules.xml` on the manager. It
chains from the Application-channel group and matches any Oracle event
source:

```xml
<group name="windows,oracle,audit,">
  <rule id="120000" level="3">
    <if_sid>60003</if_sid>
    <field name="win.system.providerName">^Oracle</field>
    <description>Oracle database audit event: $(win.system.message)</description>
    <options>no_full_log</options>
  </rule>
</group>
```

Use a rule ID that is free in your installation. Custom rules normally start
at `100000`.

Validate the rule with a record from the archives before you rely on it:

```bash
/var/ossec/bin/wazuh-logtest
```

Then paste one archived Oracle event. The output must show rule `120000`. If
your build names the fields differently, match on the field that identifies
the Oracle session instead, for example `win.eventdata.subjectUserName`.

One generic alert is enough for the first deployment. Build child rules for
the cases that need attention, such as failed logons, privilege changes, or
DDL on sensitive objects. Take the sample events from Event Viewer through
**Details > XML View**. Keep the level low enough that a busy database does
not hide the important records.

## Verification

1. Trigger one audited action, for example a new database logon.
2. On the manager, enable archiving for the duration of the test. Set
   `<logall_json>yes</logall_json>` in `/var/ossec/etc/ossec.conf` and
   restart `wazuh-manager`.
3. Search `wazuh-archives-*` in the dashboard, or read
   `/var/ossec/logs/archives/archives.json`, for events from the database
   agent. Oracle records arrive as Windows events under `data.win.*`.
4. In the dashboard, confirm the channel and the provider with this filter:

   ```text
   agent.name:"<AGENT_NAME>" AND data.win.system.channel:"Application"
   ```

5. Confirm that rule `120000` appears in `wazuh-alerts-*` with the right
   description.
6. Check for duplicates. One database action must produce one indexed event.
7. Set `<logall_json>` back to `no` and restart `wazuh-manager`.

> Archiving writes every collected event to the manager disk. It is a
> diagnostic tool here, not a setting to leave on.

## Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| `SHOW PARAMETER audit_trail` still shows the old value | The change is staged in the SPFILE | Run `SHUTDOWN IMMEDIATE` and `STARTUP`. Until then the old value is expected |
| No Oracle entries in Event Viewer | Auditing is off, or the database uses Unified Auditing | Run the `AUDIT` statements again, then check `SELECT COUNT(*) FROM UNIFIED_AUDIT_TRAIL;` |
| Entries in Event Viewer but nothing in the archives | The agent does not collect the channel | Read `ossec.log` on the agent for Event Channel errors and confirm the block in `ossec.conf` |
| Events in the archives but no alert | The rule chain does not match | Check `win.system.channel` and `win.system.providerName` in the event, then rerun `wazuh-logtest` |
| Every event appears twice | The Application channel is configured twice | Remove the duplicate `<localfile>` block from the agent or the group `agent.conf` |
| Alert volume is too high | The audit scope is wider than the detection needs | Narrow the `AUDIT` statements or add the `<query>` filter |

If the Event Log route is not an option, keep the file target and convert the
files with a script. You can also configure Oracle to write a format that
Wazuh reads directly, such as syslog.

## Related

- [Microsoft SQL Server audit events](../mssql/README.md) - the same event
  channel route for a different database
- [Windows eventchannel field extraction](../../decoders/windows-eventchannel-fields.md)
  - pull values out of the embedded XML when a field match is not enough
- [Event Channel extraction scripts](../../scripts/eventchannel-extraction/README.md)
- [Custom rule deployment](../../rules/README.md)
- [Wazuh Windows Event Channel collection](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/configuration.html#monitoring-windows-event-channel)
- [Oracle: Administering the audit trail](https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/administering-the-audit-trail.html)
