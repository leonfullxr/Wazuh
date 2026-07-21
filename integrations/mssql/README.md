<!-- Support: WS-27363, WS-34520, WS-34960, WS-37981 -->

# Monitoring Microsoft SQL Server Audit Events

Use Windows Event Channel collection to monitor SQL Server authentication and
SQL Server Audit events with a Wazuh agent installed on the database host.
This is the preferred path when the required activity is already written to
the Windows Application or Security log.

This guide does not poll arbitrary database tables. Table polling needs a
stateful query, least-privilege database credentials, checkpointing,
deduplication, and log rotation; a scheduled `SELECT *` command is not a
production audit pipeline.

## Prerequisites

- SQL Server on Windows and SQL Server Management Studio or equivalent T-SQL
  access.
- A Wazuh agent on the SQL Server host.
- Permission to configure SQL Server Audit and restart the SQL Server service
  if login-auditing settings change.
- An approved audit scope and retention policy.

Before changing Wazuh, use Event Viewer to confirm the target channel,
provider name, event IDs, and message shape. Default and named instances can
use providers such as `MSSQLSERVER` and `MSSQL$<INSTANCE>`.

## Choose the SQL Server source

| Requirement | SQL Server configuration | Typical events |
|---|---|---|
| Login success/failure only | **Server Properties > Security > Login auditing** | `18453`/`18454` success, `18456` failure |
| Auditable server/database action groups | SQL Server Audit plus an audit specification | Audit records commonly emitted as `33205` when Application Log is the target |
| Full high-volume audit trail | SQL Server Audit to a protected file target | Collect and parse the local file separately; do not force all records through Windows Event Log without sizing it |

## Procedure

### 1. Enable SQL Server Audit

The following example writes successful and failed login audit groups to the
Windows Application log. Review `ON_FAILURE` with the database owner:
`CONTINUE` preserves availability but can lose audit records if the target is
unavailable.

```sql
CREATE SERVER AUDIT Wazuh_Server_Audit
TO APPLICATION_LOG
WITH (
    QUEUE_DELAY = 1000,
    ON_FAILURE = CONTINUE
);
GO

CREATE SERVER AUDIT SPECIFICATION Wazuh_Login_Audit_Spec
FOR SERVER AUDIT Wazuh_Server_Audit
    ADD (FAILED_LOGIN_GROUP),
    ADD (SUCCESSFUL_LOGIN_GROUP)
WITH (STATE = ON);
GO

ALTER SERVER AUDIT Wazuh_Server_Audit
WITH (STATE = ON);
GO
```

Verify state:

```sql
SELECT name, is_state_enabled, type_desc
FROM sys.server_audits
WHERE name = N'Wazuh_Server_Audit';

SELECT name, is_state_enabled
FROM sys.server_audit_specifications
WHERE name = N'Wazuh_Login_Audit_Spec';
```

Alternatively, configure login auditing in SSMS under
**Server Properties > Security**. SQL Server must restart before that setting
takes effect.

### 2. Confirm Windows receives the events

Generate one approved successful login and one controlled failed login. In
Event Viewer, verify the events under **Windows Logs > Application** and note:

- `EventID`
- `Provider Name`
- `Channel`
- username and client address in the rendered message

Do not proceed based only on expected IDs; instance configuration and audit
target determine the actual channel.

### 3. Configure Wazuh collection

Wazuh Windows agents normally monitor Application, Security, and System
channels already. If Application is already collected, adding a second block
for the same channel can duplicate events.

If you intentionally replace broad Application collection with a filtered
block, add this to the agent's `ossec.conf` or a Windows group
`agent.conf`:

```xml
<localfile>
  <location>Application</location>
  <log_format>eventchannel</log_format>
  <only-future-events>yes</only-future-events>
  <query>Event/System[EventID=18453 or EventID=18454 or EventID=18456 or EventID=33205]</query>
</localfile>
```

Restart the agent:

```powershell
Restart-Service -Name WazuhSvc
Get-Service -Name WazuhSvc
```

### 4. Add only the rules you need

Wazuh includes Windows Application and SQL Server rules for common login
events. Use `wazuh-logtest` to determine the actual chain before adding a
custom rule.

For an unalerted `33205` audit event, a local rule can chain from the
Application audit-success parent used by the installed Wazuh release:

```xml
<group name="windows,mssql,audit,">
  <rule id="110201" level="5">
    <if_sid>61070</if_sid>
    <field name="win.system.eventID">^33205$</field>
    <description>SQL Server audit event: $(win.system.message)</description>
  </rule>
</group>
```

Confirm that rule `61070` is the parent in your release. Avoid creating an
alert for every SQL audit record; target high-value action groups and tune
levels to prevent important events being hidden by volume.

## Verification

1. Trigger the controlled test events again.
2. On the agent, check for Event Channel subscription errors:

   ```powershell
   Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 100
   ```

3. On the manager, inspect the event with `/var/ossec/bin/wazuh-logtest`.
4. In the dashboard, filter on:

   ```text
   agent.name:"<SQL_SERVER_AGENT>" AND
   win.system.eventID:(18453 OR 18454 OR 18456 OR 33205)
   ```

5. Verify username, client address, provider, channel, rule ID, and timestamp.
6. Confirm one database action produces one indexed event; duplicates usually
   mean the channel is configured in both local and centralized agent config.

## Security and operations

- Failed-login state information can be sensitive; restrict dashboard access.
- Size the Windows event log and Wazuh retention for the enabled audit groups.
- Keep SQL Server Audit enabled-state monitoring in operational checks.
- Use file targets for high-volume or compliance-grade audit trails and
  protect the directory against modification by database users.
- Do not embed database passwords in `sqlcmd` batch files or Wazuh command
  wodles.

## See also

- [Wazuh Windows Event Channel collection](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/configuration.html#monitoring-windows-event-channel)
- [Microsoft: Create a server audit and specification](https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/create-a-server-audit-and-server-audit-specification)
- [Microsoft SQL Server error 18456](https://learn.microsoft.com/en-us/sql/relational-databases/errors-events/mssqlserver-18456-database-engine-error)
- [Event Channel extraction scripts](../../scripts/eventchannel-extraction/README.md)
