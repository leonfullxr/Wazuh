# Email notifications for Syscheck (FIM) events

Configuration recipe for receiving email alerts on file integrity monitoring
(syscheck) events. This is configuration-only: no script needed.

## 1. Custom FIM rules

Raise the level of syscheck events you care about with custom rules
(dashboard > Server Management > Rules, or `local_rules.xml`):

```xml
<group name="syscheck,">
  <rule id="100300" level="5">
    <if_sid>550</if_sid>
    <field name="file">/home</field>
    <description>File modified in /home directory.</description>
  </rule>

  <rule id="100301" level="5">
    <if_sid>554</if_sid>
    <field name="file">/home</field>
    <description>File added to /home directory.</description>
  </rule>

  <rule id="100302" level="5">
    <if_sid>550</if_sid>
    <field name="file" type="pcre2">(?i)C:\\Users.+Downloads</field>
    <description>File modified in the downloads directory.</description>
  </rule>

  <rule id="100303" level="5">
    <if_sid>554</if_sid>
    <field name="file" type="pcre2">(?i)C:\\Users.+Downloads</field>
    <description>File added to the downloads directory.</description>
  </rule>

  <rule id="100304" level="14">
    <if_group>syscheck</if_group>
    <field name="file">^/etc/hosts$</field>
    <description>Syscheck alert on critical file.</description>
  </rule>
</group>
```

Base rules 550 (modified) and 554 (added) are the built-in syscheck events.

## 2. Email alert configuration

In the manager's `ossec.conf`:

```xml
<alerts>
  <log_alert_level>3</log_alert_level>
  <email_alert_level>12</email_alert_level>
</alerts>

<email_alerts>
  <email_to>recipient@example.com</email_to>
  <group>syscheck</group>
  <do_not_delay />
</email_alerts>
```

**Important precedence note:** the global `<alerts>` section takes precedence
over the granular `<email_alerts>` options. Regardless of the per-group
settings in `<email_alerts>`, you will still receive email notifications for
every alert at or above `<email_alert_level>`. To email only specific groups,
raise `<email_alert_level>` above your normal rule levels and give the FIM
rules you want emailed a level at or above it (like rule 100304 above).

## 3. Mail transport

The manager needs a local MTA. For Postfix on Debian/Ubuntu:

```bash
apt-get install postfix mailutils libsasl2-2 ca-certificates libsasl2-modules
```

## Alternative: integration script

For fully custom email formatting, use an integratord script instead of the
built-in email alerts and trigger it on specific rule IDs:

```xml
<integration>
  <name>custom-email.py</name>
  <hook_url>WEBHOOK</hook_url>
  <rule_id>100304</rule_id>
  <alert_format>json</alert_format>
</integration>
```

## Related

- [`../agent-email-summary`](../agent-email-summary) - HTML agent status
  report using the same Postfix/sendmail transport.
- [`../service-monitoring`](../service-monitoring) - service-down email
  alerts.
