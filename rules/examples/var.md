# Reusing Values with Rule `<var>` Elements

Use `<var>` when several rules in one XML file share a short, relatively
stable regular expression such as a host allowlist or a set of error words.
Variables reduce copy/paste drift; they are not a replacement for CDB lists
when operators must update a large allowlist without editing rules.

A variable is scoped to its **entire rule file**. It must be declared at the
base level, before any `<group>` element, and referenced as `$VARIABLE_NAME`.
Defining `<var>` inside `<rule>` is invalid.

## Prerequisites

- Choose rule IDs in the custom range `100000-120000` that are unused in the
  deployment.
- Confirm the parent rule IDs and decoded field names with
  `/var/ossec/bin/wazuh-logtest`; bundled rule IDs can differ by Wazuh
  release.
- Place custom rules under `/var/ossec/etc/rules/`, never modify
  `/var/ossec/ruleset/rules/` directly because upgrades replace it.

## Example: shared host and account allowlists

This example lowers the severity of an expected backup process on approved
hosts and raises an alert when the same service account launches it elsewhere.
Keep the variables outside the group:

```xml
<var name="BACKUP_HOSTS">^(backup01|dc01|dc02)\.example\.com$</var>
<var name="BACKUP_ACCOUNT">^EXAMPLE\\svc_backup$</var>

<group name="windows,backup_monitoring,">
  <rule id="110035" level="3">
    <if_sid>61603</if_sid>
    <field name="win.system.computer" type="pcre2">$BACKUP_HOSTS</field>
    <field name="win.eventdata.user" type="pcre2">$BACKUP_ACCOUNT</field>
    <field name="win.eventdata.originalFileName" type="pcre2">^VeeamVixProxy\.exe$</field>
    <description>Expected backup process executed by the service account on an approved host</description>
  </rule>

  <rule id="110036" level="12">
    <if_sid>61603</if_sid>
    <field name="win.system.computer" negate="yes" type="pcre2">$BACKUP_HOSTS</field>
    <field name="win.eventdata.user" type="pcre2">$BACKUP_ACCOUNT</field>
    <field name="win.eventdata.originalFileName" type="pcre2">^VeeamVixProxy\.exe$</field>
    <description>Backup service account executed the backup process on an unapproved host</description>
    <mitre>
      <id>T1078.002</id>
    </mitre>
  </rule>
</group>
```

If the relevant event sometimes stores the account in
`win.eventdata.parentUser` instead of `win.eventdata.user`, create a separate
rule for that field. Two `<field>` elements in one rule are combined with
logical **AND**, not OR.

## Example: reusable error vocabulary

Variables can also hold alternation used by `<match>`:

```xml
<var name="BACKUP_ERRORS">error|warning|failure|snapshot timeout</var>

<group name="backup_application,">
  <rule id="110040" level="7">
    <decoded_as>json</decoded_as>
    <field name="application">^backup-service$</field>
    <match>$BACKUP_ERRORS</match>
    <description>Backup application reported an error condition</description>
  </rule>
</group>
```

## Deployment and verification

Save the complete XML as
`/var/ossec/etc/rules/backup_monitoring_rules.xml`, validate ownership, and
restart only after `wazuh-logtest` loads it without errors:

```bash
sudo chown wazuh:wazuh /var/ossec/etc/rules/backup_monitoring_rules.xml
sudo chmod 640 /var/ossec/etc/rules/backup_monitoring_rules.xml
sudo /var/ossec/bin/wazuh-logtest
sudo systemctl restart wazuh-manager
sudo journalctl -u wazuh-manager --since "5 minutes ago" --no-pager
```

Test at least these cases:

1. Approved account, approved host, expected executable: rule `110035`.
2. Approved account, unapproved host, expected executable: rule `110036`.
3. Different account or executable: neither custom rule.

## When to use a CDB list instead

Use a CDB list when the values are numerous, change frequently, or must be
maintained independently from the XML. Configure the list under the
`<ruleset>` section and match it with a rule `<list>` element.

## See also

- [Wazuh rule syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
- [Wazuh custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
- [Decoder syntax](../../decoders/syntax.md)
