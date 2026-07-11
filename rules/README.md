# Custom Wazuh Rules

This section contains vendor rule suites and focused examples for detection
engineers extending the Wazuh ruleset. Rules should be deployed only after
their parent decoder, field names, severity, and expected event volume have
been verified against the target Wazuh release.

Keep production customizations under `/var/ossec/etc/rules/`; files under
`/var/ossec/ruleset/rules/` are package-managed and replaced during upgrades.
In a manager cluster, deploy the same rules and decoders to every node.

## Quick reference

| Source or task | Content |
|---|---|
| FortiGate | [`fortigate/fortigate_rules.xml`](fortigate/fortigate_rules.xml) and [decoder guide](../decoders/fortigate/README.md) |
| Vectra AI | [`vectra/rules.xml`](vectra/rules.xml) and [decoder guide](../decoders/vectra/README.md) |
| Reuse values in one rule file | [`<var>` examples](examples/var.md) |
| Build or validate custom rules | [Official custom-rule guide](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html) |

## Deployment checklist

1. Confirm custom rule IDs do not collide with any loaded rule.
2. Verify every `<if_sid>`, `<if_group>`, and decoded field in
   `/var/ossec/bin/wazuh-logtest`.
3. Test a positive match, a near miss, and a benign event.
4. Validate and restart:

   ```bash
   sudo /var/ossec/bin/wazuh-analysisd -t
   sudo systemctl restart wazuh-manager
   sudo journalctl -u wazuh-manager --since "5 minutes ago" --no-pager
   ```

5. Monitor `rule.id`, `rule.level`, and event volume after rollout. Tune or
   disable rules that create broad protocol/port alerts without enough
   detection context.

The XML in this repository is a starting point, not a universal severity
policy. Map levels and MITRE techniques to the behavior actually represented
by your source events.
