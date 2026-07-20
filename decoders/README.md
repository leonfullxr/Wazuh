# Custom Wazuh Decoders

This section is for detection engineers who need to parse logs that the
bundled Wazuh ruleset does not decode completely. It contains vendor decoder
suites plus a syntax guide for developing and testing custom decoders.

Install custom XML under `/var/ossec/etc/decoders/` on every manager node.
Treat the supplied XML as versioned source: test representative logs before
deployment, keep matching rules separate under `/var/ossec/etc/rules/`, and
repeat the tests after Wazuh or vendor upgrades.

## Quick reference

| Log source or task | Guide |
|---|---|
| FortiGate key/value syslog | [FortiGate decoders](fortigate/README.md) |
| Vectra AI CEF events | [Vectra AI decoders](vectra/README.md) |
| NetIQ Identity Manager CEF events | [NetIQ decoders](netIQ/README.md) |
| Fields buried in a Windows eventchannel message (ADFS `UserId`/`IpAddress`) | [Windows eventchannel field extraction](windows-eventchannel-fields.md) |
| Write or troubleshoot a decoder | [Decoder syntax and examples](syntax.md) |

## Safe deployment workflow

1. Capture several sanitized examples for each event type, including optional
   and reordered fields.
2. Copy the decoder XML to a uniquely named file:

   ```bash
   sudo install -o wazuh -g wazuh -m 640 <DECODER_FILE>.xml \
     /var/ossec/etc/decoders/<DECODER_FILE>.xml
   ```

3. Run `/var/ossec/bin/wazuh-logtest` and paste each sample. Verify phase 2
   selects the expected decoder and extracts the fields used by the rules.
4. Check configuration before restart:

   ```bash
   sudo /var/ossec/bin/wazuh-analysisd -t
   sudo systemctl restart wazuh-manager
   sudo journalctl -u wazuh-manager --since "5 minutes ago" --no-pager
   ```

5. Send one event through the real ingestion path and confirm the decoded
   fields and expected rule in the dashboard.

In a manager cluster, deploy the same decoder and rule files to every node
before restarting them one at a time. Decoder files are not automatically
synchronized between managers.

## Maintenance

- Do not edit `/var/ossec/ruleset/decoders/`; package upgrades replace it.
- Avoid generic decoder names that may collide with bundled or third-party
  files.
- Keep raw sample logs out of the public repository unless they are fully
  anonymized.
- A decoder only extracts fields. It does not generate an alert until a rule
  matches the decoded event.

## See also

- [Wazuh decoder syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html)
- [Wazuh custom decoders](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/custom.html)
- [Custom rules](../rules/)
