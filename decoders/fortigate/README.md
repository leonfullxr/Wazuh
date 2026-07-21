# FortiGate Decoders

This decoder suite parses FortiGate traffic and event logs delivered as
key/value syslog. It was developed against FortiOS log formats from the
7.0.x, 7.2.x, and 7.4.x families. Validate it against the exact FortiOS
release and enabled log types in your environment because vendors add and
rename fields between releases.

- Decoder XML: [`fortigate_decoders.xml`](fortigate_decoders.xml)
- Matching rule examples:
  [`fortigate_rules.xml`](../../rules/fortigate/fortigate_rules.xml)

## Overview

The suite uses sibling decoders under a parent that matches `devname=`. Each
sibling extracts one field, so optional key/value pairs can appear in
different orders. This is more resilient than one expression that assumes a
fixed field order.

## Prerequisites

- FortiGate sends syslog to a listener reachable by the Wazuh manager or an
  agent.
- The receiving `<localfile>` uses `syslog` format and points to the file or
  socket where the collector writes FortiGate events.
- You have sanitized samples for every enabled FortiGate log type.

See the [Fortinet syslog integration guide](../../integrations/fortinet/README.md)
for transport, filtering, and end-to-end verification.

## Deployment

Install the decoder and, if required, the companion rules:

```bash
sudo install -o wazuh -g wazuh -m 640 fortigate_decoders.xml \
  /var/ossec/etc/decoders/fortigate_decoders.xml
sudo install -o wazuh -g wazuh -m 640 \
  ../../rules/fortigate/fortigate_rules.xml \
  /var/ossec/etc/rules/fortigate_rules.xml
```

Run `/var/ossec/bin/wazuh-logtest` before restarting. In a manager cluster,
deploy identical files to every node, validate each node, and restart one
node at a time.

## Example log line

```text
date=2026/07/10 time=10:30:00 devname="fw-edge-01" devid="FGT-EXAMPLE" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=192.0.2.10 dstip=198.51.100.20 srcport=51514 dstport=443 proto=6 action="accept"
```

Expected phase 2 output includes the FortiGate decoder and fields such as
`devname`, `devid`, `logid`, `type`, `subtype`, `srcip`, `dstip`, ports, and
`action`. Exact fields depend on the event.

## Verification

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
sudo journalctl -u wazuh-manager --since "5 minutes ago" --no-pager
```

Then send a real test event and confirm:

1. It arrives in `/var/ossec/logs/archives/archives.json` when archives are
   enabled.
2. The dashboard document contains the expected decoded fields.
3. The intended companion rule fires and unrelated FortiGate events do not.

Review rule IDs, levels, and noisy broad matches before production use. A
decoder match alone is not evidence that every companion rule is appropriate
for your environment.

## See also

- [Fortinet syslog integration](../../integrations/fortinet/README.md)
- [Decoder syntax](../syntax.md)
- [Decoder section deployment workflow](../README.md)
