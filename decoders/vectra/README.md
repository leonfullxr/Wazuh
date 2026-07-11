# Vectra AI Decoders

This suite parses Vectra AI detection and campaign events exported as CEF over
syslog. Use it when the generic syslog decoder preserves the CEF payload but
does not expose the Vectra fields required by local rules.

- Decoder XML: [`decoders.xml`](decoders.xml)
- Companion rule examples: [`rules.xml`](../../rules/vectra/rules.xml)

## Overview

The parent recognizes Vectra program names and the children extract the CEF
header plus extensions such as category, action, device host, source and
destination addresses, threat/certainty values, event URL, protocol, and
ports.

## Prerequisites

- Configure Vectra to export CEF syslog to a collector reachable by Wazuh.
- Collect sanitized examples for both detection and campaign event classes.
- Confirm the receiving file or socket is configured with
  `<log_format>syslog</log_format>`.

## Deployment

```bash
sudo install -o wazuh -g wazuh -m 640 decoders.xml \
  /var/ossec/etc/decoders/vectra_decoders.xml
sudo install -o wazuh -g wazuh -m 640 ../../rules/vectra/rules.xml \
  /var/ossec/etc/rules/vectra_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t
```

Before restarting, test a sanitized event:

```text
Jul 10 11:12:56 sensor-01 vectra_cef: CEF:0|Vectra Networks|X Series|1|hidden_https_tunnel_cnc|Hidden HTTPS Tunnel|5.0|externalId=123456 cat=COMMAND_AND_CONTROL dvc=192.0.2.20 dvchost=sensor.example.com shost=endpoint.example.com src=192.0.2.50 flexNumber1Label=threat flexNumber1=50 flexNumber2Label=certainty flexNumber2=75 cs4Label=VectraEventURL cs4=https://vectra.example.com/detections/123456 dst=198.51.100.10 dhost=service.example.net proto=tcp dpt=443 out=1000 in=500
```

Run `/var/ossec/bin/wazuh-logtest` and verify that phase 2 selects
`custom-vectra` and extracts the fields consumed by the companion rules.

## Verification

```bash
sudo systemctl restart wazuh-manager
sudo journalctl -u wazuh-manager --since "5 minutes ago" --no-pager
```

Send one test event through the production syslog path and verify the decoded
fields in the indexed alert. Review the bundled rule IDs and levels before
deployment: the rules are examples and broad protocol/port matches can be
noisy in an environment that exports many Vectra events.

Apply the same decoder and rule versions to every manager node.

## See also

- [Decoder syntax](../syntax.md)
- [Decoder section deployment workflow](../README.md)
