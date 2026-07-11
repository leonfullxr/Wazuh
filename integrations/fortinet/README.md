# Fortinet FortiGate Syslog Integration

This guide is for network and Wazuh administrators forwarding FortiGate
traffic, event, and UTM logs into Wazuh. It covers the FortiGate sender,
transport, Wazuh collection, decoder deployment, and end-to-end verification.

Use a direct Wazuh manager listener for a small trusted network. Use a
dedicated rsyslog collector when you need buffering, TLS transport, filtering,
or an isolation boundary between firewalls and the manager.

## Prerequisites

- A FortiGate administrator account.
- A Wazuh manager or rsyslog collector reachable from the FortiGate.
- TCP or UDP port 514 allowed only from the firewall source address.
- Representative sanitized events for every enabled FortiGate log category.
- The [FortiGate decoder and rule files](../../decoders/fortigate/README.md).

Prefer TCP for delivery reliability. UDP can lose events under congestion and
does not report delivery failures. Neither plain TCP nor UDP encrypts the
payload; use a private network, VPN, or TLS-capable collector when required.

## Procedure

### 1. Configure FortiGate remote logging

In the FortiGate web interface:

1. Open **Log & Report > Log Settings**.
2. Enable **Send logs to syslog** and add the Wazuh manager or collector
   address.
3. Set port `514` and select the transport that matches the receiver.
4. Enable the required categories, such as system events, traffic, and UTM.
5. Start with `information` severity or higher, then tune after measuring
   event volume.

Menu labels differ by FortiOS release. Confirm the active settings in the
FortiGate CLI or configuration backup after saving them.

### 2. Configure the receiver

Choose one of the two supported collection patterns in the
[syslog ingestion guide](../syslog/README.md):

- Direct manager `<remote>` listener with `allowed-ips` restricted to the
  FortiGate address.
- rsyslog collector writing per-device files that a local Wazuh agent reads.

Do not enable both paths for the same firewall unless duplicate events are
intentional.

### 3. Install decoders and rules

On every Wazuh manager:

```bash
sudo install -o wazuh -g wazuh -m 640 \
  fortigate_decoders.xml \
  /var/ossec/etc/decoders/fortigate_decoders.xml
sudo install -o wazuh -g wazuh -m 640 \
  fortigate_rules.xml \
  /var/ossec/etc/rules/fortigate_rules.xml
```

Use the files from this repository and validate them with the exact FortiOS
version before restart:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo /var/ossec/bin/wazuh-logtest
```

Paste a sanitized event such as:

```text
date=2026/07/10 time=10:30:00 devname="fw-edge-01" devid="FGT-EXAMPLE" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=192.0.2.10 dstip=198.51.100.20 srcport=51514 dstport=443 proto=6 action="accept"
```

Phase 2 should select the FortiGate decoder and expose fields such as
`devname`, `logid`, `type`, `subtype`, `srcip`, `dstip`, ports, protocol, and
action. Review the matching rule and level in phase 3.

### 4. Restart safely

```bash
sudo systemctl restart wazuh-manager
sudo journalctl -u wazuh-manager --since "5 minutes ago" --no-pager
```

In a manager cluster, deploy identical XML to every node and restart one node
at a time.

## Verification

1. Generate a benign, identifiable FortiGate event, such as an allowed test
   connection from `192.0.2.10` to `198.51.100.20`.
2. Confirm packets at the receiver:

   ```bash
   sudo tcpdump -ni any 'host <FORTIGATE_IP> and (tcp port 514 or udp port 514)'
   ```

3. If using rsyslog, confirm the per-device file grows.
4. Temporarily inspect Wazuh archives if raw-event visibility is needed.
5. In the dashboard, verify the event has the expected decoder, fields, and
   rule. Confirm the source and destination were not reversed.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| No packets arrive | Wrong destination/transport, route, FortiGate local-out policy, or firewall rule |
| Packets arrive but Wazuh drops them | Source is outside `<allowed-ips>` or listener protocol does not match |
| Raw log arrives but no alert | Decoder does not match the FortiOS format, or only a level-0 parent rule matched |
| Some fields are missing | That FortiOS log type uses different key names; add a tested sibling decoder |
| Duplicate alerts | The firewall sends to two collectors, or rsyslog both forwards and writes a file consumed by an agent |
| Excessive volume | Reduce FortiGate categories/severity or narrow Wazuh rules; do not discard security-critical logs without review |

## See also

- [Generic syslog ingestion](../syslog/README.md)
- [FortiGate decoder deployment](../../decoders/fortigate/README.md)
- [Decoder syntax](../../decoders/syntax.md)
