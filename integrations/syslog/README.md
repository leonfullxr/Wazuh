# Ingesting Device Syslog into Wazuh

Use this guide for firewalls, switches, appliances, and applications that can
send syslog but cannot run a Wazuh agent. It covers two production patterns:
listening directly on the Wazuh manager, or receiving and buffering events on
a dedicated rsyslog collector with a Wazuh agent.

Syslog transport only gets the event into Wazuh. A decoder must extract useful
fields and a rule must match before an alert appears. Always verify reception,
decoding, and rule evaluation as separate steps.

## Choose an architecture

| Pattern | Use when | Trade-offs |
|---|---|---|
| Manager `<remote>` listener | A small number of trusted devices can reach the manager directly | Simple, but no disk buffer or per-device routing; Wazuh's syslog listener is plain TCP/UDP |
| rsyslog collector plus Wazuh agent | You need buffering, TLS from devices, filters, per-source files, or a network relay | More components, but better isolation and operational control |

Do not expose an unauthenticated syslog listener to the public Internet. Limit
source networks at the firewall and in `allowed-ips`; use a VPN, private
network, or a TLS-capable collector when logs cross an untrusted network.

## Option 1: direct manager listener

Add one `<remote>` block inside `/var/ossec/etc/ossec.conf`. TCP is preferred
when the sender supports it:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>tcp</protocol>
  <allowed-ips>192.0.2.0/24</allowed-ips>
  <local_ip>192.0.2.10</local_ip>
</remote>
```

`allowed-ips` is mandatory. Restrict it to the sending device or network.
Create a second block if both TCP and UDP are required; syslog does not accept
both protocols in one `<remote>` block.

Validate and restart:

```bash
sudo /var/ossec/bin/wazuh-remoted -t
sudo systemctl restart wazuh-manager
sudo ss -lntup | grep ':514'
```

Configure the device to send to `<MANAGER_IP>:514` with the same transport.

## Option 2: rsyslog collector plus agent

Install rsyslog and the Wazuh agent on a dedicated Linux collector. Use a
separate file per sender so ownership, retention, and decoder scope are
predictable.

Example `/etc/rsyslog.d/30-wazuh-devices.conf`:

```text
module(load="imtcp")
input(type="imtcp" port="514")

template(
  name="RemotePerIPFile"
  type="string"
  string="/var/log/remote/%fromhost-ip%.log"
)

if $fromhost-ip != "127.0.0.1" then {
  action(
    type="omfile"
    dynaFile="RemotePerIPFile"
    createDirs="on"
    dirCreateMode="0750"
    fileCreateMode="0640"
  )
  stop
}
```

Validate before restart:

```bash
sudo rsyslogd -N1
sudo systemctl restart rsyslog
sudo ss -lntp | grep ':514'
```

Configure the local Wazuh agent to read the files:

```xml
<localfile>
  <location>/var/log/remote/*.log</location>
  <log_format>syslog</log_format>
</localfile>
```

Make sure the agent can traverse `/var/log/remote` and read the files, then
restart it:

```bash
sudo chgrp -R wazuh /var/log/remote
sudo chmod 750 /var/log/remote
sudo chmod 640 /var/log/remote/*.log
sudo systemctl restart wazuh-agent
```

Configure log rotation for the collector files based on measured volume. Use
`copytruncate` only when necessary; rsyslog normally handles a post-rotate
HUP cleanly:

```text
/var/log/remote/*.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
    create 0640 syslog wazuh
    postrotate
        /usr/bin/systemctl kill -s HUP rsyslog.service >/dev/null 2>&1 || true
    endscript
}
```

## Verification

Check each layer in order.

1. Confirm packets reach the listener:

   ```bash
   sudo tcpdump -ni any 'tcp port 514 or udp port 514'
   ```

2. For a collector, confirm the expected source file grows:

   ```bash
   sudo tail -f /var/log/remote/<DEVICE_IP>.log
   ```

3. Confirm Wazuh receives the raw event. Temporarily enable
   `<logall_json>yes</logall_json>` only when needed, then inspect
   `/var/ossec/logs/archives/archives.json` and disable it again to avoid
   uncontrolled disk growth.

4. Paste a sanitized event into `/var/ossec/bin/wazuh-logtest`. Phase 2 must
   identify the expected decoder and phase 3 the intended rule.

5. Confirm the indexed alert by filtering on the device address, decoder, or
   rule ID in the dashboard.

## Common failures

| Symptom | Check |
|---|---|
| No packets | Device destination, route, firewall, NAT, and TCP/UDP selection |
| Packets arrive but manager is not listening | `<remote>` syntax, mandatory `allowed-ips`, port conflict, manager logs |
| Collector receives but agent does not | File path, glob, permissions, agent group configuration |
| Event is archived but no alert exists | Decoder and rule output in `wazuh-logtest`; parent rules at level 0 are intentionally not alerts |
| Duplicate copies | rsyslog rule lacks `stop`, or both direct forwarding and local file collection are enabled |

## See also

- [Fortinet FortiGate syslog](../fortinet/README.md)
- [Custom decoder workflow](../../decoders/README.md)
- [Wazuh remote syslog documentation](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/syslog.html)
- [Wazuh `<remote>` reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/remote.html)
