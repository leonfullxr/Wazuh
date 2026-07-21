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

## Receiving syslog over TLS (6514)

Some senders require encrypted syslog (Palo Alto/Prisma, many appliances). `6514` is the IANA port for syslog-over-TLS. Wazuh's own `<remote connection="syslog">` listener is **plaintext only**, so terminate TLS with an **rsyslog collector** (the `ossl`/OpenSSL stream driver) and forward the decrypted stream on to the manager or to per-source files a local agent reads.

`/etc/rsyslog.d/40-tls-input.conf`:

```text
module(
  load="imtcp"
  StreamDriver.Name="ossl"
  StreamDriver.Mode="1"          # 1 = TLS
  StreamDriver.AuthMode="anon"   # server-auth only: the sender validates our cert
)
global(
  DefaultNetstreamDriver="ossl"
  DefaultNetstreamDriverCAFile="/etc/rsyslog.d/certs/ca-chain.pem"
  DefaultNetstreamDriverCertFile="/etc/rsyslog.d/certs/server.crt"
  DefaultNetstreamDriverKeyFile="/etc/rsyslog.d/certs/server.key"
)
input(type="imtcp" port="6514")

# Then either write per-source files for the local agent (see Option 2), or relay
# the decrypted stream to the manager:
# *.*  @@<MANAGER_IP>:514
```

Notes:

- `AuthMode="anon"` = the **server** presents a certificate the sender validates; no client certificate is required. For mutual TLS, use `AuthMode="x509/name"` with a CA and permitted peers.
- The cert/key/CA must be valid PEM and the key must match the certificate. A malformed file makes rsyslog fail to open `6514` with OpenSSL **ASN.1/PEM** errors (not a "file not found") - validate first: [cert/key/chain validation](../../certificates/troubleshooting.md#validating-a-server-cert-key-and-chain).
- If the sender enforces certificate **revocation** (OCSP/CRL) - Palo Alto Strata does - a self-signed cert will be rejected. See [Palo Alto / Prisma Cloud](../prisma-cloud/README.md#certificate-requirements-the-main-blocker).

Validate and restart:

```bash
sudo rsyslogd -N1
sudo systemctl restart rsyslog
sudo ss -lntp | grep ':6514'
```

## Load balancing syslog across cluster workers

In a multi-node cluster, syslog reception does **not** balance itself. Each node runs its own listener - the `<remote connection="syslog">` block is per-node configuration and does **not** propagate through cluster sync - and whatever sits in front of the nodes decides which one a sender lands on. Two failure modes are common at scale (self-hosted on VMs/EC2, Docker, or self-managed Kubernetes like EKS/AKS alike):

- **A single endpoint pins all traffic to one node.** If every device, or a load balancer with sticky behaviour, targets one manager, that node processes the entire syslog stream while the other workers sit idle. It saturates CPU and starts dropping events even though the cluster as a whole has spare capacity.
- **UDP "sticks" to one backend.** With UDP syslog behind an L4 load balancer or a Kubernetes `Service`, connection tracking (conntrack / kube-proxy) keeps a source pinned to the same backend for the life of the flow, so a single high-volume sender never spreads. The same happens over TCP when one centralized forwarder holds a **single long-lived connection** - every event rides that one connection to one worker.

The fix is a real load balancer distributing connections across every worker's `514` listener, plus per-node listener config:

1. **Enable the syslog listener on every worker** that should receive traffic. Edit each node's `ossec.conf` (the block does not sync), then restart that node:

    ```xml
    <remote>
      <connection>syslog</connection>
      <port>514</port>
      <protocol>tcp</protocol>
      <allowed-ips>192.0.2.0/24</allowed-ips>
    </remote>
    ```

2. **Front the workers with HAProxy** (or a cloud L4 load balancer) in round-robin, health-checking each worker. Prefer **TCP** syslog - it balances far more predictably than UDP:

    ```haproxy
    frontend syslog_in
        bind *:514
        mode tcp
        default_backend syslog_workers

    backend syslog_workers
        mode tcp
        balance roundrobin
        server worker0 10.0.0.10:514 check
        server worker1 10.0.0.11:514 check
        server worker2 10.0.0.12:514 check
    ```

3. **Break connection stickiness for single-forwarder or UDP setups.** If one relay sends everything over a persistent connection, force it to reconnect periodically so it re-balances - for example rsyslog's queue `RebindInterval` (reconnect every N messages). If you must use UDP, put the LB in a per-packet mode rather than per-flow, or - better - switch the forwarder to TCP.

Verify the spread from the master with per-node received-event counts:

```bash
/var/ossec/bin/cluster_control -a -fs active | grep -Po ' wazuh-manager-\S+' | sort | uniq -c
```

If one node still shows the bulk of the events, stickiness has not been broken - revisit the LB mode and the forwarder's connection behaviour.

> **Per-node EPS limits apply after balancing.** Even with traffic spread evenly, each node enforces its own EPS ceiling (`<limits><eps>`), and short bursts above it are throttled and dropped regardless of the daily average. See [the EPS limit throttles bursts](../../troubleshooting/server/analysisd.md#the-eps-limit-limitseps-throttles-bursts) before concluding you simply need more nodes.

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
| One cluster node handles all syslog while others idle | Single endpoint or UDP/connection stickiness; see [load balancing syslog across cluster workers](#load-balancing-syslog-across-cluster-workers) |

## See also

- [Fortinet FortiGate syslog](../fortinet/README.md)
- [Palo Alto / Prisma Cloud over TLS](../prisma-cloud/README.md) - syslog-over-TLS 6514, the OCSP certificate requirement, and the JSON decoder
- [Manager dropped events, EPS, and scaling](../../troubleshooting/server/analysisd.md) - per-node EPS throttling and when to scale
- [Custom decoder workflow](../../decoders/README.md)
- [Wazuh remote syslog documentation](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/syslog.html)
- [Wazuh `<remote>` reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/remote.html)
