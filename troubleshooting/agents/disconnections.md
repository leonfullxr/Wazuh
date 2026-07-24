# Agent Disconnections

Runbook for agents that show as `Disconnected` or `Never connected` in the Wazuh dashboard, and for agents stuck in a re-registration loop.

## Table of Contents

- [How agent connectivity works](#how-agent-connectivity-works)
- [Step 1: Determine the agent state](#step-1-determine-the-agent-state)
- [Step 2: Test network connectivity from the agent](#step-2-test-network-connectivity-from-the-agent)
- [Step 3: Collect logs from both sides](#step-3-collect-logs-from-both-sides)
- [Agents disconnected but the service is running (stuck enrollment)](#agents-disconnected-but-the-service-is-running-stuck-enrollment)
- [Agent connects but forwards no logs (MTU / path-MTU black hole)](#agent-connects-but-forwards-no-logs-mtu--path-mtu-black-hole)
- [Agent enrolls on-prem but not from a cloud VPC](#agent-enrolls-on-prem-but-not-from-a-cloud-vpc)
- [Agents stuck in a re-registration loop](#agents-stuck-in-a-re-registration-loop)
- [Related guides](#related-guides)

## How agent connectivity works

Communication is outbound from the agent to the manager. Two ports must be reachable:

| Port | Purpose |
|---|---|
| `1514/TCP` | Agent to manager event communication |
| `1515/TCP` | Enrollment (registration) via agent configuration |
| `55000/TCP` | Wazuh server API (only needed if enrolling through the API) |

`Never connected` usually means enrollment succeeded (or was never attempted) but the agent cannot reach port 1514. `Disconnected` means the agent connected at some point and then stopped checking in.

## Step 1: Determine the agent state

On the manager, query the agent with `agent_control`:

```bash
/var/ossec/bin/agent_control -i <AGENT_ID> | grep Status
```

To get a fleet-wide picture on a clustered deployment:

```bash
# Registered agents
/var/ossec/bin/cluster_control -a | egrep -v "STATUS|^000" | wc -l
# Active agents
/var/ossec/bin/cluster_control -a | grep ' active ' | wc -l
```

## Step 2: Test network connectivity from the agent

Run these on a few agents that show as `Disconnected`.

**Linux / macOS** (with Netcat installed):

```bash
nc -zv <MANAGER_IP> 1514 1515 55000
```

Confirm the agent process is actually listening/connected:

```bash
netstat -vatunp | grep 514
```

**Windows** (PowerShell):

```powershell
(New-Object Net.Sockets.TcpClient).Connect("<MANAGER_IP>", 1514)
(New-Object Net.Sockets.TcpClient).Connect("<MANAGER_IP>", 1515)
(New-Object Net.Sockets.TcpClient).Connect("<MANAGER_IP>", 55000)
```

```powershell
netstat -an | findstr 1514
```

If any of these fail, the problem is in the network path (firewall, security group, NAT, proxy): fix that before touching Wazuh configuration.

## Step 3: Collect logs from both sides

- **Agent:** `/var/ossec/logs/ossec.log` (Linux/macOS) or `C:\Program Files (x86)\ossec-agent\ossec.log` (Windows). Look for connection attempts and enrollment errors.
- **Manager:** `/var/ossec/logs/ossec.log`:

  ```bash
  grep -iE 'err|warn' /var/ossec/logs/ossec.log
  ```

The official enrollment troubleshooting guide covers the most common error signatures: <https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/troubleshooting.html#troubleshooting>

## Agents disconnected but the service is running (stuck enrollment)

A mass-disconnection pattern that looks alarming but has a specific cause: many agents drop to `Disconnected` at once, yet on each host the `wazuh-agent` service is still running and its `ossec.log` shows nothing but a log-rotation line for the whole outage: no connection attempts, no errors. Restarting the agent reconnects it immediately.

That signature (live service, silent log, restart fixes it) is the classic symptom of an agent stuck waiting for an enrollment key. On agents before 4.11.1 the key request had no timeout, so if a key request stalled (a brief manager blip, or a dropped session on a proxy/LB in the path) the agent could wait forever instead of retrying, and simply went quiet. 4.11.1 added a timeout so the agent retries instead of hanging.

- **Immediate fix:** restart the stuck agents (`systemctl restart wazuh-agent`, or `NET STOP Wazuh && NET START Wazuh` on Windows): they reconnect at once.
- **Permanent fix:** upgrade agents to 4.11.1 or later (keep the manager at least as new). The restart is a workaround; only the upgrade stops it recurring.

If the agents reach the manager through a proxy or load balancer, a too-short idle timeout on that hop can trigger the whole fleet at once: every session is torn down together, and older agents then wedge on the keyless retry. Give the persistent 1514 path a long idle timeout: see [NGINX forwarding proxy](../../integrations/nginx/README.md#forwarding-proxy-for-agents-without-internet-access). Before blaming the manager, confirm the agent is genuinely wedged (service up and log silent) rather than simply unable to reach the manager ([Step 2](#step-2-test-network-connectivity-from-the-agent)).

## Agent connects but forwards no logs (MTU / path-MTU black hole)

A subtle failure that looks like a disconnection but is really a network-path problem:

- The agent enrolls and the TCP connection to 1514/1515 succeeds (`nc` passes).
- Small packets flow: the agent's handshake and keep-alives work at first.
- **Bulk transfer freezes.** As soon as the agent sends a large record (the merged shared config `merged.mg`, a full syscollector inventory, a burst of events), the transfer stalls. The agent's `last_keepalive` / `last_ack` stop advancing and the manager flips the agent to `Disconnected`, even though the socket looked healthy moments earlier.
- On the manager you may see `wazuh-remoted` churn: `New TCP connection` immediately followed by `TCP peer disconnected`, and, if enrollment is what stalls, `authd`'s `error:0A000126 ... unexpected eof while reading`.

This is the classic signature of a path-MTU black hole: somewhere on the path (a VPN, an overlay/tunnel network, a cloud load balancer, a GRE/IPsec segment) the effective MTU is smaller than the agent's interface MTU, and the ICMP "fragmentation needed" messages that would normally drive PMTU discovery are being dropped. Small packets fit and succeed; anything above the hidden limit is silently lost, so only large transfers hang. It is common on agents behind VPNs and on managers reached through overlay networks or cloud load balancers (EKS/AKS/EC2, and similar).

Diagnose with a don't-fragment ping sweep from the agent toward the manager, shrinking the payload until it passes (payload + 28 bytes = total packet size):

```bash
# Linux: -M do sets the DF bit; -s is the payload size
ping -M do -s 1472 <MANAGER_IP>    # 1472 + 28 = 1500 (standard Ethernet MTU)
ping -M do -s 1372 <MANAGER_IP>    # 1372 + 28 = 1400
ping -M do -s 1272 <MANAGER_IP>    # 1272 + 28 = 1300
```

```powershell
# Windows: -f sets DF, -l sets payload
ping -f -l 1472 <MANAGER_IP>
ping -f -l 1272 <MANAGER_IP>
```

The largest payload that does not report `Message too long` / `Packet needs to be fragmented` is your real path MTU. If 1472 fails but a smaller size succeeds, you have found the black hole.

Fix by lowering the agent host's interface MTU to fit the path (below the largest size that passed), then restart the agent:

```bash
ip link set dev <IFACE> mtu 1400        # try 1400 first; 1300 is a safe fallback for most VPN/overlay paths
systemctl restart wazuh-agent
```

Make the change persistent in the host's network configuration (netplan / NetworkManager / `ifcfg`), not just the live `ip link` command. In one investigated case, agents connected but ingested nothing until the host MTU was lowered to 1300; the buffer then drained, ACKs advanced, and logs appeared within minutes. If lowering the MTU fixes it, the durable fix is to repair PMTU discovery on the path (allow ICMP type 3 code 4) or clamp TCP MSS at the gateway (`iptables ... TCPMSS --clamp-mss-to-pmtu`), so individual hosts do not each need a manual MTU.

## Agent enrolls on-prem but not from a cloud VPC

A classic split: on-prem agents enroll and connect fine, but agents in a cloud VPC (AWS/Azure/GCP) fail with the same config and password. On-prem-works-but-cloud-doesn't means the differentiator is the cloud egress path to the manager, not Wazuh. Two agent-side signatures point straight at it:

- `agent-auth: ERROR: Could not resolve hostname: <name>` - the configured `<address>` is an internal alias that only resolves on-prem (split-horizon DNS), not from the VPC. Point the agent at the manager's actually reachable FQDN/IP from that VPC.
- `ERROR: Invalid password. Unable to add agent (from manager)`, or a TCP session that resets mid-enrollment while the manager log shows the request arriving: the request reaches `authd` but the session/return path is interrupted in between (same class as an [enrollment return-path failure](enrollment-key-conflicts.md#enrollment-loops-and-the-duplicate-name-storm)).

When the manager is reached over a private path (AWS PrivateLink / VPC Endpoint Service, VPC peering, Transit Gateway, or a site-to-site VPN) rather than the public Internet, check from an affected host:

```bash
# 1. Does the manager FQDN resolve from THIS VPC? (split-horizon DNS bites here)
nslookup <MANAGER_FQDN>
# 2. Is the port reachable over the private path?
nc -vz <MANAGER_FQDN> 1515 && nc -vz <MANAGER_FQDN> 1514
# 3. What address is the agent actually using?
grep -A2 "<server>" /var/ossec/etc/ossec.conf
```

Common causes, in order:

- **Wrong or unaccepted private endpoint.** The VPC must connect to the correct endpoint service, and for PrivateLink the *provider* side must accept the connection. An endpoint for the wrong environment, region, or availability zone fails silently: confirm the service name and its allowed regions/AZs match where the agents actually run.
- **`<address>` set to an internal-only name.** Use the endpoint's reachable FQDN, not a name that only resolves inside another network.
- **Security groups / NACLs** on the endpoint or agent subnet not permitting 1514/1515.

Once `nslookup` resolves and `nc` connects on 1514/1515 from the VPC, re-run enrollment: the `Invalid password` / reset symptoms disappear once the path is correct.

## Agents stuck in a re-registration loop

A common failure mode: when an agent fails to connect several times, it tries to generate a new key. The manager rejects the request because the agent already has a valid key, or because the disconnection was too recent, and the agent tries again, forever. In the agent's `ossec.log` you will see repeated connection attempts followed by rejected re-registrations.

Fix it by making the agent prefer reconnection over re-registration, using two `<client>` options in the agent's `ossec.conf`:

```xml
<client>
  <!-- Refresh the connection periodically even when communication is healthy -->
  <force_reconnect_interval>1h</force_reconnect_interval>
  <!-- Wait 5 minutes between reconnection attempts after a failure.
       Must be longer than the default keep-alive interval. -->
  <time-reconnect>300</time-reconnect>
</client>
```

- [`force_reconnect_interval` reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/client.html#force-reconnect-interval)
- [`time-reconnect` reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/client.html#time-reconnect)

Then:

1. Verify the agent can reach port 1515 and 1514 (`nc -zv <MANAGER_IP> 1515 1514`).
2. Restart the agent: `systemctl restart wazuh-agent`.
3. If agents remain stuck, verify the manager's agent database is intact and restart the manager to refresh its state.
4. Restarting the agent service forces an immediate reconnection attempt without waiting for the timeout.

If the loop is caused by duplicate agent names or key mismatches rather than connectivity, see [enrollment-key-conflicts.md](enrollment-key-conflicts.md).

## Related guides

- [Enrollment and key conflicts](enrollment-key-conflicts.md) - duplicate IDs and key mismatches often masquerade as disconnections
- [Certificate troubleshooting](../../certificates/troubleshooting.md#agent-connectivity-on-15141515) - expired enrollment certificate (`sslmanager.cert`) on 1515 and the `unexpected eof while reading` handshake signature
- [AWS load balancer (NLB/ALB)](aws-load-balancer.md) - `wrong version number` from a TLS listener, and cross-zone balancing across Availability Zones
- [Flooding](flooding.md) - a flooded agent buffer can precede disconnection events
- [Diagnosis script](../../scripts/diagnosis/) - collects agent status and manager logs in one pass
