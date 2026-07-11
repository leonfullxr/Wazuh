# Agent Disconnections

Runbook for agents that show as `Disconnected` or `Never connected` in the Wazuh dashboard, and for agents stuck in a re-registration loop.

## Table of Contents

- [How agent connectivity works](#how-agent-connectivity-works)
- [Step 1: Determine the agent state](#step-1-determine-the-agent-state)
- [Step 2: Test network connectivity from the agent](#step-2-test-network-connectivity-from-the-agent)
- [Step 3: Collect logs from both sides](#step-3-collect-logs-from-both-sides)
- [Agents stuck in a re-registration loop](#agents-stuck-in-a-re-registration-loop)
- [Related guides](#related-guides)

## How agent connectivity works

Communication is **outbound from the agent to the manager**. Two ports must be reachable:

| Port | Purpose |
|---|---|
| `1514/TCP` | Agent ↔ manager event communication |
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

If any of these fail, the problem is in the network path (firewall, security group, NAT, proxy) — fix that before touching Wazuh configuration.

## Step 3: Collect logs from both sides

- **Agent:** `/var/ossec/logs/ossec.log` (Linux/macOS) or `C:\Program Files (x86)\ossec-agent\ossec.log` (Windows). Look for connection attempts and enrollment errors.
- **Manager:** `/var/ossec/logs/ossec.log`:

  ```bash
  grep -iE 'err|warn' /var/ossec/logs/ossec.log
  ```

The official enrollment troubleshooting guide covers the most common error signatures: <https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/troubleshooting.html#troubleshooting>

## Agents stuck in a re-registration loop

A common failure mode: when an agent fails to connect several times, it tries to **generate a new key**. The manager rejects the request because the agent already has a valid key, or because the disconnection was too recent — and the agent tries again, forever. In the agent's `ossec.log` you will see repeated connection attempts followed by rejected re-registrations.

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

- [Enrollment and key conflicts](enrollment-key-conflicts.md) — duplicate IDs and key mismatches often masquerade as disconnections
- [Flooding](flooding.md) — a flooded agent buffer can precede disconnection events
- [Diagnosis script](../../scripts/diagnosis/) — collects agent status and manager logs in one pass
