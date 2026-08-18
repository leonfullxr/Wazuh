# NGINX Stream Load Balancer for Wazuh Agents

Use NGINX's stream module to give agents one stable address while distributing
persistent TCP/1514 connections across Wazuh worker nodes. Enrollment on
TCP/1515 is sent to the master in this design so new keys are created at the
authoritative cluster node.

This is TCP passthrough, not HTTP reverse proxying or TLS termination. Agent
protocol encryption remains end to end between the agent and Wazuh manager.

## Prerequisites

- A healthy Wazuh manager cluster with synchronized agent keys.
- An NGINX build that includes the stream module
  (`nginx -V 2>&1 | grep -- --with-stream` or a distribution stream module).
- The load-balancer address reachable by agents on TCP/1514 and TCP/1515.
- The load balancer able to reach manager nodes on the same ports.

## Procedure

1. Install or enable the NGINX stream module for the operating system.

2. Add a top-level `stream` block to `/etc/nginx/nginx.conf`, outside the
   `http` block:

   ```nginx
   stream {
       log_format wazuh_stream '$remote_addr [$time_local] '
                               '$protocol $status $bytes_sent $bytes_received '
                               '$session_time upstream=$upstream_addr';

       access_log /var/log/nginx/wazuh-stream.log wazuh_stream;

       upstream wazuh_enrollment {
           server <MASTER_NODE_IP>:1515 max_fails=3 fail_timeout=30s;
       }

       upstream wazuh_agents {
           hash $remote_addr consistent;
           server <WORKER_1_IP>:1514 max_fails=3 fail_timeout=30s;
           server <WORKER_2_IP>:1514 max_fails=3 fail_timeout=30s;
       }

       server {
           listen 1515;
           proxy_connect_timeout 5s;
           proxy_timeout 30s;
           proxy_pass wazuh_enrollment;
       }

       server {
           listen 1514;
           proxy_connect_timeout 5s;
           proxy_timeout 1h;
           proxy_pass wazuh_agents;
       }
   }
   ```

   `hash $remote_addr consistent` keeps an agent on the same worker while the
   backend set is stable and minimizes reassignment when workers change.
   NGINX Open Source uses passive failure detection here. It does not know
   cluster health beyond connection failures.

3. Validate and reload:

   ```bash
   sudo nginx -t
   sudo systemctl reload nginx
   sudo ss -lntp | grep -E ':(1514|1515)\b'
   ```

4. Point agents at the load-balancer address:

   ```xml
   <client>
     <server>
       <address><LOAD_BALANCER_FQDN></address>
       <port>1514</port>
       <protocol>tcp</protocol>
     </server>
     <notify_time>10</notify_time>
     <time-reconnect>60</time-reconnect>
     <auto_restart>yes</auto_restart>
   </client>
   ```

   Use the same address for enrollment. Preserve existing enrollment
   passwords or certificate settings.

## Forwarding proxy for agents without internet access

A common variant: the agents have **no direct route** to the manager (or Wazuh Cloud) and must egress through one internal proxy. The same `stream` mechanism applies, but with a **single upstream** (the manager or the Wazuh Cloud FQDN) instead of a worker pool:

```nginx
stream {
    upstream wazuh_enrollment { server <MANAGER_OR_CLOUD_FQDN>:1515; }
    upstream wazuh_agents     { server <MANAGER_OR_CLOUD_FQDN>:1514; }

    server {
        listen 1515;
        proxy_pass wazuh_enrollment;
        proxy_connect_timeout 30s;
        proxy_timeout 1h;
    }
    server {
        listen 1514;
        proxy_pass wazuh_agents;
        proxy_connect_timeout 30s;
        proxy_timeout 1h;          # 1514 is a PERSISTENT session - do NOT use a short timeout
    }
}
```

Agents point their `<server><address>` at the **proxy**, not the manager. Three points matter in this topology:

- **A short `proxy_timeout` on 1514 silently drops idle agents.** The event channel is a long-lived TCP session, and it can stay quiet between events. A 60-120s timeout closes it periodically. On agents before 4.11.1 that can leave the whole fleet wedged on a keyless retry. See [stuck enrollment](../../troubleshooting/agents/disconnections.md#agents-disconnected-but-the-service-is-running-stuck-enrollment). Use `1h` or longer on 1514.
- **Test through the proxy path, not around it.** Test connectivity from an agent that egresses via the proxy, or test against the proxy IP. The test then reflects what the agents experience. A direct-to-manager test that passes proves nothing about the proxy path.
- **Use the proxy only when the network requires it.** Agent-to-manager traffic is already AES-encrypted end to end. Connect agents directly to the manager FQDN where you can.

## What to balance, and what not to

The stream block should carry agent traffic only. Adding every Wazuh port to it
is the most common mistake in a hand-written config, and two of those additions
actively cause outages.

| Port | Balance it? | Reason |
|---|---|---|
| 1514/TCP | Yes, across all manager nodes | Agent event traffic. This is the reason the load balancer exists |
| 1515/TCP | To the master only | Only the master registers agents. Sending enrollment to a worker fails |
| 1516/TCP | Never | Manager cluster daemon. Node to node traffic, never through a proxy |
| 55000/TCP | No | Only the master serves the API |
| 514, 6514 | Separately, and prefer TCP | Syslog. See [ingesting device syslog](../syslog/README.md#load-balancing-syslog-across-cluster-workers) |

Two of these deserve the detail:

- **Do not put the API on 55000 behind the load balancer.** The API is served by
  the master alone. Balancing it creates a config that looks highly available
  and is not: when the master fails, agents keep working through a worker on
  1514 while every API and dashboard call fails anyway. Point API clients
  straight at the master and keep the failure mode obvious.
- **UDP syslog does not balance the way it appears to.** Connection tracking
  pins a source address to one backend for the life of the flow, so a single
  high-volume sender never spreads across workers. Prefer TCP, and for network
  devices prefer an rsyslog collector with an agent, which also adds the disk
  buffer that syslog itself has none of.

Balancing is purely TCP and IP level. The load balancer has no view of Wazuh
state, so it cannot know which node owns an agent.

## The load balancer is a single point of failure

One load balancer in front of a manager cluster leaves the whole deployment
depending on one machine. The fix does not need a second cluster, only a second
address and a fallback in the agents.

Run **two load balancers** and list both in every agent, followed by a manager
address as the last resort:

```xml
<client>
  <server>
    <address><LOAD_BALANCER_1_FQDN></address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
  <server>
    <address><LOAD_BALANCER_2_FQDN></address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
  <server>
    <address><MASTER_FQDN></address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
</client>
```

The agent walks the list in order. It connects to the first address that
answers, and moves to the next one when a connection fails.

Three properties of that behavior decide the design:

- **The load balancer must run on its own machine.** Co-locating it with a
  manager node defeats the purpose, because the node that fails takes both the
  manager and the fallback path with it. Co-locating it with a **dashboard**
  node is fine and is the usual way to get a second load balancer without extra
  hardware. The dashboard is independent of the manager cluster and consumes
  little CPU or RAM.
- **There is no automatic failback.** Once agents move to the second address
  they stay there after the first recovers. Restart the agents to rebalance.
  Restarting the manager is not usually enough, because the agents do not stay
  disconnected long enough to re-evaluate the list.
- **Enrollment still needs the master.** Whichever path an agent takes for 1514,
  registration on 1515 must reach the master.

An alternative to a second load balancer is to give half the fleet the worker
address as its second entry and the other half the master. That yields a fixed
split rather than true balancing, and it survives the loss of the load balancer.

## Verification

From an agent network:

```bash
nc -vz <LOAD_BALANCER_FQDN> 1514
nc -vz <LOAD_BALANCER_FQDN> 1515
```

Then verify behavior, not only open ports:

1. Enroll one test agent through the load balancer.
2. Confirm it appears on the master and reports as active.
3. Check which worker owns the connection:

   ```bash
   sudo tail -f /var/log/nginx/wazuh-stream.log
   sudo /var/ossec/bin/agent_control -lc
   ```

4. Stop the selected worker during a maintenance test. The agent should
   reconnect through NGINX to another healthy worker after the TCP session
   fails.
5. Restore the worker and confirm cluster health before wider rollout.

## Troubleshooting

| Symptom | Check |
|---|---|
| `unknown directive "stream"` | Install/enable the NGINX stream module |
| Port test succeeds but agent stays disconnected | Manager's TCP/1514 listener, agent key, cluster synchronization, and manager logs |
| Enrollment fails but existing agents work | Master TCP/1515 reachability and enrollment service certificate |
| Agent repeatedly moves workers | NAT changes the observed source address, backends are flapping, or config reloads change the upstream set |
| All agents fail after one worker stops | Only one backend is configured, passive failure threshold has not been reached, or firewall rejects the alternate path |
| Connections close periodically | `proxy_timeout` is too short for persistent agent sessions |

## See also

- [Wazuh load balancer documentation](https://documentation.wazuh.com/current/user-manual/wazuh-server-cluster/load-balancers.html)
- [Agent disconnection troubleshooting](../../troubleshooting/agents/disconnections.md)
- [Certificate and enrollment troubleshooting](../../certificates/troubleshooting.md#agent-connectivity-on-15141515)
- [Ingesting device syslog](../syslog/README.md) - collector architectures, and why syslog senders need one
- [Sizing a Wazuh deployment](../../upgrading/sizing.md) - node counts, including how many load balancers to plan for
