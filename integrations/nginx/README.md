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
   NGINX Open Source uses passive failure detection here; it does not know
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
