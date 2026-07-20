# Agent connections through an AWS load balancer (NLB / ALB)

Fronting the Wazuh manager with an AWS load balancer for agent enrollment (1515) and events (1514) has two recurring failure modes: a **TLS/plaintext mismatch** (`wrong version number`), and **uneven or failed distribution across Availability Zones**. This applies to any manager backend - an EC2 all-in-one, an EC2 cluster, or an EKS deployment behind an NLB.

## Table of Contents

- [Use TCP listeners, not TLS](#use-tcp-listeners-not-tls)
- [Balance evenly across Availability Zones](#balance-evenly-across-availability-zones)
- [Is the agent even using the load balancer?](#is-the-agent-even-using-the-load-balancer)
- [Stickiness](#stickiness)
- [Related](#related)

## Use TCP listeners, not TLS

The signature, in the manager log, when an agent connects through the LB:

```text
wazuh-authd: ERROR: SSL handshake failed for socket=9: error:0A00010B:SSL routines::wrong version number
```

`wrong version number` is OpenSSL for *"I expected a TLS ClientHello but the bytes I got are not one."* It is almost always a **TLS-versus-plaintext mismatch**, not a cipher or TLS-version problem - so aligning cipher suites, forcing FIPS policies, or matching TLS 1.2/1.3 on both sides will **not** fix it (all of those were tried, fruitlessly, in the field case this is distilled from).

It happens because the LB **terminates TLS** on its listener and then hands traffic to the manager in a way `authd`/`remoted` do not expect. The fix comes from how Wazuh's two agent ports actually work:

| Port | What it speaks | Who terminates it |
|---|---|---|
| **1515** (enrollment) | **TLS** | **`authd` itself** is the TLS server (default cert `etc/sslmanager.cert`) |
| **1514** (agent events) | **Not TLS** - Wazuh's own AES message encryption over plain TCP | `remoted` (a TLS listener here is *always* wrong) |

So the manager is already the TLS endpoint on 1515 and does its own encryption on 1514. An LB that terminates and re-originates TLS just gets in the way.

**Fix: use `TCP` listeners and `TCP` target groups (passthrough) for both 1514 and 1515.** Let the manager terminate its own TLS on 1515 and handle its own encryption on 1514; the NLB only forwards bytes.

- Do **not** set the listener or target group to `TLS`. A `TLS` target group makes the NLB open a *second* handshake to `authd`, which it is not set up to answer that way → `wrong version number`.
- **ACM certificates cannot be exported**, so you cannot copy the LB's ACM cert onto the manager to satisfy a second handshake even if you wanted to - another reason to pass through and let the manager use its own certificate.
- **Health checks:** a TLS or HTTP(S) health check against 1515 spams `authd` with handshake errors (hundreds of failed lines/minute). Use a plain **TCP** health check on 1514/1515, or a separate health-check port.

> If a policy genuinely requires TLS terminated at the LB, an NLB alone cannot do it for these ports - you would need a TLS-terminating proxy that then speaks Wazuh's protocol to the manager. For almost everyone, TCP passthrough is the correct and simplest answer.

If you *do* need to customise the manager's own enrollment TLS (not the LB), the `<auth>` block options are `<ssl_manager_cert>`, `<ssl_manager_key>`, `<ssl_verify_host>`, and `<ciphers>` - but the default self-signed setup works fine behind a passthrough NLB.

## Balance evenly across Availability Zones

Symptom: with a multi-node manager cluster behind an NLB, agents pile onto the nodes in one Availability Zone while nodes in other AZs get few or zero connections - and some agents fail to connect at all.

An **AWS NLB is zonal**: it has one IP per attached subnet/AZ, and with **cross-zone load balancing disabled** (the NLB default), each NLB IP only forwards to targets **in its own AZ**. The agent resolves the NLB hostname to the list of per-AZ IPs and pins to one - NLB uses a flow hash (protocol + source/dest IP/port + TCP sequence), not round-robin, and DNS often returns the IPs in a stable order, so an agent keeps landing in the same zone. Consequences:

- An AZ with two manager nodes gets ~2× the load of an AZ with one.
- An AZ with **no** manager (an empty subnet still attached to the NLB) → agents that resolve to that IP get **failed connections**.
- Enrollment (1515) is **master-only**; if DNS hands out an AZ IP whose zone has no master, registration fails there.

Fixes, in order of preference:

1. **Enable cross-zone load balancing** on the NLB. Every NLB IP can then reach targets in any AZ, so distribution evens out and empty-zone dead ends disappear. Cleanest fix. (Note: cross-zone traffic incurs inter-AZ data-transfer charges on NLB.)
2. **Do not attach empty AZs/subnets** to the NLB - every attached subnet must contain a healthy target, or its IP produces failed connections.
3. **Separate registration from reporting** - a dedicated NLB/DNS for 1515 → master and another for 1514 → all nodes, so registration IPs never point at a zone without a master.

Also make sure agents can **fail over** between manager addresses (list multiple `<server>` entries, or a resolvable LB name) so one unreachable IP does not strand them, and keep agents current - very old agents (pre-4.x) had a bug where an initially-unreachable hostname stranded the agent instead of retrying the next IP.

## Is the agent even using the load balancer?

An agent showing up on an unexpected node is often reporting **directly** to that node's IP, bypassing the LB entirely. Confirm before blaming the balancer:

```bash
# On the master: which agents report to a given node
/var/ossec/bin/cluster_control -a | grep <NODE_NAME>

# Check an agent's configured server address through the API
curl -k -u <API_USER>:<API_PASSWORD> \
  "https://<MANAGER>:55000/agents/<AGENT_ID>/config/agent/client"
# → "server":[{"address":"..."}]  should be the LB name/IP, not a node IP
```

Point every agent's `<server><address>` at the load balancer, never at an individual node.

## Stickiness

Enable target-group stickiness on the NLB so an agent's connection stays pinned to one backend for its lifetime, avoiding mid-session rebalancing that can disrupt long-lived agent sessions.

## Related

- [Agent disconnections](disconnections.md) - general connectivity triage, MTU black holes, and cloud-VPC/private-endpoint paths
- [Enrollment and key conflicts](enrollment-key-conflicts.md) - the return-path failures that also surface as enrollment resets
- [Certificate troubleshooting - agent TLS on 1514/1515](../../certificates/troubleshooting.md#agent-connectivity-on-15141515)
- [Load balancing, ingress & proxies on Kubernetes](../../containerization/kubernetes/load-balancing-and-ingress.md) - the same L4-vs-L7 rules for EKS/ingress backends, plus the ALB health-check `401` gotcha
- [NGINX stream load balancer](../../integrations/nginx/README.md) - an L4 alternative to an AWS NLB
