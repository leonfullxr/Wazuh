# 6. Expose agents and the dashboard

Agent traffic and dashboard traffic need different exposure paths. Mixing those
paths is the usual reason a healthy Wazuh install appears broken.

## 6.1 The rule

Ports **1514** (agent events) and **1515** (enrollment) carry the OSSEC
protocol over raw TCP. They require an L4 path. An HTTP Ingress or Application
Load Balancer puts an L7 proxy in front; that proxy tries to parse the agent
stream as HTTP and resets the connection.

Failures are seldom clean. Typical symptoms are partial: agents enroll but
never send data, or they send data but cannot enroll, because 1514 and 1515
took different routes. Background:
[load-balancing-and-ingress.md](../load-balancing-and-ingress.md).

Port **5601** (dashboard) is HTTPS, so an ALB is the right fit.

| Traffic | Port | Load balancer |
|---------|------|--------------|
| Agent events | 1514 | NLB, to the workers |
| Agent enrollment | 1515 | NLB, to the master |
| Wazuh API | 55000 | NLB, to the master |
| Dashboard | 5601 | ALB via Ingress |
| Indexer | 9200 | none, ClusterIP only |

## 6.2 The NLBs

The overlay defines two internal NLBs:
[`svc-wazuh.yaml`](manifests/overlay/svc-wazuh.yaml) for enrollment and the API,
[`svc-wazuh-workers.yaml`](manifests/overlay/svc-wazuh-workers.yaml) for events.

```bash
kubectl -n wazuh get svc wazuh wazuh-workers
```

Three annotations matter:

**`aws-load-balancer-scheme: internal`.** Agents reach this via VPC peering,
Transit Gateway or VPN, not the public internet. If you truly need
internet-facing agent ingestion, set `internet-facing` on purpose and add a
`loadBalancerSourceRanges` allowlist on the service. Do not depend on the
legacy `aws-load-balancer-internal` annotation: despite the name it took a
CIDR, and `0.0.0.0/0` meant internet-facing. Upstream sets exactly that on the
workers service; the overlay removes it.

**`cross-zone-load-balancing-enabled: true`.** Without this, an NLB node only
forwards to targets in its own AZ. The master lives in one AZ only, so an agent
that resolves the NLB to a node in another zone gets no target. Cross-zone
forwarding incurs inter-AZ data transfer (around $0.01/GB each way today), but
without it enrollment works from some subnets and fails from others.

**`externalTrafficPolicy: Local`.** Keeps the agent source IP, which matters
for `<use_source_ip>` in auth config or for real addresses in alerts. Only
nodes that run the pod accept traffic under this policy, which is why
cross-zone must stay enabled.

## 6.3 Agent-side failover

The NLB is not the only place that should know about both managers. List both
on the agent so it can fail over when one path is down:

```xml
<client>
  <server>
    <address>wazuh-workers.internal.example.com</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
  <server>
    <address>wazuh.internal.example.com</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
</client>
```

Agents walk the list in order and move on when a server fails. Putting the
master second is deliberate: both `master.conf` and `worker.conf` in upstream
share the same `<remote>` block, so the master accepts agent events and can
take load if every worker is down.

Enrollment always targets the master service; `authd` runs only there:

```xml
<enrollment>
  <enabled>yes</enabled>
  <manager_address>wazuh.internal.example.com</manager_address>
  <port>1515</port>
  <authorization_pass_path>/var/ossec/etc/authd.pass</authorization_pass_path>
</enrollment>
```

Use DNS names, not NLB IPs. NLB addresses can change; hardcoded IPs mean
touching the whole agent fleet again.

## 6.4 The dashboard ALB

[`ingress-dashboard.yaml`](manifests/overlay/ingress-dashboard.yaml) creates it.
Set hostname and ACM certificate ARN before apply.

```bash
kubectl -n wazuh get ingress wazuh-dashboard
kubectl -n wazuh describe ingress wazuh-dashboard | tail -20
```

`backend-protocol: HTTPS` is required because the dashboard serves TLS on 5601.
Without it the ALB sends plaintext to an HTTPS listener and every request
fails. The ALB does not verify the dashboard certificate; that is expected. It
terminates client TLS with your ACM cert and re-encrypts toward the pod.

`success-codes: "200,302,401"` matters if a health check ever targets the Wazuh
API instead of the dashboard. An unauthenticated API call correctly returns
401. The AWS Load Balancer Controller injects a pod readiness gate into the
namespace; treating 401 as failure means the gate never opens and the workload
never becomes Ready. That looks like a broken deployment and is actually a load
balancer misconfiguration. To disable readiness-gate injection:

```bash
kubectl label namespace wazuh elbv2.k8s.aws/pod-readiness-gate-inject=disabled
```

Point DNS at the ALB with a Route 53 alias, or run ExternalDNS.

## 6.5 Verify end to end

From inside the VPC:

```bash
# Enrollment and events reachable, and speaking TLS rather than HTTP
nc -zv wazuh.internal.example.com 1515
nc -zv wazuh-workers.internal.example.com 1514
openssl s_client -connect wazuh.internal.example.com:1515 </dev/null 2>&1 | head -5

# The API answers, 401 unauthenticated is the correct response
curl -sk -o /dev/null -w '%{http_code}\n' https://wazuh.internal.example.com:55000/

# Dashboard
curl -sk -o /dev/null -w '%{http_code}\n' https://wazuh.internal.example.com/
```

Then enroll one real agent and confirm both halves work. That is the check that
catches a 1514/1515 path split:

```bash
# On the agent host
/var/ossec/bin/agent-auth -m wazuh.internal.example.com
/var/ossec/bin/wazuh-control restart

# On the master: agent present AND active, not just present
kubectl -n wazuh exec wazuh-manager-master-0 -- /var/ossec/bin/agent_control -l
```

If `agent_control -l` shows `Never connected`, enrollment on 1515 succeeded and
1514 failed afterward. That is the path mismatch: one of the two ports is not
on a pure L4 path.

Next: [7. Failure drills](07-failure-drills.md).
