# Load balancing, ingress, and proxies for Wazuh on Kubernetes

**Applies to:** Wazuh 4.x on Kubernetes / OpenShift · ingress-nginx · AWS ALB/NLB · HAProxy

[Back to Kubernetes README](./README.md)

Exposing a Wazuh cluster on Kubernetes is easy to get wrong because **agent traffic is not HTTP**. Enrollment (1515) and agent events (1514) are raw TCP; the dashboard (443) and API (55000) are HTTP(S). Sending the TCP ports through an HTTP (Layer 7) ingress is the most common cause of "the agent gets a key but can't send logs" and "connection reset by peer."

## Table of Contents

- [Pick the right exposure method](#pick-the-right-exposure-method)
- [Agent traffic is raw TCP, not HTTP](#agent-traffic-is-raw-tcp-not-http)
- [Exposing agent TCP through ingress-nginx](#exposing-agent-tcp-through-ingress-nginx)
- [PROXY protocol must match end to end](#proxy-protocol-must-match-end-to-end)
- [Service types: ClusterIP, NodePort, LoadBalancer](#service-types-clusterip-nodeport-loadbalancer)
- [ALB Ingress: manager StatefulSet never becomes Ready](#alb-ingress-manager-statefulset-never-becomes-ready)
- [Dynamic HAProxy load balancing with the Wazuh helper](#dynamic-haproxy-load-balancing-with-the-wazuh-helper)
- [Verifying the path](#verifying-the-path)
- [Related](#related)

## Pick the right exposure method

| Method | Good for | Notes |
|---|---|---|
| `Service type: LoadBalancer` (per component) | The simplest external exposure; one cloud L4 LB per service | An **L4/NLB** (not an ALB) - agent ports are TCP, not HTTP |
| ingress-nginx **TCP services** ConfigMap | Sharing one ingress IP across 1514/1515 and other tenants | Requires the L4 `tcp-services` config, **not** a normal HTTP `Ingress` resource |
| `Service type: NodePort` | Labs, or when a external LB fronts the nodes | Exposes a high port per service on every node |
| HAProxy + [Wazuh helper](#dynamic-haproxy-load-balancing-with-the-wazuh-helper) | Auto-balancing agents across worker nodes with membership auto-sync | Most moving parts; best for larger clusters |
| An **HTTP `Ingress`** / **ALB** | The **dashboard (443)** and **API (55000)** only | Never for 1514/1515 - see below |

## Agent traffic is raw TCP, not HTTP

A standard `Ingress` resource (and an AWS **ALB**) is a Layer 7 HTTP proxy. Point 1514/1515 at it and it tries to parse a TLS/OSSEC byte stream as HTTP, fails, and resets the connection. Typical signatures:

```text
# agent
wazuh-agent: ERROR: SSL error (1). Connection refused by the manager. Maybe the port specified is incorrect.
wazuh-agentd: INFO: Trying to connect to server (...:1514/tcp).
wazuh-agentd: INFO: Closing connection to server (...:1514/tcp).

# ingress-nginx
recv() failed (104: Connection reset by peer) while proxying and reading from upstream on TCP stream
```

Classic half-working state: the agent **enrolls** (1515 reached the manager) but **cannot send logs** (1514 is being reset), or the reverse, because one port took an L4 path and the other took L7. Enrollment and events must **both** traverse a plain TCP (Layer 4) path.

## Exposing agent TCP through ingress-nginx

ingress-nginx forwards raw TCP through its **TCP services** ConfigMap (separate from `Ingress` objects), not through HTTP routing.

1. Map the ports to the backend Services in `tcp-services` (namespace `ingress-nginx`):

    ```yaml
    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: tcp-services
      namespace: ingress-nginx
    data:
      "1515": "<namespace>/wazuh:1515"          # enrollment -> master service
      "1514": "<namespace>/wazuh-workers:1514"   # events -> workers service
    ```

2. Confirm the controller **starts with** that ConfigMap and exposes the ports on its own Service:

    ```bash
    kubectl -n ingress-nginx describe deploy ingress-nginx-controller | grep -- --tcp-services-configmap
    kubectl -n ingress-nginx get configmap tcp-services -o yaml
    ```

    If the flag is missing, add `--tcp-services-configmap=ingress-nginx/tcp-services` to the controller args (or set `tcp: {}` entries via its Helm values) and ensure `1514`/`1515` appear in the controller Service.

3. Backend Services can stay `ClusterIP`; the controller reaches them inside the cluster. Point agents at the **ingress** address on 1514/1515, not at the pods.

## PROXY protocol must match end to end

PROXY protocol prepends the original client IP to a TCP stream. It is all-or-nothing per hop: **if any hop adds a PROXY header, every downstream hop, including the final receiver, must expect it**, or the receiver sees garbage bytes and resets the connection.

- Wazuh's agent listeners (`remoted` on 1514/1515) do **not** parse PROXY protocol. The reliable pattern is **straight TCP passthrough with no PROXY header** anywhere on the path.
- If an upstream cloud load balancer injects PROXY (some do by default), **strip or terminate it before Wazuh**, for example with an intermediate proxy that consumes the PROXY header and forwards plain TCP.
- Toggling `:PROXY` on an ingress-nginx `tcp-services` entry (`"<namespace>/wazuh-workers:1514:PROXY"`) only changes what the ingress *emits*. If flipping that flag starts or stops the path working, you have a **PROXY mismatch** somewhere. Align every hop to the same choice instead of leaving it as a lucky guess.

## Service types: ClusterIP, NodePort, LoadBalancer

- **`ClusterIP`** is reachable only inside the cluster. Use it for manager/worker Services **when an ingress or proxy fronts them**: the proxy is in-cluster and reaches the ClusterIP; external agents hit the proxy. Do not use it if agents must reach the Service *directly* from outside.
- **`LoadBalancer`** provisions an external L4 LB. On AWS, force a network (TCP) LB and, if it should be private, mark it internal:

    ```yaml
    metadata:
      annotations:
        service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
        service.beta.kubernetes.io/aws-load-balancer-backend-protocol: "tcp"
        # internal-only LB:
        service.beta.kubernetes.io/aws-load-balancer-internal: "true"
    ```

    (Older `aws-load-balancer-internal: 0.0.0.0/0` means internet-facing, not internal.)
- **`NodePort`** exposes a high port on every node. Use it when an external LB or the ingress controller fronts the nodes.

## ALB Ingress: manager StatefulSet never becomes Ready

Putting an **AWS ALB Ingress** in front of the manager can leave the manager StatefulSet stuck `not Ready` even when the pod itself is healthy. Two things stack:

1. The AWS Load Balancer Controller injects a **pod readiness gate** into the namespace, so a pod is only `Ready` once the ALB target-group health check passes.
2. The ALB health-checks the Wazuh **API (55000)**, which correctly returns **HTTP 401** to an unauthenticated probe. The ALB treats 401 as unhealthy, the gate never opens, and the STS never becomes Ready.

Tell the ALB that 401 is healthy (and to probe over HTTPS):

```yaml
metadata:
  annotations:
    alb.ingress.kubernetes.io/ssl-redirect: "443"
    alb.ingress.kubernetes.io/backend-protocol: HTTPS
    alb.ingress.kubernetes.io/healthcheck-protocol: HTTPS
    alb.ingress.kubernetes.io/success-codes: "401"
```

Or disable readiness-gate injection so the pod's own probes decide readiness:

```bash
# per namespace
kubectl label namespace <namespace> elbv2.k8s.aws/pod-readiness-gate-inject=disabled
# or on the controller: --enable-pod-readiness-gate-inject=false
```

> This ALB behaviour applies to the **API/dashboard** (HTTP). It does not make an ALB suitable for agent 1514/1515 traffic. Keep those on an L4 path.

## Dynamic HAProxy load balancing with the Wazuh helper

On larger clusters, Wazuh's HAProxy helper, a thread inside `wazuh-clusterd`,
keeps an HAProxy backend in step with cluster membership. When workers join
or leave, it calls HAProxy's Data Plane API to rewrite the backend server
list and reload. Agents connect to one stable address and are balanced with
`leastconn`, and nobody edits `haproxy.cfg` by hand.

The deployment shape is a HAProxy Deployment with the Data Plane API as a
sidecar in the same pod, plus a ClusterIP or `hostPort` so the master can
reach the API on its default port. Match the Data Plane API release to your
HAProxy branch, because the API rewrites `haproxy.cfg` for one HAProxy minor
version, and hold the API credentials in a Kubernetes Secret that the helper
configuration mirrors.

The full procedure, including the requirement that `haproxy.cfg` carries no
frontend on 1514, is in
[HAProxy and the Data Plane API as the agent load balancer](./haproxy-dataplane.md).
Reference: [Wazuh load balancer documentation](https://documentation.wazuh.com/current/user-manual/wazuh-server-cluster/load-balancers.html).

## Verifying the path

Work from the agent inward. A passing TCP connect does **not** prove the L7-vs-L4 path is correct:

```bash
# 1. From the agent: can it reach the exposed address on both ports?
(New-Object Net.Sockets.TcpClient).Connect("<INGRESS_OR_LB>", 1514)   # Windows
nc -vz <INGRESS_OR_LB> 1514 1515                                       # Linux/macOS

# 2. On the manager: are enrollment requests actually arriving?
tcpdump -n -v -i any dst port 1515

# 3. On the manager: is remoted discarding messages?
grep -A3 "Discarded" /var/ossec/var/run/wazuh-remoted.state
```

If step 1 connects but enrollment or events still fail with resets, traffic is going through an HTTP path or a PROXY mismatch. Revisit [raw TCP](#agent-traffic-is-raw-tcp-not-http) and [PROXY protocol](#proxy-protocol-must-match-end-to-end). For cluster-internal comms breaking after a namespace change, see [cluster debugging](./cluster-debugging.md#changing-the-namespace-breaks-cluster-dns).

## Related

- [Wazuh on Amazon EKS - Ingress and TLS](./eks.md#ingress-and-tls) - dashboard ingress and NLB TLS termination
- [Cluster debugging](./cluster-debugging.md) - namespace-DNS breakage and OOMKilled cluster restarts
- [OpenShift - SCCs, Routes, and Helm/GitOps](./openshift.md) - OpenShift ingress (Route) and deployment method
- [NGINX stream load balancer (non-Kubernetes)](../../integrations/nginx/README.md) - the L4 stream equivalent outside Kubernetes
- [Agents behind an AWS load balancer](../../troubleshooting/agents/aws-load-balancer.md) - TCP-vs-TLS listeners (`wrong version number`) and cross-zone balancing; applies to EKS NLB backends too
- [Distributing syslog across cluster workers](../../integrations/syslog/README.md#load-balancing-syslog-across-cluster-workers)
