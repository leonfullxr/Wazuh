# HAProxy and the Data Plane API as the agent load balancer

**Applies to:** Wazuh 4.x on Kubernetes, HAProxy, and the HAProxy Data Plane API

[Back to Kubernetes README](./README.md)

Give the agents one stable address and let HAProxy spread new connections
across the manager nodes with `leastconn`. The Wazuh HAProxy helper keeps the
backend server list in step with cluster membership by calling the Data Plane
API. Nodes join and leave, HAProxy follows, and nobody edits `haproxy.cfg` or
restarts the balancer.

## Table of Contents

- [What each part does](#what-each-part-does)
- [Three rules the helper depends on](#three-rules-the-helper-depends-on)
- [Prerequisites](#prerequisites)
- [Deployment procedure](#deployment-procedure)
- [Enable the helper on the master](#enable-the-helper-on-the-master)
- [Validation](#validation)
- [Exporting the setup for an audit](#exporting-the-setup-for-an-audit)
- [Troubleshooting](#troubleshooting)
- [Related](#related)

## What each part does

| Part | Where it runs | What it does |
|---|---|---|
| HAProxy | Deployment in its own namespace | Accepts agent TCP on 1514 and 1515 and forwards each new connection to the node with the fewest open connections |
| Data Plane API | Sidecar container in the same pod | REST control plane over HAProxy. Reads and rewrites `haproxy.cfg`, then reloads HAProxy |
| HAProxy helper | A thread inside `wazuh-clusterd`, on the master node only | Watches cluster membership and calls the Data Plane API to add and remove backend servers |

The path in words: an agent connects to HAProxy. HAProxy forwards the
connection to a manager node. When a node joins or leaves the cluster, the
helper notices, calls the Data Plane API, and the API rewrites the backend
server list and reloads HAProxy.

## Three rules the helper depends on

These come from the Wazuh reference for the helper. Breaking one of them is
the usual reason the backend never moves.

- **No frontend on port 1514.** The helper creates the frontend that binds
  1514 together with the backend. A hand-written frontend on that port
  collides with it and the helper stops operating correctly. Write the
  enrollment frontend on 1515 by hand and leave 1514 out of `haproxy.cfg`
  entirely.
- **The backend name is the helper's to choose.** `<haproxy_backend>` names
  the backend the helper creates and maintains, and its default is
  `wazuh_reporting`. Set it in `ossec.conf`, and if you also write that
  backend by hand, use the same name in `haproxy.cfg`. The helper adds and
  removes servers in that backend as membership changes.
- **The backend balances with `leastconn`.** The helper is built for the
  least-connections algorithm, and it rebalances when the imbalance passes
  the tolerance you set.

Enrollment on 1515 is not covered by the helper. Its server list is static,
so add or remove nodes there yourself when the cluster changes shape.

## Prerequisites

- A Wazuh server cluster with a master and at least one worker. The helper
  runs on the master only.
- `kubectl` access and a namespace for the balancer.
- The port each manager node listens on for agent events. The default is
  1514 on every node. If a deployment changed it, the backend has to match
  what each node really listens on, so check the manager's `<remote>` section
  or the listening sockets before you write the backend.
- A route from the master container to the Data Plane API address and port.
  The helper makes outbound HTTP calls, so the manager has to reach it.
- HAProxy on an LTS branch, and the Data Plane API from a release of the
  same branch. The API parses and rewrites `haproxy.cfg` for one HAProxy
  minor version, so a mismatched pair is the usual cause of a reload that
  fails.
- Ports: 1514 for agent events, 1515 for enrollment, 8404 for HAProxy stats
  (internal), and the API port, 5555 by default.

## Deployment procedure

The procedure below assumes namespace `wazuh` and deployment name `agent-lb`.
Rename to taste.

### Step 1. Create the namespace

```bash
kubectl create namespace wazuh
```

### Step 2. HAProxy configuration ConfigMap

The ConfigMap holds `haproxy.cfg`. Mount a writable copy: the Data Plane API
rewrites the file in place, and a ConfigMap mount is read-only, so an init
container copies it into a shared `emptyDir` at pod start.

```haproxy
global
    log stdout format raw local0 info

defaults
    mode tcp
    log global
    option tcplog
    timeout connect 10s
    timeout client 1m
    timeout server 1m

# Enrollment: a hand-written frontend the helper does not manage.
frontend wazuh_register
    mode tcp
    bind :1515
    default_backend wazuh_register

backend wazuh_register
    mode tcp
    balance leastconn
    server master_node <MASTER_NODE_IP>:1515 check
    server worker_01 <WORKER_NODE_IP>:1515 check

# Stats, for probes and inspection from inside the pod.
listen haproxy_stats
    mode http
    bind :8404
    stats enable
    stats uri /stats

# The 1514 frontend and backend come from the helper,
# which takes the name from <haproxy_backend>.
```

```bash
kubectl -n wazuh create configmap agent-lb-haproxy \
  --from-file=haproxy.cfg \
  --dry-run=client -o yaml | kubectl apply -f -
```

### Step 3. Data Plane configuration ConfigMap

`dataplaneapi.yml` tells the API where `haproxy.cfg` lives, how to reload
HAProxy, and who may call it:

```yaml
dataplaneapi:
  host: 0.0.0.0
  port: 5555
  transaction:
    transaction_dir: /tmp/haproxy
  user:
    - name: <DATAPLANE_USER>
      insecure: true
      password: <DATAPLANE_PASSWORD>
haproxy:
  config_file: /etc/haproxy/haproxy.cfg
  # /usr/sbin/haproxy for a package install, /usr/local/sbin/haproxy in the
  # official container image.
  haproxy_bin: /usr/sbin/haproxy
  reload:
    reload_delay: 5
    # A container has no init system, so `service haproxy reload` fails here.
    # Point this at a script the container can run itself, and make the
    # script executable in the init container.
    reload_cmd: /opt/dataplane/reload.sh
    restart_cmd: /opt/dataplane/reload.sh --restart
```

`insecure: true` stores the password in clear text inside this file. Keep the
file in a Secret, or store a hash instead, before the setup leaves a lab.

```bash
kubectl -n wazuh create configmap agent-lb-dataplane \
  --from-file=dataplaneapi.yml \
  --dry-run=client -o yaml | kubectl apply -f -
```

### Step 4. Create the credentials Secret

```bash
kubectl -n wazuh create secret generic agent-lb-creds \
  --from-literal=username=<DATAPLANE_USER> \
  --from-literal=password=<DATAPLANE_PASSWORD> \
  --dry-run=client -o yaml | kubectl apply -f -
```

The same pair appears in three places: `dataplaneapi.yml`, the
`<haproxy_user>` and `<haproxy_password>` tags in `ossec.conf`, and every
`curl` you run against the API. Change them together.

### Step 5. Deploy HAProxy with the API sidecar

One pod, two containers, and init containers that prepare the writable files:

- Copy `haproxy.cfg` from its ConfigMap into the shared `emptyDir`.
- Copy `dataplaneapi.yml` the same way.
- Fetch the Data Plane API binary for the same branch as your HAProxy, or
  pull the matching container image. The release archives follow this
  pattern:

```bash
curl -sL https://github.com/haproxytech/dataplaneapi/releases/download/v<VER>/dataplaneapi_<VER>_linux_x86_64.tar.gz \
  | tar xz
```

- Mark the reload script executable. A reload that fails on permissions
  leaves HAProxy running the previous configuration while the API reports
  success on the write.

```bash
kubectl apply -f agent-lb-deploy.yaml
kubectl -n wazuh rollout status deploy/agent-lb
kubectl -n wazuh get pods -o wide
```

Run one replica. The helper drives a single address, and it logs that it
ensures only one HAProxy process before it starts. A second replica would
hold its own copy of the configuration and never follow cluster membership.

### Step 6. Expose the balancer and the API

Agents need a stable address of their own: a Service on 1514 and 1515, of
type LoadBalancer when they sit outside the cluster and ClusterIP when they
do not. The API keeps its default port, 5555, in both variants below.

```bash
kubectl apply -f agent-lb-svc.yaml
kubectl apply -f agent-lb-api-svc.yaml
kubectl -n wazuh get svc
```

Choose the exposure for the API that matches where the manager runs:

- **Manager in the cluster:** the ClusterIP Service on 5555, addressed by
  its DNS name.
- **Manager outside the cluster:** a `hostPort` of 5555 on the Deployment,
  so the helper reaches the API at `<NODE_IP>:5555`. A hostPort holds one
  pod per node, which matches the single-replica rule above.

Either way the API answers only to the credentials you set in Step 4.

## Enable the helper on the master

Add the helper inside the `<cluster>` block of the master's
`/var/ossec/etc/ossec.conf`, then restart the manager:

```xml
<haproxy_helper>
  <haproxy_disabled>no</haproxy_disabled>
  <haproxy_address><API_ADDRESS></haproxy_address>
  <haproxy_port>5555</haproxy_port>
  <haproxy_protocol>http</haproxy_protocol>
  <haproxy_user><DATAPLANE_USER></haproxy_user>
  <haproxy_password><DATAPLANE_PASSWORD></haproxy_password>
  <haproxy_backend>wazuh_reporting</haproxy_backend>
</haproxy_helper>
```

`<haproxy_address>` accepts a DNS name, so an in-cluster service name goes
there when the manager shares the cluster with the balancer.

Useful knobs, all inside the same block:

| Option | Effect | Default |
|---|---|---|
| `frequency` | Seconds between checks of cluster membership | 60 |
| `imbalance_tolerance` | Share of agents one node may hold above the average before rebalancing | 0.1 |
| `agent_chunk_size` | Agents moved per rebalance operation | 100 |
| `remove_disconnected_node_after` | Seconds before a disconnected node is dropped from the backend | 10 |

Restart the manager: `/var/ossec/bin/wazuh-control restart` on a host
install, `docker restart <MANAGER_CONTAINER>` for a container, or
`kubectl rollout restart deployment/<MANAGER_DEPLOYMENT>` when it runs as a
workload.

## Validation

Work outward: pod, sockets, API, then helper.

```bash
# Pod health
kubectl -n wazuh get pods -o wide
kubectl -n wazuh describe pod -l app=agent-lb

# Listening sockets inside the HAProxy container
POD=$(kubectl -n wazuh get pod -l app=agent-lb -o jsonpath='{.items[0].metadata.name}')
kubectl -n wazuh exec -it "$POD" -c haproxy -- ss -lntp | grep -E '1514|1515|8404'
```

Read that socket list carefully. Before the helper has run once, only 1515
and 8404 are listening, because the frontend on 1514 does not exist yet. If
the image has no `ss`, read `/proc/net/tcp` instead.

```bash
# Data Plane API, from inside the manager container
curl -s -u <DATAPLANE_USER>:<DATAPLANE_PASSWORD> \
  http://<API_ADDRESS>:5555/v2/info

curl -s -u <DATAPLANE_USER>:<DATAPLANE_PASSWORD> \
  http://<API_ADDRESS>:5555/v2/services/haproxy/configuration/backends | jq

curl -s -u <DATAPLANE_USER>:<DATAPLANE_PASSWORD> \
  "http://<API_ADDRESS>:5555/v2/services/haproxy/configuration/servers?backend=wazuh_reporting&parent_type=backend" | jq
```

`/v2/info` returns the API version and build date. The servers query shows
the backend as the helper has built it.

```bash
# Helper activity, on the master
grep HAPHelper /var/ossec/logs/cluster.log | tail -50
```

A healthy start prints `Proxy was initialized`, `Starting HAProxy Helper`,
then `Obtained proxy backends`, `Obtained proxy frontends`, and `Obtained
proxy servers`.

The real test is membership. Stop or remove a worker, wait for the next
`frequency` interval, and watch its entry disappear from the servers query.
Add it back and watch it return.

## Exporting the setup for an audit

```bash
kubectl -n wazuh get cm agent-lb-haproxy -o yaml > export-agent-lb-cm.yaml
kubectl -n wazuh get cm agent-lb-dataplane -o yaml > export-agent-lb-dataplane-cm.yaml
kubectl -n wazuh get deploy agent-lb -o yaml > export-agent-lb-deploy.yaml
kubectl -n wazuh get svc agent-lb -o yaml > export-agent-lb-svc.yaml
kubectl -n wazuh get svc agent-lb-api -o yaml > export-agent-lb-api-svc.yaml
```

The Secret stays out of this set. Export it only into the secret store that
holds the original.

## Troubleshooting

| Symptom | Likely cause | What to check |
|---|---|---|
| No `HAPHelper` lines in `cluster.log` | Helper disabled, or the API address is unreachable from the master | `<haproxy_disabled>`, then `curl` the API from inside the manager container |
| API answers `401 Unauthorized` | Credentials differ between `dataplaneapi.yml` and `ossec.conf` | Compare `<haproxy_user>` and `<haproxy_password>` with the `user` entry in the YAML |
| Connection refused on 5555 | API bound to `127.0.0.1`, or the exposure does not reach the helper | `host: 0.0.0.0` in `dataplaneapi.yml`, then the Service or `hostPort` against 5555 |
| Backend list never follows membership | Backend name in HAProxy does not match `<haproxy_backend>` | Name both the same, and keep `balance leastconn` |
| Helper writes the config, HAProxy keeps the old servers | Reload command fails inside the container | `reload_cmd` must run without an init system, and the script must be executable |
| 1514 not listening | The helper has not created the frontend yet, or a hand-written 1514 frontend broke it | Helper log lines first, then remove any frontend bound to 1514 |
| Agents connect to HAProxy and no events arrive | Backend server port does not match what each node listens on | The nodes' `<remote>` port against the `server` lines |

## Related

- [Load balancing, ingress & proxies](./load-balancing-and-ingress.md) - exposure methods for agent TCP, and where this pattern sits
- [Cluster debugging](./cluster-debugging.md) - pod and DNS diagnostics when the balancer itself is healthy
- [Highly available Wazuh on EKS](./eks-ha/) - what the single master does and does not survive
- [Agents behind an AWS load balancer](../../troubleshooting/agents/aws-load-balancer.md) - the same agent path in front of an NLB or ALB
- [Wazuh documentation: load balancers](https://documentation.wazuh.com/current/user-manual/wazuh-server-cluster/load-balancers.html) - the reference helper options and the stock `haproxy.cfg`
