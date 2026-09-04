# Wazuh Helm chart

Installs a Wazuh manager cluster together with the indexer and dashboard on
Kubernetes, and can optionally run an agent DaemonSet. The chart is a Helm
translation of the
[official wazuh/wazuh-kubernetes](https://github.com/wazuh/wazuh-kubernetes)
Kustomize layout; operational fixes already covered under
[containerization/kubernetes/](../..) are baked in as the defaults.

Wazuh does **not** publish an official Helm chart. Upstream only ships
Kustomize overlays, and the long-standing ask for a chart
([wazuh-kubernetes#138](https://github.com/wazuh/wazuh-kubernetes/issues/138))
has been open since 2020 with no roadmap commitment. Treat this chart like any
other community artifact: you own it, Wazuh does not support it. Review it
before you install.

Aligned with Wazuh 4.14.x. Wazuh 5.x reshapes the upstream deployment heavily
and is not covered here yet.

## Contents

- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Scenarios](#scenarios)
- [Certificates](#certificates)
- [Credentials](#credentials)
- [Exposing agents](#exposing-agents)
- [Sizing](#sizing)
- [Platform notes](#platform-notes)
- [Differences from the upstream deployment](#differences-from-the-upstream-deployment)
- [What this chart does not do](#what-this-chart-does-not-do)
- [Upgrading](#upgrading)
- [Validation](#validation)
- [Troubleshooting](#troubleshooting)

## Requirements

- Kubernetes 1.23 or later, Helm 3.8 or later.
- A default StorageClass, or one named in `global.storageClass`. Volumes are
  `ReadWriteOnce`.
- At least two nodes if you keep the default worker anti-affinity, plus enough
  capacity for the [sizing](#sizing) below. On a laptop, start from
  `examples/values-minimal.yaml`.
- `vm.max_map_count` ≥ 262144 on nodes that run the indexer. By default the
  chart raises it via a privileged init container; on OpenShift or any cluster
  that blocks that, set the sysctl at the node and turn the container off.

## Quick start

```bash
kubectl create namespace wazuh
helm install wazuh ./wazuh -n wazuh
```

You get one master, two workers, three indexer nodes and a dashboard, all on
ClusterIP services, with certificates and passwords created by the chart.
Nothing is published outside the cluster on purpose.

Fetch the credentials:

```bash
kubectl -n wazuh get secret wazuh-credentials \
  -o go-template='{{range $k,$v := .data}}{{$k}}={{$v|base64decode}}{{"\n"}}{{end}}'
```

Open the dashboard:

```bash
kubectl -n wazuh port-forward svc/wazuh-dashboard 8443:443
```

The indexer must form its cluster first. Manager and dashboard pods restart
until it answers on 9200; expect a couple of minutes on a clean install.

## Scenarios

| File | For |
|------|-----|
| [`examples/values-minimal.yaml`](examples/values-minimal.yaml) | Single node lab, about 2 vCPU and 3 GiB total. No workers; the master keeps 1514. |
| [`examples/values-eks.yaml`](examples/values-eks.yaml) | EKS with gp3, NLBs for agent traffic, an ALB for the dashboard, zone spreading. |
| [`examples/values-openshift.yaml`](examples/values-openshift.yaml) | OpenShift and OKD: SCC bindings, node-level sysctl, a Route instead of an Ingress. |
| [`examples/values-agent-only.yaml`](examples/values-agent-only.yaml) | Just the agent DaemonSet, reporting to a manager outside this cluster. |
| [`examples/values-existing-certs.yaml`](examples/values-existing-certs.yaml) | Certificates from `wazuh-certs-tool.sh`. |
| [`examples/values-cert-manager.yaml`](examples/values-cert-manager.yaml) | cert-manager issues and rotates the internal certificates. |

Each example file notes its assumptions. Prefer the closest match over starting
from `values.yaml`.

## Certificates

Pick a mode with `certs.mode`.

**`helm`** (default) builds a CA plus four leaf certificates at install time
and, on upgrade, reuses them by looking up the existing Secret so running pods
do not see a rotation. Fine for first installs and clusters without
cert-manager.

One practical catch: Helm can only emit PKCS#1 private keys, while the indexer
loads its key via Netty, which expects PKCS#8 and otherwise fails with
`Neither RSA, DSA nor EC worked`. Wazuh images do not include `openssl`, so in
this mode the chart runs a single init container from
`wazuh/wazuh-certs-generator` solely for that binary, converts the keys, and
serves them from an `emptyDir`. Mirror that image with `certs.pkcs8InitImage`
when the cluster is airgapped. The other modes already yield PKCS#8 and skip
the init container.

**`existing`** mounts Secrets you supply, using the filenames the Wazuh images
expect. See
[`examples/values-existing-certs.yaml`](examples/values-existing-certs.yaml) for
the `wazuh-certs-tool.sh` steps and the `kubectl create secret` commands. Keys
must be PKCS#8; that tool already writes them that way.

**`cert-manager`** creates `Certificate` objects against an Issuer you provide.
cert-manager defaults to PKCS#1; the chart forces `privateKey.encoding: PKCS8`,
and any Certificate you author by hand must do the same.

### Certificate subjects matter

The indexer treats a peer as a cluster node, and a client as admin, by matching
the certificate **subject** against two allowlists in `opensearch.yml`. Both
lists are templated from `certs.subject.adminDn` and `certs.subject.nodesDn`.
Mismatches are the usual reason an indexer will not form a cluster, and the
logs rarely look like a certificate failure.

Chart-generated certificates use a bare CN, so the defaults are `CN=admin` and
`CN=indexer`. Material from `wazuh-certs-tool.sh` uses a full subject; you must
set that explicitly:

```yaml
certs:
  subject:
    adminDn: "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US"
    nodesDn: "CN=indexer,OU=Wazuh,O=Wazuh,L=California,C=US"
```

`admin_dn` uses exact LDAP-name equality and rejects wildcards. `nodes_dn` is a
string match and allows one, so
`CN=*,OU=Wazuh,O=Wazuh,L=California,C=US` covers every indexer node.

Hostname checks use the SAN, never the CN. Put every name clients will actually
use - including external hostnames and load balancer FQDNs - into
`certs.extraDnsNames`.

## Credentials

Empty passwords in `values.yaml` are generated at install and reused on upgrade
via a lookup of the existing Secret, so `helm upgrade` does not rotate them.
They only appear in the Secret; read them out and store them after the first
install. The chart ships neither a default password nor a default cluster key.

To own them yourself, point `credentials.existingSecret` at a Secret that
includes `indexer-username`, `indexer-password`, `dashboard-username`,
`dashboard-password`, `api-username`, `api-password`, `authd.pass` and
`cluster-key`. That path also works with External Secrets Operator or the
Secrets Store CSI driver.

### Rotating the indexer password later

`internal_users.yml` is read only while an empty cluster is bootstrapped.
Afterwards the user store lives in the `.opendistro_security` index, so editing
a password in `values.yaml` and upgrading alone changes nothing. Set
`indexer.security.runSecurityadmin=true` so a post-upgrade Job applies the
change with `securityadmin.sh`.

Two related details. The chart defines only the two users this stack needs,
not the stock OpenSearch demo set whose bcrypt hashes are public. Hashes are
produced by Helm at cost 10, while Wazuh ships cost 12; if that gap matters,
hash offline and feed users through `credentials.existingSecret` plus your own
security config.

## Exposing agents

Ports 1514 (events) and 1515 (enrollment) are raw TCP. Putting them behind an
HTTP Ingress or an AWS ALB makes the L7 proxy treat the agent stream as HTTP
and reset it. The usual symptom is half-broken: agents enroll but never send
data, or the reverse, because the two ports took different paths. **This chart
will not render an Ingress for 1514 or 1515 under any values combination.**

Three exposure options:

**LoadBalancer services**, one for the master (1515 and 55000) and one for
events (1514):

```yaml
service:
  master: { type: LoadBalancer }
  events: { type: LoadBalancer }
```

On AWS use NLBs. Beware the older
`aws-load-balancer-internal: 0.0.0.0/0` annotation: that means internet-facing,
not internal. The current form is `"true"`.

**ingress-nginx**, which publishes raw TCP via a ConfigMap rather than an
Ingress object. With `tcpServices.enabled=true` the chart writes the mapping.
The controller must already run with
`--tcp-services-configmap=ingress-nginx/tcp-services` and expose 1514 and 1515
on its own Service.

**NodePort**, for labs or an external load balancer you operate yourself.

If anything in front of Wazuh speaks PROXY protocol, set
`service.proxyProtocol=true`. That one flag drives both Service annotations and
the ingress-nginx mapping, because `remoted` does not parse a PROXY header and
enabling it on one hop but not the other is how you get agents that enroll and
then go silent.

The dashboard is different. It speaks HTTPS on 5601, so `dashboard.ingress` is
a normal Ingress. On an AWS ALB you also need `success-codes: "401"`, because
the Wazuh API correctly answers an unauthenticated health check with 401 and
the injected pod readiness gate otherwise never opens.

## Sizing

Defaults aim at roughly 50 agents. Upstream manifests give the manager 400m CPU
and 512Mi of memory, which OOMs the master in a two-to-five-minute loop and
takes cluster communication with it, so this chart sets higher defaults on
purpose.

| Component | ~50 agents | ~100 agents |
|-----------|-----------|------------|
| Manager master | 1 vCPU, 2 GiB | 2 vCPU, 4 GiB |
| Manager worker | 1 vCPU, 2 GiB | 2 vCPU, 4 GiB |
| Indexer | 2 vCPU, 4 GiB | 4 vCPU, 8 to 16 GiB |
| Dashboard | 1 vCPU, 1 GiB | 1 vCPU, 2 GiB |

Set `indexer.heapSize` to about half the indexer memory limit. Both `-Xms` and
`-Xmx` come from that one value; a heap that grows only delays the OOMKill.

For high availability use at least three indexer nodes (odd count) and at least
two managers behind a load balancer. See
[upgrading/sizing.md](../../../upgrading/sizing.md) for capacity planning and
[indexer/](../../../indexer/) for shard and retention planning.

### analysisd threads

`manager.analysisdThreads` defaults to 4 and the schema rejects 0. At 0,
analysisd sizes its pools from the visible CPU count - the node's count, not the
cgroup quota. On a large node with a small limit that creates thousands of
threads, starves `wazuh-db`, and surfaces as `Error 2013`, `Error 2017`,
`database is locked on endpoint: /v1/agents/sync`, plus agents active on a
worker but disconnected on the master. Throttle counters stay at zero, so they
will not help; count threads instead. Full write-up in
[agent-info-sync-failures.md](../../agent-info-sync-failures.md).

## Platform notes

Per-platform storage classes, scheduling, and common issues live in the guides next to
this chart. The chart exposes the knobs those guides tell you to change.

- [Amazon EKS](../../eks.md): gp3, zone-aware scheduling, ECR, the ALB 401 gate.
- [Azure AKS](../../aks.md): Azure Disk CSI classes, zone scheduling, Blob snapshot prerequisites.
- [Google GKE](../../gke.md): Persistent Disk CSI, and init container image pull failures that leave pods stuck in Init.
- [OpenShift and OKD](../../openshift.md): SCCs, the s6 UID blocker, `vm.max_map_count` via the Node Tuning Operator.

Two OpenShift failures deserve repeating. The manager and dashboard images run
an s6 init that must write under `/var/run` before dropping privileges, so a
random high UID from `restricted-v2` dies before init with
`unable to mkdir /var/run/s6`. Bind `anyuid` to the per-component
ServiceAccounts instead; the chart creates one SA per component so an SCC can
attach. And `restricted-v2` blocks the privileged init that raises
`vm.max_map_count`, so set `indexer.sysctlInitContainer.enabled=false` and use
a Node Tuning Operator profile.

A values file cannot clear a default map with `{}`. Helm merges it and nothing
changes. Use an explicit `null`:

```yaml
indexer:
  podSecurityContext: null
```

## Differences from the upstream deployment

Every item below is intentional relative to `wazuh/wazuh-kubernetes`, not an
oversight.

- **Internal indexer traffic uses a ClusterIP service.** Upstream points the
  manager, filebeat and dashboard at a LoadBalancer-typed `indexer` service,
  which sends intra-cluster traffic out to a cloud load balancer and back.
- **Disk watermarks are left enabled.** Upstream sets
  `cluster.routing.allocation.disk.threshold_enabled: false`. With watermarks
  off, a filling node has nothing to protect it. Restore the upstream behaviour
  through `indexer.extraConfig` if you want it.
- **Discovery uses the headless service** and lists every replica in
  `cluster.initial_master_nodes`, instead of seeding from node 0 only, so
  scaling the indexer works.
- **Certificates carry SANs**, so the dashboard verifies the chain rather than
  running with `verificationMode: none`. Upstream certificates have no SAN at
  all, which is why upstream has to disable the check.
- **The master keeps port 1514.** Both `master.conf` and `worker.conf` carry the
  same `<remote>` block, so with `manager.worker.replicas=0` the master handles
  agent events and the events Service selects it automatically. Upstream has no
  single-node mode.
- **Manager config is injected through `/wazuh-config-mount`**, which the
  entrypoint copies onto `/var/ossec` at startup, rather than mounting files
  directly over `/var/ossec/etc`. The PVC is mounted there, and a PVC silently
  wins over a ConfigMap file mount, which is how custom rules disappear.
- **Health probes exist**, TCP by default. Upstream ships none. An exec probe
  that starts an interpreter against `wazuh-db` every 30 seconds adds load to
  the exact component that is already the bottleneck when things go wrong, so
  `manager.probes.type=exec` is opt-in and needs an image with `socat`.
- **`node.max_local_storage_nodes` is dropped.** It is deprecated and pointless
  when each pod is one node.
- **No demo users.** Only the two accounts this deployment uses are defined.

## What this chart does not do

- **NetworkPolicy.** A useful policy set depends on your CNI, on where agents
  connect from and on which namespaces reach the dashboard, and a subtly wrong
  policy is worse than none. Every pod carries
  `app.kubernetes.io/component` (`manager`, `indexer`, `dashboard`, `agent`) and
  manager pods additionally carry `wazuh.com/node-type`, which is enough to
  select on. Write them alongside the release.
- **Create a namespace or a StorageClass.** Both belong to whoever owns the
  cluster. The example files include the StorageClass definitions to copy.
- **Back anything up.** A container restart is not a backup, and recreating a
  volume can permanently remove indexer data or manager state. Volumes default
  to whatever your StorageClass reclaim policy says; use `Retain`.
- **Install indexer plugins.** Plugins have to be in the image before the node
  starts, which matters if you want Azure Blob snapshot repositories.
- **Manage agent group configuration.** `agent.conf` lives on the manager under
  `/var/ossec/etc/shared/<group>/`, not in the chart.
- **Wazuh 5.x.** The upstream deployment changes shape considerably.

## Upgrading

```bash
helm upgrade wazuh ./wazuh -n wazuh
```

Certificates and passwords are looked up and reused, so an upgrade does not
rotate them. `helm template` and `--dry-run` cannot do that lookup and will show
freshly generated values instead; that is expected and does not mean an upgrade
would replace them.

Two things need a manual check when you bump the Wazuh version:

**`ossec.conf`.** `templates/manager/_ossec-conf.tpl` embeds the upstream
`master.conf` for this chart's `appVersion`, verbatim apart from a templated
`<cluster>` block. Re-diff it:

```bash
curl -sL https://raw.githubusercontent.com/wazuh/wazuh-kubernetes/v<version>/wazuh/wazuh_managers/wazuh_conf/master.conf
```

**`filebeat.yml`**, if you enabled `manager.filebeat.archivesEnabled` or
supplied your own. Extract the current default and diff it:

```bash
kubectl run --rm -it --image=wazuh/wazuh-manager:<version> extract --restart=Never -- \
  cat /var/ossec/data_tmp/exclusion/etc/filebeat/filebeat.yml
```

That file is also why archives quietly stop after an image upgrade. The
entrypoint regenerates `/etc/filebeat/filebeat.yml` at every start from a
template inside the image, after volumes are mounted, so a ConfigMap mounted at
the destination is overwritten. The chart mounts over the source template
instead. See
[archives-disabled-after-update.md](../../archives-disabled-after-update.md).

`volumeClaimTemplates` are immutable once a StatefulSet exists. Changing
`persistence.size` or `storageClass` needs the StatefulSet deleted with
`--cascade=orphan` and recreated, or a manual PVC expansion.

## Validation

This chart has been linted, rendered across ten values combinations and
schema-validated, but it has **not** been deployed to a live cluster. Test it in
a lab before production.

```bash
helm lint ./wazuh
helm template wz ./wazuh -n wazuh -f wazuh/examples/values-eks.yaml
```

What was checked:

- `helm lint` clean, and `helm template` renders for the defaults plus all six
  example files and four flag combinations.
- 194 rendered resources validated against Kubernetes 1.30 schemas with
  `kubeconform -strict`. The skipped ones are the cert-manager and OpenShift
  CRDs.
- Generated certificates verified against the generated CA with `openssl`, and
  the SAN list checked to cover every service DNS name.
- The PKCS#8 conversion run for real, and the result loaded with the Wazuh
  indexer image's own bundled JDK and Netty. The unconverted PKCS#1 key fails
  there, which is what the init container exists to prevent.
- `internal_users.yml` hashes verified against the generated passwords with
  `bcrypt`.
- Every Service selector confirmed to match the pod labels it targets, including
  the zero-worker case where the events Service has to fall back to the master.
- `master.conf` and `worker.conf` parsed as XML.

## Troubleshooting

| Symptom | Look at |
|---------|---------|
| Agents active on a worker, `disconnected` on the master; `Error 2013` or `2017` | [agent-info-sync-failures.md](../../agent-info-sync-failures.md) |
| `wazuh-archives-*` stopped receiving data after an upgrade | [archives-disabled-after-update.md](../../archives-disabled-after-update.md) |
| Agents enroll but never send events, or the reverse | [load-balancing-and-ingress.md](../../load-balancing-and-ingress.md) |
| Custom rules or dashboard settings vanish on restart | [persistent-storage.md](../../persistent-storage.md) |
| Pods stuck in Init, DNS failures, OOMKill loops | [cluster-debugging.md](../../cluster-debugging.md) |
| `s6-overlay-preinit: fatal: unable to mkdir /var/run/s6` | [openshift.md](../../openshift.md) |
| Indexer will not start, `Neither RSA, DSA nor EC worked` | A PKCS#1 private key. See [Certificates](#certificates). |
| Indexer nodes will not form a cluster, no obvious TLS error | `certs.subject.adminDn` and `certs.subject.nodesDn` do not match the certificate subjects. |
