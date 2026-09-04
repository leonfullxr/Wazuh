# Wazuh on Red Hat OpenShift / OKD

**Applies to:** Wazuh 4.x · OpenShift / OKD 4.x · [wazuh-kubernetes](https://github.com/wazuh/wazuh-kubernetes) deployment

[Back to Kubernetes README](./README.md)

## Support status

OpenShift is **not officially supported**. The `wazuh-kubernetes` manifests
target upstream Kubernetes and assume permissions OpenShift blocks by default.
OpenShift enforces **Security Context Constraints (SCCs)**, which are stricter
than plain Kubernetes Pod Security - the default `restricted-v2` SCC stops the
deployment at the first gate.

An OpenShift administrator has to grant the right SCCs (or write a custom one)
to each component's ServiceAccount before Wazuh will start. What follows is a
tested starting point, not a drop-in overlay.

## Why the default `restricted-v2` SCC fails

Two blockers keep the stock manifests from ever reaching `Ready` under
`restricted-v2`.

### 1. Random UIDs and the s6-overlay entrypoint (primary blocker)

OpenShift gives each pod a **random, high UID** (for example `1009430000`) and
refuses `root`. The Wazuh Manager relies on `s6-overlay` to supervise its
internal processes, and s6 needs root-level permissions to create its runtime
directory at startup. Under a restricted UID the container dies in pre-init:

```text
s6-overlay-preinit: fatal: unable to mkdir /var/run/s6: Permission denied
```

Neither the Manager nor the Dashboard starts. Allow these components to run as
their expected user:

- Grant the `anyuid` SCC to the Manager and Dashboard ServiceAccounts, **or**
- Build custom images whose user/group ownership lets the entrypoint work
  under an arbitrary UID.

Forcing a fixed UID is not a workable middle ground. UID `101` gets the pod to
`Running`, but internal binaries stay owned by `root:wazuh`, so tools like
`agent_control` fail with `Permission denied`. UID `999` (to match the
internal group) breaks s6-overlay pre-initialization with no clear error, and
the container never writes `ossec.conf`.

> **Confirmed behavior, not a gap in the manifests.** The image needs root for
> its startup sequence and for internal operation, not only for the
> entrypoint. Wazuh 5.0.0 swaps s6-overlay for the lighter
> [tini](https://github.com/krallin/tini) init process. That change does not
> drop the root requirement. Granting `anyuid`, or an equivalent policy that
> lets the container initialize as root before dropping privileges internally,
> is effectively required for the Manager on OpenShift.

### 2. Indexer `vm.max_map_count` init container

The Wazuh Indexer needs the host kernel setting `vm.max_map_count=262144`. The
stock manifests set this with a **privileged** `initContainer` (usually named
`increase-the-vm-max-map-count`). `restricted-v2` rejects that privileged init
container, so the indexer pod stays stuck in initialization and never becomes
`Ready`.

Two ways out:

- **Preferred - set the sysctl at the node level** with the OpenShift **Node
  Tuning Operator**. That removes the need for a privileged init container.
- **Alternative - grant the `privileged` SCC** to the indexer ServiceAccount
  so the existing init container can run.

## Recommended SCC per component

| Component | SCC | Why |
|-----------|-----|-----|
| Manager | `anyuid` | Fixed UID (`101`) outside OpenShift's random range; s6-overlay needs root-level init. |
| Indexer | `anyuid` (+ node-level sysctl, or `privileged` for the init container) | Fixed UID; needs `vm.max_map_count` and volume ownership fixes. |
| Dashboard | `anyuid` (or `restricted-v2` if the image is built to run as a non-privileged user) | Expects its own user during startup. |
| Agent (DaemonSet) | `privileged` | Needs host filesystem (`/var/log`, `/etc`, ...), host network and host PID namespaces for log collection and FIM. |

### Typical UIDs, capabilities, and settings

- **UID/GID:** Wazuh components typically run as UID `101`. OpenShift ignores
  `runAsUser` in the manifest unless the assigned SCC allows it (for example
  `anyuid`).
- **Capabilities:** the Indexer often needs `CHOWN`, `DAC_OVERRIDE`,
  `FOWNER`; a host-monitoring Agent often needs `SYS_PTRACE`,
  `DAC_READ_SEARCH`, `NET_ADMIN`.
- **`fsGroup`:** set it to the group that owns the persistent volumes
  (usually `101`, sometimes `0`) so the container can write its data
  directories.
- **SELinux:** agents that must read host files may need the `spc_t` SELinux
  type to escape confinement.

## Binding ServiceAccounts to SCCs

Bind each component's ServiceAccount to its SCC before you deploy (replace
`<namespace>` with your deployment namespace):

```bash
# Manager and Indexer
oc adm policy add-scc-to-user anyuid -z wazuh-manager  -n <namespace>
oc adm policy add-scc-to-user anyuid -z wazuh-indexer  -n <namespace>

# Dashboard
oc adm policy add-scc-to-user anyuid -z wazuh-dashboard -n <namespace>

# Agent DaemonSet
oc adm policy add-scc-to-user privileged -z wazuh-agent -n <namespace>
```

## Custom SCC (community reference)

No official custom SCC exists. The manifest below - used by community
deployments on OKD/OpenShift 4.x - forces UID `101` for the Wazuh
ServiceAccounts and is a reasonable starting point. Alone it does **not** fix
the s6-overlay root requirement or the indexer sysctl; combine it with
`anyuid` for Manager/Dashboard and a node-level sysctl (Node Tuning Operator)
for the Indexer.

```yaml
apiVersion: security.openshift.io/v1
kind: SecurityContextConstraints
metadata:
  name: wazuh-scc
allowPrivilegedContainer: false
allowedCapabilities:
- SYS_CHROOT
runAsUser:
  type: MustRunAs
  uid: 101
seLinuxContext:
  type: MustRunAs
fsGroup:
  type: MustRunAs
  ranges:
 - min: 101
    max: 101
supplementalGroups:
  type: MustRunAs
  ranges:
 - min: 101
    max: 101
users:
- system:serviceaccount:wazuh:wazuh-manager-worker
- system:serviceaccount:wazuh:wazuh-manager-master
- system:serviceaccount:wazuh:wazuh-indexer
- system:serviceaccount:wazuh:wazuh-dashboard
```

## Kustomize and persistent storage notes

- Keep `securityContext` blocks in your Kustomize overlays / values aligned
  with the SCCs you assign - a `securityContext` that fights the SCC produces
  confusing admission failures.
- The StorageClass must honour `fsGroup`, or you must `chown` the volume with
  an init container, so the pod's UID can write its PersistentVolume.

## Deploying via Helm or GitOps (Argo CD)

There is **no official Wazuh Helm chart** - the supported Kubernetes path is
the Kustomize-based
[wazuh-kubernetes](https://github.com/wazuh/wazuh-kubernetes) repo. Two
options for GitOps shops:

- **Argo CD supports Kustomize natively.** A "Helm-only" blocker is usually a
  *tenant-policy* rule, not an Argo CD limitation - point an Argo CD
  `Application` straight at the Kustomize overlay path and skip the chart.
  Try this first.
- **If a Helm chart is mandatory**, wrap the manifests in a thin,
  **unofficial** chart - one template per workload (indexer/manager/dashboard
  StatefulSets + Services) - exposing only the overrides a tenant needs:

    ```yaml
    # values.yaml (the override surface, not the whole chart)
    image:
      registry: ""            # e.g. my-registry.example.com
    indexer:   { replicas: 1, image: { repository: wazuh/wazuh-indexer,  tag: "4.14.4" }, heapSize: "512m", storage: { size: 50Gi, storageClass: "" }, existingSecret: "", resources: {} }
    manager:   { replicas: 1, image: { repository: wazuh/wazuh-manager,   tag: "4.14.4" }, storage: { size: 20Gi, storageClass: "" }, existingSecret: "", resources: {} }
    dashboard: { replicas: 1, image: { repository: wazuh/wazuh-dashboard, tag: "4.14.4" }, existingSecret: "", resources: {}, service: { type: ClusterIP, port: 443 } }
    ```

    That chart is a maintenance liability - it drifts from upstream on every
    Wazuh release and sits outside Wazuh support. Treat it as your own
    artifact. Either way, still apply the
    [SCC bindings](#binding-serviceaccounts-to-sccs) above.

**OpenShift ingress = Route.** Expose the dashboard with an OpenShift `Route`
(or the patterns in
[load balancing and ingress](./load-balancing-and-ingress.md)); keep agent
traffic on **1514/1515 over a plain TCP path** (a `LoadBalancer` Service or L4
passthrough), never an HTTP Route.

## Troubleshooting

```bash
# Which SCC was applied to a pod?
oc get pod <pod-name> -o yaml | grep scc

# Permission-denied errors point to an SCC or SELinux block
oc logs <pod-name>
```

`Permission denied` on entrypoint scripts almost always means the pod ran
under a restricted UID it did not expect - recheck the SCC binding for that
component's ServiceAccount.

### Health probes

Prefer low-cost probes on the manager pods. Use TCP socket probes on port
`55000` or `1515` for the master, and port `1514` for the workers. An exec
probe that starts a Python interpreter to query
`/var/ossec/queue/db/wdb` on a short period adds CPU load and socket churn,
which worsens contention. The restricted SCC also blocks some of these probes.
For the probe strategy, and for the wazuh-db stall those probes usually try to
catch, see
[agent-info sync failures](./agent-info-sync-failures.md#health-probes-for-manager-pods).

## Community references

These public threads document the exact permission errors and workarounds
other users hit on OpenShift:

- [wazuh-kubernetes issue #241 - Wazuh on OpenShift](https://github.com/wazuh/wazuh-kubernetes/issues/241)
- [wazuh-docker issue #790 - Can't deploy Wazuh on OpenShift](https://github.com/wazuh/wazuh-docker/issues/790)

## Related

- [Agent-info sync failures](./agent-info-sync-failures.md) - agents `active` on a worker but `disconnected` on the master: too many analysisd threads, wazuh-db storage latency, and probe strategy
- [Syscollector network inventory](../../troubleshooting/agents/syscollector-network-inventory.md) - empty interface inventory on nodes that hold a keepalived-managed API or Ingress VIP
- [Wazuh on Amazon EKS](./eks.md) - storage, affinity, and configuration details that apply on any Kubernetes distribution
- [Kubernetes persistent storage and config persistence](./persistent-storage.md)
- [Official Wazuh Kubernetes documentation](https://documentation.wazuh.com/current/deployment-options/deploying-with-kubernetes/index.html)
