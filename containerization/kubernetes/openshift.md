# Wazuh on Red Hat OpenShift / OKD

**Applies to:** Wazuh 4.x · OpenShift / OKD 4.x · [wazuh-kubernetes](https://github.com/wazuh/wazuh-kubernetes) deployment

[Back to Kubernetes README](./README.md)

## Support status

OpenShift is **not officially supported**. The `wazuh-kubernetes` manifests are written for upstream Kubernetes and assume permissions that OpenShift denies by default. OpenShift enforces **Security Context Constraints (SCCs)**, which are stricter than plain Kubernetes Pod Security - the default `restricted-v2` SCC will block the deployment at the most basic level.

Getting Wazuh running therefore requires an OpenShift administrator to grant the right SCCs (or craft a custom one) to the ServiceAccounts of each component. The guidance below is a tested starting point, not a plug-and-play overlay.

## Why the default `restricted-v2` SCC fails

Two blockers stop the stock manifests from ever reaching a `Ready` state under `restricted-v2`.

### 1. Random UIDs and the s6-overlay entrypoint (primary blocker)

OpenShift assigns each pod a **random, high UID** (for example `1009430000`) and forbids running as `root`. The Wazuh Manager uses `s6-overlay` to supervise its internal processes, and s6 needs root-level permissions to build its runtime directory at startup. Under a restricted UID the container fails during pre-init:

```text
s6-overlay-preinit: fatal: unable to mkdir /var/run/s6: Permission denied
```

The Manager (and Dashboard) never start. The fix is to let these components run as their expected user:

- Grant the `anyuid` SCC to the Manager and Dashboard ServiceAccounts, **or**
- Build custom images with the user/group ownership adjusted so the entrypoint works under an arbitrary UID.

### 2. Indexer `vm.max_map_count` init container

The Wazuh Indexer requires the host kernel setting `vm.max_map_count=262144`. The stock manifests apply this with a **privileged** `initContainer` (typically named `increase-the-vm-max-map-count`). `restricted-v2` rejects the privileged init container, so the indexer pod stays stuck in initialization and never becomes `Ready`.

Two resolution paths:

- **Preferred - set the sysctl at the node level** with the OpenShift **Node Tuning Operator**. This removes the need for a privileged init container entirely.
- **Alternative - grant the `privileged` SCC** to the indexer ServiceAccount so the existing init container is allowed to run.

## Recommended SCC per component

| Component | SCC | Why |
|-----------|-----|-----|
| Manager | `anyuid` | Fixed UID (`101`) outside OpenShift's random range; s6-overlay needs root-level init. |
| Indexer | `anyuid` (+ node-level sysctl, or `privileged` for the init container) | Fixed UID; requires `vm.max_map_count` and volume ownership fixes. |
| Dashboard | `anyuid` (or `restricted-v2` if the image is built to run as a non-privileged user) | Expects its own user during startup. |
| Agent (DaemonSet) | `privileged` | Needs host filesystem (`/var/log`, `/etc`, ...), host network and host PID namespaces for log collection and FIM. |

### Typical UIDs, capabilities, and settings

- **UID/GID:** Wazuh components generally run as UID `101`. OpenShift ignores `runAsUser` in the manifest unless the assigned SCC permits it (e.g. `anyuid`).
- **Capabilities:** the Indexer commonly needs `CHOWN`, `DAC_OVERRIDE`, `FOWNER`; a host-monitoring Agent commonly needs `SYS_PTRACE`, `DAC_READ_SEARCH`, `NET_ADMIN`.
- **`fsGroup`:** set it to the group that owns the persistent volumes (usually `101`, sometimes `0`) so the container can write to its data directories.
- **SELinux:** agents that must read host files may need the `spc_t` SELinux type to bypass confinement.

## Binding ServiceAccounts to SCCs

Bind each component's ServiceAccount to its SCC before deploying (replace `<namespace>` with your deployment namespace):

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

There is no official custom SCC. The following manifest - used by community deployments on OKD/OpenShift 4.x - forces UID `101` for the Wazuh ServiceAccounts and is a reasonable starting point. It does **not** by itself solve the s6-overlay root requirement or the indexer sysctl; pair it with `anyuid` for the Manager/Dashboard and a node-level sysctl (Node Tuning Operator) for the Indexer.

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

- Keep the `securityContext` blocks in your Kustomize overlays / values consistent with the SCCs you assign - a `securityContext` that contradicts the SCC produces confusing admission failures.
- The StorageClass must honour `fsGroup`, or you must `chown` the volume with an init container, so the pod's UID can write to its PersistentVolume.

## Troubleshooting

```bash
# Which SCC was applied to a pod?
oc get pod <pod-name> -o yaml | grep scc

# Permission-denied errors point to an SCC or SELinux block
oc logs <pod-name>
```

`Permission denied` on entrypoint scripts almost always means the pod ran under a restricted UID it did not expect - revisit the SCC binding for that component's ServiceAccount.

## Community references

These public discussions capture the exact permission errors and workarounds other users hit on OpenShift:

- [wazuh-kubernetes issue #241 - Wazuh on OpenShift](https://github.com/wazuh/wazuh-kubernetes/issues/241)
- [wazuh-docker issue #790 - Can't deploy Wazuh on OpenShift](https://github.com/wazuh/wazuh-docker/issues/790)

## Related

- [Wazuh on Amazon EKS](./eks.md) - storage, affinity, and configuration details that carry over to any Kubernetes distribution
- [Kubernetes persistent storage and config persistence](./persistent-storage.md)
- [Official Wazuh Kubernetes documentation](https://documentation.wazuh.com/current/deployment-options/deploying-with-kubernetes/index.html)
