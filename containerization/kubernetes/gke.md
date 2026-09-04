# Wazuh on Google Kubernetes Engine (GKE)

**Applies to:** Wazuh 4.x · GKE · [wazuh-kubernetes](https://github.com/wazuh/wazuh-kubernetes) deployment

[Back to Kubernetes README](./README.md)

## Overview

You can adapt the official [Kubernetes deployment](https://documentation.wazuh.com/current/deployment-options/deploying-with-kubernetes/index.html)
to GKE by parking provider-specific edits in a Kustomize overlay. Expect
changes around the persistent-disk CSI storage class, how you expose
workloads, and Google Cloud identity/secrets.

## Prerequisites

- A GKE Standard cluster with the Compute Engine Persistent Disk CSI driver.
- Schedulable nodes in the zones you plan to use.
- Measured storage, IOPS, throughput, memory, and retention needs.
- A clone of `wazuh-kubernetes` at the Wazuh version you are deploying.

## Storage class for GKE

Build a GKE overlay; do not edit the EKS base. Current GKE clusters use the
CSI provisioner `pd.csi.storage.gke.io`:

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: wazuh-storage
provisioner: pd.csi.storage.gke.io
parameters:
  type: pd-balanced
  csi.storage.k8s.io/fstype: ext4
volumeBindingMode: WaitForFirstConsumer
reclaimPolicy: Retain
allowVolumeExpansion: true
```

Treat `pd-balanced` as a starting point, not a promise. Benchmark `pd-ssd` or
supported Hyperdisk classes when indexer latency, IOPS, or recovery time miss
the target. `WaitForFirstConsumer` places a zonal disk where the pod is
scheduled; pair it with topology spread constraints so indexer pods and their
replicas do not all sit in one zone.

Certificate generation and the Kustomize apply step still follow the official
guide. Expose the dashboard through a reviewed GKE Gateway/Ingress or
LoadBalancer design, and keep internal component certificates separate from
edge TLS.

## Deployment gotchas

**Indexer pods stuck `Pending` / `Init` with `ImagePullBackOff`.** Before the
main container starts, the indexer StatefulSet runs two `busybox`-based init
containers: one that `chown`s the data directory (`volume-mount-hack`) and one
that sets `vm.max_map_count` (`increase-the-vm-max-map-count`). If the node
cannot pull `busybox` from Docker Hub (anonymous pull-rate limits, or blocked
egress to the registry), those init containers loop on `ImagePullBackOff` and
the pod never leaves initialization. `kubectl describe pod` shows the failing
pull.

Fix registry access, not the manifest: open egress to the image registry,
authenticate to Docker Hub to raise the rate limit, or mirror `busybox` into
Artifact Registry and retarget the init containers. This shows up on GKE more
often than elsewhere because outbound access is frequently locked down by
default.

## Community resources

These community write-ups are not validated by Wazuh, but they walk through
the full GKE path:

- [Wazuh GKE deployment walkthrough (Medium)](https://medium.com/%40aishuvinod09/wazuh-gke-deployment-aec5b2dc9f9b) - cloning wazuh-kubernetes, generating certs, GKE Ingress with Google-managed certificates, and GCP role notes.
- [wazuh-kubernetes-gke sample repo](https://github.com/ankit-arora-369/wazuh-kubernetes-gke/blob/master/instructions.md) - includes a `gcp-pd-storage-class.yaml` and GKE-friendly services/ingress (dated, but still a useful reference).

## Verification

```bash
kubectl get storageclass wazuh-storage -o yaml
kubectl get nodes \
  -L topology.kubernetes.io/region,topology.kubernetes.io/zone
kubectl get pods,pvc,pv -n wazuh -o wide
kubectl rollout status statefulset/wazuh-indexer -n wazuh
kubectl top pods -n wazuh
```

Confirm every PVC is bound, indexer pods sit across the intended zones, and
no pod still depends on the deprecated in-tree `kubernetes.io/gce-pd`
provisioner. In Dev Tools, check cluster health, allocation, heap, and disk
usage under representative load.

## Related

- [Wazuh on Amazon EKS](./eks.md) - storage, affinity, ingress, and SSO details that mostly carry over to GKE
- [Wazuh agent deployment - DaemonSet & Sidecar](./wazuh-agent-deployment.md) - agent coverage for GKE nodes
- [Cluster debugging](./cluster-debugging.md)
- [GCP Pub/Sub ingestion](../../cloud/gcp-pubsub.md) - GKE control-plane and other Google Cloud logs
- [GKE Persistent Disk CSI driver](https://cloud.google.com/kubernetes-engine/docs/how-to/persistent-volumes/gce-pd-csi-driver)
