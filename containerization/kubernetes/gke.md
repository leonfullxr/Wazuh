# Wazuh on Google Kubernetes Engine (GKE)

**Applies to:** Wazuh 4.x · GKE · [wazuh-kubernetes](https://github.com/wazuh/wazuh-kubernetes) deployment

[Back to Kubernetes README](./README.md)

## Overview

The official [Kubernetes deployment](https://documentation.wazuh.com/current/deployment-options/deploying-with-kubernetes/index.html)
can be adapted to GKE by keeping provider-specific changes in a Kustomize
overlay. The main changes are the persistent-disk CSI storage class, workload
exposure, and Google Cloud identity/secrets.

## Prerequisites

- A GKE Standard cluster with the Compute Engine Persistent Disk CSI driver.
- Schedulable nodes across the intended zones.
- Measured storage, IOPS, throughput, memory, and retention requirements.
- A clone of the `wazuh-kubernetes` repository at the Wazuh version being
  deployed.

## Storage class for GKE

Create a GKE overlay instead of editing the EKS base. Current GKE clusters use
the CSI provisioner `pd.csi.storage.gke.io`:

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

`pd-balanced` is a baseline, not a guarantee. Benchmark `pd-ssd` or supported
Hyperdisk classes when indexer latency, IOPS, or recovery time misses the
service objective. `WaitForFirstConsumer` creates a zonal disk where the pod
is scheduled; combine it with topology spread constraints so indexer pods and
their replicas do not all occupy one zone.

The remaining base procedure (certificate generation and Kustomize apply)
follows the official guide. Expose the dashboard through a reviewed GKE
Gateway/Ingress or LoadBalancer design and keep internal component
certificates separate from edge TLS.

## Deployment gotchas

**Indexer pods stuck `Pending` / `Init` with `ImagePullBackOff`.** The indexer StatefulSet runs two `busybox`-based init containers before the main container starts: one that `chown`s the data directory (`volume-mount-hack`) and one that sets `vm.max_map_count` (`increase-the-vm-max-map-count`). If the node cannot pull `busybox` from Docker Hub - Docker Hub anonymous pull-rate limits, or blocked egress to the registry - these init containers loop on `ImagePullBackOff` and the pod never leaves initialization. `kubectl describe pod` shows the failing pull.

Fix the registry access rather than the manifest: allow egress to the image registry, authenticate to Docker Hub to lift the rate limit, or mirror the `busybox` image into Artifact Registry and point the init containers at it. This surfaces on GKE more than on other platforms because outbound access is often restricted by default.

## Community resources

These community guides are not validated by Wazuh but cover the full GKE flow:

- [Wazuh GKE deployment walkthrough (Medium)](https://medium.com/%40aishuvinod09/wazuh-gke-deployment-aec5b2dc9f9b) - cloning wazuh-kubernetes, generating certs, GKE Ingress with Google-managed certificates, and GCP role notes.
- [wazuh-kubernetes-gke sample repo](https://github.com/ankit-arora-369/wazuh-kubernetes-gke/blob/master/instructions.md) - includes a `gcp-pd-storage-class.yaml` and GKE-friendly services/ingress (dated, but a useful reference).

## Verification

```bash
kubectl get storageclass wazuh-storage -o yaml
kubectl get nodes \
  -L topology.kubernetes.io/region,topology.kubernetes.io/zone
kubectl get pods,pvc,pv -n wazuh -o wide
kubectl rollout status statefulset/wazuh-indexer -n wazuh
kubectl top pods -n wazuh
```

Confirm that all PVCs are bound, indexer pods are spread across the intended
zones, and no pod depends on the deprecated in-tree
`kubernetes.io/gce-pd` provisioner. In Dev Tools, verify cluster health,
allocation, heap, and disk usage under representative load.

## Related

- [Wazuh on Amazon EKS](./eks.md) - storage, affinity, ingress, and SSO details that mostly translate to GKE
- [Wazuh agent deployment - DaemonSet & Sidecar](./wazuh-agent-deployment.md) - agent coverage for GKE nodes
- [Cluster debugging](./cluster-debugging.md)
- [GCP Pub/Sub ingestion](../../cloud/gcp-pubsub.md) - GKE control-plane and other Google Cloud logs
- [GKE Persistent Disk CSI driver](https://cloud.google.com/kubernetes-engine/docs/how-to/persistent-volumes/gce-pd-csi-driver)
