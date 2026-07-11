# Wazuh on Azure Kubernetes Service (AKS)

**Applies to:** Wazuh 4.x, AKS, and the
[`wazuh-kubernetes`](https://github.com/wazuh/wazuh-kubernetes) deployment.

This guide covers AKS-specific storage, scheduling, capacity, snapshots, and
verification. Follow the official Wazuh Kubernetes procedure for certificate
generation and base manifests; keep Azure changes in a Kustomize overlay so
upstream upgrades remain reviewable.

## Prerequisites

- An AKS cluster with the Azure Disk CSI driver.
- At least three schedulable indexer nodes for a three-indexer deployment.
- Azure Disk quota and zone availability for the selected SKU.
- Measured daily primary-data volume, retention, replica count, and recovery
  objectives.

## Storage class

Wazuh Indexer is the I/O-sensitive component. Start with a premium Azure Disk
class and benchmark indexing, search, and recovery before selecting a cheaper
or faster tier. Premium SSD v2 requires regional/zone support and
`cachingMode: None`.

Example retained Premium SSD v2 class:

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: wazuh-indexer-premium-v2
provisioner: disk.csi.azure.com
parameters:
  skuName: PremiumV2_LRS
  cachingMode: None
reclaimPolicy: Retain
volumeBindingMode: WaitForFirstConsumer
allowVolumeExpansion: true
```

Use `managed-csi-premium` or a custom `Premium_LRS`/`Premium_ZRS` class when
Premium SSD v2 is unavailable. `WaitForFirstConsumer` lets Kubernetes create
the disk in the zone selected for the pod. `Retain` protects the underlying
disk if a PVC is deleted, but also requires an explicit cleanup process.

Reference this class only from the indexer volume claim template. Managers
and the dashboard have different capacity and I/O requirements.

## Zones and scheduling

Azure Disks are normally `ReadWriteOnce`; a StatefulSet pod must return to a
node that can attach its existing disk. Spread indexer replicas across zones
with pod anti-affinity or topology spread constraints, while allowing each
PVC to bind in its pod's zone.

Verify before deployment:

```bash
kubectl get nodes \
  -L topology.kubernetes.io/region,topology.kubernetes.io/zone
kubectl get storageclass wazuh-indexer-premium-v2 -o yaml
```

After scheduling:

```bash
kubectl get pods -n wazuh -o wide
kubectl get pvc,pv -n wazuh
kubectl describe pod -n wazuh <INDEXER_POD>
```

Do not force all indexers into one zone merely to solve a volume-attachment
error. Fix storage binding and scheduling constraints, then confirm primary
and replica shards are distributed across failure domains.

## Capacity planning

Calculate storage from measured primary data, not a fixed environment size:

```text
raw indexed storage =
  daily primary data * retention days * (1 + replica count)
```

Add headroom for segment merges, shard relocation, translogs, snapshots in
progress, and disk watermarks. The result is cluster-wide; distribute it
across indexer PVCs while ensuring the cluster can recover from the loss of
one node.

Use the [Indexer optimization hub](../../indexer/README.md) for shard size,
replica, heap, and retention decisions. Set JVM minimum and maximum heap to
equal values, normally near half the container memory limit, then validate
garbage collection and heap pressure. Treat 32 GB as a benchmark boundary,
not a universal hard cap.

## Azure Blob snapshots

Azure Blob is a snapshot repository, not a transparent warm data tier. The
Wazuh Indexer image does not automatically gain Azure repository support:

1. Build and test a custom image with the `repository-azure` plugin matching
   the exact bundled OpenSearch version.
2. Install the plugin on every indexer node before startup.
3. Provide Azure credentials through the OpenSearch keystore or use supported
   managed-identity settings for the bundled OpenSearch version.
4. Register and verify the repository, then test a restore into a separate
   cluster.

Do not use the Azure Archive access tier for snapshots that OpenSearch must
restore directly; archived blobs require rehydration first.

Plugin changes alter the indexer image and upgrade path. If that operational
cost is not acceptable, use an externally supported backup design instead of
installing plugins manually in running pods.

## Verification

After applying the AKS overlay:

```bash
kubectl rollout status statefulset/wazuh-indexer -n wazuh
kubectl get pods,pvc,pv -n wazuh -o wide
kubectl top pods -n wazuh
```

From Wazuh Dashboard Dev Tools:

```http
GET _cluster/health
GET _cat/nodes?v&h=name,node.role,heap.percent,ram.percent,disk.used_percent
GET _cat/allocation?v
GET _cat/shards?v&h=index,shard,prirep,state,node
```

The cluster must be green, every PVC bound, indexers spread as designed, and
disk/heap pressure stable during representative ingestion.

## See also

- [Official Wazuh Kubernetes deployment](https://documentation.wazuh.com/current/deployment-options/deploying-with-kubernetes/index.html)
- [AKS Azure Disk CSI volumes](https://learn.microsoft.com/en-us/azure/aks/create-volume-azure-disk)
- [Persistent Wazuh configuration](./persistent-storage.md)
- [Kubernetes cluster debugging](./cluster-debugging.md)
- [Agent DaemonSet and sidecar patterns](./wazuh-agent-deployment.md)
- [Device syslog ingestion](../../integrations/syslog/README.md)
