# Wazuh on Azure Kubernetes Service (AKS)

**Applies to:** Wazuh 4.x, AKS, and the
[`wazuh-kubernetes`](https://github.com/wazuh/wazuh-kubernetes) deployment.

AKS-specific storage, scheduling, capacity, snapshots, and checks live here.
Use the official Wazuh Kubernetes procedure for certificates and base
manifests. Put Azure-only edits in a Kustomize overlay so upstream upgrades
stay easy to review.

## Prerequisites

- An AKS cluster that has the Azure Disk CSI driver.
- Enough schedulable indexer nodes for a three-indexer layout (at least three).
- Azure Disk quota and zone capacity for the SKU you pick.
- Measured daily primary-data volume, retention, replica count, and recovery
  objectives.

## Storage class

The indexer is the I/O-heavy piece. Begin with a premium Azure Disk class;
benchmark indexing, search, and recovery before you move to a cheaper or
faster tier. Premium SSD v2 needs regional/zone support and
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

When Premium SSD v2 is not available, use `managed-csi-premium` or a custom
`Premium_LRS`/`Premium_ZRS` class. `WaitForFirstConsumer` creates the disk in
the zone Kubernetes picks for the pod. `Retain` keeps the underlying disk if
someone deletes a PVC, which also means you need an explicit cleanup process.

Point only the indexer volume claim template at this class. Managers and the
dashboard need different capacity and I/O profiles.

## Zones and scheduling

Azure Disks are usually `ReadWriteOnce`, so a StatefulSet pod has to land on a
node that can attach its existing disk. Spread indexer replicas across zones
with pod anti-affinity or topology spread constraints, and let each PVC bind
in its pod's zone.

Check before you deploy:

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

Do not pack every indexer into one zone just to dodge a volume-attachment
error. Correct the storage binding and scheduling constraints, then confirm
primary and replica shards sit across failure domains.

## Capacity planning

Size storage from measured primary data, not from a fixed environment label:

```text
raw indexed storage =
  daily primary data * retention days * (1 + replica count)
```

Leave headroom for segment merges, shard relocation, translogs, in-flight
snapshots, and disk watermarks. That figure is cluster-wide; split it across
indexer PVCs and still leave enough room to recover after losing one node.

Use the [Indexer optimization hub](../../indexer/README.md) for shard size,
replica, heap, and retention choices. Set JVM min and max heap to the same
value, typically near half the container memory limit, then watch garbage
collection and heap pressure. Treat 32 GB as a benchmark boundary, not a
universal hard limit.

## Azure Blob snapshots

Azure Blob is a snapshot repository, not a transparent warm tier. The Wazuh
Indexer image does not pick up Azure repository support on its own:

1. Build and test a custom image that ships the `repository-azure` plugin for
   the exact bundled OpenSearch version.
2. Install the plugin on every indexer node before startup.
3. Supply Azure credentials through the OpenSearch keystore, or use supported
   managed-identity settings for that OpenSearch version.
4. Register and verify the repository, then restore into a separate cluster
   as a test.

Skip the Azure Archive access tier for snapshots OpenSearch must restore
directly; archived blobs need rehydration first.

Plugin installs change the indexer image and the upgrade path. If that cost
is too high, pick an externally supported backup design instead of installing
plugins by hand inside running pods.

## Verification

After the AKS overlay is applied:

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

Expect a green cluster, every PVC bound, indexers spread as designed, and
stable disk/heap pressure under representative ingestion.

## See also

- [Official Wazuh Kubernetes deployment](https://documentation.wazuh.com/current/deployment-options/deploying-with-kubernetes/index.html)
- [AKS Azure Disk CSI volumes](https://learn.microsoft.com/en-us/azure/aks/create-volume-azure-disk)
- [Persistent Wazuh configuration](./persistent-storage.md)
- [Kubernetes cluster debugging](./cluster-debugging.md)
- [Agent DaemonSet and sidecar patterns](./wazuh-agent-deployment.md)
- [Device syslog ingestion](../../integrations/syslog/README.md)
