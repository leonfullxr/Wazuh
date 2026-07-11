# Wazuh on Google Kubernetes Engine (GKE)

**Applies to:** Wazuh 4.x · GKE · [wazuh-kubernetes](https://github.com/wazuh/wazuh-kubernetes) deployment

[Back to Kubernetes README](./README.md)

## Overview

There is no official Wazuh deployment guide for GKE, but the official [Kubernetes deployment](https://documentation.wazuh.com/current/deployment-options/deploying-with-kubernetes/index.html) (written with AWS EKS in mind) adapts to GKE with one main change: the storage class.

## Storage class for GKE

In your clone of the [wazuh-kubernetes](https://github.com/wazuh/wazuh-kubernetes) repository, replace the EKS storage class (`envs/eks/storage-class.yaml`) with a GCE Persistent Disk provisioner:

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: wazuh-storage
provisioner: kubernetes.io/gce-pd
parameters:
  type: pd-standard
volumeBindingMode: WaitForFirstConsumer
reclaimPolicy: Retain
```

For production indexer workloads, consider `pd-ssd` (or `pd-balanced`) instead of `pd-standard` — the indexer is the most I/O-sensitive component.

The rest of the procedure (certificate generation, Kustomize apply, exposing the dashboard) follows the official guide. For the dashboard you can use a GKE Ingress with Google-managed certificates instead of a LoadBalancer service.

## Community resources

These community guides are not validated by Wazuh but cover the full GKE flow:

- [Wazuh GKE deployment walkthrough (Medium)](https://medium.com/%40aishuvinod09/wazuh-gke-deployment-aec5b2dc9f9b) — cloning wazuh-kubernetes, generating certs, GKE Ingress with Google-managed certificates, and GCP role notes.
- [wazuh-kubernetes-gke sample repo](https://github.com/ankit-arora-369/wazuh-kubernetes-gke/blob/master/instructions.md) — includes a `gcp-pd-storage-class.yaml` and GKE-friendly services/ingress (dated, but a useful reference).

## Monitoring GKE audit logs

To monitor the GKE control plane itself (rather than deploying Wazuh *on* GKE), route the audit logs through Cloud Logging → Pub/Sub and ingest them with the Wazuh [GCP Pub/Sub module](https://documentation.wazuh.com/current/cloud-security/gcp/index.html) (`<gcp-pubsub>`). The Wazuh blog post [Monitoring GKE audit logs](https://wazuh.com/blog/monitoring-gke-audit-logs/) walks through the IAM setup, log sink, and module configuration.

## Related

- [Wazuh on Amazon EKS](./eks.md) — storage, affinity, ingress, and SSO details that mostly translate to GKE
- [Wazuh agent deployment - DaemonSet & Sidecar](./wazuh-agent-deployment.md) — agent coverage for GKE nodes
- [Cluster debugging](./cluster-debugging.md)
