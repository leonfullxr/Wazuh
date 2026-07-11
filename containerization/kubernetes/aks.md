# Wazuh on Azure AKS

**Applies to:** Wazuh 4.x · Azure Kubernetes Service (AKS) · Wazuh indexer (OpenSearch) sizing

[Back to Kubernetes README](./README.md)

## Table of Contents

- [Overview](#overview)
- [Disk selection and sizing](#disk-selection-and-sizing)
- [Hot/warm storage tiers and snapshots](#hotwarm-storage-tiers-and-snapshots)
- [Node sizing](#node-sizing)
- [Ingesting logs from a centralized syslog server](#ingesting-logs-from-a-centralized-syslog-server)
- [Monitoring AKS workloads with the agent](#monitoring-aks-workloads-with-the-agent)

## Overview

Sizing and architecture notes for running the Wazuh central components on AKS. The numbers below come from a reference scenario of roughly 12 TB of indexed data over a 180-day retention window; scale them to your own ingestion volume.

## Disk selection and sizing

- **Recommended disk type:** for the Wazuh indexer (OpenSearch) in production, **Premium SSD v2** offers the best balance of price, IOPS, and throughput while keeping the low latency indexing requires. Ultra Disk is usually overkill; Standard SSD is generally not suitable for the hot tier due to IOPS limits.
- **Hot tier sizing:** with a 12 TB / 180-day total estimate, a 30-day hot tier needs roughly **2 TB** of high-performance storage.
- **Account for replicas:** if `number_of_replicas` is 1 (recommended for high availability), the storage requirement **doubles**.
- Reference: [Wazuh index lifecycle management](https://documentation.wazuh.com/current/user-manual/wazuh-indexer-cluster/index-lifecycle-management.html)

## Hot/warm storage tiers and snapshots

- **Hot/warm architecture on AKS:** use separate **node pools** with labels (e.g. `node_type=hot`, `node_type=warm`), combined with Kubernetes **taints and tolerations** and OpenSearch **shard allocation awareness**, so hot indices stay on high-performance nodes and warm indices move to nodes backed by cheaper storage.
- **Azure Blob Storage for long retention:** move data older than 30–60 days to Blob Storage snapshots using the OpenSearch `repository-azure` plugin.
  - Use the **Hot** or **Cool** access tiers for snapshot repositories that may need restoring. Avoid the **Archive** tier for direct snapshot integration — it requires manual rehydration before OpenSearch can read the data.

## Node sizing

- OpenSearch is memory-intensive. For a ~12 TB environment, indexer nodes should have **32–64 GB of RAM**, with the JVM heap set to 50% of available RAM (capped at 32 GB).
- Always deploy the Wazuh indexer and manager as **StatefulSets** to get stable network identities and persistent storage binding, following the [official Kubernetes deployment](https://documentation.wazuh.com/current/deployment-options/deploying-with-kubernetes/index.html).

## Ingesting logs from a centralized syslog server

If logs are aggregated on a central syslog server before reaching Wazuh, two options work well:

1. Install a **Wazuh agent on the syslog server** and configure `localfile` blocks to read and forward the aggregated log files to the manager.
2. Route the logs through an **Azure Event Hub** and pull them with the Wazuh [Azure integration module](https://documentation.wazuh.com/current/cloud-security/azure/index.html).

## Monitoring AKS workloads with the agent

To monitor the AKS cluster itself, run the Wazuh agent as a **DaemonSet** and read the container logs at `/var/log/containers` and/or `/var/log/pods` on each node.

A useful refinement is to put **Fluent Bit** in front of the agent: Fluent Bit tails and processes the pod logs, tags them with source pod/instance metadata, filters out noise (reducing the EPS the agent has to handle), and writes the result to a file the agent ingests.

See [Wazuh agent deployment on Kubernetes](./wazuh-agent-deployment.md) for ready-to-use DaemonSet manifests.

## Related

- [Wazuh agent deployment - DaemonSet & Sidecar](./wazuh-agent-deployment.md)
- [Wazuh on Amazon EKS](./eks.md) — the EKS counterpart of this guide
- [Wazuh on GKE](./gke.md)
