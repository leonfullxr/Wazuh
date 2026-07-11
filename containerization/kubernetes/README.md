# Wazuh - Kubernetes

Kubernetes deployment patterns, ConfigMap-based configuration management, and troubleshooting for Wazuh multi-node clusters running as StatefulSets.

## Managed platforms

| Guide | Description |
|-------|-------------|
| [Amazon EKS](./eks.md) | Storage classes (gp3), pod affinity & Availability Zones, ECR, LoadBalancer-to-Ingress migration, TLS, SSO, secrets management, custom CAs, and agent enrollment |
| [Azure AKS](./aks.md) | Disk selection (Premium SSD v2), indexer sizing, hot/warm node pools, Azure Blob snapshots, and agent-based AKS monitoring |
| [Google GKE](./gke.md) | GCE Persistent Disk storage class, community deployment guides, and GKE audit log ingestion via Pub/Sub |

## Agent deployment

| Guide | Description |
|-------|-------------|
| [Wazuh agent deployment - DaemonSet & Sidecar](./wazuh-agent-deployment.md) | Deploy Wazuh agents across cluster nodes as a DaemonSet, or alongside a specific application as a sidecar container (official `wazuh/wazuh-agent` image) |
| [Agent on a Kubernetes node](./agent-on-node.md) | Supported approach: native agent on the node's host OS, monitoring pod logs exposed via `hostPath` plus Docker events |
| [Containerized agent - custom image](./agent-daemonset.md) | Unsupported/custom approach: self-built agent image as a DaemonSet or docker-compose service, plus EKS Fargate logging to CloudWatch |

## Configuration & operations

| Guide | Description |
|-------|-------------|
| [AWS credentials via Secrets/ConfigMaps](./aws-credentials.md) | Persist multi-profile AWS module credentials across manager pod restarts |
| [Cluster debugging](./cluster-debugging.md) | kubectl/minikube diagnostic commands: pod inspection, DNS issues, indexer file transfer, dashboard logs |
| [Archives disabled after pod update](./archives-disabled-after-update.md) | `wazuh-archives-*` indices stop receiving data after image upgrades due to `filebeat.yml` being regenerated at pod startup; ConfigMap + `subPath` mitigation |

See also [FIM in containerized environments](../FIM.md) for what file integrity monitoring can and cannot do in each agent deployment model.
