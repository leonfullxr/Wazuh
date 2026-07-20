# Wazuh - Kubernetes

Kubernetes deployment patterns, ConfigMap-based configuration management, and troubleshooting for Wazuh multi-node clusters running as StatefulSets.

## Managed platforms

| Guide | Description |
|-------|-------------|
| [Amazon EKS](./eks.md) | Storage classes (gp3), pod affinity & Availability Zones, ECR, LoadBalancer-to-Ingress migration, TLS, SSO, secrets management, custom CAs, and agent enrollment |
| [Azure AKS](./aks.md) | Azure Disk CSI classes, zone-aware scheduling, indexer capacity planning, Azure Blob snapshot prerequisites, and verification |
| [Google GKE](./gke.md) | Persistent Disk CSI storage class, zone-aware scheduling, init-container image-pull failures, and verification |
| [Red Hat OpenShift / OKD](./openshift.md) | Adapting the deployment to OpenShift's Security Context Constraints: the s6-overlay UID blocker, indexer `vm.max_map_count` via the Node Tuning Operator, per-component SCCs, ServiceAccount bindings, and a community custom SCC |

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
| [Cluster debugging](./cluster-debugging.md) | kubectl/minikube diagnostic commands: pod inspection, DNS issues, indexer file transfer, dashboard logs, namespace-change DNS breakage, and OOMKilled restart loops |
| [Load balancing, ingress & proxies](./load-balancing-and-ingress.md) | Exposing agent TCP (1514/1515) vs HTTP (dashboard/API): ingress-nginx TCP services, PROXY protocol, service types, the ALB health-check `401` gotcha, and dynamic HAProxy load balancing with the Wazuh helper |
| [Archives disabled after pod update](./archives-disabled-after-update.md) | `wazuh-archives-*` indices stop receiving data after image upgrades due to `filebeat.yml` being regenerated at pod startup; ConfigMap + `subPath` mitigation |
| [Persisting configuration and custom content](./persistent-storage.md) | What survives a pod restart vs. what is regenerated from the image; persisting dashboard config (RBAC `run_as`) and custom rules/decoders via ConfigMap + `subPath` |

See also [FIM in containerized environments](../FIM.md) for what file integrity monitoring can and cannot do in each agent deployment model.
