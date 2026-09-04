# Wazuh - Kubernetes

Patterns for running Wazuh as StatefulSets on Kubernetes, managing config through ConfigMaps, and diagnosing multi-node cluster issues.

## Managed platforms

| Guide | Description |
|-------|-------------|
| [Amazon EKS](./eks.md) | gp3 storage classes, pod affinity and Availability Zones, ECR, LoadBalancer-to-Ingress migration, TLS, SSO, secrets, custom CAs, agent enrollment |
| [Azure AKS](./aks.md) | Azure Disk CSI classes, zone-aware scheduling, indexer capacity sizing, Azure Blob snapshot prerequisites, verification steps |
| [Google GKE](./gke.md) | Persistent Disk CSI storage class, zone-aware scheduling, init-container image-pull failures, verification |
| [Red Hat OpenShift / OKD](./openshift.md) | Fitting the stack under OpenShift Security Context Constraints: s6-overlay UID blocker, indexer `vm.max_map_count` via Node Tuning Operator, per-component SCCs, ServiceAccount bindings, community custom SCC |

## Agent deployment

| Guide | Description |
|-------|-------------|
| [Wazuh agent deployment - DaemonSet & Sidecar](./wazuh-agent-deployment.md) | Roll agents onto every cluster node as a DaemonSet, or attach one beside an app as a sidecar (official `wazuh/wazuh-agent` image) |
| [Agent on a Kubernetes node](./agent-on-node.md) | Supported path: install the native agent on the node OS; watch pod logs via `hostPath` and Docker events |
| [Containerized agent - custom image](./agent-daemonset.md) | Unsupported/custom path: home-built agent image as DaemonSet or docker-compose service, plus EKS Fargate logging to CloudWatch |

## Helm chart

| Guide | Description |
|-------|-------------|
| [Wazuh Helm chart](./helm/wazuh/) | Community chart covering the full stack: manager master/worker StatefulSets, indexer, dashboard, optional agent DaemonSet. Three certificate modes, single-node and HA presets, EKS/OpenShift examples, operational fixes from the guides below baked in as defaults. No official Wazuh Helm chart exists. |

## Configuration & operations

| Guide | Description |
|-------|-------------|
| [AWS credentials via Secrets/ConfigMaps](./aws-credentials.md) | Keep multi-profile AWS module credentials alive across manager pod restarts |
| [Cluster debugging](./cluster-debugging.md) | kubectl/minikube diagnostics: pod inspection, DNS problems, indexer file transfer, dashboard logs, namespace-change DNS breakage, OOMKilled restart loops |
| [Agent-info sync failures](./agent-info-sync-failures.md) | Agents `active` on a worker yet `disconnected` on the master: `Error 2013` and `2017`, `wdb-http.sock` that accepts a request then sends nothing back, analysisd thread pools sized to node CPU instead of the cgroup quota, wazuh-db storage latency, safe health probes |
| [Load balancing, ingress & proxies](./load-balancing-and-ingress.md) | Exposing agent TCP (1514/1515) versus HTTP (dashboard/API): ingress-nginx TCP services, PROXY protocol, service types, ALB health-check `401` behavior, dynamic HAProxy load balancing with the Wazuh helper |
| [Archives disabled after pod update](./archives-disabled-after-update.md) | `wazuh-archives-*` indices stop getting data after image upgrades because `filebeat.yml` is rewritten at pod startup; ConfigMap + `subPath` fix |
| [Persisting configuration and custom content](./persistent-storage.md) | What lasts through a pod restart versus what the image regenerates; keeping dashboard config (RBAC `run_as`) and custom rules/decoders via ConfigMap + `subPath` |

Also see [FIM in containerized environments](../../fim/containers.md) for what file integrity monitoring can and cannot cover under each agent deployment model.
