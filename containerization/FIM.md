# FIM in containerized environments

**Applies to:** Wazuh 4.x, Docker hosts and Kubernetes nodes

[Back to containerization README](./README.md)

## Table of Contents

- [Overview](#overview)
- [Layer 1: the infrastructure](#layer-1-the-infrastructure)
- [Layer 2: the containers](#layer-2-the-containers)
- [Recommended setup: agent on the host](#recommended-setup-agent-on-the-host)
- [Volumes vs bind mounts](#volumes-vs-bind-mounts)
- [Monitoring container files through shared volumes](#monitoring-container-files-through-shared-volumes)
- [Example centralized syscheck configuration](#example-centralized-syscheck-configuration)

## Overview

Container security monitoring with Wazuh works at two layers, and where you can run FIM (syscheck) depends on where the agent runs:

| Where the agent runs | FIM available? | What it can see |
|----------------------|----------------|-----------------|
| On the Docker host / K8s node (recommended) | Yes: full | Host filesystem, plus any container data exposed via volumes/bind mounts; Docker & K8s APIs |
| Inside a container (DaemonSet) | Limited | Only volumes mounted into the agent container, not officially supported |
| EKS Fargate / fully managed pods | No | No node access; use cloud log ingestion instead ([details](./kubernetes/agent-daemonset.md#eks-fargate-ship-logs-to-cloudwatch)) |

## Layer 1: the infrastructure

Monitoring the Docker host or Kubernetes node itself:

- **API integration:** the agent (or manager) pulls events directly from the [Docker engine API](https://documentation.wazuh.com/current/user-manual/capabilities/container-security/monitoring-docker.html) or the Kubernetes API.
- **Self-managed infrastructure:** deploy the Wazuh agent on the Docker host / K8s node. The agent monitors the host for threats and anomalies and talks to the Docker/K8s APIs. See [monitoring Docker servers](https://documentation.wazuh.com/current/user-manual/capabilities/container-security/index.html) and [deploying with Kubernetes](https://documentation.wazuh.com/current/deployment-options/deploying-with-kubernetes/index.html).
- **Hosted infrastructure (GKE, EKS, ...):** connect an agent (or the manager) to the cloud provider and ingest the audit logs, e.g. [monitoring GKE audit logs](https://wazuh.com/blog/monitoring-gke-audit-logs/).

Typical alerts at this layer: a Docker image is modified, a container runs in privileged mode, a user runs a command inside a container, a new pod is created, K8s network configuration changes, new software installed on the host, host vulnerabilities, failed hardening checks.

## Layer 2: the containers

Two options for monitoring the containers themselves:

1. **Agent as a DaemonSet pod:** the agent accesses the filesystems other containers expose through volumes: reading logs, detecting config changes. Not officially supported, and FIM is not available against arbitrary container filesystems; the agent only sees what is mounted into its own pod. See [containerized agent (custom image)](./kubernetes/agent-daemonset.md).
2. **Agent directly on the host (recommended):** full agent capabilities: FIM, log collection, SCA, Docker listener. See [deploying an agent on a K8s node](./kubernetes/agent-on-node.md).

## Recommended setup: agent on the host

If installing the agent on the host is feasible:

1. [Install the Wazuh agent](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html) and connect it to the manager.
2. Enable the [Docker listener](https://documentation.wazuh.com/current/user-manual/capabilities/container-security/monitoring-docker.html) to capture container events.
3. [Configure FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/how-to-configure-fim.html) on the directories backing the Docker volumes.
4. Optionally monitor command output (`docker ps`, etc.): see [Docker container security monitoring with Wazuh](https://wazuh.com/blog/docker-container-security-monitoring-with-wazuh/).

## Volumes vs bind mounts

Both mechanisms expose container data where a host-level agent can watch it:

- **Volumes** are managed entirely by Docker, live outside the container lifecycle, and work reliably across platforms (including Windows container hosts). Good for sharing data between containers or with other compute services.
- **Bind mounts** map an explicit host directory into the container, which makes the path on the host predictable: convenient for pointing syscheck at it.

```bash
# Bind mounts
docker run --mount type=bind,source="$(pwd)"/mariadb_data,target=/var/lib/mysql ...
docker run -v "$(pwd)"/mariadb_data:/var/lib/mysql ...

# Volumes
docker run --mount source=mariadb_data,target=/var/lib/mysql ...
docker run -v mariadb_data:/var/lib/mysql ...
```

## Monitoring container files through shared volumes

On Kubernetes, expose the files to the node with a `hostPath` volume; the node-level agent then runs FIM/log collection on the host directory:

```yaml
spec:
  containers:
  - image: nginx
    name: nginx-container
    volumeMounts:
    - mountPath: /var/log/nginx
      name: nginx-logs
  volumes:
  - name: nginx-logs
    hostPath:
      path: /nginx-app-logs   # directory on the node the agent monitors
      type: Directory
```

## Example centralized syscheck configuration

Apply syscheck settings to all node agents at once through a group's shared `agent.conf` (see [agent groups and centralized configuration](https://wazuh.com/blog/agent-groups-and-centralized-configuration/)). Example combining broad host FIM with the mounted volume above:

```xml
<agent_config>
  <labels>
    <label key="group">FIM</label>
  </labels>
  <syscheck>
    <directories check_all="yes">/run,/home,/tmp,/root,/var</directories>
    <ignore>/var/cache</ignore>
    <ignore>/var/spool</ignore>
    <ignore>/var/lib/apt</ignore>
    <ignore>/var/log</ignore>
    <ignore>/media</ignore>
    <scan_time>6:00</scan_time>
    <frequency>86400</frequency>
  </syscheck>
  <localfile>
    <log_format>syslog</log_format>
    <location>/nginx-app-logs/*.log</location>
  </localfile>
</agent_config>
```

Tune the `<directories>` and `<ignore>` entries to your workloads: excluding high-churn paths (package caches, spool, logs) keeps FIM noise and database size manageable.

## Related

- [Deploying an agent on a Kubernetes node](./kubernetes/agent-on-node.md)
- [Containerized agent as a DaemonSet](./kubernetes/agent-daemonset.md)
- [Wazuh agent deployment - DaemonSet & Sidecar](./kubernetes/wazuh-agent-deployment.md)
