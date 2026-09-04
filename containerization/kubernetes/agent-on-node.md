# Deploying a Wazuh agent on a Kubernetes node

**Applies to:** Wazuh 4.x · any Kubernetes distribution (tested on Rancher/k3s-style clusters)

[Back to Kubernetes README](./README.md)

## Overview

The simplest **supported** path for monitoring Kubernetes workloads is to install the Wazuh agent on each node's host OS and surface workload logs on the host with `hostPath` volumes. That gives the agent full capabilities (FIM, SCA, log collection, Docker events) that a containerized agent cannot match.

This walkthrough uses an NGINX deployment: pods write logs to a hostPath, and the node-level agent tails those files and watches Docker events.

## Why on the node instead of in a container

There is no official Wazuh agent image or DaemonSet. Running the agent inside a container brings two limits that a node-level install avoids:

- **The agent reports the container's OS, not the node's.** An agent in a pod inventories the container image. Package list, SCA results, and system inventory describe the container, not the worker node you care about. Bind-mounting host paths into the container does not fully fix this: the installed-package list and similar data are still queried from inside the container.
- **Heterogeneous workload logs are hard to normalize.** Logs from different workloads on a node rarely share one format (syslog, JSON, and so on). You cannot infer the format from the file name, so parsing often fails and needs per-source custom decoders.

A host OS install avoids both problems: the agent sees the real node (FIM, SCA, inventory) and reads each workload's logs from a path where you control the format.

## 1. Expose application logs to the host

Deploy the application with its log directory mounted on the node via `hostPath`. NGINX writes to `/var/log/nginx` inside the container; that path is bound to `/var/log/kubernetes/nginx` **on the node**:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-test-app
  namespace: wazuh
  labels:
    k8s-app: nginx-test
spec:
  replicas: 5
  selector:
    matchLabels:
      name: nginx-app
  template:
    metadata:
      labels:
        name: nginx-app
    spec:
      containers:
 - name: nginx
        image: nginx
        ports:
 - containerPort: 80
        volumeMounts:
        # NGINX stores its logs here inside the container
 - name: nginx-logs
          mountPath: /var/log/nginx/
      volumes:
 - name: nginx-logs
        hostPath:
          # Path on the node that the Wazuh agent will monitor
          path: /var/log/kubernetes/nginx/
```

Replicas land across the nodes. Each node's agent only sees the logs of pods running on that node:

<details>
<summary>Pod distribution across nodes</summary>

```text
NAME                         READY   STATUS    RESTARTS   AGE   IP           NODE
nginx-test-app-aaaaa-11111   1/1     Running   0          5m    192.0.2.11   worker-2
nginx-test-app-aaaaa-22222   1/1     Running   0          5m    192.0.2.12   control-plane
nginx-test-app-aaaaa-33333   1/1     Running   0          5m    192.0.2.13   worker-1
nginx-test-app-aaaaa-44444   1/1     Running   0          5m    192.0.2.14   worker-2
nginx-test-app-aaaaa-55555   1/1     Running   0          5m    192.0.2.15   control-plane
```

</details>

## 2. Create an agent group on the manager

```bash
/var/ossec/bin/agent_groups -a -g kubernetes
```

## 3. Install the agent on every node

Install the Wazuh agent on the **host OS** of each Kubernetes node (not in a container), following the [standard installation guide](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html), and put the agents in the `kubernetes` group.

## 4. Push centralized configuration to the group

Edit `/var/ossec/etc/shared/kubernetes/agent.conf` on the manager:

```xml
<agent_config>
  <!-- Docker events via the Docker API -->
  <wodle name="docker-listener">
    <disabled>no</disabled>
  </wodle>
  <!-- NGINX logs from the hostPath volume -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/kubernetes/nginx/*.log</location>
  </localfile>
</agent_config>
```

Every node then ships two sources: Docker event logs (container lifecycle, exec, scaling) and NGINX access/error logs from the shared volume.

## 5. Test

Hit the service load balancer with a web attack to confirm log collection and rule matching (Shellshock fires rule 31168 out of the box):

```bash
curl -H "User-Agent: () { :; }; /bin/eject" http://<LOAD_BALANCER_IP>:<PORT>/cgi-bin/test.sh
```

Confirm Docker event collection by scaling the deployment:

```bash
kubectl scale deploy nginx-test-app --replicas=1 -n wazuh
```

Both actions should produce alerts on the Wazuh dashboard.

## Dynamic and autoscaling clusters

When nodes come and go automatically, enrollment must be unattended. Nobody registers each new node by hand. Practical points:

- **Bootstrap install and enrollment at node startup.** On self-managed node pools, put agent installation and enrollment in the node's bootstrap or startup script (cloud user data) so each new node registers as it joins. Assign it to the group above so centralized configuration applies immediately.
- **Do not hard-code the registration password in plaintext.** Putting `WAZUH_REGISTRATION_PASSWORD` in a bootstrap script or machine image exposes it. Fetch it at boot from a secrets manager, and keep enrollment scoped tightly.
- **Fully managed node pools may not expose a bootstrap hook.** With managed workers (for example EKS-managed node groups), you often cannot inject a startup script. Options are a **custom machine image** with the agent preinstalled (works, but you maintain and update that image yourself) or accepting the thinner coverage of an in-cluster agent.
- **Route agent traffic through a stable endpoint.** Node IPs churn, so point agents at the manager through a load balancer (for example an NLB) instead of a fixed node address. Enrollment and reporting then survive scaling events.

## Related

- [Wazuh agent deployment - DaemonSet & Sidecar](./wazuh-agent-deployment.md) - running the agent *inside* the cluster instead
- [Containerized agent (custom image)](./agent-daemonset.md) - when host access is not possible
- [FIM in containerized environments](../../fim/containers.md) - extending this setup with file integrity monitoring over the mounted volumes
