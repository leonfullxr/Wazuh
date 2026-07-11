# Deploying a Wazuh agent on a Kubernetes node

**Applies to:** Wazuh 4.x · any Kubernetes distribution (tested on Rancher/k3s-style clusters)

[Back to Kubernetes README](./README.md)

## Overview

The simplest **supported** way to monitor Kubernetes workloads is to install the Wazuh agent natively on each node's host OS and expose the workload logs to the host through `hostPath` volumes. The agent then gets full capabilities (FIM, SCA, log collection, Docker events) that a containerized agent cannot provide.

This walkthrough monitors an NGINX deployment: pod logs are written to a hostPath, and the node-level agent tails them and watches Docker events.

## 1. Expose application logs to the host

Create the application deployment with its log directory mounted on the node via `hostPath`. NGINX writes to `/var/log/nginx` inside the container, which is bound to `/var/log/kubernetes/nginx` **on the node**:

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

The replicas spread across the nodes, and each node's agent sees the logs of the pods running on it:

<details>
<summary>Pod distribution across nodes</summary>

```
NAME                              READY   STATUS    RESTARTS   AGE   IP           NODE
nginx-test-app-54d4c9b59d-59kc2   1/1     Running   0          44m   10.42.1.7    worker-2
nginx-test-app-54d4c9b59d-9qpj8   1/1     Running   0          44m   10.42.0.19   control-plane
nginx-test-app-54d4c9b59d-bcxcc   1/1     Running   0          45m   10.42.2.6    worker-1
nginx-test-app-54d4c9b59d-fbjhm   1/1     Running   0          45m   10.42.1.6    worker-2
nginx-test-app-54d4c9b59d-fx22v   1/1     Running   0          45m   10.42.0.18   control-plane
```

</details>

## 2. Create an agent group on the manager

```bash
/var/ossec/bin/agent_groups -a -g kubernetes
```

## 3. Install the agent on every node

Install the Wazuh agent on the **host OS** of each Kubernetes node (not in a container), following the [standard installation guide](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html), and assign the agents to the `kubernetes` group.

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

This ships two data sources from every node: Docker event logs (container lifecycle, exec, scaling) and the NGINX access/error logs from the shared volume.

## 5. Test

Generate a web attack against the service's load balancer to verify log collection and rule matching (Shellshock triggers rule 31168 out of the box):

```bash
curl -H "User-Agent: () { :; }; /bin/eject" http://<LOAD_BALANCER_IP>:<PORT>/cgi-bin/test.sh
```

Verify Docker event collection by scaling the deployment:

```bash
kubectl scale deploy nginx-test-app --replicas=1 -n wazuh
```

Both actions should produce alerts on the Wazuh dashboard.

## Related

- [Wazuh agent deployment — DaemonSet & Sidecar](./wazuh-agent-deployment.md) — running the agent *inside* the cluster instead
- [Containerized agent (custom image)](./agent-daemonset.md) — when host access is not possible
- [FIM in containerized environments](../FIM.md) — extending this setup with file integrity monitoring over the mounted volumes
