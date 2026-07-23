# Containerized Wazuh agent - custom image as a DaemonSet

**Applies to:** Wazuh 4.x, Docker / Kubernetes, custom-built agent image

[Back to Kubernetes README](./README.md)

> **Not officially supported.** Running the Wazuh agent inside a container is a custom setup: Wazuh does not natively support containerized agents, and some capabilities (notably FIM against other containers' filesystems) are limited. You must build the image yourself and host it in a private registry so all worker nodes can pull it.
>
> For the officially recommended alternatives see [Deploying an agent on a Kubernetes node](./agent-on-node.md) (agent on the host OS) and [Wazuh agent deployment - DaemonSet & Sidecar](./wazuh-agent-deployment.md) (modern manifests based on the official `wazuh/wazuh-agent` image).

## Table of Contents

- [Concept and limitations](#concept-and-limitations)
- [Build the agent image](#build-the-agent-image)
- [Single host: docker-compose](#single-host-docker-compose)
- [Kubernetes: DaemonSet](#kubernetes-daemonset)
- [Centralized configuration for the agent group](#centralized-configuration-for-the-agent-group)
- [EKS Fargate: ship logs to CloudWatch](#eks-fargate-ship-logs-to-cloudwatch)

## Concept and limitations

- A container cannot connect to the Docker host's services: that is by design. A containerized agent does not "see" the host the way a natively installed agent does.
- What a containerized agent (DaemonSet) *can* do is mount the volumes where other containers write, and monitor the files/logs found there.
- Optionally, a script on the Docker host can copy host/Docker logs into a volume the agent mounts, so the agent ships them to the manager.
- Mounting `/var/run/docker.sock` into the agent container lets the `docker-listener` wodle monitor Docker events (container start/stop, exec, etc.).

## Build the agent image

`Dockerfile`: replace the `.deb` URL with the version matching your manager (keep the `-1` package revision suffix):

```dockerfile
FROM python:3.9-slim-buster

# Dependencies
RUN apt-get update \
 && apt-get install curl procps apt-transport-https lsb-release -y \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
 && mkdir /scripts /config \
 && pip3 install docker

# Install the Wazuh agent
RUN curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_<VERSION>-1_amd64.deb \
 && dpkg -i ./wazuh-agent.deb

# Entrypoint
ADD entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
```

`entrypoint.sh`: enrolls against the manager and enables the `docker-listener` wodle:

```bash
#!/bin/bash
pip3 install docker
echo "<ossec_config><wodle name=\"docker-listener\"><disabled>no</disabled></wodle></ossec_config>" >> /var/ossec/etc/ossec.conf
/var/ossec/bin/agent-auth -m $MANAGER_IP
sed -i "s/MANAGER_IP/$MANAGER_IP/g" /var/ossec/etc/ossec.conf
/var/ossec/bin/wazuh-control restart
tail -f /var/ossec/logs/ossec.log
exit 1
```

Build and push to your private registry:

```bash
docker build -t wazuh-agent:<VERSION> .
docker push <REGISTRY>/wazuh-agent:<VERSION>
```

## Single host: docker-compose

For a single Docker host (no Kubernetes), the same image runs under compose:

```yaml
version: '3.7'
services:
  wazuh1.agent:
    image: wazuh-agent:latest
    hostname: wazuh1.agent
    restart: always
    environment:
      - MANAGER_IP=<YOUR_MANAGER_IP>
    volumes:
      - agent1-wazuh-etc:/var/ossec/etc
volumes:
  agent1-wazuh-etc:
```

Persisting `/var/ossec/etc` keeps the agent key across container recreations, avoiding duplicate agent registrations.

## Kubernetes: DaemonSet

`wazuh-daemonset.yaml`: one agent pod per node. The example mounts an NGINX log volume plus the Docker socket and container log directory:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: wazuh
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: wazuh-agent
  namespace: wazuh
  labels:
    k8s-app: wazuh-agent
spec:
  selector:
    matchLabels:
      name: wazuh-agent
  template:
    metadata:
      labels:
        name: wazuh-agent
    spec:
      tolerations:
      # Allows the DaemonSet to run on control-plane nodes.
      # Remove if your control-plane nodes can't run pods.
      - key: node-role.kubernetes.io/master
        effect: NoSchedule
      containers:
      - name: wazuh-agent
        # Modify the image tag with your version
        image: <REGISTRY>/wazuh-agent:<VERSION>
        resources:
          limits:
            memory: 200Mi
          requests:
            cpu: 100m
            memory: 200Mi
        env:
        # Wazuh manager IP
        - name: WAZUH_MANAGER_IP
          value: "10.0.0.10"
        # Wazuh agent group
        - name: WAZUH_AGENT_GROUP
          value: "kubernetes"
        volumeMounts:
        # Application logs shared via hostPath
        - name: nginx-logs
          mountPath: /var/log/wazuh/nginx/
          readOnly: true
        # Optional: Docker events + container logs
        - name: docker
          mountPath: /var/run/docker.sock
        - name: varlibdockercontainers
          mountPath: /var/lib/docker/containers
      terminationGracePeriodSeconds: 5
      volumes:
      - name: nginx-logs
        hostPath:
          path: /var/log/kubernetes/nginx/
      - name: docker
        hostPath:
          path: /var/run/docker.sock
      - name: varlibdockercontainers
        hostPath:
          path: /var/lib/docker/containers
```

Customize the image tag, manager IP, agent group (see [agent groups and centralized configuration](https://wazuh.com/blog/agent-groups-and-centralized-configuration/)), and the mounted volumes. Then apply and verify one pod lands on every node:

```bash
kubectl apply -f wazuh-daemonset.yaml
# namespace/wazuh created
# daemonset.apps/wazuh-agent created

kubectl get pods -n wazuh -o wide
```

<details>
<summary>Expected output: one agent pod per node</summary>

```text
NAME                READY   STATUS    RESTARTS   AGE     IP            NODE
wazuh-agent-tq6p7   1/1     Running   0          142m    10.42.1.56    worker-2
wazuh-agent-w5kdt   1/1     Running   0          145m    10.42.0.196   control-plane
wazuh-agent-xlkh2   1/1     Running   0          145m    10.42.2.77    worker-1
```

</details>

## Centralized configuration for the agent group

On the manager, define a `localfile` in the shared configuration of the group the DaemonSet enrolls into (`/var/ossec/etc/shared/kubernetes/agent.conf`):

```xml
<agent_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/wazuh/nginx/*.log</location>
  </localfile>
</agent_config>
```

The monitored application (NGINX in this example) must write its logs to the same hostPath volume the Wazuh agent mounts. See [Deploying an agent on a Kubernetes node](./agent-on-node.md) for the matching application-side manifest.

## EKS Fargate: ship logs to CloudWatch

On EKS Fargate there are no nodes you control, so a DaemonSet (and FIM) is not possible. The alternative is routing container logs to CloudWatch and ingesting them with the Wazuh [CloudWatch Logs module](https://documentation.wazuh.com/current/cloud-security/amazon/services/supported-services/cloudwatchlogs.html).

1. Configure Fargate logging per the [official EKS documentation](https://docs.aws.amazon.com/eks/latest/userguide/fargate-logging.html). You need an existing namespace and a [Fargate pod execution role](https://docs.aws.amazon.com/eks/latest/userguide/fargate-getting-started.html#fargate-sg-pod-execution-role).
2. Create the dedicated `aws-observability` namespace (`aws-observability-namespace.yaml`):

   ```yaml
   kind: Namespace
   apiVersion: v1
   metadata:
     name: aws-observability
     labels:
       aws-observability: enabled
   ```

   ```bash
   kubectl apply -f aws-observability-namespace.yaml
   ```

3. Create the log-router ConfigMap (`aws-logging-cloudwatch-configmap.yaml`) using the [CloudWatch Fluent Bit plugin](https://github.com/aws/amazon-cloudwatch-logs-for-fluent-bit): set the parameters in the `OUTPUT` section for your region and log group:

   ```yaml
   kind: ConfigMap
   apiVersion: v1
   metadata:
     name: aws-logging
     namespace: aws-observability
   data:
     output.conf: |
       [OUTPUT]
           Name cloudwatch_logs
           Match *
           region us-east-1
           log_group_name fluent-bit-cloudwatch
           log_stream_prefix from-fluent-bit-
           auto_create_group true
     parsers.conf: |
       [PARSER]
           Name crio
           Format Regex
           Regex ^(?<time>[^ ]+) (?<stream>stdout|stderr) (?<logtag>P|F) (?<log>.*)$
           Time_Key time
           Time_Format %Y-%m-%dT%H:%M:%S.%L%z
     filters.conf: |
       [FILTER]
           Name parser
           Match *
           Key_name log
           Parser crio
           Reserve_Data True
           Preserve_Key True
   ```

   ```bash
   kubectl apply -f aws-logging-cloudwatch-configmap.yaml
   ```

4. Create an IAM policy allowing `logs:CreateLogStream`, `logs:CreateLogGroup`, `logs:DescribeLogStreams`, and `logs:PutLogEvents` ([example permissions.json](https://raw.githubusercontent.com/aws-samples/amazon-eks-fluent-logging-examples/mainline/examples/fargate/cloudwatchlogs/permissions.json)) and attach it to the Fargate pod execution role.

> **Note:** all pods under profiles using this execution role/policy will send logs to CloudWatch. If the pod configuration changes, the pod must be recreated for logging changes to take effect.

## Related

- [Wazuh agent deployment - DaemonSet & Sidecar](./wazuh-agent-deployment.md) - modern approach using the official `wazuh/wazuh-agent` image
- [Deploying an agent on a Kubernetes node](./agent-on-node.md) - supported host-level alternative
- [FIM in containerized environments](../FIM.md) - why FIM is limited inside containers
- [Wazuh on Amazon EKS](./eks.md)
