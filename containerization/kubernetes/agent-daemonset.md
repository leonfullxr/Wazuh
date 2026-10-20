# Containerized Wazuh agent - custom image

How to run the Wazuh agent from an image you build yourself, as a Docker
container or a Kubernetes DaemonSet. It covers when a custom image is worth it,
how to keep agent identity on nodes that come and go, how to clean up agents
from replaced nodes, and what to check before adopting a community agent image.

> **Applies to:** Wazuh 4.14.x agents on Docker hosts and Kubernetes nodes. The
> image is a reference you build and own. Wazuh supports the agent package, not
> the image around it. Tested against a 4.14.5 manager in a Docker lab.

[Back to Kubernetes README](./README.md)

## Table of Contents

- [When a custom image is worth it](#when-a-custom-image-is-worth-it)
- [Build the image](#build-the-image)
- [Single Docker host](#single-docker-host)
- [Kubernetes DaemonSet](#kubernetes-daemonset)
- [Centralized configuration for the agent group](#centralized-configuration-for-the-agent-group)
- [Agent identity on nodes that come and go](#agent-identity-on-nodes-that-come-and-go)
- [Enrollment: password or API](#enrollment-password-or-api)
- [Reviewing a community agent image](#reviewing-a-community-agent-image)
- [EKS Fargate: ship logs to CloudWatch](#eks-fargate-ship-logs-to-cloudwatch)
- [Related](#related)

## When a custom image is worth it

Start from the official image. Build your own only when something rules it out.

| Situation | Use |
|---|---|
| Public images allowed, standard nodes | The official [`wazuh/wazuh-agent`](https://hub.docker.com/r/wazuh/wazuh-agent) image with the [documented DaemonSet](./wazuh-agent-deployment.md) or the [Helm chart](./helm/wazuh/README.md#agent-daemonset) |
| Base-image policy (hardened Debian, UBI, Amazon Linux), internal registry only, image scanning gates | The image in this guide, rebuilt on your base |
| Node OS accepts packages | The native agent on the node: [Agent on a Kubernetes node](./agent-on-node.md) |
| No nodes at all (EKS Fargate) | No agent. [Ship logs to CloudWatch](#eks-fargate-ship-logs-to-cloudwatch) |

A custom image does not lift the limits of running in a container. The agent
sees only what is mounted into its pod, syscollector and SCA describe the
container rather than the node, and FIM cannot attribute changes to a user. See
[FIM in containerized environments](../../fim/containers.md).

## Build the image

The reference files are in
[`scripts/agent-container-image/`](../../scripts/agent-container-image/):

- **`Dockerfile`:** Debian 12 slim plus `wazuh-agent` from the signed Wazuh
  repository, pinned with `WAZUH_VERSION`. About 113 MB.
- **`entrypoint.sh`:** writes an `ossec.conf` that only connects and enrolls,
  starts the agent, and stops it cleanly on `SIGTERM`.

```bash
docker build --build-arg WAZUH_VERSION=4.14.9-1 -t <REGISTRY>/wazuh-agent:4.14.9 scripts/agent-container-image
docker push <REGISTRY>/wazuh-agent:4.14.9
```

Keep the agent version at or below the manager version.

Design choices worth keeping if you adapt it:

- **Collection lives on the manager.** The image carries no `<localfile>` or
  FIM paths. The group `agent.conf` decides what each fleet collects, so a
  change is a manager edit, not an image rebuild.
- **Inventory modules off.** Syscollector, SCA and rootcheck are disabled in
  the rendered `ossec.conf`. A group can turn them back on.
- **Clean shutdown.** The entrypoint traps `SIGTERM` and runs
  `wazuh-control stop`. In the lab a `docker stop` completed in about one
  second with exit code 0, instead of waiting for the kill timeout.
- **No API credentials on the agent.** Enrollment uses the `authd` password
  from a mounted file.

## Single Docker host

```yaml
services:
  wazuh-agent:
    image: <REGISTRY>/wazuh-agent:4.14.9
    hostname: docker-host-01
    restart: unless-stopped
    environment:
      WAZUH_MANAGER: <MANAGER_FQDN>
      WAZUH_AGENT_GROUP: docker-hosts
      WAZUH_STATE_DIR: /state
    volumes:
      - agent-state:/state
      - ./authd.pass:/run/secrets/wazuh/authd.pass:ro
      - /var/log:/host/var/log:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
volumes:
  agent-state:
```

`WAZUH_STATE_DIR` keeps the agent key on the `agent-state` volume, so a
recreated container comes back with the same agent ID. The Docker socket is
only needed for the `docker-listener` wodle, which also needs `python3` and the
`docker` Python package in the image.

## Kubernetes DaemonSet

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: wazuh-agent
  namespace: wazuh
spec:
  selector:
    matchLabels: { app: wazuh-agent }
  updateStrategy:
    rollingUpdate: { maxUnavailable: 1 }
  template:
    metadata:
      labels: { app: wazuh-agent }
    spec:
      automountServiceAccountToken: false
      terminationGracePeriodSeconds: 30
      tolerations:
        - key: node-role.kubernetes.io/control-plane
          operator: Exists
          effect: NoSchedule
      containers:
        - name: wazuh-agent
          image: <REGISTRY>/wazuh-agent:4.14.9
          env:
            - name: WAZUH_MANAGER              # events, port 1514
              value: wazuh-workers.wazuh.svc
            - name: WAZUH_REGISTRATION_SERVER  # enrollment, port 1515
              value: wazuh.wazuh.svc
            - name: WAZUH_AGENT_GROUP
              value: k8s-nodes
            - name: WAZUH_STATE_DIR
              value: /state
            - name: WAZUH_AGENT_NAME
              valueFrom: { fieldRef: { fieldPath: spec.nodeName } }
          securityContext:
            runAsUser: 0
          resources:
            requests: { cpu: 50m, memory: 128Mi }
            limits: { memory: 512Mi }
          volumeMounts:
            - { name: state, mountPath: /state }
            - { name: authd, mountPath: /run/secrets/wazuh, readOnly: true }
            - { name: host-etc, mountPath: /host/etc, readOnly: true }
            - { name: host-log, mountPath: /host/var/log, readOnly: true }
      volumes:
        - name: state
          hostPath: { path: /var/lib/wazuh-agent, type: DirectoryOrCreate }
        - name: authd
          secret: { secretName: wazuh-authd-pass }
        - name: host-etc
          hostPath: { path: /etc, type: Directory }
        - name: host-log
          hostPath: { path: /var/log, type: Directory }
```

```bash
kubectl -n wazuh create secret generic wazuh-authd-pass --from-literal=authd.pass='<ENROLLMENT_PASSWORD>'
kubectl apply -f wazuh-agent-daemonset.yaml
kubectl -n wazuh get pods -l app=wazuh-agent -o wide   # one pod per node
```

Notes on the manifest:

- **Only the key is on the node.** The hostPath holds `client.keys` and nothing
  else. Binaries and defaults always come from the image, so changing the tag
  upgrades the agent. Manifests that seed all of `/var/ossec` onto the hostPath
  once keep running the first version they received; see
  [Upgrading the agent image](./wazuh-agent-deployment.md#upgrading-the-agent-image).
- **Root without privileged.** The agent starts as root and drops to the
  `wazuh` user. The container is not privileged and host paths are read-only,
  but Pod Security `baseline` forbids hostPath volumes, so the namespace needs
  the `privileged` level. Keep the agent in its own namespace for that reason. SELinux-enforcing nodes such as
  Bottlerocket may still deny reads outside `/var/log`; see the
  [chart notes](./helm/wazuh/README.md#agent-daemonset) before you reach for
  `privileged`.
- **Mount what you collect, under `/host`.** Add host paths read-only as the
  group configuration needs them, and nothing else.

## Centralized configuration for the agent group

Paths in the group `agent.conf` are the agent's view, so they carry the `/host`
prefix. On the manager, `/var/ossec/etc/shared/k8s-nodes/agent.conf`:

```xml
<agent_config>
  <syscheck>
    <directories check_all="yes" realtime="yes" report_changes="yes">/host/etc</directories>
    <nodiff type="sregex">\.key$</nodiff>
  </syscheck>
  <localfile>
    <log_format>syslog</log_format>
    <location>/host/var/log/messages</location>
  </localfile>
</agent_config>
```

Check it with `/var/ossec/bin/verify-agent-conf` before saving. The agent
restarts by itself when the group file changes. In the lab, a change to a file
on the host side of a read-only mount raised rule 550 in realtime mode with the
diff attached, so inotify events do reach the agent through the bind mount.

Two behaviors to plan for:

- **The first scan after a start is a silent baseline.** A file changed while
  the agent was stopped updates the manager's FIM inventory (new hash,
  `changes` counter) at the next start, but raises no alert. Persisting
  `/var/ossec/queue/fim/db` did not change this in the lab. Frequent pod
  restarts widen that window, so keep rollouts infrequent and review the FIM
  inventory, not only alerts, after maintenance.
- **`<nodiff>` for secrets.** `report_changes` sends file content to the
  indexer. Exclude private keys and credential files.

## Agent identity on nodes that come and go

The agent is named after the node (`spec.nodeName`), and its ID lives in
`client.keys`.

| Event | What happens | Action |
|---|---|---|
| Pod restart or rollout | The key is restored from the hostPath, same agent ID | None |
| Node replaced or scaled in | The new node has a new name and enrolls as a new agent; the old entry stays `disconnected` | Remove old entries with the [stale agent cleanup](../../scripts/agent-management/README.md#stale-agent-cleanup-for-replaced-nodes) CronJob |
| Agent removed on the manager while the node still runs | The agent reconnects, is rejected, and enrolls again under a new ID within seconds | None, but its history continues under the new ID |
| Key lost but entry still present (hostPath wiped) | Enrollment under the same name is refused until the old agent has been disconnected for `<auth><force><disconnected_time>` (1h by default). Agent: `Duplicate agent name: <AGENT_NAME>. Unable to add agent (from manager)`. Manager: `Agent '005' can't be replaced since it is not disconnected.` | Wait, or remove the old entry |

Wazuh 4.x has no setting that deletes long-disconnected agents. The
`<auth><force>` options only govern replacing an agent that enrolls again with
the same name or IP. On autoscaled node groups the cleanup job is therefore part
of the deployment, not an afterthought.

The entrypoint copies the key back to the state directory every 30 seconds and
on stop. A symlink does not work: the agent replaces `client.keys` when it
enrolls, which turns the link into a regular file.

## Enrollment: password or API

| | `authd` password (port 1515) | API insert (port 55000) |
|---|---|---|
| Secret on every node | Enrollment password: can only enroll agents | API credentials: as much as the API user can do |
| Network | 1515 to the master | 55000 to the master |
| Agent ID on re-enrollment | New ID unless the key was kept | Can reuse an ID with `POST /agents/insert` and `force` |
| Moving parts | None beyond the agent | A script that inserts the agent, imports the key with `manage_agents -i`, then restarts |

Use the password. Choose the API path only when 1515 cannot be reached, and then
give it a dedicated API user with `agent:create` and nothing else, never the
`wazuh-wui` administrator. Registration is not the place for cleanup either:
removing stale agents belongs in one scheduled job with a scoped user, not in
every node's startup.

## Reviewing a community agent image

Community agent images are a reasonable starting point and a common source of
surprises. Check these before deploying one, here with the findings from a
review of
[pyToshka/docker-wazuh-agent](https://github.com/pyToshka/docker-wazuh-agent)
(agent 4.14.1, checked in October 2026):

| Check | What to look for | Found in that image |
|---|---|---|
| Credentials on nodes | API user or admin credentials in node pods | Registers through the API with a user and password in every pod, `wazuh-wui` in the examples |
| TLS | Certificate verification for every API call | `WAZUH_API_SSL_VERIFY` defaults to false |
| Side effects at startup | Writes or deletes beyond the agent's own entry | When a pod finds its previous entry, it deletes it, then deletes every agent in any group that has been disconnected or never connected for 21 days, and inserts itself again |
| Health probe | The probe endpoint actually answers | The health server on port 5000 has no GET handler, so every request drops the connection. The repository's DaemonSet probes `/healz`, so the liveness probe would fail and restart each pod about every 90 seconds (40 s delay plus five failed checks), repeating the startup deletions each time |
| Configuration scope | Paths and modules that describe the host | Monitors `/etc` and `/var/log/auth.log` of the container, not `/host`, and runs syscollector, SCA and rootcheck against the image |
| Manager-side settings | Blocks that do nothing on an agent | `<auth>` and a VirusTotal `<integration>` in the agent `ossec.conf`, plus OpenSCAP and CIS-CAT wodles with Java in the image |
| Remote commands | `wazuh_command.remote_commands=1` or `logcollector.remote_commands=1` | Enabled, so anyone who edits the group `agent.conf` can run commands as root on every node |
| Pod privileges | `privileged`, `hostPID`, `hostIPC`, writable host mounts | All three, plus `/var/run` and `/dev` from the host mounted read-write |
| Image source | Pinned tag or digest from a registry you trust | The DaemonSet pulls `kennyopennix/wazuh-agent:latest` with `imagePullPolicy: Always`, while the README publishes `opennix/wazuh-agent` |

The health-probe finding is easy to confirm without a cluster: run a
`BaseHTTPRequestHandler` subclass with no `do_GET` and a `log_message` that
raises, and a client sees `RemoteDisconnected` instead of an HTTP status.

What is worth keeping from that design is the idea of tying agent identity to
the node name and of cleaning up after replaced nodes. This guide does both
without API credentials on the nodes.

## EKS Fargate: ship logs to CloudWatch

EKS Fargate gives you no nodes to manage, so a DaemonSet (and FIM) cannot run.
Instead, send container logs to CloudWatch and pull them in with the Wazuh
[CloudWatch Logs module](https://documentation.wazuh.com/current/cloud-security/amazon/services/supported-services/cloudwatchlogs.html).

1. Set up Fargate logging as described in the [official EKS documentation](https://docs.aws.amazon.com/eks/latest/userguide/fargate-logging.html). You need an existing namespace and a [Fargate pod execution role](https://docs.aws.amazon.com/eks/latest/userguide/fargate-getting-started.html#fargate-sg-pod-execution-role).
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

3. Create the log-router ConfigMap (`aws-logging-cloudwatch-configmap.yaml`) with the [CloudWatch Fluent Bit plugin](https://github.com/aws/amazon-cloudwatch-logs-for-fluent-bit). Fill in the `OUTPUT` section for your region and log group:

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

4. Create an IAM policy that allows `logs:CreateLogStream`, `logs:CreateLogGroup`, `logs:DescribeLogStreams`, and `logs:PutLogEvents` ([example permissions.json](https://raw.githubusercontent.com/aws-samples/amazon-eks-fluent-logging-examples/mainline/examples/fargate/cloudwatchlogs/permissions.json)), then attach it to the Fargate pod execution role.

> **Note:** every pod under profiles that use this execution role and policy sends logs to CloudWatch. After you change pod configuration, recreate the pod so logging picks up the change.

## Related

- [Wazuh agent deployment - DaemonSet and sidecar](./wazuh-agent-deployment.md) - the official image and manifests, and the upgrade fix for seeded hostPaths
- [Agent DaemonSet in the Helm chart](./helm/wazuh/README.md#agent-daemonset) - the same model as chart values, plus SELinux notes for Bottlerocket
- [Stale agent cleanup](../../scripts/agent-management/README.md#stale-agent-cleanup-for-replaced-nodes) - scoped API user and CronJob
- [Agent on a Kubernetes node](./agent-on-node.md) - the native agent where the node OS allows it
- [FIM in containerized environments](../../fim/containers.md) - what FIM can see from a container
- [Enrollment key conflicts](../../troubleshooting/agents/enrollment-key-conflicts.md) - duplicate names and `<force>` behavior
- [Wazuh on Amazon EKS](./eks.md)
