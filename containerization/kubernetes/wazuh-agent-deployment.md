# Wazuh agent deployment on Kubernetes

**Applies to:** Wazuh 4.x - Kubernetes (EKS, self-managed, k3s)

[Back to Kubernetes README](./README.md)

## Overview

The Wazuh agent can be deployed natively within a Kubernetes cluster to monitor workloads, pods, and container activity at runtime. Two deployment models are supported depending on the monitoring scope required.

| Model | Scope | Best for |
|-------|-------|----------|
| [DaemonSet](#daemonset-deployment) | One agent per node - monitors the node and all containers on it | Full-cluster coverage, general-purpose monitoring |
| [Sidecar](#sidecar-deployment) | One agent per pod - monitors a specific application only | Targeted monitoring of sensitive workloads, isolated log collection |

### How agent configuration works in both models

Both deployment models use the same core init container pattern, with the DaemonSet manifest adding one extra permissions-fix step:

1. **`cleanup-ossec-stale`** - removes stale PID and lock files from previous runs to ensure a clean start
2. **`seed-ossec-tree`** - on first run, copies the full `/var/ossec` tree from the image into the persistent volume; skipped on subsequent starts if data already exists
3. **`write-ossec-config`** - generates `ossec.conf` at runtime using environment variables for the manager address, port, and agent name
4. **`fix-authd-pass-perms`** - copies the enrollment password from a Kubernetes Secret into the agent's expected path with correct ownership
5. **`fix-permissions`** - adjusts ownership and permissions on the mounted agent data so the DaemonSet deployment can start with the expected filesystem access

The main container then starts the agent against the pre-configured data volume.

## Prerequisites

- A running Wazuh Manager cluster with external load balancer IPs exposed for ports `1514` (agent communication) and `1515` (enrollment)
- The enrollment password configured on the Wazuh Manager at `/var/ossec/etc/authd.pass`
- `kubectl` access to the target cluster with permissions to create Namespaces, DaemonSets/StatefulSets, Secrets, and (for sidecar) PersistentVolumeClaims

Before deploying, identify the two external IPs you will need:

```bash
# Wazuh worker load balancer - used for agent traffic (port 1514)
kubectl get svc -n wazuh wazuh-workers

# Wazuh manager load balancer - used for enrollment (port 1515)
kubectl get svc -n wazuh wazuh
```

## DaemonSet deployment

The DaemonSet model deploys one agent per node automatically. New nodes added to the cluster receive an agent without any manual intervention.

### Manifest

Save as `wazuh-agent-daemonset.yaml`. Replace `<EXTERNAL_IP_WAZUH_WORKER>` and `<EXTERNAL_IP_WAZUH>` with the values retrieved above.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: wazuh-daemonset
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: wazuh-agent
  namespace: wazuh-daemonset
spec:
  selector:
    matchLabels:
      app: wazuh-agent
  template:
    metadata:
      labels:
        app: wazuh-agent
    spec:
      serviceAccountName: default
      terminationGracePeriodSeconds: 20

      initContainers:
        - name: cleanup-ossec-stale
          image: busybox:1.36
          imagePullPolicy: IfNotPresent
          command: ["/bin/sh", "-lc"]
          args:
            - |
              set -e
              echo "[init] Cleaning old locks..."
              mkdir -p /agent/var/run /agent/queue/ossec
              rm -f /agent/var/run/*.pid || true
              rm -f /agent/queue/ossec/*.lock || true
          volumeMounts:
            - name: ossec-data
              mountPath: /agent

        - name: seed-ossec-tree
          image: wazuh/wazuh-agent:4.14.5
          imagePullPolicy: IfNotPresent
          command: ["/bin/sh", "-lc"]
          args:
            - |
              set -e
              echo "[init] Checking if seeding is required..."
              if [ ! -d /agent/bin ]; then
                echo "[init] Seeding /var/ossec to hostPath..."
                tar -C /var/ossec -cf - . | tar -C /agent -xpf -
              else
                echo "[init] Existing data found, skipping seed"
              fi
          volumeMounts:
            - name: ossec-data
              mountPath: /agent

        - name: fix-permissions
          image: busybox:1.36
          imagePullPolicy: IfNotPresent
          command: ["/bin/sh", "-lc"]
          args:
            - |
              set -e
              echo "[init] Fixing permissions..."
              for d in etc logs queue var rids tmp "active-response"; do
                [ -d "/agent/$d" ] && chown -R 999:999 "/agent/$d"
              done
              chown -R 0:0 /agent/bin /agent/lib || true
              find /agent/bin -type f -exec chmod 0755 {} \; || true
          volumeMounts:
            - name: ossec-data
              mountPath: /agent

        - name: write-ossec-config
          image: busybox:1.36
          imagePullPolicy: IfNotPresent
          env:
            - name: WAZUH_MANAGER
              value: "<EXTERNAL_IP_WAZUH_WORKER>"
            - name: WAZUH_PORT
              value: "1514"
            - name: WAZUH_PROTOCOL
              value: "tcp"
            - name: WAZUH_REGISTRATION_SERVER
              value: "<EXTERNAL_IP_WAZUH>"
            - name: WAZUH_REGISTRATION_PORT
              value: "1515"
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
          command: ["/bin/sh", "-lc"]
          args:
            - |
              set -e
              echo "[init] Writing ossec.conf..."
              mkdir -p /agent/etc
              cat > /agent/etc/ossec.conf <<EOF
              <ossec_config>
                <client>
                  <server>
                    <address>${WAZUH_MANAGER}</address>
                    <port>${WAZUH_PORT}</port>
                    <protocol>${WAZUH_PROTOCOL}</protocol>
                  </server>
                  <enrollment>
                    <enabled>yes</enabled>
                    <agent_name>${NODE_NAME}</agent_name>
                    <manager_address>${WAZUH_REGISTRATION_SERVER}</manager_address>
                    <port>${WAZUH_REGISTRATION_PORT}</port>
                    <authorization_pass_path>/var/ossec/etc/authd.pass</authorization_pass_path>
                  </enrollment>
                </client>
              </ossec_config>
              EOF
              chown 999:999 /agent/etc/ossec.conf
              chmod 0640 /agent/etc/ossec.conf
          volumeMounts:
            - name: ossec-data
              mountPath: /agent

        - name: fix-authd-pass-perms
          image: busybox:1.36
          imagePullPolicy: IfNotPresent
          command: ["/bin/sh", "-lc"]
          args:
            - |
              set -e
              echo "[init] Copying authd.pass from Secret..."
              mkdir -p /agent/etc
              cp /secret/authd.pass /agent/etc/authd.pass
              chown 0:999 /agent/etc/authd.pass
              chmod 0640 /agent/etc/authd.pass
          volumeMounts:
            - name: ossec-data
              mountPath: /agent
            - name: wazuh-authd-pass
              mountPath: /secret/authd.pass
              subPath: authd.pass
              readOnly: true

      containers:
        - name: wazuh-agent
          image: wazuh/wazuh-agent:4.14.5
          imagePullPolicy: IfNotPresent
          command: ["/bin/sh", "-lc"]
          args:
            - |
              set -e
              ln -sf /var/ossec/etc/ossec.conf /etc/ossec.conf || true
              exec /init
          env:
            - name: WAZUH_MANAGER
              value: "<EXTERNAL_IP_WAZUH_WORKER>"
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
          securityContext:
            runAsUser: 0
            allowPrivilegeEscalation: true
            capabilities:
              add: ["SETGID", "SETUID"]
          volumeMounts:
            - name: varlog
              mountPath: /var/log
              readOnly: true
            - name: ossec-data
              mountPath: /var/ossec

      volumes:
        - name: varlog
          hostPath:
            path: /var/log
            type: Directory
        - name: ossec-data
          hostPath:
            path: /var/lib/wazuh
            type: DirectoryOrCreate
        - name: wazuh-authd-pass
          secret:
            secretName: wazuh-authd-pass
```

> **hostPath note:** The DaemonSet uses a `hostPath` volume at `/var/lib/wazuh` on each node for agent data. This means agent state is local to the node and is lost if the node is terminated (e.g., in auto-scaling groups). This is generally acceptable for DaemonSet agents since re-enrollment is automatic, but be aware of duplicate agent entries in the Wazuh Manager if nodes are frequently replaced.

### Deployment steps

```bash
# 1. Create the namespace
kubectl create namespace wazuh-daemonset

# 2. Create the enrollment password Secret
#    Replace 'password' with the value from /var/ossec/etc/authd.pass on the Manager
kubectl create secret generic wazuh-authd-pass \
  -n wazuh-daemonset \
  --from-literal=authd.pass=password

# 3. Deploy
kubectl apply -f wazuh-agent-daemonset.yaml
```

### Verification

```bash
# Confirm one pod per node
kubectl get pods -n wazuh-daemonset -o wide

# Expected - one pod per node, all Running:
# NAME                READY   STATUS    RESTARTS   AGE   IP          NODE
# wazuh-agent-t2fwl   1/1     Running   0          2m    10.42.0.9   node-1
# wazuh-agent-xk9pl   1/1     Running   0          2m    10.42.1.3   node-2

# Inspect agent logs for enrollment confirmation
kubectl logs -n wazuh-daemonset -l app=wazuh-agent --tail=50
```

On the Wazuh Manager, confirm agent registration:

```bash
/var/ossec/bin/agent_control -l
```

## Sidecar deployment

The sidecar model runs the Wazuh agent as a companion container inside a specific application pod, sharing the pod's network namespace and, optionally, its log volumes. This is shown below using Apache Tomcat as the example application.

Key differences from the DaemonSet model:

- Uses a **PersistentVolumeClaim** for agent data rather than a hostPath, making it suitable for managed node pools where hostPath access may be restricted
- Agent name is derived from `metadata.name` (the pod name) rather than the node name
- A shared `application-data` volume allows the agent container to read application logs directly

### Manifest

Save as `wazuh-agent-sidecar.yaml`. Replace `<EXTERNAL_IP_WAZUH_WORKER>` and `<EXTERNAL_IP_WAZUH>` before applying.

> **StorageClass note:** the manifest uses `storageClassName: gp2`, which is the default for AWS EKS. Check available StorageClasses in your cluster and update accordingly before applying:
> ```bash
> kubectl get sc
> ```

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: wazuh-sidecar
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: tomcat-wazuh-agent
  namespace: wazuh-sidecar
spec:
  serviceName: tomcat-app
  replicas: 1
  selector:
    matchLabels:
      app: tomcat-wazuh-agent
  template:
    metadata:
      labels:
        app: tomcat-wazuh-agent
    spec:
      terminationGracePeriodSeconds: 20
      securityContext:
        fsGroup: 999
        fsGroupChangePolicy: OnRootMismatch

      initContainers:
        - name: cleanup-ossec-stale
          image: busybox:1.36
          imagePullPolicy: IfNotPresent
          securityContext:
            runAsUser: 0
          command: ["/bin/sh", "-lc"]
          args:
            - |
              set -e
              mkdir -p /agent/var/run /agent/queue/ossec
              rm -f /agent/var/run/*.pid || true
              rm -f /agent/queue/ossec/*.lock || true
          volumeMounts:
            - name: wazuh-agent-data
              mountPath: /agent

        - name: seed-ossec-tree
          image: wazuh/wazuh-agent:4.14.5
          imagePullPolicy: IfNotPresent
          securityContext:
            runAsUser: 0
          command: ["/bin/sh", "-lc"]
          args:
            - |
              set -e
              if [ ! -d /agent/bin ]; then
                echo "Seeding /var/ossec into PVC..."
                tar -C /var/ossec -cf - . | tar -C /agent -xpf -
              else
                echo "Existing Wazuh data found, skipping seed."
              fi
          volumeMounts:
            - name: wazuh-agent-data
              mountPath: /agent

        - name: write-ossec-config
          image: busybox:1.36
          imagePullPolicy: IfNotPresent
          securityContext:
            runAsUser: 0
          env:
            - name: WAZUH_MANAGER
              value: "<EXTERNAL_IP_WAZUH_WORKER>"
            - name: WAZUH_PORT
              value: "1514"
            - name: WAZUH_PROTOCOL
              value: "tcp"
            - name: WAZUH_REGISTRATION_SERVER
              value: "<EXTERNAL_IP_WAZUH>"
            - name: WAZUH_REGISTRATION_PORT
              value: "1515"
            - name: WAZUH_AGENT_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
          command: ["/bin/sh", "-lc"]
          args:
            - |
              set -e
              mkdir -p /agent/etc
              cat > /agent/etc/ossec.conf <<'EOF'
              <ossec_config>
                <client>
                  <server>
                    <address>${WAZUH_MANAGER}</address>
                    <port>${WAZUH_PORT}</port>
                    <protocol>${WAZUH_PROTOCOL}</protocol>
                  </server>
                  <enrollment>
                    <enabled>yes</enabled>
                    <agent_name>${WAZUH_AGENT_NAME}</agent_name>
                    <manager_address>${WAZUH_REGISTRATION_SERVER}</manager_address>
                    <port>${WAZUH_REGISTRATION_PORT}</port>
                    <authorization_pass_path>/var/ossec/etc/authd.pass</authorization_pass_path>
                  </enrollment>
                </client>
                <localfile>
                  <log_format>syslog</log_format>
                  <location>/usr/local/tomcat/logs/catalina.out</location>
                </localfile>
              </ossec_config>
              EOF

              sed -i \
                -e "s|\${WAZUH_MANAGER}|${WAZUH_MANAGER}|g" \
                -e "s|\${WAZUH_PORT}|${WAZUH_PORT}|g" \
                -e "s|\${WAZUH_PROTOCOL}|${WAZUH_PROTOCOL}|g" \
                -e "s|\${WAZUH_REGISTRATION_SERVER}|${WAZUH_REGISTRATION_SERVER}|g" \
                -e "s|\${WAZUH_REGISTRATION_PORT}|${WAZUH_REGISTRATION_PORT}|g" \
                -e "s|\${WAZUH_AGENT_NAME}|${WAZUH_AGENT_NAME}|g" \
                /agent/etc/ossec.conf

              chown 999:999 /agent/etc/ossec.conf
              chmod 0640 /agent/etc/ossec.conf
          volumeMounts:
            - name: wazuh-agent-data
              mountPath: /agent

        - name: fix-authd-pass-perms
          image: busybox:1.36
          imagePullPolicy: IfNotPresent
          securityContext:
            runAsUser: 0
          command: ["/bin/sh", "-lc"]
          args:
            - |
              set -e
              mkdir -p /agent/etc
              cp /secret/authd.pass /agent/etc/authd.pass
              chown 0:999 /agent/etc/authd.pass
              chmod 0640 /agent/etc/authd.pass
          volumeMounts:
            - name: wazuh-agent-data
              mountPath: /agent
            - name: wazuh-authd-pass
              mountPath: /secret/authd.pass
              subPath: authd.pass
              readOnly: true

      containers:
        - name: tomcat
          image: tomcat:10.1-jdk17
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 8080
          volumeMounts:
            - name: application-data
              mountPath: /usr/local/tomcat/logs

        - name: wazuh-agent
          image: wazuh/wazuh-agent:4.14.5
          imagePullPolicy: IfNotPresent
          lifecycle:
            preStop:
              exec:
                command: ["/bin/sh", "-lc", "/var/ossec/bin/ossec-control stop || true; sleep 2"]
          command: ["/bin/sh", "-lc"]
          args:
            - |
              set -e
              ln -sf /var/ossec/etc/ossec.conf /etc/ossec.conf
              exec /init
          env:
            - name: WAZUH_MANAGER
              value: "<EXTERNAL_IP_WAZUH_WORKER>"
            - name: WAZUH_PORT
              value: "1514"
            - name: WAZUH_PROTOCOL
              value: "tcp"
            - name: WAZUH_REGISTRATION_SERVER
              value: "<EXTERNAL_IP_WAZUH>"
            - name: WAZUH_REGISTRATION_PORT
              value: "1515"
            - name: WAZUH_AGENT_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
          securityContext:
            runAsUser: 0
            runAsGroup: 0
          volumeMounts:
            - name: wazuh-agent-data
              mountPath: /var/ossec
            - name: application-data
              mountPath: /usr/local/tomcat/logs

      volumes:
        - name: wazuh-authd-pass
          secret:
            secretName: wazuh-authd-pass

  volumeClaimTemplates:
    - metadata:
        name: wazuh-agent-data
      spec:
        accessModes: ["ReadWriteOnce"]
        storageClassName: gp2   # Update to match your cluster's StorageClass
        resources:
          requests:
            storage: 3Gi
    - metadata:
        name: application-data
      spec:
        accessModes: ["ReadWriteOnce"]
        storageClassName: gp2   # Update to match your cluster's StorageClass
        resources:
          requests:
            storage: 5Gi
---
apiVersion: v1
kind: Service
metadata:
  name: tomcat-app
  namespace: wazuh-sidecar
spec:
  selector:
    app: tomcat-wazuh-agent
  type: NodePort
  ports:
    - protocol: TCP
      port: 80
      targetPort: 8080
      nodePort: 30013
```

### Deployment steps

```bash
# 1. Check available StorageClasses and update the manifest if needed
kubectl get sc

# 2. Create the namespace
kubectl create namespace wazuh-sidecar

# 3. Create the enrollment password Secret
kubectl create secret generic wazuh-authd-pass \
  -n wazuh-sidecar \
  --from-literal=authd.pass=password

# 4. Deploy
kubectl apply -f wazuh-agent-sidecar.yaml
```

### Verification

```bash
# Confirm both containers in the pod are Running (READY should show 2/2)
kubectl get pods -n wazuh-sidecar

# Expected:
# NAME                     READY   STATUS    RESTARTS   AGE
# tomcat-wazuh-agent-0     2/2     Running   0          30s

# Inspect agent logs
kubectl logs -n wazuh-sidecar tomcat-wazuh-agent-0 -c wazuh-agent --tail=50

# Inspect application logs
kubectl logs -n wazuh-sidecar tomcat-wazuh-agent-0 -c tomcat --tail=50
```

On the Wazuh Manager, confirm agent registration:

```bash
/var/ossec/bin/agent_control -l
```

## Adapting the sidecar to a different application

The Tomcat example can be adapted to any application by modifying three things in the manifest:

1. **Main application container** - replace the `tomcat` container image and its `volumeMounts` with your application
2. **`localfile` block in `write-ossec-config`** - update the `<location>` path to point to your application's log file
3. **`application-data` PVC size** - adjust `storage` under `volumeClaimTemplates` to match expected log volume

Everything else - the init container chain, the Secret mount, the enrollment flow - remains unchanged.