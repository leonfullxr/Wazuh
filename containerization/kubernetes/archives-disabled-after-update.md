# Archives disabled after pod update

**Applies to:** Wazuh 4.x · Kubernetes StatefulSet deployments (Manager + Worker + Indexers)

[Back to Kubernetes README](./README.md)

## Problem

After you upgrade the Wazuh Manager image and roll the StatefulSet, `wazuh-archives-*` indices stop getting documents in OpenSearch. The Wazuh Dashboard Archives view stays empty even though logs are written to disk. Nothing is lost; ingestion is broken, not storage.

Mounting a ConfigMap straight onto `/etc/filebeat/filebeat.yml` does not stick. The setting flips back to `false` on every pod startup, same pattern as the Docker Compose bind mount case.

## Root cause

Same mechanism as the [Docker variant](../docker/archives-disabled-after-update.md). At every startup the container entrypoint regenerates `/etc/filebeat/filebeat.yml` from a bundled internal template:

```text
Source template (inside image):
  /var/ossec/data_tmp/exclusion/etc/filebeat/filebeat.yml

Written to at startup:
  /etc/filebeat/filebeat.yml   ← standard ConfigMap mounts target this path
```

That write runs after the volume mount is applied, so the ConfigMap is overwritten with no warning. The default template ships with `archives: enabled: false`.

Tracked upstream at [wazuh-docker #2240](https://github.com/wazuh/wazuh-docker/issues/2240).

## Solution - ConfigMap with subPath mount

Mount the ConfigMap over the source template, not the destination, and use `subPath` so you do not replace the whole directory.

> **Why `subPath` is required:** without it, Kubernetes replaces the entire target directory with the ConfigMap contents and wipes other files the container expects there. `subPath` mounts only that one file and leaves the rest of the directory alone.

### Step 1 - Extract the default template

Always start from the full default for your version, not a minimal stub:

```bash
kubectl run --rm -it --image=wazuh/wazuh-manager:<version> extract \
  --restart=Never -- cat /var/ossec/data_tmp/exclusion/etc/filebeat/filebeat.yml
```

### Step 2 - Create the ConfigMap

Create `wazuh-filebeat-configmap.yaml` from the extracted content, with `archives: enabled: true`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: wazuh-filebeat-config
  namespace: wazuh
data:
  filebeat.yml: |
    filebeat.modules:
 - module: wazuh
        alerts:
          enabled: true
        archives:
          enabled: true    # ← change this from false to true
    # Paste the remaining sections from the extracted default here.
```

Apply it:

```bash
kubectl apply -f wazuh-filebeat-configmap.yaml
```

### Step 3 - Mount the ConfigMap in the Manager and Worker StatefulSets

Add the following to `spec.template.spec` in both `wazuh-master-sts.yaml` and `wazuh-worker-sts.yaml`:

```yaml
spec:
  template:
    spec:
      containers:
 - name: wazuh-manager
          volumeMounts:
 - name: filebeat-config
              mountPath: /var/ossec/data_tmp/exclusion/etc/filebeat/filebeat.yml
              subPath: filebeat.yml
              readOnly: true
      volumes:
 - name: filebeat-config
          configMap:
            name: wazuh-filebeat-config
```

Apply and roll:

```bash
kubectl apply -f wazuh-master-sts.yaml
kubectl apply -f wazuh-worker-sts.yaml
kubectl rollout restart statefulset/wazuh-master -n wazuh
kubectl rollout restart statefulset/wazuh-worker -n wazuh
```

## Behaviour across upgrades

The ConfigMap is its own Kubernetes resource. It is not tied to the pod, StatefulSet, or image version. When you bump the Wazuh `image:` tag and roll the StatefulSet, the ConfigMap stays put and the mount is reapplied to new pods automatically. You do not need to re-apply it after an upgrade.

## Upgrade procedure

A new Wazuh version may change the internal template. Before you roll the StatefulSet:

```bash
# Extract the new version's default template
kubectl run --rm -it --image=wazuh/wazuh-manager:<new-version> extract \
  --restart=Never -- cat /var/ossec/data_tmp/exclusion/etc/filebeat/filebeat.yml > /tmp/filebeat-new.yml

# Diff against your current ConfigMap
kubectl get configmap wazuh-filebeat-config -n wazuh \
  -o jsonpath='{.data.filebeat\.yml}' > /tmp/filebeat-current.yml

diff /tmp/filebeat-current.yml /tmp/filebeat-new.yml
```

Update the ConfigMap first, then roll the StatefulSet:

```bash
kubectl apply -f wazuh-filebeat-configmap.yaml
kubectl rollout restart statefulset/wazuh-master -n wazuh
kubectl rollout restart statefulset/wazuh-worker -n wazuh
```

> **ConfigMap hot-reload note:** Kubernetes does not restart pods automatically when a ConfigMap changes if the mount uses `subPath`. Always roll manually after you update the ConfigMap.

## Helm deployments

If Helm manages the cluster, define the ConfigMap as a Helm template under `templates/filebeat-configmap.yaml` and reference it from the StatefulSet template. Then `helm upgrade` carries the ConfigMap forward, and `values.yaml` stays the single source of truth across environments.

## Verification

```bash
# 1. Confirm the configuration is active inside the pod
kubectl exec -n wazuh <wazuh-master-pod> -- \
  cat /etc/filebeat/filebeat.yml | grep -A3 archives

# Expected output:
#     archives:
#       enabled: true

# 2. Test Filebeat connectivity to the indexer
kubectl exec -n wazuh <wazuh-master-pod> -- filebeat test output

# 3. Check for archive indices in OpenSearch
curl -sk -u admin:<password> \
  "https://<indexer-host>:9200/_cat/indices/wazuh-archives-*?v&h=index,health,docs.count"

# 4. If the index is absent, inspect Filebeat logs inside the pod
kubectl exec -n wazuh <wazuh-master-pod> -- tail -f /var/log/filebeat/filebeat
```

## Related

- [Docker variant of this issue](../docker/archives-disabled-after-update.md)
- [wazuh-docker #2240](https://github.com/wazuh/wazuh-docker/issues/2240)
- [Wazuh archives documentation](https://documentation.wazuh.com/current/user-manual/manager/wazuh-archives.html)
