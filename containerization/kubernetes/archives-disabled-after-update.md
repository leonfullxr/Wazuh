# Archives disabled after pod update

**Applies to:** Wazuh 4.x, Kubernetes StatefulSet deployments (Manager + Worker + Indexers)

[Back to Kubernetes README](./README.md)

## Problem

After upgrading the Wazuh Manager image and rolling the StatefulSet, `wazuh-archives-*` indices stop receiving documents in OpenSearch. The Wazuh Dashboard shows no data in the Archives view despite logs being written to disk. No data is lost: the issue is with ingestion, not storage.

A ConfigMap mounted to `/etc/filebeat/filebeat.yml` directly has no lasting effect: the setting reverts to `false` on every pod startup, identical to the Docker Compose bind mount behaviour.

## Root cause

Same underlying mechanism as the [Docker variant](../docker/archives-disabled-after-update.md). The container entrypoint regenerates `/etc/filebeat/filebeat.yml` at every startup from a bundled internal template:

```text
Source template (inside image):
  /var/ossec/data_tmp/exclusion/etc/filebeat/filebeat.yml

Written to at startup:
  /etc/filebeat/filebeat.yml   <- standard ConfigMap mounts target this path
```

The write happens after the volume mount is applied, so the ConfigMap is silently overwritten. The default template ships with `archives: enabled: false`.

Tracked upstream at [wazuh-docker #2240](https://github.com/wazuh/wazuh-docker/issues/2240).

## Solution - ConfigMap with subPath mount

Mount the ConfigMap over the source template instead of the destination, using `subPath` to avoid replacing the entire directory.

> **Why `subPath` is required:** without it, Kubernetes replaces the entire target directory with the ConfigMap contents, which destroys other files the container expects at that path. `subPath` targets only the single file, leaving the rest of the directory intact.

### Step 1 - Extract the default template

Always start from the full default for your version rather than a minimal file:

```bash
kubectl run --rm -it --image=wazuh/wazuh-manager:<version> extract \
  --restart=Never -- cat /var/ossec/data_tmp/exclusion/etc/filebeat/filebeat.yml
```

### Step 2 - Create the ConfigMap

Create `wazuh-filebeat-configmap.yaml` using the extracted content, with `archives: enabled: true`:

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
          enabled: true    # <- change this from false to true
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

The ConfigMap is a standalone Kubernetes resource: it is not tied to the pod, StatefulSet, or image version. When you upgrade the Wazuh image by updating the `image:` tag and rolling the StatefulSet, the ConfigMap remains in place and the mount is reapplied to new pods automatically. No manual re-application is required after an upgrade.

## Upgrade procedure

When moving to a new Wazuh version, the internal template may have changed. Before rolling the StatefulSet:

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

> **ConfigMap hot-reload note:** Kubernetes does not automatically restart pods when a ConfigMap changes if the mount uses `subPath`. A manual rollout is always required after updating the ConfigMap.

## Helm deployments

If you manage the cluster via Helm, define the ConfigMap as a Helm template under `templates/filebeat-configmap.yaml` and reference it in the StatefulSet template. This ensures `helm upgrade` carries the ConfigMap forward automatically, giving you a single source of truth in `values.yaml` across environments.

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
