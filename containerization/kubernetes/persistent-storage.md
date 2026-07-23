# Persisting configuration and custom content across pod restarts

**Applies to:** Wazuh 4.x - Kubernetes StatefulSet deployments - [wazuh-kubernetes](https://github.com/wazuh/wazuh-kubernetes) deployment

[Back to Kubernetes README](./README.md)

## The problem

On a local install, configuration and customizations survive a restart because they live on the host filesystem. In Kubernetes that is only true for paths backed by a **PersistentVolume**. Anything a container writes to an ephemeral path is regenerated from the image on every pod restart or image upgrade - so hand-edited config inside a running pod is silently lost the next time the pod is rescheduled.

Two things follow from this:

1. Customizations that must persist have to be injected declaratively (a ConfigMap mount) or written to a path that is on a PersistentVolume.
2. You need to know which paths in each component are persistent and which are not.

## Which paths are persistent?

The storage layout is defined in the `wazuh-kubernetes` repository itself. To see what each component keeps on a PersistentVolume versus what it regenerates from the image, read the volume and `volumeClaimTemplate` definitions in:

- `envs/local-env/` (and the equivalent overlay for your platform) - the StorageClass and PVC sizing.
- `wazuh/wazuh_managers/` - the Manager/Worker StatefulSets, including the paths mounted onto persistent volumes for rules, decoders, and agent state.
- `wazuh/indexer_stack/` - the indexer and dashboard manifests.

Anything not listed as a volume mount in these manifests lives on the container's ephemeral layer and does **not** survive a restart.

## Persisting a config file with a ConfigMap + `subPath`

The reliable way to persist a single configuration file (rather than a whole directory) is to generate a ConfigMap from it and mount it over the exact file path with `subPath`. This re-applies the file every time the container is (re)deployed.

A common case is enabling RBAC / `run_as` in the Dashboard, which requires `run_as: true` in `wazuh.yml` - a value that would otherwise reset on each pod restart.

**Step 1 - add the file to the ConfigMap generator.** In `wazuh/kustomization.yml`, add the file under the relevant `configMapGenerator` entry (for the dashboard, the `dashboard-conf` generator):

```yaml
configMapGenerator:
  - name: dashboard-conf
    files:
      - opensearch_dashboards.yml
      - wazuh.yml            # add your customized copy here
```

**Step 2 - mount it in the deployment.** In the dashboard deployment (`wazuh/indexer_stack/wazuh-dashboard/dashboard-deploy.yaml`), mount the file with `subPath` so only that file is replaced, not the whole directory:

```yaml
volumeMounts:
  - name: config
    mountPath: /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
    subPath: wazuh.yml
    readOnly: false
```

> **Why `subPath`:** without it, Kubernetes replaces the entire target directory with the ConfigMap contents, wiping other files the container expects there. `subPath` targets the single file only.

Because a ConfigMap is a standalone resource, it is reapplied to every new pod automatically - including after an image upgrade. Note that pods are **not** restarted automatically when the ConfigMap changes under a `subPath` mount; roll the workload manually (`kubectl rollout restart`) to pick up an edit.

## Custom rules and decoders

Custom rules and decoders can be baked into every new environment the same way. The Manager StatefulSet (`wazuh/wazuh_managers/wazuh-master-sts.yaml`) already mounts the paths that hold custom rules and decoders onto persistent storage, so content placed there survives restarts. To ship a fixed set of rules/decoders as part of the deployment itself, generate a ConfigMap from your rule/decoder files and mount them into those paths - giving you a repeatable, single-source-of-truth config you can stamp out across environments.

## Related

- [Archives disabled after pod update](./archives-disabled-after-update.md) - the same ConfigMap + `subPath` technique applied to `filebeat.yml`, including how to extract the correct default template first
- [AWS credentials via Secrets/ConfigMaps](./aws-credentials.md) - persisting module credentials across pod restarts
- [Wazuh on Amazon EKS](./eks.md) - storage class selection and Kustomize overlay conventions
