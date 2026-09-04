# Persisting configuration and custom content across pod restarts

**Applies to:** Wazuh 4.x · Kubernetes StatefulSet deployments · [wazuh-kubernetes](https://github.com/wazuh/wazuh-kubernetes) deployment

[Back to Kubernetes README](./README.md)

## The problem

On a bare-metal or VM install, config and customizations survive a restart
because they sit on the host disk. On Kubernetes that only holds for paths
backed by a **PersistentVolume**. Anything written to an ephemeral path is
rebuilt from the image on every pod restart or image upgrade — so edits made
by hand inside a running pod vanish the next time the pod is rescheduled.

Two practical consequences:

1. Anything that must stick around has to be injected declaratively (a
   ConfigMap mount) or written to a path that sits on a PersistentVolume.
2. You need a clear map of which paths in each component are persistent and
   which are not.

## Which paths are persistent?

The storage layout lives in the `wazuh-kubernetes` repository. To see what
each component keeps on a PersistentVolume versus what it rebuilds from the
image, read the volume and `volumeClaimTemplate` definitions in:

- `envs/local-env/` (and the matching overlay for your platform) — StorageClass
  and PVC sizing.
- `wazuh/wazuh_managers/` — Manager/Worker StatefulSets, including paths
  mounted onto persistent volumes for rules, decoders, and agent state.
- `wazuh/indexer_stack/` — indexer and dashboard manifests.

Any path that is not a volume mount in these manifests sits on the container's
ephemeral layer and does **not** survive a restart.

## Persisting a config file with a ConfigMap + `subPath`

To keep a single configuration file (not a whole directory), generate a
ConfigMap from it and mount that file onto the exact path with `subPath`. The
file is reapplied every time the container is (re)deployed.

A frequent case is turning on RBAC / `run_as` in the Dashboard, which needs
`run_as: true` in `wazuh.yml` — a value that would otherwise reset on each pod
restart.

**Step 1 — add the file to the ConfigMap generator.** In
`wazuh/kustomization.yml`, list the file under the relevant
`configMapGenerator` entry (for the dashboard, the `dashboard-conf`
generator):

```yaml
configMapGenerator:
  - name: dashboard-conf
    files:
      - opensearch_dashboards.yml
      - wazuh.yml            # add your customized copy here
```

**Step 2 — mount it in the deployment.** In the dashboard deployment
(`wazuh/indexer_stack/wazuh-dashboard/dashboard-deploy.yaml`), mount the file
with `subPath` so only that file is replaced, not the whole directory:

```yaml
volumeMounts:
  - name: config
    mountPath: /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
    subPath: wazuh.yml
    readOnly: false
```

> **Why `subPath`:** without it, Kubernetes swaps the entire target directory
> for the ConfigMap contents and wipes other files the container expects
> there. `subPath` replaces only that one file.

A ConfigMap is its own resource, so every new pod picks it up automatically —
including after an image upgrade. Pods are **not** restarted on their own when
a ConfigMap changes under a `subPath` mount; run
`kubectl rollout restart` on the workload to pick up an edit.

## Custom rules and decoders

Custom rules and decoders can be shipped into every new environment the same
way. The Manager StatefulSet (`wazuh/wazuh_managers/wazuh-master-sts.yaml`)
already mounts the custom rules and decoders paths onto persistent storage, so
content there survives restarts. To bake a fixed set of rules/decoders into
the deployment itself, generate a ConfigMap from those files and mount them
into those paths — one repeatable source of truth you can stamp across
environments.

## Related

- [Archives disabled after pod update](./archives-disabled-after-update.md) - same ConfigMap + `subPath` pattern for `filebeat.yml`, including how to pull the correct default template first
- [AWS credentials via Secrets/ConfigMaps](./aws-credentials.md) - keeping module credentials across pod restarts
- [Wazuh on Amazon EKS](./eks.md) - storage class selection and Kustomize overlay conventions
