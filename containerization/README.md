# Wazuh containerization

This section covers deployment, configuration, persistence, and
troubleshooting for Wazuh running in containerized environments. Docker and
Kubernetes have separate hubs because their storage, networking, rollout, and
failure models differ substantially.

Start from the official Wazuh image and manifests for the target release.
Apply environment-specific changes as reviewed overlays, keep secrets outside
the repository, and verify persistent data plus cluster health before and
after every rollout.

## Platforms

| Folder | Description |
|--------|-------------|
| [`docker/`](./docker/README.md) | Docker Compose deployments - single-node, multi-node cluster, network/proxy debugging, and specialised configurations |
| [`kubernetes/`](./kubernetes/README.md) | Kubernetes deployments - StatefulSet clusters, managed platforms (EKS, AKS, GKE, OpenShift), agent deployment models, config persistence, and cluster debugging |

## Other files in this section

| File | Description |
|------|-------------|
| [`FIM.md`](./FIM.md) | File Integrity Monitoring in containerized environments - what FIM can and cannot do per agent deployment model, volumes vs bind mounts, and centralized syscheck configuration |
| `puppet.txt` | Puppet-based provisioning notes for Wazuh agent deployment |

## Quick reference

| Need | Guide |
|---|---|
| Docker deployment or migration | [Docker hub](./docker/README.md) |
| EKS, AKS, GKE, or OpenShift | [Kubernetes hub](./kubernetes/README.md) |
| Persist custom rules, decoders, or dashboard settings | [Kubernetes persistence](./kubernetes/persistent-storage.md) |
| Diagnose pod, DNS, or service failures | [Kubernetes debugging](./kubernetes/cluster-debugging.md) |
| Understand FIM coverage in containers | [Container FIM](./FIM.md) |

## General notes

- All Docker Compose examples target **Wazuh 4.x** and have been tested on 4.12–4.14.
- Kubernetes manifests follow the official Wazuh single-index multi-node layout (Manager + Worker + 3 Indexers).
- Where a fix or workaround targets a specific Wazuh version range, it is noted inline in the relevant README.
- Configurations marked `:ro` (read-only mounts) are intentional - they prevent the container entrypoint from overwriting customisations at runtime.
