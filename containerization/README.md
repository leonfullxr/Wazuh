# Wazuh containerization

This section covers deployment, configuration, and troubleshooting for Wazuh running in containerised environments. Each platform has its own dedicated guide covering deployment patterns, known issues, and tested mitigations.

## Platforms

| Folder | Description |
|--------|-------------|
| [`docker/`](./docker/README.md) | Docker Compose deployments — single-node, multi-node cluster, network/proxy debugging, and specialised configurations |
| [`kubernetes/`](./kubernetes/README.md) | Kubernetes deployments — StatefulSet clusters, managed platforms (EKS, AKS, GKE), agent deployment models, and cluster debugging |

## Other files in this section

| File | Description |
|------|-------------|
| [`FIM.md`](./FIM.md) | File Integrity Monitoring in containerized environments — what FIM can and cannot do per agent deployment model, volumes vs bind mounts, and centralized syscheck configuration |
| `puppet.txt` | Puppet-based provisioning notes for Wazuh agent deployment |

## General notes

- All Docker Compose examples target **Wazuh 4.x** and have been tested on 4.12–4.14.
- Kubernetes manifests follow the official Wazuh single-index multi-node layout (Manager + Worker + 3 Indexers).
- Where a fix or workaround targets a specific Wazuh version range, it is noted inline in the relevant README.
- Configurations marked `:ro` (read-only mounts) are intentional — they prevent the container entrypoint from overwriting customisations at runtime.
