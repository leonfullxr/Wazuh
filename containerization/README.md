# Wazuh containerization

This section covers deployment, configuration, and troubleshooting for Wazuh running in containerised environments. Each platform has its own dedicated guide covering deployment patterns, known issues, and tested mitigations.

## Platforms

| Folder | Description |
|--------|-------------|
| [`docker/`](./docker/README.md) | Docker Compose deployments — single-node, multi-node cluster, and specialised configurations |
| [`kubernetes/`](./kubernetes/README.md) | Kubernetes deployments — StatefulSet-based clusters, ConfigMap patterns, and upgrade guidance |

## Other files in this section

| File | Description |
|------|-------------|
| [`FIM.md`](./FIM.md) | File Integrity Monitoring configuration notes for containerised agents |
| `puppet.txt` | Puppet-based provisioning notes for Wazuh agent deployment |

## General notes

- All Docker Compose examples target **Wazuh 4.x** and have been tested on 4.12–4.14.
- Kubernetes manifests follow the official Wazuh single-index multi-node layout (Manager + Worker + 3 Indexers).
- Where a fix or workaround targets a specific Wazuh version range, it is noted inline in the relevant README.
- Configurations marked `:ro` (read-only mounts) are intentional — they prevent the container entrypoint from overwriting customisations at runtime.
