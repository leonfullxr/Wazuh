# Wazuh - Kubernetes

Kubernetes deployment patterns, ConfigMap-based configuration management, and troubleshooting for Wazuh multi-node clusters running as StatefulSets.

> This section is being actively built out. Manifests and further deployment guides will be added here. Contributions are welcome.

## Guides & troubleshooting

| Guide | Description |
|-------|-------------|
| [Archives disabled after pod update](./archives-disabled-after-update.md) | `wazuh-archives-*` indices stop receiving data after image upgrades due to `filebeat.yml` being regenerated at pod startup; ConfigMap + `subPath` mitigation |
