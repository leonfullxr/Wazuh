# Wazuh - Docker

Docker Compose configurations, deployment patterns, and troubleshooting for Wazuh multi-node and single-node clusters.

## Configurations

| Folder | Description |
|--------|-------------|
| [`single-node/`](./single-node/) | Minimal all-in-one deployment for labs and small environments |
| [`daemonset/`](./daemonset/) | Wazuh agent deployed as a DaemonSet-style container across hosts |
| [`ldap/`](./ldap/) | Manager configuration with LDAP/Active Directory authentication integration |
| [`soc-nginx/`](./soc-nginx/) | Nginx reverse proxy in front of the Wazuh Dashboard for SOC-facing deployments |

## Guides & troubleshooting

| Guide | Description |
|-------|-------------|
| [Archives disabled after container update](./archives-disabled-after-update.md) | `wazuh-archives-*` indices stop receiving data after image upgrades due to `filebeat.yml` being regenerated at container startup |
| [Network & proxy debugging](./network-proxy-debugging.md) | Inspecting container networking, service-to-service reachability, and HTTP proxy connectivity in Wazuh compose stacks |
