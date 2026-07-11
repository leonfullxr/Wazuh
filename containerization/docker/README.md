# Wazuh - Docker

This section is for administrators running Wazuh central components or agents
with Docker. It covers deployment shape, persistent volumes, upgrades,
networking, reverse proxies, backup, and migration.

Use the official `wazuh-docker` release matching your Wazuh version as the
base. The configurations in this repository are overlays and operational
examples; validate image tags, mounted configuration, credentials, and
certificate paths before deployment.

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
| [Docker Swarm and Portainer](./swarm.md) | Running Wazuh as a Swarm stack: overlay networks, service constraints, and common deployment pitfalls |
| [Backup and migration](./backup-and-migration.md) | Backing up and restoring Wazuh Docker volumes, and migrating a containerized deployment to a new host |

## Quick reference

| Task or symptom | Start here |
|---|---|
| Build a lab or small single-node stack | [Single-node and Traefik overlay](./single-node/README.md) |
| `wazuh-archives-*` stops after an image update | [Archives disabled after update](./archives-disabled-after-update.md) |
| Containers cannot reach each other or an HTTP proxy | [Network and proxy debugging](./network-proxy-debugging.md) |
| Move the deployment to another host | [Backup and migration](./backup-and-migration.md) |
| Run a manager cluster under Docker Swarm | [Docker Swarm](./swarm.md) |
| Put the dashboard behind NGINX | [SOC NGINX proxy](./soc-nginx/README.md) |

Back up named volumes and the deployment configuration before changing image
versions. A container restart is not a backup, and recreating a volume can
permanently remove indexer data or manager state.
