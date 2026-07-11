# Upgrading and Deployment

Operational guides for planning, deploying, upgrading, and verifying a Wazuh environment.

## Contents

| Guide | Description |
|---|---|
| [Pre-Upgrade Checklist](pre-upgrade-checklist.md) | Backups, health checks, and compatibility verification before touching anything |
| [Upgrading Agents](upgrading-agents.md) | Fleet-wide agent upgrades via the RESTful API or the `agent_upgrade` CLI |
| [Deployment Architecture](deployment-architecture.md) | Planning questions, hardware prerequisites, firewall ports, and connectivity requirements |
| [Health Check](healthcheck.md) | Per-component verification commands for the manager, Filebeat, indexer, and dashboard |
| [Sizing](sizing.md) | Capacity planning: the questionnaire, EPS, retention, and reference points |

## Upgrade order

Always upgrade the central components before the agents, in this order (see the [official upgrade guide](https://documentation.wazuh.com/current/upgrade-guide/index.html)):

1. **Wazuh indexer**
2. **Wazuh server** (manager + Filebeat)
3. **Wazuh dashboard**
4. **Wazuh agents** last

Agents must never run a newer version than the manager.
