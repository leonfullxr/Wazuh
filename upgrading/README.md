# Upgrading and Deployment

This section is for administrators planning architecture changes, upgrades,
and disaster recovery. The runbooks cover readiness checks, backups, component
order, post-change verification, capacity, and failover.

Treat an upgrade as a controlled change, not a package-manager task. Establish
a healthy baseline, verify backup restoration, read every intermediate release
note, and define rollback criteria before changing the first central
component.

## Contents

| Guide | Description |
|---|---|
| [Pre-Upgrade Checklist](pre-upgrade-checklist.md) | Backups, health checks, and compatibility verification before touching anything |
| [Deployment Architecture](deployment-architecture.md) | Planning questions, hardware prerequisites, firewall ports, and connectivity requirements |
| [Disaster Recovery](disaster-recovery.md) | Active/passive multi-site DR: load-balancer failover, configuration and data sync between sites, and failback |
| [Health Check](healthcheck.md) | Per-component verification commands for the manager, Filebeat, indexer, and dashboard |


## Upgrade order

Always upgrade the central components before the agents, in this order (see the [official upgrade guide](https://documentation.wazuh.com/current/upgrade-guide/index.html)):

1. **Wazuh indexer**
2. **Wazuh server** (manager + Filebeat)
3. **Wazuh dashboard**
4. **Wazuh agents** last

Agents must never run a newer version than the manager.

## Quick reference

| Situation | Start here |
|---|---|
| Preparing any central-component upgrade | [Pre-upgrade checklist](pre-upgrade-checklist.md) |
| Confirming health before or after a change | [Health check](healthcheck.md) |
| Designing ports, nodes, or component placement | [Deployment architecture](deployment-architecture.md) |
| Planning site failover and failback | [Disaster recovery](disaster-recovery.md) |
