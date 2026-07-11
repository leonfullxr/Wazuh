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
| [Upgrading Agents](upgrading-agents.md) | Fleet-wide agent upgrades via the RESTful API or the `agent_upgrade` CLI |
| [Deployment Architecture](deployment-architecture.md) | Planning questions, hardware prerequisites, firewall ports, and connectivity requirements |
| [Disaster Recovery](disaster-recovery.md) | Active/passive multi-site DR: load-balancer failover, configuration and data sync between sites, and failback |
| [Health Check](healthcheck.md) | Per-component verification commands for the manager, Filebeat, indexer, and dashboard |
| [Sizing](sizing.md) | Capacity planning: the questionnaire, EPS, retention, and reference points |
| [Wazuh 5.0 Migration FAQ](qa-5.0.md) | 4.x → 5.0 architectural changes and migration checklist |

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
| Upgrading an agent fleet | [Agent upgrade runbook](upgrading-agents.md) |
| Designing ports, nodes, or component placement | [Deployment architecture](deployment-architecture.md) |
| Estimating resources and retention | [Sizing](sizing.md) and [Indexer optimization](../indexer/README.md) |
| Planning site failover and failback | [Disaster recovery](disaster-recovery.md) |
| Assessing Wazuh 5.0 migration impact | [Wazuh 5.0 migration FAQ](qa-5.0.md) |
