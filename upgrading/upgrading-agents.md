# Upgrading Agents

## Table of Contents
- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Upgrading via the API (Dashboard Dev Tools)](#upgrading-via-the-api-dashboard-dev-tools)
- [Upgrading via the CLI](#upgrading-via-the-cli)
- [Troubleshooting: Agents Disappear After a Manager Restart](#troubleshooting-agents-disappear-after-a-manager-restart)

## Introduction

Wazuh agents can be upgraded centrally, either through the dashboard's API console (RESTful API) or directly on the manager with the `agent_upgrade` CLI. After receiving the upgrade command, agents automatically restart and report back with their new version.

Official reference: [Upgrading Wazuh agents - Wazuh documentation](https://documentation.wazuh.com/current/upgrade-guide/wazuh-agent/index.html).

## Prerequisites

- **Upgrade the central components first** — see the [Pre-Upgrade Checklist](pre-upgrade-checklist.md). Agents can never be upgraded to a version higher than the manager.
- Agents must be **active** (connected) to receive the upgrade command.
- The manager fetches the WPK upgrade packages from `packages.wazuh.com`, so it needs outbound access to that host. For air-gapped setups, build and host a [custom WPK package](https://documentation.wazuh.com/current/user-manual/agent/agent-management/remote-upgrading/create-custom-wpk.html) internally.

## Upgrading via the API (Dashboard Dev Tools)

1. In the Wazuh dashboard, open the API console:

   > **Note:** Since 4.8 the dashboard menu changed — the console lives under **Server management > Dev Tools**. On older versions it is **Tools > API Console**.

2. Trigger an upgrade of all agents:

   ```
   PUT /agents/upgrade?agents_list=all
   ```

   You can also target specific agents with a comma-separated list, e.g. `agents_list=001,002`.

3. Verify the result:

   ```
   GET /agents/upgrade_result
   ```

## Upgrading via the CLI

On the Wazuh manager node:

1. List agents running an outdated version:

   ```bash
   /var/ossec/bin/agent_upgrade -l
   ```

2. Upgrade one or more agents by ID:

   ```bash
   /var/ossec/bin/agent_upgrade -a 001 002
   ```

3. Each upgraded agent restarts automatically. Confirm the new version:

   ```bash
   /var/ossec/bin/agent_control -i <AGENT_ID>
   ```

## Troubleshooting: Agents Disappear After a Manager Restart

If agents appear in the dashboard right after a manager restart but then vanish, it usually points to one or more of the following:

1. Wazuh services (manager, indexer, dashboard) not running — check `systemctl status` on each.
2. A misconfiguration in `ossec.conf`.
3. Errors in the indexer or in Filebeat. When Filebeat fails, alerts stop being visible on the dashboard even though agents keep reporting.

Work through the [Health Check](healthcheck.md) commands per component to find where the pipeline breaks.
