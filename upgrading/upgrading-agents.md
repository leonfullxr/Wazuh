# Upgrading Agents

## Table of Contents
- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Upgrading via the API (Dashboard Dev Tools)](#upgrading-via-the-api-dashboard-dev-tools)
- [Upgrading from a Custom WPK Repository](#upgrading-from-a-custom-wpk-repository)
- [Upgrading via the CLI](#upgrading-via-the-cli)
- [Scheduling Automatic Agent Upgrades](#scheduling-automatic-agent-upgrades)
- [Troubleshooting: Agents Disappear After a Manager Restart](#troubleshooting-agents-disappear-after-a-manager-restart)

## Introduction

Wazuh agents can be upgraded centrally, either through the dashboard's API console (RESTful API) or directly on the manager with the `agent_upgrade` CLI. After receiving the upgrade command, agents automatically restart and report back with their new version.

Official reference: [Upgrading Wazuh agents - Wazuh documentation](https://documentation.wazuh.com/current/upgrade-guide/wazuh-agent/index.html).

## Prerequisites

- **Upgrade the central components first** - see the [Pre-Upgrade Checklist](pre-upgrade-checklist.md). Agents can never be upgraded to a version higher than the manager.
- Agents must be **active** (connected) to receive the upgrade command.
- The manager fetches the WPK upgrade packages from `packages.wazuh.com`, so it needs outbound access to that host. For air-gapped setups, build and host a [custom WPK package](https://documentation.wazuh.com/current/user-manual/agent/agent-management/remote-upgrading/create-custom-wpk.html) internally - see [Upgrading from a Custom WPK Repository](#upgrading-from-a-custom-wpk-repository).

## Upgrading via the API (Dashboard Dev Tools)

1. In the Wazuh dashboard, open the API console:

   > **Note:** Since 4.8 the dashboard menu changed - the console lives under **Server management > Dev Tools**. On older versions it is **Tools > API Console**.

2. Trigger an upgrade of all agents:

   ```
   PUT /agents/upgrade?agents_list=all
   ```

   You can also target specific agents with a comma-separated list, e.g. `agents_list=001,002`.

3. Verify the result:

   ```
   GET /agents/upgrade_result
   ```

## Upgrading from a Custom WPK Repository

When the manager cannot (or should not) reach `packages.wazuh.com` - air-gapped networks, or environments that mirror packages internally - point the upgrade request at an internal WPK repository with the `wpk_repo` parameter:

```http
PUT /agents/upgrade?agents_list=all&wpk_repo=wpk-repo.example.com:8080/wazuh/wpk/&use_http=true&wait_for_complete=true
```

- `wpk_repo` - host (and optional port/path) of the internal repository. It must mirror the directory layout of the official WPK repository.
- `use_http=true` - required when the internal repository is served over plain HTTP instead of HTTPS.
- `wait_for_complete=true` - makes the API call block until the upgrade tasks are dispatched, which is convenient when the call is issued from a script.

The same parameters are accepted by the `agent_upgrade` CLI (`-r <REPO>` and `--http`). See [Create a custom WPK package](https://documentation.wazuh.com/current/user-manual/agent/agent-management/remote-upgrading/create-custom-wpk.html) for building and hosting the packages.

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

## Scheduling Automatic Agent Upgrades

Agent upgrades can be automated so that any agent falling behind the target version is upgraded on a schedule, without manual API calls. The pattern is a script that calls the Wazuh API upgrade endpoint, executed periodically by the manager's [command wodle](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-command.html).

1. Write a script (Python is convenient - the manager ships its own interpreter at `/var/ossec/framework/python/bin/python3`) that:
   - Authenticates against the Wazuh API (`https://<WAZUH_MANAGER_IP>:55000`) with a dedicated API user.
   - Lists active agents running a version older than the target version.
   - Calls `PUT /agents/upgrade` for those agents (add `wpk_repo`/`use_http` if you use an internal repository).

2. Place it on the **master node** and restrict its permissions - it contains or reads API credentials:

   ```bash
   cp custom-upgrade_wazuh_agents.py /var/ossec/integrations/
   chown root:wazuh /var/ossec/integrations/custom-upgrade_wazuh_agents.py
   chmod 750 /var/ossec/integrations/custom-upgrade_wazuh_agents.py
   ```

3. Schedule it in the master node's `ossec.conf`:

   ```xml
   <wodle name="command">
     <tag>Automatic agents upgrade</tag>
     <command>/var/ossec/framework/python/bin/python3 /var/ossec/integrations/custom-upgrade_wazuh_agents.py</command>
     <time>08:00</time>
     <run_on_start>no</run_on_start>
     <ignore_output>yes</ignore_output>
   </wodle>
   ```

   This runs the script every day at 08:00; adjust `<time>` (or use `<interval>`) to fit your maintenance windows.

Keep the target version pinned to the manager's version - an automated job must never try to push agents past the manager. Do not hardcode credentials in configuration management playbooks; store them securely and validate the script in a test environment before enabling it in production.

## Troubleshooting: Agents Disappear After a Manager Restart

If agents appear in the dashboard right after a manager restart but then vanish, it usually points to one or more of the following:

1. Wazuh services (manager, indexer, dashboard) not running - check `systemctl status` on each.
2. A misconfiguration in `ossec.conf`.
3. Errors in the indexer or in Filebeat. When Filebeat fails, alerts stop being visible on the dashboard even though agents keep reporting.

Work through the [Health Check](healthcheck.md) commands per component to find where the pipeline breaks.
