# Upgrading Wazuh Agents

Agents are the last component in an upgrade, and the only one you upgrade from a distance. This guide covers the version rules, the two upgrade methods, the prerequisites that cause most failures, and how to verify the result.

> **Applies to:** Wazuh agents 4.x on Linux, Windows, and macOS. Upgrade the
> central components first. See the [pre-upgrade checklist](pre-upgrade-checklist.md).

## Table of Contents

- [Version rules](#version-rules)
- [Choose a method](#choose-a-method)
- [Before you start](#before-you-start)
- [Method 1: remote upgrade from the manager](#method-1-remote-upgrade-from-the-manager)
  - [From the command line](#from-the-command-line)
  - [From the API](#from-the-api)
  - [Upgrade in waves](#upgrade-in-waves)
- [Method 2: package manager on the endpoint](#method-2-package-manager-on-the-endpoint)
- [Air-gapped networks](#air-gapped-networks)
- [Verify the result](#verify-the-result)
- [When an upgrade fails](#when-an-upgrade-fails)
- [Rollback](#rollback)
- [Related](#related)

## Version rules

Three rules decide what you can do, and in which order:

1. **An agent must never run a newer version than its manager.** This is the rule that sets the upgrade order. Upgrade the indexer, then the manager, then the dashboard, then the agents.
2. **An agent may run an older version than its manager.** An older agent keeps reporting. It does not gain the capabilities that the new version adds.
3. **Do not leave agents behind indefinitely.** Wazuh supports an agent that lags the manager, but each release widens the gap in decoders, modules, and inventory fields.

A fleet where every agent matches the manager is the goal. A fleet where a few agents lag by one minor version is normal and safe.

## Choose a method

| Method | Use it when | Cost |
|---|---|---|
| Remote upgrade (WPK) from the manager | You control the fleet from Wazuh and the agents are reachable | Needs the WPK signing CA on every agent, and a WPK source the manager can reach |
| Package manager on the endpoint | You already run a patching tool, such as Ansible, Intune, SCCM, or Puppet | Needs the Wazuh repository on every endpoint, and version pinning |
| Manual reinstall | A small number of endpoints, or a repair after a failed upgrade | Manual work per endpoint |

Both automated methods are supported. Pick the one that matches how the rest of the estate is patched. Mixing them across different platforms is normal, for example WPK for Linux servers and a management tool for Windows workstations.

## Before you start

Confirm every item. Most remote-upgrade failures come from the first three.

- [ ] **The central components are upgraded and healthy.** Run the [health check](healthcheck.md) first. Do not upgrade agents against a manager that is still converging.
- [ ] **The agent is `Active`.** A remote upgrade needs a live connection. Check with `/var/ossec/bin/agent_control -l`.
- [ ] **The agent trusts the WPK signing CA.** Agents at 4.3.7 and earlier ship a root CA that Wazuh has since rotated. Those agents reject current WPK packages until you install the new CA. See [WPK certificates](../troubleshooting/agents/custom-wpk.md).
- [ ] **The manager can reach a WPK source.** By default that is `https://packages.wazuh.com`. For a closed network, see [air-gapped networks](#air-gapped-networks).
- [ ] **You recorded a baseline.** Save the current version of every agent before the change, so you can tell what moved:

  ```bash
  /var/ossec/bin/agent_control -l
  ```

## Method 1: remote upgrade from the manager

The manager sends a signed WPK package to the agent. The agent verifies the signature, installs the package, and restarts itself.

### From the command line

Run these on the manager. On a cluster, run them on the master.

List the agents that are behind the manager:

```bash
/var/ossec/bin/agent_upgrade -l
```

Upgrade named agents to the manager version:

```bash
/var/ossec/bin/agent_upgrade -a 004,005,006
```

Pin a specific target version:

```bash
/var/ossec/bin/agent_upgrade -a 004 -v v4.7.4
```

Expected output names both versions, so you can confirm the move:

```text
Upgrading...
Upgraded agents:
     Agent 004 upgraded: Wazuh v4.7.1 -> v4.7.4
```

Run `agent_upgrade --help` for the full option list, including forcing an upgrade and supplying a local WPK file. The options differ between minor versions, so check the binary on the manager rather than a general reference.

### From the API

The API drives the same mechanism and suits scripted rollouts. List the agents that are behind:

```bash
curl -k -X GET "https://<MANAGER_IP>:55000/agents/outdated" \
  -H "Authorization: Bearer $TOKEN"
```

Start the upgrade. The call returns one task per agent and does not wait for the result:

```bash
curl -k -X PUT "https://<MANAGER_IP>:55000/agents/upgrade?agents_list=004,005,006" \
  -H "Authorization: Bearer $TOKEN"
```

Poll for the outcome:

```bash
curl -k -X GET "https://<MANAGER_IP>:55000/agents/upgrade_result?agents_list=004,005,006" \
  -H "Authorization: Bearer $TOKEN"
```

Each agent reports its own task state, so a batch can partly succeed. Read every entry, not the HTTP status of the request. See the [API reference](https://documentation.wazuh.com/current/user-manual/api/reference.html) for the full parameter list, including the target version and a custom WPK repository.

### Upgrade in waves

Never upgrade the whole fleet in one call.

1. Upgrade **one** agent. Verify it reconnects and reports.
2. Upgrade a pilot group of 5 to 10 agents that covers each operating system in the estate.
3. Verify again, then continue in batches.
4. Keep each batch small enough that the manager absorbs the reconnections without a load spike.

Every upgraded agent restarts and reconnects. A large batch produces a reconnection burst on the manager, which looks like an incident and can mask a real failure.

## Method 2: package manager on the endpoint

Install the Wazuh repository on the endpoint, then install a pinned version. Pinning matters, because the repository always offers the newest release, and that release may be newer than your manager.

Debian and Ubuntu:

```bash
apt-get update
apt-get install wazuh-agent=4.7.4-1
```

RHEL, CentOS, and Amazon Linux:

```bash
yum install wazuh-agent-4.7.4-1
```

On Windows and macOS, run the installer for the target version over the existing installation.

Two points apply to every platform:

- **The upgrade keeps the existing `ossec.conf`.** Review the packaged default afterward for options that the new version added. Compare, then merge by hand. Do not replace a working configuration with the default.
- **Hold the package afterward** if the endpoint patches itself automatically. An unattended upgrade can push an agent past the manager version and break rule 1. On Debian and Ubuntu use `apt-mark hold wazuh-agent`, and on RHEL family systems set `exclude=wazuh-agent` in the repository file between upgrades.

## Air-gapped networks

A remote upgrade needs the manager to reach a WPK source, not the agents. The agents only need to reach the manager. This makes WPK a good fit for a closed network, because you supply the packages once on the manager.

Two options:

- **Supply a local WPK file.** Copy the WPK onto the manager and pass it to `agent_upgrade`. Run `agent_upgrade --help` for the option name in your version.
- **Host an internal WPK repository.** Mirror the package layout on an internal HTTP server, then point the upgrade at it with the custom repository parameter.

Both routes still verify the package signature on the agent, so the WPK signing CA must be present. To build and sign your own packages, see the [custom WPK documentation](https://documentation.wazuh.com/current/user-manual/agent/agent-management/remote-upgrading/custom-wpk-packages.html).

## Verify the result

Check from the manager first, because that is the view the dashboard shows:

```bash
/var/ossec/bin/agent_control -l
/var/ossec/bin/agent_control -i <AGENT_ID>
```

Or query the API for a version report across the fleet:

```bash
curl -k -X GET "https://<MANAGER_IP>:55000/agents?select=id,name,version,status" \
  -H "Authorization: Bearer $TOKEN"
```

Then confirm on one endpoint of each platform:

```bash
/var/ossec/bin/wazuh-control info
```

An agent that reports the new version and returns to `Active` is upgraded. An agent that reports the new version and stays `Disconnected` has a connectivity problem, not an upgrade problem. See [disconnections](../troubleshooting/agents/disconnections.md).

## When an upgrade fails

| Signature | Likely cause |
|---|---|
| Certificate or signature verification errors | The agent trusts an old WPK root CA. See [WPK certificates](../troubleshooting/agents/custom-wpk.md) |
| `Send lock restart error`, `Send open file error` | Packet loss or resets between agent and manager, not a corrupt package |
| The task never leaves the in-progress state | The agent lost its connection during the transfer. Confirm it is `Active`, then retry |
| The agent refuses the target version | The requested version is newer than the manager, or older than the agent |
| Nothing happens and no task appears | The agent was not `Active` when the call ran |

Retry a failed agent **one at a time** with the target version pinned. A batch retry hides which agent failed and why.

## Rollback

A WPK upgrade has no remote rollback. The manager cannot downgrade an agent.

To return an endpoint to its previous version, install the older package and keep `client.keys`. The agent then keeps its identity and does not enroll again.

1. Back up `client.keys` and `ossec.conf` from the agent.
2. Uninstall the current agent package.
3. Install the previous version.
4. Restore the two files and restart the agent.

Because rollback is manual and per endpoint, the pilot group in [upgrade in waves](#upgrade-in-waves) is the real safeguard. Find the problem on 5 endpoints, not on 1000.

## Related

- [Pre-upgrade checklist](pre-upgrade-checklist.md) - backups and health checks for the central components
- [Health check](healthcheck.md) - per-component verification before and after the change
- [Deployment architecture](deployment-architecture.md) - the ports and the internet access an upgrade needs
- [WPK certificates and remote upgrade failures](../troubleshooting/agents/custom-wpk.md) - the WPK root CA, and recovery from a failed upgrade
- [Agent disconnections](../troubleshooting/agents/disconnections.md) - an agent that upgrades but does not reconnect
- [Official agent upgrade guide](https://documentation.wazuh.com/current/upgrade-guide/wazuh-agent/index.html)
