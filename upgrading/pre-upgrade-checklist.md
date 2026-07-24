# Pre-Upgrade Checklist

## Table of Contents
- [Introduction](#introduction)
- [Upgrade Order](#upgrade-order)
- [Health Check First](#health-check-first)
- [Backups](#backups)
  - [Wazuh Manager](#wazuh-manager)
  - [Filebeat](#filebeat)
  - [Wazuh Indexer](#wazuh-indexer)
  - [Wazuh Dashboard](#wazuh-dashboard)
- [Verifying Installed Package Versions](#verifying-installed-package-versions)
- [Large Version Jumps: Fresh-Cluster Migration](#large-version-jumps-fresh-cluster-migration)
- [Final Notes](#final-notes)

## Introduction

Before upgrading a Wazuh environment, verify that everything is healthy and take backups of every component's configuration and state. Upgrading on top of an environment with pre-existing errors makes any post-upgrade issue much harder to diagnose, and without backups there is no clean rollback path.

Also confirm you have working admin credentials at hand before starting: the indexer `admin` user, the Wazuh API user, and SSH access to every node.

Official reference: [Upgrade guide - Wazuh documentation](https://documentation.wazuh.com/current/upgrade-guide/index.html).

## Upgrade Order

Upgrade the central components in this order, and the agents last:

1. Wazuh indexer
2. Wazuh server (manager + Filebeat)
3. Wazuh dashboard
4. Wazuh agents, see [Upgrading Agents](upgrading-agents.md)

Agents must never end up on a newer version than the manager.

## Health Check First

Run the full per-component verification in [Health Check](healthcheck.md) before the upgrade, fix anything that is not green, and run it again after the upgrade to compare. As a minimum:

```bash
# Indexer reachable and cluster nodes visible
curl -k -u admin:<PASSWORD> https://<WAZUH_INDEXER_IP>:9200
curl -k -u admin:<PASSWORD> https://<WAZUH_INDEXER_IP>:9200/_cat/nodes?v

# Filebeat can ship to the indexer
filebeat test output

# Manager cluster status (multi-node deployments)
/var/ossec/bin/cluster_control -l
```

## Backups

If the environment runs on virtual machines, the ideal is to take a complete VM snapshot of each node when possible. In addition (or when snapshots are not an option), back up the following per component.

### Wazuh Manager

- `/var/ossec/api/configuration`
- `/var/ossec/etc`
- `/var/ossec/logs`
- `/var/ossec/queue/rootcheck`
- `/var/ossec/queue/agent-groups`
- `/var/ossec/queue/agent-info`
- `/var/ossec/queue/agents-timestamp`
- `/var/ossec/queue/agentless`
- `/var/ossec/queue/cluster`
- `/var/ossec/queue/rids`
- `/var/ossec/queue/fts`
- `/var/ossec/var/multigroups`

> **Note:** On Wazuh 4.4 and later, `/var/ossec/queue/agent-groups` and `/var/ossec/queue/agent-info` no longer exist: group assignments now live inside `global.db`. It is fine if those two directories are missing.

The following must be copied with the manager service stopped to guarantee database consistency:

- `/var/ossec/var/db/global.db`
- `/var/ossec/queue/db`

```bash
systemctl stop wazuh-manager
# copy the two paths above
systemctl start wazuh-manager
```

### Filebeat

On the manager node(s):

- `/etc/filebeat/filebeat.yml`
- `/etc/filebeat/wazuh-template.json`
- `/etc/filebeat/certs/`

### Wazuh Indexer

- `/etc/wazuh-indexer/opensearch.yml`
- `/etc/systemd/system/wazuh-indexer.service`
- `/etc/wazuh-indexer/jvm.options`
- `/etc/wazuh-indexer/certs/`
- `/etc/wazuh-indexer/opensearch-security/` (internal users, roles, RBAC configuration)

### Wazuh Dashboard

- `/etc/wazuh-dashboard/opensearch_dashboards.yml`
- `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml`
- `/etc/wazuh-dashboard/certs/`

You can also export custom dashboards and visualizations from Management > Saved Objects: they are stored in the `.kibana` index.

> **Note:** In current 4.x versions the Wazuh app configuration lives at `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml`, not the older `plugins/wazuh/wazuh.yml` path.

## Verifying Installed Package Versions

Record the currently installed versions so you know exactly what you are upgrading from.

Debian/Ubuntu:

```bash
dpkg -l | grep wazuh
dpkg -s wazuh-manager
apt-cache policy wazuh-manager
```

RHEL/CentOS/Fedora:

```bash
rpm -qa | grep '^wazuh'
rpm -qi wazuh-manager
dnf list installed 'wazuh*'   # or: yum list installed 'wazuh*'
```

## Large Version Jumps: Fresh-Cluster Migration

When an environment is only a version or two behind, an in-place upgrade in the order above is the normal path. When it is several major versions behind (for example, moving a 4.2-era cluster to the current 4.x release), building a fresh cluster at the target version and cutting agents over to it (a "blue/green" migration) is often safer than a long chain of sequential in-place upgrades. The running environment stays untouched as a fallback, and you validate the new one before any cutover.

> **Note:** When you provision the target cluster, remember the topology constraints: a cluster has exactly one master node (scale out by adding worker nodes), while multiple dashboard nodes are supported.

### Carry over only what agents need to reconnect

If you do not need to migrate historical data (only enough state for existing agents to reconnect without re-enrolling), restore these paths from the old server onto the new one:

- `/var/ossec/etc` - the important one. Contains `client.keys` (agent identities/keys), `ossec.conf`, custom `rules/`, `decoders/`, `lists/*.cdb`, and the `shared/` group configuration. Restoring it lets existing agents reconnect without re-enrollment.
- `/var/ossec/var/multigroups` - multi-group membership mapping.
- `/var/ossec/api/configuration` - API configuration.
- `/var/ossec/integrations`, `/var/ossec/wodles`, `/var/ossec/active-response/bin`, `/var/ossec/agentless` - custom integrations, wodles, active-response binaries, and agentless scripts.

Reapply the correct ownership (`root:wazuh`) and permissions after copying, then restart the manager.

> **Note:** Agent group membership storage changed between versions. On 4.2-era releases it lived under `/var/ossec/queue/agent-groups/`; on current 4.x releases membership is tracked in `global.db` and the group *configuration* lives under `/var/ossec/etc/shared/`. Do not expect the old `agent-groups/` directory to exist on the new cluster: restoring `/var/ossec/etc/shared/` and letting the manager rebuild membership is the supported path.

### Do not overwrite newer defaults

Copy your customizations, not the old default files. Restoring an old `ossec.conf` or old default rule/decoder files wholesale over a newer version can reintroduce removed options or mask new defaults. Merge your changes into the files shipped with the new release, and test custom rules and decoders against the new version with `wazuh-logtest` before cutover.

### Regenerate certificates and repoint agents

- Generate new TLS certificates for the new cluster (manager, indexer, dashboard). Do not reuse the old cluster's certificates.
- Agents and other log sources that point at the old manager IP must be repointed. Either assign the same IP to the new server, or update the manager address on every endpoint. If a load balancer fronts agent traffic, you only need to update its backend (manager) IPs.

### Pre-cutover validation checklist

Before cutting production agents over to the new cluster:

- All services healthy on the new cluster: run the full [Health Check](healthcheck.md).
- Custom rules/decoders produce the expected alerts (`wazuh-logtest`).
- A test agent enrolls, connects, and lands in the correct group.
- Dashboards, saved objects, and alerting all work.
- Release notes for every major version between source and target have been reviewed for breaking changes.
- The old environment is still intact as a rollback target.

For the full backup/restore procedure, see the official [migration guide](https://documentation.wazuh.com/current/migration-guide/index.html).

## Final Notes

- If you are more than one minor version behind, review the [upgrade guide](https://documentation.wazuh.com/current/upgrade-guide/index.html) for version-specific steps: older releases may require intermediate upgrades or additional migration steps. For jumps across several major versions, weigh a fresh-cluster migration (see above) against a long chain of in-place upgrades.
- The vulnerability detection module often needs a re-scan (and sometimes a feed reset) after a major upgrade; verify its state as part of the post-upgrade health check.
- Only proceed to [Upgrading Agents](upgrading-agents.md) once all central components are upgraded and healthy.
