# Wazuh Troubleshooting

Operational troubleshooting guides for the Wazuh server (manager) and agents, distilled from real-world support scenarios. Each guide is written as a symptom-driven runbook: what you see, how to confirm the root cause, and how to fix it.

> Indexer (OpenSearch) troubleshooting - shards, ISM, reindexing, and disk
> watermarks - lives in [`../indexer/`](../indexer/). Certificate generation
> and TLS troubleshooting live in [`../certificates/`](../certificates/).

## Table of Contents

- [Quick symptom lookup](#quick-symptom-lookup)
- [Agents](#agents)
- [Server / manager](#server--manager)
- [Access and authentication](#access-and-authentication)
- [Useful tooling](#useful-tooling)

## Quick symptom lookup

| Symptom | Guide |
|---|---|
| Agents show `Disconnected` or `Never connected` in the dashboard | [agents/disconnections.md](agents/disconnections.md) |
| Agent connects but forwards no logs; manager flips it to `Disconnected` on bulk transfer | [agents/disconnections.md](agents/disconnections.md#agent-connects-but-forwards-no-logs-mtu--path-mtu-black-hole) |
| Agent enrolls on-prem but fails from an AWS/cloud VPC (`Could not resolve hostname` / `Invalid password`) | [agents/disconnections.md](agents/disconnections.md#agent-enrolls-on-prem-but-not-from-a-cloud-vpc) |
| `SSL routines::wrong version number` on 1514/1515 behind an AWS NLB/load balancer | [agents/aws-load-balancer.md](agents/aws-load-balancer.md#use-tcp-listeners-not-tls) |
| Agents unevenly balanced or failing across AWS Availability Zones | [agents/aws-load-balancer.md](agents/aws-load-balancer.md#balance-evenly-across-availability-zones) |
| Agent keeps re-registering instead of reconnecting | [agents/disconnections.md](agents/disconnections.md#agents-stuck-in-a-re-registration-loop) |
| Agents mass-disconnect but the service is running and `ossec.log` shows only log rotation | [agents/disconnections.md](agents/disconnections.md#agents-disconnected-but-the-service-is-running-stuck-enrollment) |
| `authd` handshake fails with `unexpected eof while reading` on 1515 | [certificates/troubleshooting.md](../certificates/troubleshooting.md#agent-connectivity-on-15141515) |
| `Duplicate agent name` / agent key already in use warnings | [agents/enrollment-key-conflicts.md](agents/enrollment-key-conflicts.md) |
| `authd` rejects enrollment: `duplicate name ... registration time` or `... not disconnected` | [agents/enrollment-key-conflicts.md](agents/enrollment-key-conflicts.md#decoding-authd-enrollment-rejections) |
| Agent stuck `never_connected`: `Waiting for server reply` then `SSL read (unable to receive message)` | [agents/enrollment-key-conflicts.md](agents/enrollment-key-conflicts.md#enrollment-loops-and-the-duplicate-name-storm) |
| `Invalid password` enrollment storm, or `Too many connections. Rejecting.` on authd | [agents/enrollment-key-conflicts.md](agents/enrollment-key-conflicts.md#decoding-authd-enrollment-rejections) |
| `Agent buffer is full` warnings, events dropped at the agent | [agents/flooding.md](agents/flooding.md) |
| A handful of rules generate most of your alert volume | [agents/flooding.md](agents/flooding.md#step-2-reduce-noise-at-the-source) |
| macOS agent collects nothing useful / needs health metrics | [agents/macos.md](agents/macos.md) |
| Windows registry monitoring misses changes or creates noise | [agents/windows-registry.md](agents/windows-registry.md) |
| Remote agent upgrade fails with WPK certificate or `Send lock restart error` | [agents/custom-wpk.md](agents/custom-wpk.md) |
| `events_dropped` / `discarded_count` non-zero on the manager | [server/analysisd.md](server/analysisd.md) |
| Events dropped only in short bursts, or one cluster node saturates while others idle | [server/analysisd.md](server/analysisd.md#the-eps-limit-limitseps-throttles-bursts) |
| Need to measure how many events per second the manager receives | [server/analysisd.md](server/analysisd.md#measuring-eps) |
| Syslog ingestion overloads one node / uneven load across cluster workers | [../integrations/syslog/README.md](../integrations/syslog/README.md#load-balancing-syslog-across-cluster-workers) |
| Vulnerability data stale, missing, or `/var/ossec/queue` bloated | [server/vulnerability-detection.md](server/vulnerability-detection.md) |
| `queue/indexer/` grows tens of GB per node and never drains (SST files pile up) | [server/indexer-connector-queue-growth.md](server/indexer-connector-queue-growth.md) |
| `indexer-connector: The request is too large` / `was repaired because it was corrupt` | [server/indexer-connector-queue-growth.md](server/indexer-connector-queue-growth.md) |
| `wazuh-states-inventory-packages` shows only partial agent/package coverage | [server/indexer-connector-queue-growth.md](server/indexer-connector-queue-growth.md#inventory-packages-partial-coverage-after-a-reset) |
| Email alerts not delivered (Postfix / Office 365) | [server/postfix-email.md](server/postfix-email.md) |
| Agent fails to start on a hardened host (`noexec` on `/var`) | [server/mount-permissions.md](server/mount-permissions.md) |
| Lost the API or indexer `admin` password | [passwords-recovery.md](passwords-recovery.md) |
| LDAP / Active Directory login to the dashboard fails | [ldap-ad.md](ldap-ad.md) |
| TLS, `bad_certificate`, certificate-chain, or HTTPS failures | [Certificate troubleshooting](../certificates/troubleshooting.md) |
| SAML login fails, returns ACS 404/500, or works intermittently | [SAML SSO](../certificates/sso-saml.md) |
| Need a multi-site failover and failback procedure | [Disaster recovery](../upgrading/disaster-recovery.md) |

## Agents

- [Disconnections](agents/disconnections.md) - connectivity tests for ports 1514/1515, log checks on both sides, and fixing re-registration loops with `force_reconnect_interval` / `time-reconnect`.
- [AWS load balancer (NLB/ALB)](agents/aws-load-balancer.md) - TCP-vs-TLS listeners (`wrong version number`), cross-zone balancing across Availability Zones, health checks, and stickiness for agents behind an AWS load balancer.
- [Enrollment and key conflicts](agents/enrollment-key-conflicts.md) - duplicate IDs, key mismatches, roaming laptops/VPN clients, and force re-enrollment.
- [Flooding and noisy alerts](agents/flooding.md) - how the agent buffer works, finding the noisy source, tuning `client_buffer`, and silencing noisy rules or Windows event IDs.
- [macOS agents](agents/macos.md) - unified log collection queries and CPU/memory/disk/network health metrics via `full_command`.
- [Windows registry monitoring](agents/windows-registry.md) - registry FIM scope, value checks, exclusions, and verification.
- [Custom WPK and remote upgrades](agents/custom-wpk.md) - renewing the WPK root CA on agents and recovering failed remote upgrades.

## Server / manager

- [Analysisd, EPS, and dropped events](server/analysisd.md) - statistics files, queue/thread tuning, memory sizing of queues, measuring EPS, and when to scale out.
- [Vulnerability Detection](server/vulnerability-detection.md) - how the VD queues work internally, diagnostics to collect, full state reset, and fixing stale per-agent data.
- [IndexerConnector queue growth](server/indexer-connector-queue-growth.md) - `queue/indexer/` never drains: telling a real drain failure (missing keystore, unclean-shutdown corruption, oversized bulks) from expected steady-state growth, resetting a cluster cleanly, and repopulating inventory-packages coverage.
- [Postfix email delivery](server/postfix-email.md) - diagnosing SMTP relay failures with tcpdump; firewall resets vs. Postfix misconfiguration.
- [Mount permissions](server/mount-permissions.md) - running Wazuh under a `noexec` `/var` partition with a dedicated `exec` mount.

## Access and authentication

- [Password reset and recovery](passwords-recovery.md) - Wazuh API users, indexer internal users, the Filebeat keystore, and restoring a previous password from backup.
- [LDAP / Active Directory](ldap-ad.md) - preparing AD (OUs, bind user, access group), and fixing TLS hostname-verification failures.

## Disaster recovery

- [Disaster recovery](../upgrading/disaster-recovery.md) - active/passive site design, LB/DNS/AWS ELB failover, replication, failback (also [planning checklist](../upgrading/deployment-architecture.md#disaster-recovery)).

## Useful tooling

- [`../scripts/diagnosis/`](../scripts/diagnosis/) - collects a full diagnostic report (manager, indexer, cluster, agents) and runs an upgrade-readiness healthcheck. Run this first when opening any investigation.
- [`../scripts/EPS/`](../scripts/EPS/) - real-time events-per-second measurement script for the manager.
