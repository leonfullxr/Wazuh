# Wazuh Troubleshooting

Operational troubleshooting guides for the Wazuh server (manager) and agents, distilled from real-world support scenarios. Each guide is written as a symptom-driven runbook: what you see, how to confirm the root cause, and how to fix it.

> Indexer (OpenSearch) troubleshooting — shards, ILM, reindexing, disk watermarks — lives in [`../indexer/`](../indexer/). Certificate generation and TLS troubleshooting are covered in their own section.

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
| Agent keeps re-registering instead of reconnecting | [agents/disconnections.md](agents/disconnections.md#agents-stuck-in-a-re-registration-loop) |
| `Duplicate agent name` / agent key already in use warnings | [agents/enrollment-key-conflicts.md](agents/enrollment-key-conflicts.md) |
| `Agent buffer is full` warnings, events dropped at the agent | [agents/flooding.md](agents/flooding.md) |
| A handful of rules generate most of your alert volume | [agents/flooding.md](agents/flooding.md#step-2-reduce-noise-at-the-source) |
| macOS agent collects nothing useful / needs health metrics | [agents/macos.md](agents/macos.md) |
| Remote agent upgrade fails with WPK certificate or `Send lock restart error` | [agents/custom-wpk.md](agents/custom-wpk.md) |
| `events_dropped` / `discarded_count` non-zero on the manager | [server/analysisd.md](server/analysisd.md) |
| Need to measure how many events per second the manager receives | [server/analysisd.md](server/analysisd.md#measuring-eps) |
| Vulnerability data stale, missing, or `/var/ossec/queue` bloated | [server/vulnerability-detection.md](server/vulnerability-detection.md) |
| Email alerts not delivered (Postfix / Office 365) | [server/postfix-email.md](server/postfix-email.md) |
| Agent fails to start on a hardened host (`noexec` on `/var`) | [server/mount-permissions.md](server/mount-permissions.md) |
| Lost the API or indexer `admin` password | [passwords-recovery.md](passwords-recovery.md) |
| LDAP / Active Directory login to the dashboard fails | [ldap-ad.md](ldap-ad.md) |

## Agents

- [Disconnections](agents/disconnections.md) — connectivity tests for ports 1514/1515, log checks on both sides, and fixing re-registration loops with `force_reconnect_interval` / `time-reconnect`.
- [Enrollment and key conflicts](agents/enrollment-key-conflicts.md) — duplicate IDs, key mismatches, roaming laptops/VPN clients, and force re-enrollment.
- [Flooding and noisy alerts](agents/flooding.md) — how the agent buffer works, finding the noisy source, tuning `client_buffer`, and silencing noisy rules or Windows event IDs.
- [macOS agents](agents/macos.md) — unified log collection queries and CPU/memory/disk/network health metrics via `full_command`.
- [Custom WPK and remote upgrades](agents/custom-wpk.md) — renewing the WPK root CA on agents and recovering failed remote upgrades.

## Server / manager

- [Analysisd, EPS, and dropped events](server/analysisd.md) — statistics files, queue/thread tuning, memory sizing of queues, measuring EPS, and when to scale out.
- [Vulnerability Detection](server/vulnerability-detection.md) — how the VD queues work internally, diagnostics to collect, full state reset, and fixing stale per-agent data.
- [Postfix email delivery](server/postfix-email.md) — diagnosing SMTP relay failures with tcpdump; firewall resets vs. Postfix misconfiguration.
- [Mount permissions](server/mount-permissions.md) — running Wazuh under a `noexec` `/var` partition with a dedicated `exec` mount.

## Access and authentication

- [Password reset and recovery](passwords-recovery.md) — Wazuh API users, indexer internal users, the Filebeat keystore, and restoring a previous password from backup.
- [LDAP / Active Directory](ldap-ad.md) — preparing AD (OUs, bind user, access group), and fixing TLS hostname-verification failures.

## Useful tooling

- [`../scripts/diagnosis/`](../scripts/diagnosis/) — collects a full diagnostic report (manager, indexer, cluster, agents) and runs an upgrade-readiness healthcheck. Run this first when opening any investigation.
- [`../scripts/EPS/`](../scripts/EPS/) — real-time events-per-second measurement script for the manager.
