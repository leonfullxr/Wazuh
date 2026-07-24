<!-- Support: WS-26647 -->

# Disaster Recovery Architecture

Runbook for an active/passive Wazuh deployment: a primary site handles production traffic; a standby DR site at another location takes over when the primary is lost. Agents and log sources should target a stable front-end (load balancer hostname or DNS name), not a manager IP directly, so failover is transparent.

See also [Deployment Architecture](deployment-architecture.md) for sizing and firewall ports.

## Table of Contents

- [Goals](#goals)
- [Architecture overview](#architecture-overview)
- [Security](#security)
- [What must be replicated](#what-must-be-replicated)
- [Keeping the two sites in sync](#keeping-the-two-sites-in-sync)
- [Failover patterns](#failover-patterns)
  - [Load balancer (ALB / NGINX / AWS ELB)](#load-balancer-alb--nginx--aws-elb)
  - [DNS failover](#dns-failover)
- [Lifecycle](#lifecycle)
- [Failback and data recovery](#failback-and-data-recovery)
- [Planning checklist](#planning-checklist)
- [Documentation](#documentation)

## Goals

- **High availability:** continue operating when the primary site is unreachable.
- **Data redundancy:** replicate manager configuration and, optionally, indexer data so the DR site is not empty at cutover.
- **Fast recovery:** automate detection and traffic switch via health checks (LB or DNS); recovery time depends entirely on what you implement upstream of Wazuh.

## Architecture overview

| Component | Role |
|---|---|
| **Primary site** | Live manager cluster, indexer, dashboard. Agents report here; alerts are generated here under normal operation. |
| **DR site** | Mirror environment, kept ready to take over. Sized to carry full production load, not a thin standby. |
| **Front-end** | Load balancer or DNS name that agents use instead of a manager IP. Routes to primary when healthy; to DR when primary fails. |

Only one site generates alerts at a time when agents report solely to the primary. The DR indexer may still receive a copy of events (see [Indexer data](#indexer-data-and-alerts)) without duplicate alerting.

## Security

- **Firewall rules** on both sites must allow agent ports (see [port matrix](#port-matrix)) and block everything else.
- **API access:** restrict source IPs that can reach the Wazuh API on the DR environment.
- **Encryption:** agent traffic uses Wazuh's AES-encrypted protocol (1514/1515). Terminate TLS on the LB or dashboard/API as required (443/55000).
- **Responsibility split:** Wazuh supports the product stack (manager cluster, indexer, dashboard). The customer typically owns automation for LB/DNS failover and cross-site data sync unless covered by a separate SOW.

## What must be replicated

Replicate to the DR manager before you rely on failover:

- Agent enrollment data (`client.keys`, agent name, ID, group membership)
- Group configuration
- Custom rules and decoders
- Custom CDB lists
- Custom SCA policies

Use a single source of truth outside both sites (commonly a Git repository): the primary pushes configuration; the DR site pulls the same content after cutover or continuously.

## Keeping the two sites in sync

The load balancer or DNS layer only routes traffic. It does not sync configuration or indexer data.

### Configuration

Maintain one authoritative config store (Git is the usual pattern). On failover, the DR managers must already have (or quickly receive) the same rules, decoders, groups, and agent keys as the primary.

### Indexer data and alerts

By default, indexer data is not synchronized between sites, and only the primary generates alerts while agents point there.

To avoid an empty DR indexer at cutover, run a second Filebeat output on the primary managers that forwards events to the DR indexer nodes in parallel with the primary indexer. This keeps a continuous copy without duplicate alerts from both sites during normal operation.

> **Note:** Historical alerts created at the DR site during an outage exist only there until failback. Use [Wazuh alert backups](https://wazuh.com/blog/recover-your-data-using-wazuh-alert-backups/) to recover that window into the primary if needed.

## Failover patterns

Choose one front-end mechanism and document activation/failback before go-live.

### Load balancer (ALB / NGINX / AWS ELB)

**When to use:** You want health-check-driven failover with minimal agent reconfiguration. Agents keep connecting to the same LB VIP or hostname.

**How it works:**

1. LB listens on agent-facing ports and forwards to the primary manager pool when health checks pass.
2. Health checks fail (HTTP/TCP to manager API, agent port, or a dedicated health endpoint) so traffic shifts to the DR pool.
3. After primary recovery, health checks succeed again so traffic returns (automatic or manual, depending on product).

**NGINX (open source):** provides passive health checks only. Active health checks (required for reliable automatic failover/failback) need [NGINX Plus](https://docs.nginx.com/nginx/admin-guide/load-balancer/http-health-check/) or another LB with active probes. See [NGINX in a Wazuh cluster](https://wazuh.com/blog/nginx-load-balancer-in-a-wazuh-cluster/).

**AWS ELB (external to your DC):** common for hybrid primary on-prem + DR in cloud (or both in AWS).

- **Listeners:** TCP 1514/1515 for agents; HTTPS 443 for API/dashboard as needed. [NLB](https://aws.amazon.com/blogs/aws/new-application-load-balancing-via-ip-address-to-aws-on-premises-resources/) supports TCP to on-prem targets.
- **Health checks:** target primary pool; on failure, route to DR targets.
- **Security groups:** restrict sources to authorized agent networks.
- **IAM:** least-privilege roles for ELB to target registration.
- **Optional:** Auto Scaling groups, cross-zone load balancing for zone resilience.
- **Operations:** CloudWatch alarms when failover triggers.

**Wazuh Cloud as DR:** same LB pattern; agent metadata (keys, name, ID) is replicated by the Cloud service. Ports differ slightly, see [port matrix](#port-matrix).

### DNS failover

**When to use:** Agents resolve a DNS name to the manager front-end; you switch the A/AAAA record (or use a DNS provider with health-checked failover) instead of an in-path LB.

**How it works:**

1. Normal operation: DNS resolves to primary site IPs.
2. Monitoring detects primary failure: DNS record updates to DR site IPs (TTL affects propagation delay).
3. Failback: restore primary, verify health, flip DNS back.

**Considerations:**

- Agent and enrollment traffic may cache DNS; keep TTL low for the manager hostname used at enrollment time.
- Test failover and failback regularly; DNS-only designs often need runbook discipline.
- Same [replication](#what-must-be-replicated) and [port](#port-matrix) requirements as the LB pattern.

## Lifecycle

Applies to both LB and DNS designs:

| Phase | Actions |
|---|---|
| **Normal operation** | Front-end routes to primary. Replicate config (and optionally indexer data). Run health checks continuously. |
| **Activation** | Primary fails health checks, so front-end points to DR. DR site serves agents and generates alerts. |
| **DR operation** | Monitor DR capacity. Operate as production until failback. |
| **Failback** | Restore primary; sync any DR-only data (alerts, config drift); gradually or fully shift front-end back to primary; DR returns to standby. |
| **Ongoing** | Test failover on a schedule. Update runbooks when architecture changes. |

## Failback and data recovery

When the primary is repaired:

1. Sync configuration and agent state from DR (or from Git) so primary matches DR.
2. Recover alerts generated only on the DR site during the outage: [alert backup recovery](https://wazuh.com/blog/recover-your-data-using-wazuh-alert-backups/).
3. Re-enable health checks and redirect the front-end to primary (gradual redirect is safer for large fleets).

## Port matrix

| Port | On-prem primary / DR | Wazuh Cloud DR |
|---|---|---|
| 1514/TCP | Agent event channel | Agent event channel |
| 1515/TCP | Agent enrollment | Not used (Cloud enrollment model) |
| 55000/TCP | Wazuh API | - |
| 443/TCP | Dashboard / API over HTTPS | API and dashboard |

The front-end (LB or DNS target) must accept the ports your agents and operators use and forward to the active site.

## Planning checklist

- [ ] Choose failover mechanism: cloud LB with active health checks, NGINX Plus, DNS failover, or AWS ELB.
- [ ] Define a configuration source of truth (Git) and wire both sites to it.
- [ ] Replicate [mandatory manager data](#what-must-be-replicated).
- [ ] Decide whether the DR indexer is continuously fed (second Filebeat output) or rebuilt from backups at cutover.
- [ ] Document activation and failback procedures; assign owners for LB/DNS vs Wazuh stack.
- [ ] Size DR for full production load.
- [ ] Restrict API and dashboard access on both sites.
- [ ] **Test failover** at least once before relying on DR in production.

## Documentation

- [Wazuh architecture](https://documentation.wazuh.com/current/getting-started/architecture.html)
- [Recover data using Wazuh alert backups](https://wazuh.com/blog/recover-your-data-using-wazuh-alert-backups/)
- [NGINX load balancer in a Wazuh cluster](https://wazuh.com/blog/nginx-load-balancer-in-a-wazuh-cluster/)
- [NGINX HTTP health checks](https://docs.nginx.com/nginx/admin-guide/load-balancer/http-health-check/)
- [AWS Elastic Load Balancing](https://aws.amazon.com/elasticloadbalancing/)

## See also

- [Deployment Architecture](deployment-architecture.md) - sizing and firewall baseline
- [Pre-Upgrade Checklist](pre-upgrade-checklist.md) - backup practices before major changes
- [Agent disconnections](../troubleshooting/agents/disconnections.md) - verify 1514/1515 after failover
- [Agent deployment](../scripts/agent-deployment/README.md) - mass enrollment; keys must exist on DR
- [Certificate troubleshooting](../certificates/troubleshooting.md) - TLS on API/dashboard in both sites
- [Password recovery](../troubleshooting/passwords-recovery.md) - if DR was restored from backup without credentials
