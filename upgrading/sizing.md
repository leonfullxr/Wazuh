# Sizing

## Table of Contents
- [Introduction](#introduction)
- [Sizing Questionnaire](#sizing-questionnaire)
- [Reference Points](#reference-points)

## Introduction

Capacity planning for a Wazuh deployment. Size against the expected **events per second (EPS) and retention requirements**, not just the agent count - log-heavy sources (firewalls via syslog, cloud modules such as AWS or Azure) usually dominate the ingest volume.

## Sizing Questionnaire

Gather these numbers before choosing hardware:

- **Number of workstations** - if possible, broken down by OS.
- **Number of servers** - also broken down by OS if possible.
- **Number of network devices** (firewalls, switches, routers shipping syslog).
- **Cloud monitoring?** If so, an estimation of the events per second (EPS) it will generate.
- **Alerts hot storage retention period.**
- **Alerts cold storage retention period.**
- **Archives hot storage retention period.**
- **Archives cold storage retention period.**
- **Is high availability a requirement?**

## Reference Points

- The official [installation requirements](https://documentation.wazuh.com/current/installation-guide/wazuh-server/index.html) and [quickstart](https://documentation.wazuh.com/current/quickstart.html) pages carry the hardware tables (protected endpoints vs. cores/RAM/disk). Use them as a starting point, then adjust for EPS and retention.
- When sizing a replacement for an existing environment, **measure the actual EPS** on the current one rather than estimating. A quick approximation: compare `wazuh-analysisd` totals in `/var/ossec/var/run/wazuh-analysisd.state` over an interval, or divide the daily alert index growth by 86400.
- The retention answers map directly to index lifecycle management: hot vs. cold tiers and deletion policies on the `wazuh-alerts-*` and `wazuh-archives-*` indices determine the bulk of the disk requirement.
- **High availability** implies a Wazuh manager cluster, a multi-node indexer cluster, and a load balancer (e.g. NGINX in TCP/stream mode) distributing agent traffic on ports 1514/1515 across the manager nodes - see [Deployment Architecture](deployment-architecture.md) for the port matrix.
