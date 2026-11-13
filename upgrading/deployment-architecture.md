# Deployment Architecture

## Table of Contents
- [Introduction](#introduction)
- [Planning Questions](#planning-questions)
- [Prerequisites](#prerequisites)
  - [Reference Architecture](#reference-architecture)
  - [Firewall Ports](#firewall-ports)
- [Internet Connectivity Requirements](#internet-connectivity-requirements)
- [Connecting cloud and remote systems without exposing the cluster](#connecting-cloud-and-remote-systems-without-exposing-the-cluster)
  - [Use cases](#use-cases)
  - [Ports and exposure](#ports-and-exposure)
  - [Agent traffic through a gateway](#agent-traffic-through-a-gateway)
  - [Cloud and SaaS log collection](#cloud-and-saas-log-collection)
  - [SOAR and automation](#soar-and-automation)
  - [Remote access to the dashboard and API](#remote-access-to-the-dashboard-and-api)
  - [Limitations](#limitations)
- [Documentation](#documentation)

## Introduction

Checklist for planning a new Wazuh deployment (or validating an existing one before an upgrade): the questions to answer up front, the minimum architecture, and the network requirements between components.

## Planning Questions

Answer these before provisioning anything:

- Has an architecture **sizing** been done? If not, start with the [Sizing](sizing.md) questionnaire.
- Distributed deployment (recommended) or All-in-One?
- Physical servers or virtual machines?
- If virtual machines: on-premises hypervisor or a cloud provider (AWS, Azure, ...)?
- Traditional deployment or containerized (Docker/Kubernetes)?

## Prerequisites

### Reference Architecture

A minimal distributed deployment (adjust per the [Sizing](sizing.md) outcome):

| Node | Cores | RAM | Disk |
|---|---|---|---|
| Wazuh manager | 8 | 16 GB | 100 GB |
| Wazuh indexer | 8 | 16 GB | 100 GB |

Plus:

- Admin (SSH) access to the target servers.
- Required firewall rules/ports open between components (below).

### Firewall Ports

**Wazuh server**

| Port | Purpose |
|---|---|
| 1514/TCP | Agent connection service (default) |
| 1514/UDP | Agent connection service (optional, disabled by default) |
| 1515/TCP | Agent enrollment service |
| 1516/TCP | Wazuh cluster daemon |
| 514/UDP | Syslog collector (default syslog transport, disabled by default) |
| 514/TCP | Syslog collector (optional, disabled by default) |
| 55000/TCP | Wazuh server RESTful API |

**Wazuh indexer**

| Port | Purpose |
|---|---|
| 9200/TCP | Indexer RESTful API |
| 9300-9400/TCP | Indexer cluster communication |

**Wazuh dashboard**

| Port | Purpose |
|---|---|
| 443/TCP | Web user interface |

## Internet Connectivity Requirements

- **During installation**, internet access is required to download packages. Once installation is complete, the servers can operate without internet access.
- **Vulnerability detection** needs connectivity to the Wazuh CTI service ([https://cti.wazuh.com](https://cti.wazuh.com/)) to fetch vulnerability feeds. It can alternatively be configured with the [offline update method](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/configuring-scans.html).
- **Agent upgrades** require the manager to reach [https://packages.wazuh.com](https://packages.wazuh.com/) - only needed when upgrading agents (see [Upgrading Agents](upgrading-agents.md)).

## Connecting cloud and remote systems without exposing the cluster

Only the agent channel has to be reachable from outside the network: 1514/TCP for events and 1515/TCP for enrollment. Both can be published through a TCP (layer 4) gateway or load balancer in a DMZ, or carried over a site-to-site VPN. The dashboard, server API, indexer, and cluster ports stay private. The VPN and zero-trust products are network-level, so Wazuh sees only the addresses they present to it.

### Use cases

| Use case | Pattern | Traffic direction | Guides |
|---|---|---|---|
| Cloud-hosted agents report to the cluster | Site-to-site VPN where possible; otherwise a TCP gateway in a DMZ that passes 1514 and 1515 through | Agent connects to the gateway, which forwards to the managers | [AWS NLB/ALB](../troubleshooting/agents/aws-load-balancer.md), [HAProxy helper](../containerization/kubernetes/haproxy-dataplane.md), [NGINX stream](../integrations/nginx/README.md) |
| Logs from cloud platforms and SaaS | Cloud module on a collector agent or on the manager, in one place per module; the collector pulls over outbound 443 and reports on 1514 | Outbound only, from the collector | [AWS](../cloud/aws.md), [Azure](../cloud/azure.md), [GCP Pub/Sub](../cloud/gcp-pubsub.md) |
| Cloud devices that can only send syslog | rsyslog collector with a Wazuh agent reading its file, so the managers need no syslog listener | Device to collector; collector to managers on 1514 | [Syslog](../integrations/syslog/README.md#option-2-rsyslog-collector-plus-agent) |
| Alerts out to a SOAR platform | Integration block on every manager node, posting to the platform over HTTPS | Outbound from the managers only | [Webhook integration](../integrations/webhook/README.md) |
| API calls in from a SOAR platform | Preferred: a runner inside your network or on the VPN. Otherwise a gateway that allowlists the platform's egress addresses | Inbound to 55000 through the gateway only | [NGINX stream](../integrations/nginx/README.md) |
| Remote users on the dashboard and API | VPN or identity-aware access proxy in front of 443, with SSO on the dashboard | Inbound 443 through the VPN or proxy only | [SAML SSO](../certificates/sso-saml.md) |

### Ports and exposure

| Port | Service | Reached by | Outside exposure |
|---|---|---|---|
| 1514/TCP | Agent events | Agents, through the gateway or VPN | Gateway only, when agents are outside the network |
| 1515/TCP | Agent enrollment | Agents, through the gateway or VPN, to the master | Same as 1514 |
| 1516/TCP | Cluster daemon | Managers only | Never, and never through a proxy |
| 55000/TCP | Server API | Dashboard, and allowlisted automation | Never directly; through a gateway only if required |
| 443/TCP | Dashboard | Remote users | VPN or access proxy only |
| 9200/TCP | Indexer API | Managers and dashboard | Never |
| 9300-9400/TCP | Indexer cluster | Indexer nodes | Never |
| 514/UDP or TCP | Manager syslog listener (optional, disabled by default) | Devices you choose | Avoid; use a collector agent instead |

### Agent traffic through a gateway

- Pass TCP through at layer 4, and do not terminate or inspect TLS on 1514 or 1515. authd terminates its own TLS on 1515, so a TLS listener in front of it breaks enrollment. See [use TCP listeners](../troubleshooting/agents/aws-load-balancer.md#use-tcp-listeners-not-tls). Use TCP, not UDP, on 1514.
- Send 1515 to the master only. The NGINX guide in this repo sends enrollment only to the master and states that enrollment sent to a worker fails. The upstream HAProxy example lists workers on 1515 too, but the upstream [load balancer page](https://documentation.wazuh.com/current/user-manual/wazuh-server-cluster/load-balancers.html) does not say whether workers forward enrollment to the master. Do not rely on forwarding unless you have tested it on your version.
- Balance 1514 across all nodes. A plain NGINX or HAProxy setup spreads only new connections, so agents already connected stay where they are. The [HAProxy helper](../containerization/kubernetes/haproxy-dataplane.md) rebalances agents, and it requires a least-connections balancer. Without it, set `<force_reconnect_interval>` in the agent's `<client>` block so agents reconnect and spread out (see [disconnections](../troubleshooting/agents/disconnections.md#agents-stuck-in-a-re-registration-loop)).
- Keep `<use_source_ip>` at `no`, which is the documented default. With `no`, an agent is added with the address `any`, which is what you want behind a gateway. The [auth reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/auth.html) does not describe NAT behavior, so test enrollment from each network path.
- List both nodes, or both gateways, in the agent's `<client>` block so agents fail over when one path is down (see [6.3 Agent-side failover](../containerization/kubernetes/eks-ha/06-expose-agents.md#63-agent-side-failover)).
- If one balancer cannot serve both registration and reporting, use separate names: one for 1515 to the master, one for 1514 to all nodes. See [aws-load-balancer.md](../troubleshooting/agents/aws-load-balancer.md).

### Cloud and SaaS log collection

- Choose one place per module. The AWS and Azure modules run on the manager or on a Linux agent. The Office 365, GitHub, and Microsoft Graph modules can be configured on the manager or an agent, and Wazuh recommends enabling each one in a single place to avoid duplicate events. The repo's [GCP Pub/Sub guide](../cloud/gcp-pubsub.md) runs its subscriber on the manager VM, so use that layout unless you build a collector agent yourself.
- The AWS module on an agent needs Python and `boto3` on that agent (see [AWS](../cloud/aws.md)).
- Only outbound 443 is needed from the collector. The endpoints depend on the module. For Azure and Office 365 they include `login.microsoftonline.com` and the Office 365 management endpoints. Check the [Office 365 module reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/office365-module.html) for your version.

### SOAR and automation

- Outbound alerts: an `<integration>` block runs on the manager node that analyzes an agent's events. The repo's syslog and vulnerability-detection guides record that `ossec.conf` blocks do not propagate through cluster sync, so repeat the block on every manager. The `timeout` (default 10 seconds) and `retries` (default 3) are per-integration settings, documented in the [integration reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html).
- Inbound API calls: run the SOAR runner inside your network or on the VPN, so 55000 is never published. If the platform must call the API directly, publish 55000 only through a gateway that allowlists its egress addresses. Only the master serves the API, so do not balance it across nodes.
- Give the platform a dedicated API user with the narrowest role it needs.

### Remote access to the dashboard and API

- Users reach 443 through the VPN or an identity-aware access proxy only. The dashboard reaches the API (55000) and the indexer (9200) from inside the network, so remote users never need those ports.
- Put SSO in front of the dashboard. [SAML is documented in this repo](../certificates/sso-saml.md). OIDC was not confirmed against the 4.14 documentation in this review, so verify it before offering it.

### Limitations

- A VPN, zero-trust product, or NAT gateway changes the source address Wazuh sees. Behind NAT, many agents can share one address, which affects `use_source_ip` and the source fields in alerts.
- Enrollment is master-only in the repo's guides (see above). Test worker enrollment before relying on it.
- In a cluster, `<remote>`, `<integration>`, and similar blocks are per node. Make the same change on every node.
- Port 1516 must never pass through a proxy, and the API is not balanced.
- Agents keep long-lived connections, so a balancer spreads load only as agents reconnect.

## Disaster recovery

Full runbook: [Disaster Recovery Architecture](disaster-recovery.md).

When the primary Wazuh site may become unreachable, plan an **active/passive** standby site with automated failover (load balancer health checks or DNS switch). Before go-live:

- [ ] Choose failover mechanism (ALB/NGINX/AWS ELB or DNS)
- [ ] Standby DR environment mirrors primary capacity (on-prem or Wazuh Cloud)
- [ ] Replicate agent keys, groups, custom rules/decoders, CDB lists, SCA policies
- [ ] Configuration source of truth (e.g. Git) shared by both sites
- [ ] Health checks on primary; documented activation and failback
- [ ] Periodic DR failover test

**DR ports (typical on-prem):** 1514/TCP (agents), 1515/TCP (enrollment), 55000/TCP (API). Wazuh Cloud DR often uses 1514 + 443. Details in [disaster-recovery.md](disaster-recovery.md#port-matrix).

## Documentation

- [Architecture - Getting started with Wazuh](https://documentation.wazuh.com/current/getting-started/architecture.html)
- [Installation guide](https://documentation.wazuh.com/current/installation-guide/index.html)
- [Quickstart](https://documentation.wazuh.com/current/quickstart.html)
- [Load balancers - Wazuh server cluster](https://documentation.wazuh.com/current/user-manual/wazuh-server-cluster/load-balancers.html)
- [Integration reference (ossec.conf)](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html)
- [Authentication reference (ossec.conf, use_source_ip)](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/auth.html)
- [Office 365 module reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/office365-module.html)
