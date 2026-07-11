# Deployment Architecture

## Table of Contents
- [Introduction](#introduction)
- [Planning Questions](#planning-questions)
- [Prerequisites](#prerequisites)
  - [Reference Architecture](#reference-architecture)
  - [Firewall Ports](#firewall-ports)
- [Internet Connectivity Requirements](#internet-connectivity-requirements)
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
- **Agent upgrades** require the manager to reach [https://packages.wazuh.com](https://packages.wazuh.com/) — only needed when upgrading agents (see [Upgrading Agents](upgrading-agents.md)).

## Documentation

- [Architecture - Getting started with Wazuh](https://documentation.wazuh.com/current/getting-started/architecture.html)
- [Installation guide](https://documentation.wazuh.com/current/installation-guide/index.html)
- [Quickstart](https://documentation.wazuh.com/current/quickstart.html)
