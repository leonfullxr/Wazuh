# Wazuh Knowledge Base

Field-tested Wazuh configurations, operational guides, and scripts for
administrators and detection engineers. The knowledge base focuses on
repeatable production procedures: prerequisites, commands, verification,
failure modes, and rollback or recovery considerations.

This repository complements, rather than replaces, the
[official Wazuh documentation](https://documentation.wazuh.com/) and
[official integrations repository](https://github.com/wazuh/integrations).
Confirm paths and behavior against the installed Wazuh version and test
changes outside production first.

**Obsidian vault sync:** See [SYNC_MAPPING.md](SYNC_MAPPING.md) for how this repository maps to the personal Obsidian knowledge vault.

**Disclaimer**: The content in this repository is provided "as is" without warranty of any kind, express or implied. Users are responsible for evaluating the security, quality, and compatibility of any code or configurations they choose to use. Test in a lab before applying to production.

## Repository structure

### Infrastructure & operations

- [containerization/](containerization/) - Wazuh in Docker and Kubernetes: EKS, AKS, GKE, OpenShift, persistent storage, agent DaemonSets, FIM inside containers, cluster debugging, Docker Swarm, backup/migration, Docker networking and proxy diagnostics.
- [cloud/](cloud/) - Cloud log ingestion and infrastructure: AWS (`aws-s3` wodle, IAM), Azure (Log Analytics, MS Graph), GCP Pub/Sub, plus Wazuh Cloud usage and dashboard RBAC.
- [indexer/](indexer/) - Wazuh Indexer optimization and troubleshooting hub: shard/heap planning, replicas, ISM retention and rollover decisions, disk recovery, reindexing, ingest-pipeline customization, cross-cluster search, and security auditing.
- [upgrading/](upgrading/) - Pre-upgrade checklist, agent upgrades via API/CLI, deployment architecture and port matrix, per-component health checks, capacity planning and sizing, disaster recovery, Wazuh 5.0 migration FAQ.
- [certificates/](certificates/) - TLS certificate lifecycle for every component, HTTPS for dashboards on private IPs, SAML SSO, and a certificate troubleshooting playbook.
- [troubleshooting/](troubleshooting/) - Symptom-driven guides: agent disconnections, flooding and buffer tuning, enrollment conflicts, analysisd queue/EPS tuning, vulnerability detection internals and reset, password recovery, LDAP/AD, Windows registry monitoring.

### Integrations & detection

- [integrations/](integrations/) - Integration hub for Fortinet and generic syslog, NGINX agent load balancing, webhooks, MSSQL audit events, Splunk SOAR/Logstash forwarding, threat intelligence, and SaaS audit collection.
- [rules/](rules/) - Custom rule deployment guidance, FortiGate and Vectra suites, and validated [`<var>` examples](rules/examples/var.md).
- [decoders/](decoders/) - Decoder deployment workflow, FortiGate, Vectra, and NetIQ suites, plus a [syntax reference](decoders/syntax.md).
- [sca/](sca/) - Security Configuration Assessment content and RHEL hardening scripts.

### Automation & tooling

- [scripts/](scripts/) - Operational scripts, each with its own README: agent management and deployment, service and resource monitoring, alert retention and deletion policies, syscheck email notifications, granular email alerting, active-response CDB blocklist, eventchannel extraction, EPS measurement, diagnosis, MaxMind updates, all-in-one installs.
- [ansible/](ansible/) - Ansible playbooks (agent renaming).
- [packages/](packages/) - Platform-specific packaging notes (Solaris).
- [images/](images/) - Vagrant lab images (Windows, FreeBSD).

## Contributing

Feel free to fork, edit and reuse anything here at your own risk; some configurations may need adaptation to your environment. Contact me if something needs clarification.
