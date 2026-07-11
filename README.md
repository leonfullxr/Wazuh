# Wazuh Knowledge Base

Field-tested Wazuh configurations, operational guides and scripts, distilled from hands-on deployment, tuning and troubleshooting work. Everything here is written for real-world use: each guide explains not just the how but the why, with verified commands and configuration.

Please refer to the official integration repository, which is maintained and updated: https://github.com/wazuh/integrations

**Disclaimer**: The content in this repository is provided "as is" without warranty of any kind, express or implied. Users are responsible for evaluating the security, quality, and compatibility of any code or configurations they choose to use. Test in a lab before applying to production.

## Repository structure

### Infrastructure & operations

- [containerization/](containerization/) - Wazuh in Docker and Kubernetes: EKS, AKS and GKE deployment guides, agent DaemonSets, FIM inside containers, cluster debugging, Docker networking and proxy diagnostics.
- [cloud/](cloud/) - Cloud log ingestion and infrastructure: AWS (`aws-s3` wodle, IAM), Azure (Log Analytics, MS Graph), GCP Pub/Sub, plus Wazuh Cloud usage and dashboard RBAC.
- [indexer/](indexer/) - Wazuh Indexer (OpenSearch) operations and fine tuning: shard sizing and management, ISM/ILM retention, disk-space forensics, reindexing, index separation, replicas, GeoIP enrichment, cross-cluster search, security auditing.
- [upgrading/](upgrading/) - Pre-upgrade checklist, agent upgrades via API/CLI, deployment architecture and port matrix, per-component health checks, capacity planning and sizing.
- [certificates/](certificates/) - TLS certificate lifecycle for every component, HTTPS for dashboards on private IPs, SAML SSO, and a certificate troubleshooting playbook.
- [troubleshooting/](troubleshooting/) - Symptom-driven guides: agent disconnections, flooding and buffer tuning, enrollment conflicts, analysisd queue/EPS tuning, vulnerability detection internals and reset, password recovery, LDAP/AD.

### Integrations & detection

- [integrations/](integrations/) - Third-party integrations: threat intel (MISP, AlienVault OTX, VirusTotal, AbuseIPDB), LDAP/AD, Splunk, OpenSearch, alerting (Jira, Confluence, Teams), and an LLM-powered AI assistant PoC.
- [rules/](rules/) - Custom rule sets (FortiGate, Vectra).
- [decoders/](decoders/) - Custom decoders (FortiGate, Vectra, NetIQ).
- [sca/](sca/) - Security Configuration Assessment content and RHEL hardening scripts.

### Automation & tooling

- [scripts/](scripts/) - Operational scripts, each with its own README: agent management and deployment, service and resource monitoring, alert retention and deletion policies, syscheck email notifications, eventchannel extraction, EPS measurement, diagnosis, MaxMind updates, all-in-one installs.
- [ansible/](ansible/) - Ansible playbooks (agent renaming).
- [packages/](packages/) - Platform-specific packaging notes (Solaris).
- [images/](images/) - Vagrant lab images (Windows, FreeBSD).

## Contributing

Feel free to fork, edit and reuse anything here at your own risk; some configurations may need adaptation to your environment. Contact me if something needs clarification.
