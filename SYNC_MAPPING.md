# Obsidian Vault ↔ Repository Mapping

This document correlates the personal **Obsidian knowledge vault** with this public **Wazuh knowledge-base** repository. The vault is the working notebook (JIRA links, draft notes, wikilinks); the repo is the curated, shareable version.

| | Path |
|---|---|
| **Obsidian vault** | `ETSHIT/Notes/Obsidian/Wazuh/` |
| **This repository** | `ETSHIT/Github/Wazuh/` (branch: `knowledge-base`) |
| **Interrupted enrichment branch** | `kb-enrichment` (5 commits ahead - cherry-picked into `knowledge-base` Jul 2026) |

## Conventions when syncing

| Obsidian | Repository |
|---|---|
| `[[Note name]]` wikilinks | Relative markdown links (`../section/file.md`) |
| JIRA URLs at file top | `<!-- Support: WS-xxxxx -->` comment or **References** section |
| `MOC - *.md` hub notes | Section `README.md` indexes |
| `_archive/` stubs | Merged into active notes; not copied to repo |
| Mixed EN/ES | Preserved per document |

## Section mapping

| Obsidian folder | Repository folder | Notes |
|---|---|---|
| `integrations/` | `integrations/` + `cloud/` | Cloud providers live under `cloud/` |
| `kubernetes/` + `docker/` | `containerization/kubernetes/` + `containerization/docker/` | |
| `troubleshooting/` (root) | `troubleshooting/` | |
| `troubleshooting/indexer/` | `indexer/` | |
| `troubleshooting/cloud/` | `cloud/wazuh-cloud-service.md` | Consolidated SaaS doc |
| `troubleshooting/server/` | `troubleshooting/server/` | |
| `troubleshooting/SSL*.md`, `LDAP*.md` | `certificates/` + `troubleshooting/` | Split by topic |
| `upgrading/` | `upgrading/` | |
| `scripts/` | `scripts/<name>/README.md` | One README per script folder |
| `decoders/` | `decoders/<vendor>/` | XML in repo; prose in `decoders/syntax.md` + vendor READMEs |
| `rules/` | `rules/` | |
| `configurations/` | `certificates/` + `containerization/` | HTTPS → certificates; VM network → lab notes |

## Topic index (Obsidian → repo)

### Synced (repo is current or richer)

| Obsidian | Repository |
|---|---|
| `troubleshooting/Agent disconnection.md` | `troubleshooting/agents/disconnections.md` |
| `troubleshooting/Agent Flooding.md` | `troubleshooting/agents/flooding.md` |
| `troubleshooting/Agent key already in use.md` | `troubleshooting/agents/enrollment-key-conflicts.md` |
| `troubleshooting/Custom WPK.md` | `troubleshooting/agents/custom-wpk.md` |
| `troubleshooting/MacOS.md` | `troubleshooting/agents/macos.md` |
| `troubleshooting/LDAP - AD.md` | `troubleshooting/ldap-ad.md` |
| `troubleshooting/Passwords - reset & recovery.md` | `troubleshooting/passwords-recovery.md` |
| `troubleshooting/server/*.md` | `troubleshooting/server/*.md` |
| `troubleshooting/indexer/*.md` | `indexer/*.md` |
| `upgrading/*.md` (except QA) | `upgrading/*.md` |
| `integrations/AWS.md` | `cloud/aws.md` |
| `integrations/Azure.md` | `cloud/azure.md` |
| `integrations/Google Cloud logs*.md` | `cloud/gcp-pubsub.md` |
| `integrations/MISP.md` | `integrations/misp/README.md` |
| `integrations/Syslog.md` + `Rsyslog - Linux.md` | `integrations/syslog/README.md` |
| `integrations/Fortinet.md` | `integrations/fortinet/README.md` |
| `integrations/nginx.md` | `integrations/nginx/README.md` |
| `integrations/Webhook.md` | `integrations/webhook/README.md` |
| `integrations/MSSQL - audit logs via eventchannel.md` | `integrations/mssql/README.md` |
| `integrations/Splunk.md` (Logstash path) | `integrations/splunk/logstash-forwarding.md` |
| `troubleshooting/indexer/Auditing.md` (indexer audit section) | `indexer/security-audit-logs.md` |
| `troubleshooting/indexer/CCS configuration.md` (LDAP section) | `indexer/cross-cluster-search.md#6-ldap-authorization-across-ccs-environments` |
| `kubernetes/*.md` | `containerization/kubernetes/*.md` |
| `docker/Docker network*.md` | `containerization/docker/network-proxy-debugging.md` |
| `configurations/HTTPS-SSL Private for IP.md` | `certificates/https-for-private-ip.md` |
| `scripts/*.md` | `scripts/*/README.md` |

### Ported from `kb-enrichment` branch (Jul 2026)

| Repository file | Source |
|---|---|
| `upgrading/disaster-recovery.md` | Obsidian `DR.md` + `kb-enrichment` (merged Jul 2026) |
| `containerization/kubernetes/openshift.md` | Archive + support cases |
| `containerization/kubernetes/persistent-storage.md` | Archive |
| `containerization/docker/swarm.md` | Archive |
| `containerization/docker/backup-and-migration.md` | Support cases |
| `scripts/email-alerting/README.md` | Obsidian email alerting recipes |
| `scripts/active-response/README.md` | Archive AR integration |
| `certificates/troubleshooting.md` (expanded) | Obsidian `SSL - certificates.md` |

### New in repo from Obsidian (Jul 2026)

| Repository file | Obsidian source |
|---|---|
| `decoders/syntax.md` | `decoders/Decoder syntax & examples.md` |
| `rules/examples/var.md` | `rules/var.md` |
| `upgrading/qa-5.0.md` | `upgrading/QA - 5.0.md` |
| `troubleshooting/agents/windows-registry.md` | `troubleshooting/Windows registry.md` |

### Consolidated or deleted in the public KB (Jul 2026)

| Former repository path | Canonical location / decision |
|---|---|
| `indexer/misc-operations.md` | Timestamp procedure moved to `indexer/ingest-pipeline-customization.md`; password recovery deduplicated into `troubleshooting/passwords-recovery.md` |
| `troubleshooting/disaster-recovery.md` | Deleted pointer; `troubleshooting/README.md` links directly to `upgrading/disaster-recovery.md` |
| `integrations/LDAP/README.md` | Deleted duplicate/personal note; canonical guide is `troubleshooting/ldap-ad.md` |
| `integrations/alerts/teams/*` | Deleted unsafe obsolete webhook sample; use `integrations/webhook/README.md` and the current Teams Workflows endpoint |
| `integrations/splunk/splunk_install.md` | Deleted stale product-installation notes; Splunk integration hub now separates SOAR and Logstash forwarding |
| `integrations/opensearch/map_server/README.md` | Deleted duplicate personal walkthrough; canonical maps/HTTPS procedure is `certificates/https-for-private-ip.md` |
| `containerization/docker/single-node/traefik/README.md` | Merged into `containerization/docker/single-node/README.md` |
| `decoders/fortigate/README.me` | Deleted typo/duplicate; canonical file is `decoders/fortigate/README.md` |

### Obsidian-only (candidates for future repo docs)

Integration guides without a production-ready repo home yet: Bitdefender,
IBM, Zabbix, SealPath, JumpCloud, Grafana, Sophos, Incident.io, Sysmon-macOS,
and Ansible (a playbook exists). Keycloak is covered as the example IdP in
`certificates/sso-saml.md`.

MSSQL table polling and the event-message parsing script remain Obsidian-only.
The table procedure explicitly lacked a tested implementation, and the parser
needs a defined schema, loop prevention, durable retries, and regression tests
before publication.

Repo-only (no Obsidian note): AlienVault OTX, VirusTotal, AbuseIPDB, Confluence/Teams alerting, `scripts/diagnosis/`, `scripts/recovery/`, Docker single-node/Traefik variants.

## Sync workflow

1. Edit and enrich in **Obsidian** (fast capture, JIRA refs, wikilinks).
2. When a note is stable, port to the matching **repo** path: strip wikilinks, add TOC if long, verify commands in a lab.
3. Update this mapping and the section `README.md`.
4. Commit on `knowledge-base`; open PR to `main` when ready to publish.
