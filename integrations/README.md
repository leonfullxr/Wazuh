# Wazuh Integrations

This section is for administrators connecting Wazuh to log sources,
identity providers, threat-intelligence services, notification endpoints,
and downstream analytics platforms. Guides describe the data direction,
security boundary, deployment procedure, and verification steps.

Choose the architecture before copying configuration. Inbound device logs,
per-alert webhooks, enrichment scripts, and bulk forwarding have different
delivery and failure semantics. Keep credentials out of scripts, verify TLS,
filter at a sustainable volume, and test both success and outage behavior.

## Quick reference

| Task | Guide |
|---|---|
| Receive firewall or appliance syslog | [Generic syslog ingestion](syslog/README.md) |
| Forward FortiGate logs and deploy its decoder | [Fortinet FortiGate](fortinet/README.md) |
| Ingest Palo Alto / Prisma Cloud logs (syslog over TLS, OCSP cert) | [Palo Alto / Prisma Cloud](prisma-cloud/README.md) |
| Load-balance agent TCP connections across manager workers | [NGINX stream load balancer](nginx/README.md) |
| Send selected alerts to an HTTPS endpoint | [Generic webhook](webhook/README.md) |
| Monitor SQL Server login and audit events | [Microsoft SQL Server](mssql/README.md) |
| Send alerts to Splunk SOAR | [Splunk SOAR hook](splunk/README.md) |
| Copy Wazuh Indexer alerts to Splunk through Logstash | [Splunk Logstash forwarding](splunk/logstash-forwarding.md) |
| Authenticate dashboard users with LDAP/AD | [LDAP and Active Directory](../troubleshooting/ldap-ad.md) |
| Configure SAML SSO with Keycloak, Entra ID, or another IdP | [SAML SSO](../certificates/sso-saml.md) |
| Serve OpenSearch maps locally over HTTPS | [Private-IP dashboard and maps HTTPS](../certificates/https-for-private-ip.md) |

## Threat intelligence and enrichment

| Integration | Purpose |
|---|---|
| [AlienVault OTX](alienvault_otx/README.md) | Enrich public IPs, domains, and SHA-256 indicators; includes rules, retry queues, and a dashboard |
| [MISP](misp/README.md) | Query MISP for indicators extracted from Wazuh alerts |
| [VirusTotal](virustotal/README.md) | Enrich source IPs through the VirusTotal v3 API |
| `abuseipdb/` | Code and rules exist, but the integration still needs a validated public runbook before production adoption |

Threat-intelligence verdicts are context, not ground truth. Rate-limit queries,
exclude private and known infrastructure addresses, preserve the original
alert, and measure false positives before attaching active response.

## Alert delivery and SaaS audit collection

- The [SaaS audit collection hub](alerts/README.md) links the Jira and
  Confluence normalization pipelines.
- The [generic webhook guide](webhook/README.md) is the baseline for outbound
  alert delivery, including endpoints implemented through Microsoft Teams
  Workflows or an internal integration gateway.

Review vendor API versions and authentication models before deployment.
Webhook URLs are credentials and must never appear in committed examples or
logs.

## Experimental work

`ai-assistant/` is an experimental proof of concept, not part of the
production KB procedures indexed above. Treat it as a separate application
with its own security and deployment review.

## Obsidian-only backlog

The personal source vault also contains Bitdefender, IBM, Zabbix, SealPath,
Grafana, JumpCloud, Sophos, Sysmon for macOS, and other integration notes.
They remain unpublished until each can provide a complete, verified
procedure. No empty integration folders are created for backlog items.

## See also

- [Cloud log ingestion](../cloud/README.md)
- [Custom decoders](../decoders/README.md)
- [Custom rules](../rules/README.md)
- [Official Wazuh integrations repository](https://github.com/wazuh/integrations)
