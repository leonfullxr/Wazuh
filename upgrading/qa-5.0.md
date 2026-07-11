<!-- Support: WS-38488 -->

# Wazuh 5.0 Migration FAQ

Architectural changes, limitations, and continuity guidance for 4.x → 5.0 upgrade planning.

**References:** [Wazuh Common Schema (WCS)](https://github.com/wazuh/wazuh-dashboard) · [Wazuh CTI blog](https://wazuh.com/blog/introducing-wazuh-cti/)

## Pre-migration checklist

- [ ] Run [health check](healthcheck.md) on the current 4.x environment and document baseline
- [ ] Plan a **clean manager install** (5.0 replaces `analysisd` with the Wazuh Engine)
- [ ] Coordinate with Wazuh support for the configuration/content migration script
- [ ] Confirm 4.x agents remain compatible - upgrade agents last ([upgrading agents](upgrading-agents.md))
- [ ] Plan indexer strategy: rolling indexer upgrades supported; historical `wazuh-alerts-*` data is **not** converted to `wazuh-findings-v5-*`
- [ ] Review custom XML rules/decoders - 5.0 uses YML ruleset syntax
- [ ] Update runbooks for new terminology (Syscheck → FIM, Rootcheck → Malware Detection)

## Migration process (4.x → 5.0)

5.0 requires a **clean manager installation** due to the shift from `analysisd` to the **Wazuh Engine** (state-based **Findings** model).

- Spin up a new server; migrate content via support-provided migration script
- 4.x agents remain compatible during transition
- Historical 4.x data stays in `wazuh-alerts-*` - not migrated to `wazuh-findings-v5-*` or `wazuh-events-v5-*`

## Key differences

### Architectural re-engineering

- `analysisd` → **Wazuh Engine** (higher throughput, modular)
- **Filebeat removed** from server - manager writes directly to indexer
- Fewer moving parts, lower resource use

### YML ruleset and WCS

- XML → YML for rules and decoders
- Telemetry normalized via **Wazuh Common Schema (WCS)** (ECS-compatible)

### Stateful findings vs. alerts

| Data type | Index pattern |
|-----------|---------------|
| Historical alerts (4.x) | `wazuh-alerts-4.x-*` |
| V5 findings | `wazuh-findings-v5-*` |

Findings track **state** (Detected → Resolved) rather than single events.

### UI and terminology

- Out-of-the-box dashboards (MITRE, PCI DSS, GDPR, NIST 800-53)
- Syscheck → **FIM**, Rootcheck → **Malware Detection**

### Wazuh CTI

- Hourly IOC/CVE updates (100M+ indicators)
- Native log enrichment

## Business continuity

- Clustering enabled by default on new installs
- **Self-Protection (Flood Control)** during indexer saturation
- Rolling indexer upgrades supported (manager = clean install)
- DR patterns: [disaster recovery](disaster-recovery.md), [deployment architecture](deployment-architecture.md)

## Vulnerability detection (5.0)

- State-based findings in `wazuh-findings-v5-vulnerabilities-*`
- Centralized CVE sourcing from indexer
- Security Posture UI (vulnerabilities + IT Hygiene + SCA)

## See also

- [Pre-upgrade checklist](pre-upgrade-checklist.md)
- [Health check](healthcheck.md)
- [Upgrading agents](upgrading-agents.md)
