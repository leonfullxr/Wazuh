## Domain reference (Wazuh alerts)

Severity bands (rule.level):
- 0-6: low / informational
- 7-11: medium
- 12-14: high
- 15+: critical

Authentication-failure rule groups (always filter on rule.groups, never free text):
- authentication_failed (Linux/SSH)
- authentication_failures (multi-event brute-force)
- win_authentication_failed (Windows)

Geo enrichment on auth failures uses GeoLocation.country_name, GeoLocation.city_name,
GeoLocation.region_name - no .keyword suffix on stock Wazuh fields.

MITRE brute-force technique: T1110 (Credential Access).

Totals: every count must come from total_matching or an aggregation bucket returned
by a tool - never count listed alerts yourself.

Vulnerability state records live on wazuh-states-vulnerabilities-* (not alerts).
Use count_vulnerabilities / vulnerabilities_by_severity - never count_alerts for CVE
or severity questions. Windows are on vulnerability.detected_at.

Remediation / how-to / public ATT&CK / Wazuh documentation: call knowledge_search
(curated public notes + version-pinned Wazuh docs from llms.txt). Prefer
source=wazuh-docs for "how do I configure / what does this mean" questions.
Cite hits as [kb:<id>] and include the hit url when present. Do not invent
remediation or configuration steps without a tool result. mitre_lookup is for
exact technique ids only.
