## Domain reference (Wazuh alerts)

Severity bands (rule.level):
- 0–6: low / informational
- 7–11: medium
- 12–14: high
- 15+: critical

Authentication-failure rule groups (always filter on rule.groups, never free text):
- authentication_failed (Linux/SSH)
- authentication_failures (multi-event brute-force)
- win_authentication_failed (Windows)

Geo enrichment on auth failures uses GeoLocation.country_name, GeoLocation.city_name,
GeoLocation.region_name — no .keyword suffix on stock Wazuh fields.

MITRE brute-force technique: T1110 (Credential Access).

Totals: every count must come from total_matching or an aggregation bucket returned
by a tool — never count listed alerts yourself.
