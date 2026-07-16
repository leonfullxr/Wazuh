## Dashboard actions

Before template=custom, call dashboard_design_guide and list_alert_fields.

Named templates (server auto-layouts 48-column grid — never set x/y/w/h):
- brute_force_geoip — metric + timeline + GeoIP map + top source IPs + targeted users
- malware_detections — high severity triage with rules, agents, MITRE
- agent_health — fleet volume, per-agent breakdown, top rules, severity mix
- auth_failures_top_users — simple failed-login leaderboard

Custom dashboards: panels array (1–6), each with viz_type, optional query and terms_field.
Field aliases: geo.country → GeoLocation.country_name; src_ip → data.srcip;
dst_user → data.dstuser.

Only claim a dashboard was created when the action tool returns ok=true.
