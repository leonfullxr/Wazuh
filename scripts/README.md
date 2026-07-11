# Scripts

Operational scripts and automation for Wazuh. Each subdirectory contains a
README with usage instructions plus the script/config files.

## Installation & deployment

- [all-in-one-single-node](all-in-one-single-node/) - unattended all-in-one
  installers (indexer + manager + dashboard + filebeat).
- [agent-deployment](agent-deployment/) - mass agent rollout methods (GPO,
  PDQ, Ansible, deployment variables, enrollment options).
- [agent-management](agent-management/) - interactive agent group management
  via the Wazuh API.
- [rasberrypi4_setup.sh](rasberrypi4_setup.sh) - Wazuh setup on a Raspberry
  Pi 4.

## Monitoring & reporting

- [service-monitoring](service-monitoring/) - cron watchdog that emails when
  Wazuh services go down (single- and multi-node variants).
- [agent-email-summary](agent-email-summary/) - HTML email report of
  disconnected/pending/never-connected agents.
- [resource-monitoring](resource-monitoring/) - CPU/memory/disk/load metrics
  as Wazuh alerts, with decoders and threshold rules (Linux and Windows).
- [email-alerting](email-alerting/) - granular email alerting: generic vs.
  granular manager-side options, per-agent-group/per-OS routing, and the
  indexer-side OpenSearch Alerting module.
- [syscheck-email-notifications](syscheck-email-notifications/) - email
  alerts for FIM (syscheck) events.
- [diagnosis](diagnosis/) - environment diagnostics collection and upgrade
  readiness healthcheck.
- [EPS](EPS/) - events-per-second calculation on the manager.

## Detection & response

- [active-response](active-response/) - block attacker IPs via the built-in
  `firewall-drop` or a custom CDB-blocklist integration script.

## Data retention & housekeeping

- [policy-deletion](policy-deletion/) - filesystem log cleanup (cron),
  targeted indexed-alert deletion by rule ID/date range, and an ISM policy.
- [alert-search](alert-search/) - find alerts in `alerts.json` by rule ID and
  time window.
- [rotate_logs.sh](rotate_logs.sh) - log rotation helper.
- [recovery](recovery/) - re-inject archived events into the pipeline.

## Event processing

- [eventchannel-extraction](eventchannel-extraction/) - extract structured
  data from Windows eventchannel `message` fields via an integratord script.
- [otlp-syslog-extraction](otlp-syslog-extraction/) - realtime extraction of
  syslog lines embedded in OpenTelemetry JSON logs.
- [custom-json](custom-json/) - custom JSON log extraction.

## Misc

- [update_maxmind_database](update_maxmind_database/) - MaxMind GeoIP
  database updates.
