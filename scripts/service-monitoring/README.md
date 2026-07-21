# Wazuh services monitoring (cron watchdog)

Simple cron-driven watchdogs that check whether the Wazuh services are running
and send an email alert when any of them is down.

## Requirements

- A configured mail transport agent (e.g. Postfix) and `mailutils` on the
  monitoring host:

  ```bash
  apt-get install postfix mailutils
  ```

- Edit `EMAIL_FROM` / `EMAIL_TO` at the top of each script.

## All-in-one environment

`wazuh-services-monitoring.sh` checks `wazuh-manager`, `wazuh-indexer`,
`wazuh-dashboard`, and `filebeat` locally with `systemctl is-active` and mails
an alert for each service that is not active.

Schedule it hourly:

```bash
crontab -e
0 * * * * /path/to/wazuh-services-monitoring.sh
```

## Multi-node environment

`wazuh-services-monitoring-multinode.sh` runs centrally and checks services on
remote nodes over SSH. Requirements:

- Passwordless SSH from the monitoring server to each node.
- Edit the `NODES_SERVICES` map to match your topology, e.g.:

  ```bash
  NODES_SERVICES["wazuh-master"]="wazuh-manager filebeat"
  NODES_SERVICES["wazuh-indexer"]="wazuh-indexer"
  ```

Schedule it the same way as the single-node script.

## Related

- [`../agent-email-summary`](../agent-email-summary) - HTML email report of
  agent status via the Wazuh API.
- [`../resource-monitoring`](../resource-monitoring) - host CPU/memory/disk
  metrics as Wazuh alerts.
