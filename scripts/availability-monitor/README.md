# LAN server and service availability monitoring

Active up/down monitoring for servers and critical TCP services on an internal
network, polled from one host and delivered as Wazuh alerts. The poller sends
one alert when a host or port goes down and one when it comes back, including
how long it was down, so existing email and Telegram notifications stay quiet
while an outage continues.

The checks, the state machine, the rules, and the notification wiring are all
in this folder: `availability_monitor.py`, `availability_monitor.service`, and
`availability_rules.xml`.

> Applies to a self-hosted Wazuh deployment with a Linux polling node on the
> same LAN as the targets: an Ubuntu host already running a Wazuh agent, or
> the Wazuh server itself.

## Table of Contents

- [Why not only agent disconnection alerts](#why-not-only-agent-disconnection-alerts)
- [Choosing the check](#choosing-the-check)
- [Architecture](#architecture)
- [Step 1: list the targets](#step-1-list-the-targets)
- [Step 2: install the poller](#step-2-install-the-poller)
- [Step 3: run it as a service](#step-3-run-it-as-a-service)
- [Step 4: deliver the events](#step-4-deliver-the-events)
- [Step 5: rules](#step-5-rules)
- [Step 6: notifications by email and Telegram](#step-6-notifications-by-email-and-telegram)
- [Sizing and tuning](#sizing-and-tuning)
- [Verification and troubleshooting](#verification-and-troubleshooting)
- [Related](#related)

## Why not only agent disconnection alerts

Wazuh already alerts when an agent stops reporting, and for many setups that is
enough. It is the wrong signal for host availability, though:

- It reports lost communication with the manager, not host state. A stopped
  agent process, a routing problem, and a switched-off server all look the same.
- It only covers hosts that run an agent, and it depends on that agent running.
- It says nothing about a service that is up while the agent is fine.

An active probe from one machine on the same LAN gives an independent view of
any address you can reach, agent or not, and can also test a specific service
port.

## Choosing the check

| Check | Answers | Watch out for |
|---|---|---|
| ICMP ping | Is the host up at all? | Hosts or firewalls that drop ICMP look permanently down; a high check rate across many hosts adds LAN traffic |
| TCP connect | Is a specific service accepting connections? | Proves only a Layer 4 handshake. A port answers while the application behind it is hung |

Use both: ping for the host, one TCP connect per service you care about. The
TCP check uses `socket.connect_ex()` with an explicit timeout, so a port that
silently drops packets fails after the timeout instead of hanging the poller,
and the return code distinguishes "connected" (0), "connection refused" (the
host is up but nothing is listening), and "timed out" (filtered or host down).

Treat the interval as the accuracy bound. A check every 60 seconds detects an
outage within a minute and reports a downtime figure that can be off by up to
one interval: an outage that falls entirely between two checks is reported as
one full interval.

## Architecture

1. `targets.csv` lists the hosts and ports to poll. It is re-read every round,
   so edits take effect without a restart.
2. `availability_monitor.py` runs under systemd, polls everything in parallel,
   and compares the result with the last state kept in
   `/var/ossec/logs/availability_monitor_state.json`.
3. Every check sends one JSON event to the local Wazuh queue socket. The event
   carries `reachability_event` with one of four values: `up`, `down`,
   `still_down`, `recovered`.
4. The rules match only `down` and `recovered`, so an outage generates exactly
   one alert and one recovery alert no matter how many rounds it spans.
5. The manager's existing email and Telegram paths are pointed at those rule
   IDs, which gives one notification per channel per transition.

## Step 1: list the targets

Create the target file:

```bash
sudo mkdir -p /etc/availability_monitor
sudo vim /etc/availability_monitor/targets.csv
```

Format: `name,target,port,port,...`. `name` is what appears in the alert.

```csv
# name, target, ports
app-server-01,10.0.0.22,22,443
db-server-01,10.0.0.31,5432
app-server-02,10.0.0.23
```

Blank lines and lines starting with `#` are skipped. A target with no ports
gets a ping check only.

## Step 2: install the poller

```bash
sudo mkdir -p /opt/availability_monitor
sudo cp availability_monitor.py /opt/availability_monitor/
sudo chmod 750 /opt/availability_monitor/availability_monitor.py
```

Run it in the foreground for a round or two before wiring it up (stop it with
Ctrl+C when you are satisfied):

```bash
sudo /usr/bin/python3 /opt/availability_monitor/availability_monitor.py --debug
```

The debug run prints each event as it is sent, including any socket error.

## Step 3: run it as a service

```bash
sudo cp availability_monitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now availability_monitor.service
sudo systemctl status availability_monitor.service
```

Interval and target file can be overridden in the unit without editing the
script, through `AVAILABILITY_INTERVAL_SECONDS` and
`AVAILABILITY_TARGETS_FILE`. After changing the unit:

```bash
sudo systemctl daemon-reload
sudo systemctl restart availability_monitor.service
```

> The unit runs as root so `ping` and the raw ICMP socket work. If you drop the
> user, either allow unprivileged ICMP through `net.ipv4.ping_group_range` or
> rely on port checks only.

## Step 4: deliver the events

The script pushes every event itself, straight to the local queue socket
`/var/ossec/queue/sockets/queue`, in the format Wazuh's own modules use:
`1:{program_name}:{json}` over a Unix datagram socket. That socket exists on
both agents and managers (it moved from `queue/ossec/queue` in Wazuh 4.2) and
needs no agent-side configuration. If it is missing, the script logs an error
naming the path and drops that round instead of crashing, so a stopped agent
shows up as a gap rather than as a silent failure.

The alternative used elsewhere in this repo is a `command` localfile that
collects a script's stdout (see [`../resource-monitoring`](../resource-monitoring)).
Adapting this poller to that pattern means adding a one-round mode, moving the
schedule from systemd to logcollector, and accepting that the startup and
warning lines are collected as events too. Choose one path only: configured
twice, every check is ingested twice.

## Step 5: rules

Copy the rules to the manager and load them:

```bash
sudo cp availability_rules.xml /var/ossec/etc/rules/local_availability.xml
```

In the dashboard: **Menu > Server management > Rules**, add or edit the rule
file, then **Save** and **Reload**.

| Rule | Level | Fires on |
|---|---|---|
| 100050 | 0 | Every event from the monitor (parent, never alerts alone) |
| 100051 | 12 | Host went down (ping) |
| 100052 | 7 | Host recovered (ping) |
| 100053 | 12 | Port went down |
| 100054 | 7 | Port recovered |

`up` and `still_down` events match only the level 0 parent, which is what keeps
a continuing outage silent. Both alerting levels sit above the default
`log_alert_level` of 3, so both alert and index.

Check a single event before trusting the live stream: run
`/var/ossec/bin/wazuh-logtest` on the manager and paste one of the sample JSON
events from the top of `availability_monitor.py`. The `up` sample matches only
rule 100050, and the `down` port sample matches rule 100053.

## Step 6: notifications by email and Telegram

Because deduplication happens in the poller, each channel sees at most one
message per transition. Wire the channels to the four rule IDs, not to a level
or to every alert.

### Email

The global `<email_alert_level>` defaults to 12, so the level 7
recovery rules produce no mail. Either lower that value, or force mail for the
recovery rules only:

```xml
<rule id="100052" level="7">
  <if_sid>100050</if_sid>
  <field name="reachability_check">ping</field>
  <field name="reachability_event">recovered</field>
  <alert_by_email />
  <description>Server $(reachability_server) ($(reachability_target)) recovered at $(reachability_timestamp) after $(reachability_downtime_human) downtime.</description>
</rule>
```

### Telegram

Wazuh has no built-in Telegram output, so send through your
existing `<integration>` script (the same mechanism as the
[webhook integration](../../integrations/webhook/README.md)):

```xml
<integration>
  <name>custom-telegram</name>
  <hook_url>https://api.telegram.org/bot[BOT_TOKEN]/sendMessage</hook_url>
  <rule_id>100051,100052,100053,100054</rule_id>
  <alert_format>json</alert_format>
</integration>
```

Your script maps the alert to the short message you want, for example:

```text
Server Offline
Name: app-server-01
Status: Offline
Detected At: 2026-01-01 10:15:00
```

and for a recovery:

```text
Server Recovered
Name: app-server-01
Status: Online
Recovered At: 2026-01-01 12:45:30
Downtime Duration: 2h 30m 30s
```

Everything needed is already in the alert: `rule.description` carries the name,
target, reason, timestamp, and downtime in one string, and the individual
`reachability_*` fields are in the event payload for anything else.

Validate the integration before relying on it:

```bash
sudo /var/ossec/bin/wazuh-integratord -t
sudo systemctl restart wazuh-manager
```

> Place the integration script and block on every node that processes alerts,
> keep the token out of version control, and filter by `rule_id` so unrelated
> alerts never reach the channel. See the
> [webhook guide](../../integrations/webhook/README.md) for hardening notes.

## Sizing and tuning

- **Round budget.** Each round runs `hosts x (1 + ports)` checks with
  `MAX_WORKERS` in flight. With 100 hosts, three checks each, one minute
  interval, and 30 workers at 1 to 2 seconds per check, a round finishes in
  well under a minute. If `journalctl -u availability_monitor` shows rounds
  taking close to the interval, raise `MAX_WORKERS` or the interval.
- **LAN traffic.** One echo request plus one TCP handshake per target per
  round is negligible at this scale. Traffic only becomes a concern if you cut
  the interval to a few seconds across hundreds of hosts.
- **Alert volume.** Steady state produces no alerts at all: only transitions
  match rules. The events still flow every round, which is what lets you chart
  availability later.
- **Detection latency vs load.** Halving the interval halves detection latency
  and doubles the check rate. Pick the interval from how fast you need to know,
  not from how fast you can poll.

## Verification and troubleshooting

1. **Service started but nothing arrives.** `journalctl -u
   availability_monitor` reports `Wazuh socket /var/ossec/queue/sockets/queue
   does not exist.` when the agent or manager is stopped. The events are
   dropped rather than queued, so start `wazuh-agent` or `wazuh-manager` and
   the next round delivers.
2. **Events arrive, no alerts.** Filter Threat Hunting on
   `rule.groups: availability_monitor`. If the raw events are there but no
   rule matched, re-run `wazuh-logtest` with the event and check the rules were
   reloaded.
3. **Duplicate alerts.** Confirm only one delivery path is configured
   (Step 4), and that no second copy of the rules file is loaded.
4. **A host that blocks ICMP always reports down.** Expected: use port checks
   for it and drop the ping row, or stop filtering ICMP on that host.
5. **A recovery alert after a poller restart with a missing downtime figure.**
   The state file was removed or the disk wiped. Delete
   `/var/ossec/logs/availability_monitor_state.json` only during a maintenance
   window: a host that is down at that moment produces a fresh `down` alert on
   the next round.
6. **Ports report `connection refused` while the host is up.** The TCP
   handshake reached the host and was rejected, so the service is not
   listening. That is a service alert, not a host alert.

## Related

- [`../service-monitoring`](../service-monitoring) - cron watchdog that mails
  when the Wazuh services themselves go down
- [`../resource-monitoring`](../resource-monitoring) - host CPU, memory, disk,
  and load metrics as Wazuh alerts
- [`../email-alerting`](../email-alerting) - granular email routing by group,
  level, and agent label
- [`../../integrations/webhook`](../../integrations/webhook) - the
  `<integration>` pattern used for Telegram and other destinations
- [`../../troubleshooting/agents/disconnections.md`](../../troubleshooting/agents/disconnections.md)
  - what an agent disconnect alert does and does not tell you
- [`../../rules/README.md`](../../rules/README.md) - writing and deploying
  custom rules
