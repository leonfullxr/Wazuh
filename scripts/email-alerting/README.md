# Granular email alerting

Two independent layers can send alert emails, and they are useful in different
situations:

- **Manager-side** (`ossec.conf`): the manager mails alerts directly through a
  local MTA. Indexer-independent: it keeps working even when the dashboard or
  indexer is unavailable (shard limit hit, disk full, etc.), which is a common
  reason people miss dashboard alerts.
- **Indexer-side** (OpenSearch Alerting module in the dashboard): monitors run
  queries against indexed data on a schedule and deliver notifications through
  channels (Email, Slack, Teams, Chime, SNS, custom webhook). More flexible for
  correlation, custom formatting, and per-group routing, but depends on the
  indexer being healthy.

Pick manager-side for resilient, simple level/rule/group routing; pick
indexer-side when you need rich queries, custom message bodies, or scalable
per-agent-group routing.

## Manager-side email

### Generic options (all alerts above a level)

In the `<global>` and `<alerts>` sections of the manager's `ossec.conf`:

```xml
<ossec_config>
  <global>
    <alerts_log>yes</alerts_log>
    <email_notification>yes</email_notification>
    <smtp_server>localhost</smtp_server>
    <email_from>wazuh@example.com</email_from>
    <email_to>recipient@example.com</email_to>
    <email_maxperhour>20</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>
</ossec_config>
```

`<email_notification>` must be `yes` to enable any email (generic or granular).
`<smtp_server>` is `localhost` when a local MTA relays the mail (see
[Mail transport](#mail-transport)).

### Granular options (per rule, group, or level)

`<email_alerts>` blocks extend the generic options to route specific alerts to
specific recipients. Add one block per recipient/criteria combination:

```xml
<!-- Route specific rule IDs to one recipient -->
<email_alerts>
  <email_to>soc@example.com</email_to>
  <rule_id>503, 504, 505, 506</rule_id>
  <do_not_delay />
</email_alerts>

<!-- Route an entire rule group to another recipient -->
<email_alerts>
  <email_to>fim-team@example.com</email_to>
  <group>syscheck</group>
  <do_not_delay />
</email_alerts>
```

Useful sub-options: `<level>` (minimum level for this block), `<group>`,
`<rule_id>`, `<event_location>` (single agent/location), `<format>` (`sms` for
short bodies), and `<do_not_delay/>` to send immediately instead of batching.

**Precedence gotcha:** the global `<alerts>` section takes precedence over the
granular `<email_alerts>` blocks. Regardless of the per-block criteria, you
still receive email for *every* alert at or above the global
`<email_alert_level>`. To email *only* specific groups/rules, raise the global
`<email_alert_level>` above your normal rule levels and give the rules you want
emailed a level at or above it.

## Per-OS / per-agent-group routing

Goal: Windows admins get alerts only from Windows agents, Linux admins only
from Linux agents, without listing hundreds of `<event_location>` hosts.

The scalable foundation is agent groups, not per-host config. Put agents in
groups and stamp a label on each group's configuration
(`/var/ossec/etc/shared/<group>/agent.conf`):

```xml
<agent_config>
  <labels>
    <label key="group">Windows</label>
  </labels>
</agent_config>
```

The label surfaces on every alert as `agent.labels.group`, which both layers
can filter on.

- **Manager-side:** there is no native "route by label" option. The only
  manager-side way is a custom integration script that reads the label
  field on each alert and sends to the matching address. Wire it to fire above
  a level, then branch inside the script (place the script and block on *all*
  managers):

  ```xml
  <integration>
    <name>custom-email.py</name>
    <level>12</level>
    <alert_format>json</alert_format>
    <options>JSON</options>
  </integration>
  ```

- **Indexer-side (recommended for this use case):** create one monitor per
  group, each filtering on `agent.labels.group` and mailing a group-specific
  recipient. This scales cleanly and needs no per-host or per-manager changes.
  See below.

## Indexer-side: OpenSearch Alerting module

Three parts: SMTP sender, notification channel, and a monitor with a trigger
and an action.

### 1. Notifications (sender, recipients, channel)

Dashboard > **Notifications**:

1. **Email senders** > create a sender: give it a name, set the SMTP host and
   port (for a local relay, port `25`).
2. **Email recipient groups** > create a group with one or more addresses
   (e.g. `windows-admins@example.com`).
3. **Channels** > create an Email channel: pick the SMTP sender as sender type
   and the recipient group as default recipients. Use Send test message to
   confirm delivery before wiring up monitors.

### 2. Monitor

Dashboard > **Alerting** > **Create monitor**:

- Type Per query monitor, method Extraction query editor.
- Data source: index pattern `wazuh-alerts-*`, time field `timestamp`.
- Set the run schedule (e.g. every 1 minute for near-real-time, or a longer
  digest interval).

Example query for "high-severity alerts (level 12-14) from the Windows agent
group in the last minute". Change `Windows` to `Linux` (and the channel) for
the second monitor:

```json
{
  "size": 500,
  "query": {
    "bool": {
      "filter": [
        { "match_all": { "boost": 1 } },
        {
          "match_phrase": {
            "agent.labels.group": {
              "query": "Windows",
              "slop": 0,
              "zero_terms_query": "NONE",
              "boost": 1
            }
          }
        },
        {
          "range": {
            "rule.level": {
              "from": 12, "to": 15,
              "include_lower": true, "include_upper": false,
              "boost": 1
            }
          }
        },
        {
          "range": {
            "@timestamp": {
              "from": "{{period_end}}||-1m",
              "to": "{{period_end}}",
              "include_lower": true, "include_upper": true,
              "format": "epoch_millis",
              "boost": 1
            }
          }
        }
      ],
      "adjust_pure_negative": true,
      "boost": 1
    }
  },
  "_source": {
    "includes": [
      "agent.id", "agent.ip", "agent.name",
      "rule.id", "rule.description", "full_log", "@timestamp"
    ],
    "excludes": []
  }
}
```

A quick way to build the base query: create the equivalent filter in
**Discover**, then **Inspect > Request** and copy it. Trim the copied query to
the fields above (remove the huge `docvalue_fields`/`highlight` blocks the UI
adds) and make the time range relative with `{{period_end}}` so it re-runs
correctly on schedule.

### 3. Trigger and action

- **Trigger:** alert when the result count is above zero:
  `ctx.results[0].hits.total.value > 0`.
- **Action:** send to the Email channel created above. Use a Mustache body to
  enrich the mail:

  ```
  Monitor {{ctx.monitor.name}} just entered alert status. Please investigate.
    - Trigger: {{ctx.trigger.name}}
    - Severity: {{ctx.trigger.severity}}
    - Period start: {{ctx.periodStart}} UTC
    - Period end: {{ctx.periodEnd}} UTC

  {{#ctx.results.0.hits.hits}}
  - Agent name: {{_source.agent.name}}
  - Agent ID: {{_source.agent.id}}
  - Agent IP: {{_source.agent.ip}}
  - Rule ID: {{_source.rule.id}}
  - Description: {{_source.rule.description}}
  - Full log: {{_source.full_log}}
  --------------------------------------------------
  {{/ctx.results.0.hits.hits}}
  ```

Use Preview / Send test message to check the body renders, then save.

## Gotchas and operations

- **Alerting emails are not Wazuh alerts.** Monitor alerts are generated
  *inside the indexer* from stored data. They do not appear in Discover and are
  managed only within the Alerting module.
- **Migrating Elastic Watchers to OpenSearch monitors.** There is no
  import/export tool: recreate monitors and translate the query/trigger to
  OpenSearch syntax. The most common breakage after a copy is the payload path:
  Elastic's `ctx.payload.hits.hits` must become `ctx.results.0.hits.hits`.
- **Blank test message.** "Send test message" sends exactly what the message
  preview shows. A blank body means a Mustache syntax error (often the
  `ctx.payload` to `ctx.results.0` issue above), not a test-harness quirk.
- **"Too many dynamic script compilations within, max: [75/5m]".** Inline
  Mustache/Painless scripts are compiled and cached; too many distinct inline
  scripts overflow the cache and hit the compilation-rate limit. You can raise
  it via the indexer API, but a high value can degrade or crash the cluster:
  treat it as a stopgap, and reduce the number of distinct inline scripts
  (reuse a common template) as the real fix:

  ```
  PUT _cluster/settings
  {
    "persistent": { "script.max_compilations_rate": "250/5m" }
  }
  ```

- **Alert states.** *Active* = ongoing, unacknowledged; *Acknowledged* =
  ongoing, a user acknowledged it; *Completed* = the condition is no longer
  met; *Ignored* = completed but never acknowledged (informational, a high
  "Ignored" count is normal, not an error).
- **No UI import of a full monitor.** The dashboard has no "import monitor from
  JSON". Create monitors programmatically with the Alerting API and channels
  with the Notifications API.
- **Correlating multiple conditions.** Chain monitors with composite
  monitors for correlated alerts (analogous to composite rules), instead of
  one giant query.

## Mail transport

Manager-side email and any local SMTP relay need an MTA on the manager. On
Debian/Ubuntu:

```bash
apt-get install postfix mailutils libsasl2-2 ca-certificates libsasl2-modules
```

For an external relay that requires authentication, configure SASL in Postfix
(SMTP-auth) and set `<smtp_server>` to the relay host. On Wazuh Cloud, the
platform relays mail for you: provide sender, host, port, and recipients.

## Related

- [`../syscheck-email-notifications`](../syscheck-email-notifications) - the
  FIM-specific case of manager-side granular email alerts.
- [`../service-monitoring`](../service-monitoring) - service-down email alerts.
- [`../active-response`](../active-response) - react to (not just notify on)
  detections.
