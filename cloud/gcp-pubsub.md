# Google Cloud Log Ingestion via Pub/Sub with Application Default Credentials

## Table of Contents
- [Introduction](#introduction)
- [Step 1: Install Python Dependencies](#step-1-install-python-dependencies)
- [Step 2: Create a Service Account](#step-2-create-a-service-account)
- [Step 3: Attach the Service Account to the Wazuh Manager VM](#step-3-attach-the-service-account-to-the-wazuh-manager-vm)
- [Step 4: Test Connectivity with the Metadata Server](#step-4-test-connectivity-with-the-metadata-server)
- [Step 5: Configure the Subscriber Script and Local File Monitor](#step-5-configure-the-subscriber-script-and-local-file-monitor)
- [Step 6: Configure Rules](#step-6-configure-rules)
- [Step 7: Verify Events](#step-7-verify-events)
- [Troubleshooting: some events never reach the dashboard](#troubleshooting-some-events-never-reach-the-dashboard)
- [References](#references)
- [Related](#related)

## Introduction

This guide integrates Google Cloud logs into Wazuh using **Pub/Sub with Application Default Credentials (ADC)**. The Wazuh manager runs on a GCE VM with an attached service account, so **no private key or credential JSON files are required** -- authentication happens through the instance metadata server.

The flow: Google Cloud services publish logs to a Pub/Sub topic (typically via a Cloud Logging sink), a small subscriber script on the Wazuh manager pulls the messages, writes them to a local log file wrapped in a `{"gcp": ...}` envelope, and a `localfile` monitor feeds them into the Wazuh pipeline. GKE audit logs are typically ingested through this same pipeline.

> Wazuh also ships a native `gcp-pubsub` module (see the [official GCP documentation](https://documentation.wazuh.com/current/cloud-security/gcp/index.html)); the ADC approach below is useful when you specifically want to avoid distributing service account key files.

## Step 1: Install Python Dependencies

Follow the official Wazuh documentation: [Installing dependencies - Wazuh documentation](https://documentation.wazuh.com/current/cloud-security/gcp/prerequisites/dependencies.html#installing-dependencies)

## Step 2: Create a Service Account

1. In the Google Cloud Console, navigate to **IAM & Admin > Service Accounts**.
2. Click **+ CREATE SERVICE ACCOUNT**.
3. Provide a **name** and **description**, then click **CREATE AND CONTINUE**.
4. Assign the following **roles** to the service account:
   - **Pub/Sub Publisher**
   - **Pub/Sub Subscriber**
   - **Pub/Sub Viewer**
5. Click **Done**.

## Step 3: Attach the Service Account to the Wazuh Manager VM

1. Go to the **VM instances** page in GCP and select the VM running the Wazuh manager.
2. **Stop** the VM, then click **Edit**.
3. In the **Service Account** section, select the service account created earlier from the drop-down list.
4. In the **Access scopes** section, select **Set access for each API** and enable the **Cloud Pub/Sub** scope (leave the other APIs at their defaults unless you need them).
5. Click **Save**, then **Start/Resume** the VM.

## Step 4: Test Connectivity with the Metadata Server

Run the following from the Wazuh manager VM:

```bash
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"
```

If the setup is correct, this returns an **access token**, confirming the VM can authenticate without a private key.

## Step 5: Configure the Subscriber Script and Local File Monitor

1. Create the file where the Pub/Sub logs will be stored:

   ```bash
   touch /var/ossec/logs/gcp-pubsub.log
   chmod 660 /var/ossec/logs/gcp-pubsub.log
   chown wazuh: /var/ossec/logs/gcp-pubsub.log
   ```

2. Create the script `/var/ossec/integrations/gcp_pubsub.py` with the content below, replacing `[PROJECT_ID]` with your GCP project ID and `[SUBSCRIPTION_ID]` with the name of your Pub/Sub subscription:

   ```python
   #!/usr/bin/env python3
   import sys
   import json
   import logging

   from google.cloud import pubsub_v1
   from google.auth import default

   LOG_FILE = "/var/ossec/logs/gcp-pubsub.log"

   logging.basicConfig(
       filename=LOG_FILE,
       format="%(message)s",
       level=logging.INFO
   )

   PROJECT_ID = "[PROJECT_ID]"
   SUBSCRIPTION_ID = "[SUBSCRIPTION_ID]"


   def callback(message):
       try:
           data = message.data.decode("utf-8")
           payload = json.loads(data)
           wrapped = {"gcp": payload}
           logging.info(json.dumps(wrapped))
           message.ack()
       except Exception as e:
           print(f"Error processing message: {e}", file=sys.stderr)
           message.nack()


   def main():
       credentials, project = default()
       subscriber = pubsub_v1.SubscriberClient(credentials=credentials)
       subscription_path = subscriber.subscription_path(PROJECT_ID, SUBSCRIPTION_ID)
       print(f"Listening for messages on {subscription_path}...")
       streaming_pull = subscriber.subscribe(subscription_path, callback=callback)
       try:
           streaming_pull.result()
       except KeyboardInterrupt:
           streaming_pull.cancel()


   if __name__ == "__main__":
       main()
   ```

3. Set the proper permissions:

   ```bash
   chmod 750 /var/ossec/integrations/gcp_pubsub.py
   chown root:wazuh /var/ossec/integrations/gcp_pubsub.py
   ```

4. Enable the file monitor and the script. On the Wazuh dashboard go to **Menu > Server management > Settings > Edit configuration** and add at the end of the file:

   ```xml
   <localfile>
     <log_format>syslog</log_format>
     <location>/var/ossec/logs/gcp-pubsub.log</location>
   </localfile>

   <wodle name="command">
     <disabled>no</disabled>
     <tag>pubsub</tag>
     <command>/var/ossec/framework/python/bin/python3 /var/ossec/integrations/gcp_pubsub.py</command>
     <interval>1m</interval>
     <ignore_output>yes</ignore_output>
     <run_on_start>yes</run_on_start>
     <timeout>0</timeout>
   </wodle>
   ```

   Click **Save** and restart the manager.

## Step 6: Configure Rules

Go to **Menu > Server management > Rules > Add new rule file**, name the file `gcp_overwrite`, and paste the following base rule so the wrapped JSON events are decoded:

```xml
<group name="gcp,">
  <!-- GCP Pub/Sub events -->
  <rule id="65000" level="0" overwrite="yes">
    <decoded_as>json</decoded_as>
    <match>{"gcp":</match>
    <options>no_full_log</options>
    <description>GCP alert.</description>
  </rule>
</group>
```

Click **Save**, then **Restart**. Build child rules on top of `65000` (raising the level for the event types you care about) so events actually alert.

## Step 7: Verify Events

Go to **Menu > Threat Intelligence > Threat hunting > Events** and add a filter such as `rule.groups: gcp` (or filter on the `data.gcp` fields). Incoming Pub/Sub messages should appear with their payload under `data.gcp.*`.

If an event is visible in Google Cloud but never appears here, or it appears hours or days late, work through the troubleshooting section below.

## Troubleshooting: some events never reach the dashboard

The integration is up and other log types flow normally, yet specific events (a failed database login, a role or privilege change, a single statement) are missing from the dashboard, apparently at random. Sometimes one test run produces an alert and the identical test run produces nothing.

Two unrelated failures produce that picture, and they are fixed in different places. Split them before changing any configuration.

### First, split the two failures

1. **Archive everything the manager receives.** Add `<logall_json>yes</logall_json>` to `/var/ossec/etc/ossec.conf`, restart `wazuh-manager`, and let it run for the duration of the test. Events are written to `/var/ossec/logs/archives/archives.json`.
2. **Exercise one event per class you care about.** A scratch set that covers the usual branches:
   - a failed login (`psql -h <DB_IP> -U <DB_USER> -W`, then a wrong password)
   - a role change: `CREATE ROLE`, `GRANT`, `REVOKE`, `DROP ROLE`
   - a syntax error
   - a data export, for example `COPY (SELECT ...) TO STDOUT`
   - a query against a table that does not exist
   - a session setting change inside a transaction

   Give every scratch object a marker name you can grep for afterwards.
3. **Grep `archives.json` for the marker.**
   - **Not found.** The event never reached the manager, so the problem is upstream in the log delivery path. Continue with the two sections below.
   - **Found, but no alert.** The manager received and decoded the event, so the problem is in the rules. Continue with [the rules section](#the-event-arrives-but-never-alerts).
4. **Rule out drops inside the manager.** Read the `drop` counters in `/var/ossec/var/run/wazuh-analysisd.state` while you repeat the tests. They must not increase; a rising counter points at manager saturation rather than at Pub/Sub or at the rules. See [analysisd troubleshooting](../troubleshooting/server/analysisd.md).

> Set `<logall_json>` back to `no` and restart the manager when the test is over. Archives are a diagnostic tool here, not a setting to leave on.

### The subscription is saturated

Applies to the native `gcp-pubsub` wodle. The ADC subscriber script in Step 5 has no message cap, but a single streaming process still has a finite rate, so the same backlog metrics apply to it.

Each wodle execution pulls at most `max_messages` messages (default `100`) and exits. `interval` decides how often it runs, and `num_threads` splits the work inside one cycle without raising that cap. Sustained throughput is therefore:

```text
max_messages x (minutes per day / interval in minutes)
```

When the sink publishes faster than this, undelivered messages pile up in the subscription until they reach its retention limit (seven days by default) and Pub/Sub deletes them. Once the backlog is pinned at that ceiling, old messages expire as fast as new ones arrive, so nothing grows and nothing warns: the loss is silent. The messages that do get through arrive days stale and out of order, which is exactly why the missing events look random.

**Evidence.** All four signatures together confirm this root cause:

| Check | Signature of a saturated subscription |
|---|---|
| Pull cycles in `ossec.log` | Every cycle reports exactly `max_messages`, for example `Received and acknowledged 100 messages`, and never a lower number |
| `num_undelivered_messages` | Flat at its ceiling for hours: it neither grows nor drains |
| Timestamps inside one pull | Events from several different days mixed in a single response, up to the retention period stale |
| `archives.json` | Every event the wodle did process is present, so the Wazuh side of the path is clean |

To see the caps actually used, set `wazuh_modules.debug=2` in `/var/ossec/etc/local_internal_options.conf`, restart the manager, and grep `ossec.log` for `Launching command: wodles/gcloud/gcloud`, which prints `--max_messages` and `--num_threads` for every cycle.

**Sizing.** Compare the daily throughput with the rate the sink publishes:

| Configuration | Daily throughput |
|---|---|
| `interval` 30m, `max_messages` 100 | 4,800 messages per day |
| `interval` 2m, `max_messages` 100 | 72,000 messages per day |
| `interval` 1m, `max_messages` 5000 | up to 7,200,000 messages per day |

A stream of about five messages per second is roughly 400,000 events per day, so only the last shape keeps up. Shorten the interval rather than stretching it: each cycle pays a few seconds of Python start-up before it pulls anything, which makes a frequent cycle with a large cap cheaper than a rare cycle with a small one.

**Fix.** Run the wodle often, with a cap sized for the rate it has to drain:

```xml
<wodle name="gcp-pubsub">
  <enabled>yes</enabled>
  <pull_on_start>yes</pull_on_start>
  <interval>1m</interval>
  <max_messages>5000</max_messages>
  <num_threads>4</num_threads>
  <project_id>[PROJECT_ID]</project_id>
  <subscription_name>[SUBSCRIPTION_ID]</subscription_name>
  <credentials_file>[CREDENTIALS_FILE]</credentials_file>
</wodle>
```

Size `max_messages x cycles per day` to comfortably exceed the publish rate you measure after narrowing the sink filter (next section). Raise `num_threads` if a single cycle takes longer than the interval.

**Then drain what is queued.** With millions of stale messages waiting, the wodle would spend days replaying history while current events keep expiring. After the new throughput is in place, seek the subscription to the current time so the backlog is discarded:

```bash
gcloud pubsub subscriptions seek [SUBSCRIPTION_ID] --timestamp="$(date -u +%FT%TZ)"
```

**Then check the subscription's own settings.** Keep message retention longer than the worst outage you expect from the manager, and leave the acknowledgement deadline alone unless pulls time out. A manager that is down longer than the retention period loses those messages regardless of the wodle configuration.

**Verification.** Pull cycles in `ossec.log` start reporting fewer messages than `max_messages`, `num_undelivered_messages` trends down, and a fresh test event shows up in `archives.json` within one cycle. As long as a cycle still reports exactly `max_messages`, the subscription is not being drained.

### The sink filter is too broad

The Log Router filter decides what competes for the subscription's bandwidth. A filter with no severity or event-type condition captures every log line the database instance emits, and connection churn from `log_connections` / `log_disconnections` is normally most of it. In one sizing exercise, about 98 of every 100 sampled events were connection or disconnection lines, while the DDL, role and privilege stream the integration was built to collect had never arrived at all: it was drowned out before the wodle ever saw it.

1. **Sample what the sink delivers.** Run the sink's own filter in Log Explorer over a representative window and group the results by log name and severity. Count how much of the volume is connection churn.
2. **Exclude the churn.** Add an exclusion filter for the connection and disconnection lines, or restrict the filter to the event types you alert on. Whatever you exclude stops competing for bandwidth.
3. **Do not filter on severity alone.** A monitoring exporter that fails once a minute sits in the ERROR bucket permanently and will dominate it. Exclude that pattern as well, and check first whether it is a genuine missing grant on the exporter's database role rather than noise you can drop.
4. **Leave the audit stream unfiltered.** Keep the `cloudaudit.googleapis.com/data_access` filter unrestricted so PgAudit entries for DDL, role and privilege changes are not competing with connection churn.
5. **Re-measure, then re-size.** Narrowing the filter lowers the publish rate. Size `max_messages` and `interval` against the rate measured after the change, not before it.

### The event arrives but never alerts

The manager decoded the event and it is in `archives.json`, but the dashboard shows nothing. The cause is the alert threshold: `<log_alert_level>` defaults to `3`, and an event matched by a level 0 to level 2 rule is discarded after decoding. It never reaches `alerts.log` or `alerts.json`, so the indexer never receives it and no visualization can show it. The stock GCP base rules sit below that threshold.

Overwrite the base rule at level 3 or higher, as in Step 6, then build the detection rules as children of it. While debugging a rule that refuses to fire:

- **Point at the rule that matched.** `<if_sid>` must list the rule id recorded in the event (`rule.id`), not the parent you assumed would match.
- **Mind case.** Field matching is case sensitive. Use `type="pcre2"` with `(?i)` when the payload casing varies between messages.
- **`no_full_log` hides the payload.** It keeps noisy rules quiet, but it also strips the text you are trying to debug against. Drop it until the rule fires as expected.
- **Frequency rules need repetitions.** `<frequency>` counts matches inside `<timeframe>`, so a single test statement never triggers them. Repeat the test within the window, or test the parent alone.
- **Restart the manager after editing rules** so `analysisd` reloads them.

**Verification.** The same test event appears in **Threat hunting > Events** with `rule.level` at or above the threshold. If it is in `archives.json` but still absent from `wazuh-alerts-*`, the level is still too low.

## References

- [Using Wazuh to monitor Google Cloud - Wazuh documentation](https://documentation.wazuh.com/current/cloud-security/gcp/index.html)
- [GCP dependencies installation](https://documentation.wazuh.com/current/cloud-security/gcp/prerequisites/dependencies.html)
- [AWS log ingestion](aws.md) -- the S3/SQS counterpart of this pipeline
- [Azure log ingestion](azure.md)

## Related

- [Troubleshooting hub](../troubleshooting/README.md): manager-side drops, queue growth, and agent-side loss
- [Custom rules](../rules/README.md): writing and deploying the child rules referenced above
- [Alert management](https://documentation.wazuh.com/current/user-manual/manager/alert-management.html): `log_alert_level` and the alert threshold
- [AWS log ingestion](aws.md) and [Azure log ingestion](azure.md): the same provider-first verification order applies to those pipelines
