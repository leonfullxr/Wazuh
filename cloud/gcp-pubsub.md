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
- [References](#references)

## Introduction

This guide integrates Google Cloud logs into Wazuh using Pub/Sub with Application Default Credentials (ADC). The Wazuh manager runs on a GCE VM with an attached service account, so no private key or credential JSON files are required -- authentication happens through the instance metadata server.

The flow: Google Cloud services publish logs to a Pub/Sub topic (typically via a Cloud Logging sink), a small subscriber script on the Wazuh manager pulls the messages, writes them to a local log file wrapped in a `{"gcp": ...}` envelope, and a `localfile` monitor feeds them into the Wazuh pipeline. GKE audit logs are typically ingested through this same pipeline.

> Wazuh also ships a native `gcp-pubsub` module (see the [official GCP documentation](https://documentation.wazuh.com/current/cloud-security/gcp/index.html)); the ADC approach below is useful when you specifically want to avoid distributing service account key files.

## Step 1: Install Python Dependencies

Follow the official Wazuh documentation: [Installing dependencies - Wazuh documentation](https://documentation.wazuh.com/current/cloud-security/gcp/prerequisites/dependencies.html#installing-dependencies)

## Step 2: Create a Service Account

1. In the Google Cloud Console, navigate to IAM & Admin > Service Accounts.
2. Click + CREATE SERVICE ACCOUNT.
3. Provide a name and description, then click CREATE AND CONTINUE.
4. Assign the following roles to the service account:
   - Pub/Sub Publisher
   - Pub/Sub Subscriber
   - Pub/Sub Viewer
5. Click Done.

## Step 3: Attach the Service Account to the Wazuh Manager VM

1. Go to the VM instances page in GCP and select the VM running the Wazuh manager.
2. Stop the VM, then click Edit.
3. In the Service Account section, select the service account created earlier from the drop-down list.
4. In the Access scopes section, select Set access for each API and enable the Cloud Pub/Sub scope (leave the other APIs at their defaults unless you need them).
5. Click Save, then Start/Resume the VM.

## Step 4: Test Connectivity with the Metadata Server

Run the following from the Wazuh manager VM:

```bash
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"
```

If the setup is correct, this returns an access token, confirming the VM can authenticate without a private key.

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

4. Enable the file monitor and the script. On the Wazuh dashboard go to Menu > Server management > Settings > Edit configuration and add at the end of the file:

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

   Click Save and restart the manager.

## Step 6: Configure Rules

Go to Menu > Server management > Rules > Add new rule file, name the file `gcp_overwrite`, and paste the following base rule so the wrapped JSON events are decoded:

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

Click Save, then Restart. Build child rules on top of `65000` (raising the level for the event types you care about) so events actually alert.

## Step 7: Verify Events

Go to Menu > Threat Intelligence > Threat hunting > Events and add a filter such as `rule.groups: gcp` (or filter on the `data.gcp` fields). Incoming Pub/Sub messages should appear with their payload under `data.gcp.*`.

## References

- [Using Wazuh to monitor Google Cloud - Wazuh documentation](https://documentation.wazuh.com/current/cloud-security/gcp/index.html)
- [GCP dependencies installation](https://documentation.wazuh.com/current/cloud-security/gcp/prerequisites/dependencies.html)
- [AWS log ingestion](aws.md) -- the S3/SQS counterpart of this pipeline
- [Azure log ingestion](azure.md)
