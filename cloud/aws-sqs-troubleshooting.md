# Troubleshooting AWS S3/SQS log ingestion (aws-s3 subscriber)

The `<subscriber type="buckets">` path (and `security_hub` / `security_lake`) is the recommended way to ingest high-volume or custom S3 logs: S3 sends an event notification to an SQS queue, and Wazuh's `aws-s3` module drains the queue instead of listing the bucket. It fails in a handful of recurring, recognizable ways. This guide is symptom-driven: match the exit code or error string, then apply the fix.

> Applies to Wazuh 4.x, the `aws-s3` wodle on a self-hosted manager or agent (EC2/VM, Docker, self-managed EKS/AKS). For first-time setup, IAM, and credentials see [aws.md](aws.md).

## Table of Contents

- [How the SQS subscriber works (vs bucket polling)](#how-the-sqs-subscriber-works-vs-bucket-polling)
- [Exit codes at a glance](#exit-codes-at-a-glance)
- [Queue does not exist, verify the given name (exit 20)](#queue-does-not-exist-verify-the-given-name-exit-20)
- [Cross-account iam_role_arn fails (pre-4.14.7 bug)](#cross-account-iam_role_arn-fails-pre-4147-bug)
- [NoSuchKey - the specified key does not exist (exit 12/1)](#nosuchkey---the-specified-key-does-not-exist-exit-121)
- [gzip objects fail: utf-8 codec can't decode byte 0x8b (exit 12)](#gzip-objects-fail-utf-8-codec-cant-decode-byte-0x8b-exit-12)
- [One consumer per queue (exit 21, duplicates, "Too many connections")](#one-consumer-per-queue-exit-21-duplicates-too-many-connections)
- [Interval overtaken - the wodle can't keep up](#interval-overtaken---the-wodle-cant-keep-up)
- [VisibilityTimeout and a dedicated queue](#visibilitytimeout-and-a-dedicated-queue)
- [Custom-bucket logs arrive but don't alert](#custom-bucket-logs-arrive-but-dont-alert)
- [Non-supported sources (third-party SaaS)](#non-supported-sources-third-party-saas)
- [Event too large - "Message too long"](#event-too-large---message-too-long)
- [Debugging](#debugging)
- [Related](#related)

## How the SQS subscriber works (vs bucket polling)

```
AWS service -> S3 object -> S3 event notification -> SQS queue -> aws-s3 subscriber
                                                                  | 1. receive message(s)
                                                                  | 2. GetObject from S3
                                                                  | 3. parse and send to analysisd
                                                                  + 4. delete message from SQS
```

| | `<bucket type="...">` polling | `<subscriber type="buckets">` (SQS) |
|---|---|---|
| Progress tracking | Local SQLite marker under `/var/ossec/wodles/aws/` | SQS tracks delivery, no local marker |
| Discovery each cycle | S3 `LIST` of the bucket (an AWS-billed op every interval, even with no new files) | Reads messages already queued |
| Latency | Higher (list and compare each cycle) | Lower (events pre-queued) |
| `only_logs_after` | Honored on first run | Not available for subscriber tags |
| Queue ownership | n/a | Wazuh deletes messages, so the queue must be dedicated to Wazuh |

Because there is no local marker, messages that piled up while Wazuh was down are all still there when it returns (within the queue's retention). Conversely, a queue left with stale messages replays old logs, so clear the queue if you re-point it at a fresh source.

## Exit codes at a glance

The module logs `Subscriber: buckets <queue> - Returned exit code N`. The codes seen most often on the SQS path:

| Exit code | Meaning | Section |
|---|---|---|
| `2` | Bad arguments (e.g. a space or URL in the queue name) | [queue name](#queue-does-not-exist-verify-the-given-name-exit-20) |
| `12` | Error while processing a fetched object (NoSuchKey, gzip decode, and so on) | [NoSuchKey](#nosuchkey---the-specified-key-does-not-exist-exit-121), [gzip](#gzip-objects-fail-utf-8-codec-cant-decode-byte-0x8b-exit-12) |
| `20` | Queue does not exist / not found | [exit 20](#queue-does-not-exist-verify-the-given-name-exit-20) |
| `21` | Failed fetch/delete from SQS (often multiple consumers) | [one consumer](#one-consumer-per-queue-exit-21-duplicates-too-many-connections) |

The full list is in the [official troubleshooting codes](https://documentation.wazuh.com/current/cloud-security/amazon/troubleshooting.html). The string after the code is what matters, so always read it.

## Queue does not exist, verify the given name (exit 20)

```
wazuh-modulesd:aws-s3: WARNING: Subscriber: buckets my-logs-sqs  -  Returned exit code 20
wazuh-modulesd:aws-s3: WARNING: Subscriber: buckets my-logs-sqs  -  Queue does not exist, verify the given name
```

Work through these in order; the queue almost always does exist:

1. **Region mismatch (most common).** With no region configured, the module defaults to `us-east-1`, so a queue in any other region then "does not exist". Set the region in the profile's config (`region = eu-central-1`). On a containerized or managed manager where you cannot edit `/root/.aws/config`, make sure the mounted profile config carries the region (see [aws.md: Kubernetes credentials](aws.md#persisting-credentials-in-kubernetes)). Confirm from the host:

    ```bash
    aws sqs get-queue-url --queue-name my-logs-sqs --region eu-central-1 --profile my-profile
    ```

2. **The `<sqs_name>` must be the queue name, not its URL or ARN.**
3. **Invalid queue name.** SQS names allow only alphanumerics, `-`, and `_`, up to 80 chars. A space (`My SQS`) yields exit code 2 or parse errors, so rename the queue.
4. **Cross-account with `<iam_role_arn>`** on a pre-4.14.7 agent, see [the bug below](#cross-account-iam_role_arn-fails-pre-4147-bug).
5. **IAM.** Missing `sqs:GetQueueUrl` (plus `sqs:ReceiveMessage`, `sqs:DeleteMessage`, `sqs:GetQueueAttributes`).

## Cross-account iam_role_arn fails (pre-4.14.7 bug)

Setup: the manager authenticates in account A (instance role or IRSA), while the SQS queue and its role live in account B, reached with `<iam_role_arn>`. Manually assuming the role works and lists the queue, but the wodle reports exit 20 `Queue does not exist`:

```bash
# Works (proves the queue and permissions are fine): manual assume-role, then:
/var/ossec/wodles/aws/aws-s3 --subscriber buckets --queue my-logs-sqs --debug 2
# Fails via the module's own -i/--iam_role_arn path with "Queue does not exist"
```

Root cause: the subscriber built its STS client without the assumed role, so `get_caller_identity()` returned account A's ID. That ID was passed to `get_queue_url` as `QueueOwnerAWSAccountId`, so SQS looked for the queue in account A and did not find it.

Fix: upgrade to 4.14.7+ ([wazuh/wazuh#36197](https://github.com/wazuh/wazuh/issues/36197)). Pre-4.14.7 workaround: drop `QueueOwnerAWSAccountId` from the `get_queue_url` call in `subscribers/sqs_queue.py`. The SQS client is already authenticated with the account-B assumed-role credentials, so it resolves the owner from the caller:

```bash
systemctl stop wazuh-manager
sed -i.bak -zE 's/get_queue_url\(QueueName=self\.sqs_name,\s*QueueOwnerAWSAccountId=self\.account_id\)/get_queue_url(QueueName=self.sqs_name)/' \
    /var/ossec/wodles/aws/subscribers/sqs_queue.py
rm -f /var/ossec/wodles/aws/subscribers/__pycache__/sqs_queue.*.pyc
systemctl start wazuh-manager
```

> On containers this file edit is ephemeral: it is lost on pod restart. Bake it in via an init-container or a ConfigMap-mounted file (see [Kubernetes persistent config](../containerization/kubernetes/persistent-storage.md)), or just upgrade. Prefer upgrading.

## NoSuchKey - the specified key does not exist (exit 12/1)

```
wazuh-modulesd:aws-s3: WARNING: Subscriber: buckets my-logs-sqs  -  Returned exit code 12
An error occurred (NoSuchKey) when calling the GetObject operation: The specified key does not exist.
```

The SQS message points at an S3 object the module then cannot GET. Two distinct causes:

1. **The object was deleted before Wazuh fetched it.** A short S3 lifecycle rule, or another process (or a second Wazuh consumer), removed it. A single such "poison" message can stall an older module that tracebacks instead of skipping. Fixes: attach an SQS Dead Letter Queue with a redrive policy (e.g. after 5-10 receives) so poison messages leave the main queue; make sure Wazuh is the [only consumer](#one-consumer-per-queue-exit-21-duplicates-too-many-connections); and keep the module current (recent versions skip a missing object and continue).
2. **Special characters in the object key.** S3 event notifications URL-encode the key, so a key containing a colon arrives as `...-21%3A36-...json`; if the module requests the encoded form, S3 returns `NoSuchKey` for the literal key. Avoid `:` and other reserved characters in object names. Also confirm the S3-to-SQS notification is actually wired: the SQS queue's access policy must grant `SQS:SendMessage` to the S3 service for that bucket ARN, or messages never arrive (or arrive malformed).

## gzip objects fail: utf-8 codec can't decode byte 0x8b (exit 12)

```
wazuh-modulesd:aws-s3: WARNING: Subscriber: buckets my-logs-sqs  -  Returned exit code 12
'utf-8' codec can't decode byte 0x8b in position 1: invalid start byte
```

`0x8b` is the gzip magic byte: the object is gzip-compressed, and the custom-buckets subscriber does not reliably decompress it (unlike the native `cloudtrail` and `guardduty` bucket types, which carry their own decompression logic). Options:

- **Deliver custom logs uncompressed** to S3 (e.g. turn off compression in the Firehose or exporter writing the bucket). Simplest.
- **Decompress before ingestion.** An S3 Object Lambda that gunzips on read, or a Firehose transformation Lambda that writes plaintext.
- **Use the dedicated `bucket type`** for a supported service (CloudTrail, GuardDuty, VPC Flow, and so on), which handles gzip natively. Do not route it through the custom subscriber.

## One consumer per queue (exit 21, duplicates, "Too many connections")

Each SQS message is received and deleted by a single consumer. Pointing several managers or pods at the same queue makes them race, producing `Returned exit code 21` (failed fetch/delete), `Too many connections. Rejecting.`, and duplicate or missed events.

- Do not run the same `<subscriber>` block on multiple managers against one queue, and do not autoscale (HPA/KEDA) transient worker pods onto a shared queue. Workers also need a manual, non-automatic cluster join and leave, which compounds the problem.
- Scale the SQS path in this order:
  1. **Vertical.** More CPU/RAM on the single consumer, and a shorter [`<interval>`](#interval-overtaken---the-wodle-cant-keep-up).
  2. **Fan-out.** Split logs across multiple buckets or queues (or SNS into multiple SQS queues), with one dedicated consumer per queue.
  3. **Dedicated agents.** Run the wodle on agents (one per queue or service) that forward events to the manager over the normal agent channel; the manager's load balancer then distributes the analysis. Mind the agent EPS and buffer limits (`client_buffer`, default 500 EPS, up to 1000; queue 5000, up to 100000).
- FIFO queues and VisibilityTimeout tuning help with ordering and de-duplication, but do not make a queue safe for multiple Wazuh consumers.

## Interval overtaken - the wodle can't keep up

```
wazuh-modulesd:aws-s3: INFO: Fetching logs finished.
wazuh-modulesd:aws-s3: WARNING: Interval overtaken.
```

The AWS module is single-threaded: if a run is still fetching when `<interval>` fires, the next run is skipped and the backlog grows. Set `<interval>` a little longer than the average fetch time (5-10 min is typical; drop to `1m` only for steady, low-volume queues). If the warning persists no matter the interval, one consumer cannot keep up with the source rate, so [fan out or scale](#one-consumer-per-queue-exit-21-duplicates-too-many-connections).

## VisibilityTimeout and a dedicated queue

Wazuh receives a message, downloads and processes the object, then deletes the message. If processing takes longer than the queue's VisibilityTimeout, SQS makes the message visible again and another receive re-processes it, producing duplicates. Set VisibilityTimeout to at least the time needed to process your largest object (a common rule of thumb is 6x that). Because Wazuh deletes what it reads, the queue must be exclusive to Wazuh; never share it with another consumer.

## Custom-bucket logs arrive but don't alert

Custom (non-service) logs decode as JSON and match the base rule `80200`, which is level 0: decoded, indexed if archiving is on, but no alert. Add a custom rule keyed on the custom source, with level 3 or higher:

```xml
<group name="amazon,aws,">
  <rule id="100200" level="3">
    <if_sid>80200</if_sid>
    <field name="aws.source">custom</field>
    <options>no_full_log</options>
    <description>AWS custom log from bucket $(aws.log_info.s3bucket).</description>
  </rule>
</group>
```

Two related gotchas:

- Routing a supported service through `subscriber type="buckets"` (custom) instead of its dedicated `bucket type` (`alb`, `cloudtrail`, and so on) means you lose the service-specific decoders and rules; those only fire for the dedicated bucket types. Use the dedicated type where one exists, and use custom plus your own rules only for sources Wazuh does not support natively.
- Writing a custom decoder for a nested vendor JSON payload: put a `custom_json` `JSON_Decoder` parent first, and keep the child regex specific enough that it does not shadow other JSON logs. See [decoders/syntax.md](../decoders/syntax.md).

## Non-supported sources (third-party SaaS)

Only the bucket, service, and subscriber types listed in [aws.md](aws.md#what-it-can-ingest) are first-class. A third-party product (a SaaS threat feed, an appliance) that merely drops files into S3 is ingested through the generic `subscriber type="buckets"` (or `bucket type="custom"`) and decoded with your own rules; it is not a supported service with built-in parsing. A product that does not write to S3 at all cannot be consumed by `aws-s3`, so forward its logs some other way (syslog, an agent `localfile`, an API-poll script).

## Event too large - "Message too long"

A single S3 object shipped as one event can exceed Wazuh's per-event size cap:

```
DEBUG: Event size exceeds the maximum allowed limit of 65535 bytes.
ERROR: Message too long to send to Wazuh.  Skipping message...
DEBUG: +++ ERROR: Message longer than buffer socket for Wazuh. Consider increasing rmem_max. Skipping message...
```

The cause is one giant record (e.g. a multi-MB log file written as a single line), not the total volume. The object must be one log per line, and CSV must include a header row. See [analysisd event size limit](../troubleshooting/server/analysisd.md#event-size-limit-message-too-long) for the limit and the socket-buffer angle.

## Debugging

Run the subscriber by hand with the exact parameters from your config; the CLI prints the debug output directly:

```bash
/var/ossec/wodles/aws/aws-s3 --subscriber buckets --queue my-logs-sqs \
  --aws_profile my-profile --debug 2 --skip_on_error
# add --iam_role_arn arn:aws:iam::<ACCOUNT_ID>:role/<ROLE> for cross-account
```

Or enable module debug and watch the log:

```bash
sed -i "s/^wazuh_modules.debug=0/wazuh_modules.debug=2/" /var/ossec/etc/internal_options.conf
/var/ossec/bin/wazuh-control restart
grep -Ei "aws-s3" /var/ossec/logs/ossec.log
```

Confirm the AWS side independently: `aws sqs get-queue-url`, `aws sqs get-queue-attributes`, `aws s3 ls s3://my-logs-bucket/`.

## Related

- [AWS log ingestion setup (aws-s3)](aws.md) - IAM, credentials, bucket/service/subscriber blocks, Kubernetes credential mounts
- [analysisd - event size limit and dropped events](../troubleshooting/server/analysisd.md) - the 64 KiB per-event cap and EPS throttling
- [Kubernetes persistent config](../containerization/kubernetes/persistent-storage.md) - making a patched wodle file / config survive pod restarts
- [Custom decoders](../decoders/) / [custom rules](../rules/) - turning custom-bucket logs into alerts
- [wazuh/wazuh#36197](https://github.com/wazuh/wazuh/issues/36197) - the cross-account SQS fix (4.14.7)
