# AWS Log Ingestion (aws-s3 module)

## Table of Contents
- [Introduction](#introduction)
- [What It Can Ingest](#what-it-can-ingest)
- [Prerequisites and Credentials](#prerequisites-and-credentials)
- [Minimal Configuration](#minimal-configuration)
- [Persisting Credentials in Kubernetes](#persisting-credentials-in-kubernetes)
- [Common Pitfalls](#common-pitfalls)
- [Debugging](#debugging)
- [References](#references)

## Introduction

Wazuh ingests AWS security data through the **AWS module**, configured as the `aws-s3` wodle in `ossec.conf`. It is a Python module (it lives in `/var/ossec/wodles/aws/aws-s3`) that runs on the manager or on an agent, pulls logs from S3 buckets, AWS service APIs, or SQS queues, and feeds them to `analysisd` as JSON. Events show up with `aws.*` fields and are matched by the built-in `amazon` rule group, with a dedicated Amazon Web Services dashboard module.

Official docs: [Amazon Web Services - Wazuh documentation](https://documentation.wazuh.com/current/cloud-security/amazon/index.html)

## What It Can Ingest

Three configuration blocks are available inside `<wodle name="aws-s3">`:

| Block | Mechanism | Supported types |
|---|---|---|
| `<bucket type="...">` | Logs delivered to an S3 bucket | `cloudtrail` (API/account activity), `guardduty` (findings), `vpcflow` (VPC Flow Logs), `config` (AWS Config), `waf`, `alb`/`clb`/`nlb` (load balancer access logs), `server_access` (S3 server access logs), `cisco_umbrella`, and `custom` for arbitrary JSON/text logs dropped into a bucket |
| `<service type="...">` | Direct API polling | `cloudwatchlogs` (CloudWatch Logs log groups), `inspector` (Inspector Classic) |
| `<subscriber type="...">` | SQS-driven ingestion | `security_lake` (Amazon Security Lake, OCSF/parquet), plus `buckets` and `security_hub` subscribers for SQS-notified bucket/Security Hub data |

> The SQS `<subscriber>` path has its own recurring failures (`Queue does not exist`, `NoSuchKey`, gzip decode errors, cross-account `iam_role_arn`, one-consumer-per-queue, scaling). They are collected as a symptom-driven runbook in [aws-sqs-troubleshooting.md](aws-sqs-troubleshooting.md).

## Prerequisites and Credentials

- An IAM principal with read access to the sources. At minimum:
  - Buckets: `s3:GetObject` + `s3:ListBucket`
  - CloudWatch Logs: `logs:DescribeLogGroups`, `logs:DescribeLogStreams`, `logs:GetLogEvents`
  - Subscribers: SQS receive/delete permissions
- Credential resolution (see [Configuring AWS credentials](https://documentation.wazuh.com/current/cloud-security/amazon/prerequisites/credentials.html)), in order of preference:
  - Shared credentials file `/root/.aws/credentials` with named profiles, referenced via `<aws_profile>`
  - IAM roles / EC2 instance profiles
  - Role assumption with `<iam_role_arn>`
  - Environment variables

  Hardcoding access keys in `ossec.conf` is deprecated in 4.x -- use profiles.
- The services themselves must be configured on the AWS side to deliver to the bucket (e.g. a CloudTrail trail writing to S3, VPC Flow Logs with an S3 destination).
- If the module runs on an agent instead of the manager, Python and `boto3` must be available there.

## Minimal Configuration

```xml
<wodle name="aws-s3">
  <disabled>no</disabled>
  <interval>10m</interval>
  <run_on_start>yes</run_on_start>
  <skip_on_error>yes</skip_on_error>

  <bucket type="cloudtrail">
    <name>YOUR_CLOUDTRAIL_BUCKET</name>
    <aws_profile>default</aws_profile>
    <only_logs_after>2026-JAN-01</only_logs_after>
    <regions>eu-west-1</regions>
  </bucket>
</wodle>
```

Add more `<bucket>` / `<service>` / `<subscriber>` blocks for other sources. Full option reference: [wodle name="aws-s3"](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-s3.html)

## Persisting Credentials in Kubernetes

When the Wazuh manager runs as a container (e.g. on EKS), keep the AWS profile files out of the image and mount them from a Secret and a ConfigMap so they survive pod recreation.

1. Create the credentials file with one or more named profiles:

   ```ini
   [default]
   aws_access_key_id = YOUR_ACCESS_KEY
   aws_secret_access_key = YOUR_SECRET_KEY

   [prod]
   aws_access_key_id = YOUR_PROD_ACCESS_KEY
   aws_secret_access_key = YOUR_PROD_SECRET_KEY
   ```

   ```bash
   kubectl create secret generic awscredentials --from-file=./credentials
   ```

2. Create the profile config (regions per profile):

   ```ini
   [default]
   region = us-east-1
   [profile prod]
   region = us-east-1
   ```

   ```bash
   kubectl create configmap configawsprofile --from-file=./awsprofileconfig
   ```

3. Mount both into the manager StatefulSet:

<details>
<summary>Click to expand StatefulSet volume mount example</summary>

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: wazuh-manager-worker
  namespace: wazuh
spec:
  replicas: 1
  selector:
    matchLabels:
      app: wazuh-manager-worker
  serviceName: wazuh-manager-worker
  template:
    metadata:
      labels:
        app: wazuh-manager-worker
    spec:
      containers:
      - name: wazuh
        image: wazuh/wazuh-manager:4.12.0
        volumeMounts:
        - name: aws-credentials
          mountPath: /root/.aws/credentials   # path inside the container
          subPath: credentials                # must match the key in the Secret
        - name: config
          mountPath: /root/.aws/config
          subPath: awsprofileconfig           # must match the key in the ConfigMap
      volumes:
      - name: aws-credentials
        secret:
          secretName: awscredentials
      - name: config
        configMap:
          name: configawsprofile
```

</details>

Verify inside the pod with `aws configure list` and `aws s3 ls --profile <profile_name>`.

## Common Pitfalls

- **State database.** Processed files are tracked in SQLite databases under `/var/ossec/wodles/aws/` (e.g. `s3_cloudtrail.db`). `only_logs_after` only matters on the *first* run; to re-ingest you must clear the relevant DB entries or run the script manually with `--reparse`.
- **Huge first run.** Large or old buckets make the initial pull take hours and generate S3 API costs. Constrain the scope with `only_logs_after`, `<regions>`, `<path>`, and a sensible `<interval>`.
- **Date format.** `only_logs_after` uses `YYYY-MMM-DD` (e.g. `2026-JAN-01`), not ISO 8601.
- **Permissions errors.** `AccessDenied` or throttling from AWS usually means the IAM policy is missing list/get permissions on the exact bucket and prefix, or the wrong profile is being picked up -- the wodle runs as root, so it reads `/root/.aws/credentials`.
- **Multi-account organizations.** CloudTrail organization trails need `<aws_organization_id>` so the S3 path layout is resolved correctly.

## Debugging

Enable module debug logging and re-check `ossec.log`:

```bash
sed -i "s/^wazuh_modules.debug=0/wazuh_modules.debug=2/" /var/ossec/etc/internal_options.conf
/var/ossec/bin/wazuh-control restart
grep -Ei "aws" /var/ossec/logs/ossec.log
```

Or run the wodle by hand with the same parameters as your config:

```bash
/var/ossec/wodles/aws/aws-s3 --bucket YOUR_BUCKET --aws_profile default \
  --only_logs_after 2026-JAN-01 --type cloudtrail --debug 2 --skip_on_error
```

Troubleshooting page: [AWS troubleshooting - Wazuh documentation](https://documentation.wazuh.com/current/cloud-security/amazon/troubleshooting.html)

## References

- [Using Wazuh to monitor AWS](https://documentation.wazuh.com/current/cloud-security/amazon/index.html)
- [wodle name="aws-s3" reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-s3.html)
- [AWS S3/SQS ingestion troubleshooting](aws-sqs-troubleshooting.md) - exit codes, cross-account, gzip, scaling
- [Google Cloud Pub/Sub ingestion](gcp-pubsub.md) -- the GCP counterpart of this module
- [Azure log ingestion](azure.md)
