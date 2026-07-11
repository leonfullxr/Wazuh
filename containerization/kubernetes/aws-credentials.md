# Persisting AWS credentials for the Wazuh manager on Kubernetes

**Applies to:** Wazuh 4.x manager on Kubernetes (EKS or any distribution) · Wazuh AWS module (`aws-s3` wodle)

[Back to Kubernetes README](./README.md)

## Overview

The Wazuh AWS module needs credential/profile files inside the manager container. If you write them into the pod's filesystem by hand, they disappear on every pod recreation. Mount them from a **Secret** (credentials) and a **ConfigMap** (profile config) instead - the files then survive any pod restart or image upgrade.

This pattern supports multiple AWS profiles, which is useful when one manager pulls logs from several accounts.

## 1. Create the credentials Secret

`credentials`:

```ini
[default]
aws_access_key_id = <ACCESS_KEY_ID>
aws_secret_access_key = <SECRET_ACCESS_KEY>

[dev]
aws_access_key_id = <DEV_ACCESS_KEY_ID>
aws_secret_access_key = <DEV_SECRET_ACCESS_KEY>

[prod]
aws_access_key_id = <PROD_ACCESS_KEY_ID>
aws_secret_access_key = <PROD_SECRET_ACCESS_KEY>
```

```bash
kubectl create secret generic awscredentials -n wazuh --from-file=./credentials
```

## 2. Create the profile ConfigMap

`awsprofileconfig`:

```ini
[default]
region = us-east-1
[profile dev]
region = us-east-1
[profile prod]
region = us-east-1
```

```bash
kubectl create configmap configawsprofile -n wazuh --from-file=./awsprofileconfig
```

## 3. Mount both into the manager StatefulSet

Add the volumes and mounts to the Wazuh manager (worker) StatefulSet. The `subPath` must match the key inside the Secret/ConfigMap (i.e., the original file name):

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
          mountPath: /var/ossec/etc/.aws-credentials  # Path referenced by the AWS wodle
          subPath: credentials                        # Must match the key in the Secret
        - name: config
          mountPath: /root/.aws/config                # Standard AWS CLI config path
          subPath: awsprofileconfig                   # Must match the key in the ConfigMap
      volumes:
      - name: aws-credentials
        secret:
          secretName: awscredentials
      - name: config
        configMap:
          name: configawsprofile
```

Because the files come from a Secret and a ConfigMap, recreating the Wazuh pods causes no credential loss.

## Troubleshooting the AWS module inside the pod

Exec into the manager pod and raise the wodle debug level, then run the module manually:

```bash
# Raise AWS module verbosity
grep wazuh_modules.debug /var/ossec/etc/internal_options.conf
sed -i "s/^wazuh_modules.debug=0/wazuh_modules.debug=2/" /var/ossec/etc/internal_options.conf
/var/ossec/bin/wazuh-control restart

# Watch for AWS-related log entries
grep -Ei "aws" /var/ossec/logs/ossec.log

# Run the module manually against a bucket with a specific profile
/var/ossec/wodles/aws/aws-s3 --bucket <BUCKET_NAME> --aws_profile default \
  --only_logs_after 2024-JAN-01 --type config --debug 2 --skip_on_error

# Verify the credentials are visible to the AWS CLI/SDK
aws configure list
aws s3 ls --profile <PROFILE_NAME>
```

## Related

- [Wazuh on Amazon EKS](./eks.md) - the deployment where this is typically needed
- [Wazuh AWS integration documentation](https://documentation.wazuh.com/current/cloud-security/amazon/index.html)
