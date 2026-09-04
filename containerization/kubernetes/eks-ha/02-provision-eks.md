# 2. Provision the EKS cluster

Two routes, same cluster. Choose one.

- **[eksctl](#eksctl)** when you only need the cluster. One config file, one
  command, about 20 minutes.
- **[Terraform](#terraform)** when the cluster should live in state with the
  rest of your infrastructure.

Either path yields: three AZs, one NAT gateway per AZ, six single-AZ managed
node groups, IRSA, and the four addons the deployment needs. Node group layout
is the critical piece; [1. Architecture](01-architecture.md) explains why you
use one Auto Scaling group per AZ instead of one spanning all three.

## Before you start

Verify the Kubernetes version; do not trust the value in the config file.
Versions leave standard support on a published schedule, then cost six times as
much per cluster-hour under extended support. A number copied from a guide can
become an unexpected bill.

```bash
aws eks describe-cluster-versions --query 'clusterVersions[].{v:clusterVersion,status:versionStatus,eol:endOfStandardSupportDate}' --output table
```

The authoritative table is the
[EKS Kubernetes versions page](https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html).
At the time of writing, standard support covers 1.34, 1.35 and 1.36, and the
config files here pin 1.35.

Quotas worth checking before you find out the hard way:

```bash
# On-demand standard vCPUs. Six m6i.xlarge is 24 vCPU; the default is often 32.
aws service-quotas get-service-quota --service-code ec2 --quota-code L-1216C47A
# Elastic IPs. One NAT gateway per AZ needs three.
aws service-quotas get-service-quota --service-code ec2 --quota-code L-0263D0A3
```

You also need IAM permissions to create VPCs, EKS clusters, IAM roles and
policies, Auto Scaling groups and load balancers. Anything less than that fails
part way through and leaves you cleaning up.

## eksctl

```bash
# Install or update eksctl. Check the current release rather than pinning a
# version from a guide: https://github.com/eksctl-io/eksctl/releases
curl -sL "https://github.com/eksctl-io/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" \
  | tar xz -C /tmp && sudo install -m 0755 /tmp/eksctl /usr/local/bin/eksctl
eksctl version
```

Edit [`manifests/eksctl/cluster.yaml`](manifests/eksctl/cluster.yaml): set the
region, the three AZ names, and `ACCOUNT_ID` in the load balancer controller
policy ARN. Then:

```bash
eksctl create cluster -f manifests/eksctl/cluster.yaml
```

Expect roughly 20 minutes, mostly CloudFormation wait time.

The config points at an IAM policy for the load balancer controller that does
not exist yet. Create it first, as
[3. Cluster prerequisites](03-cluster-prerequisites.md) describes, or drop that
`serviceAccounts` entry for now and add it later with
`eksctl create iamserviceaccount`.

Verify:

```bash
kubectl get nodes -L topology.kubernetes.io/zone,wazuh.io/role
```

You should see six nodes, two per AZ, three labelled `indexer` and three
labelled `manager`. If the zones are not spread across three AZs, stop and fix
that now; nothing downstream will make up for it.

## Terraform

[`manifests/terraform/main.tf`](manifests/terraform/main.tf) builds the
equivalent cluster with the `terraform-aws-modules` VPC and EKS modules, and
additionally creates the IRSA roles for the EBS CSI driver, the load balancer
controller and the cluster autoscaler, so the prerequisites step is shorter.

```bash
cd manifests/terraform
terraform init
terraform plan -out tf.plan
terraform apply tf.plan
$(terraform output -raw update_kubeconfig)
```

Module versions use `~>` pins on purpose. The `terraform-aws-modules/eks`
module ships breaking changes between majors; read that version's upgrade notes
before bumping, rather than jumping to whatever is newest.

Note the two node group maps. The module default is one node group across every
private subnet, which would give you a multi-AZ Auto Scaling group. These
override `subnet_ids` to a single subnet per group precisely to avoid that.

Take the role ARNs from the outputs; the next step needs them:

```bash
terraform output lb_controller_role_arn
terraform output cluster_autoscaler_role_arn
```

## What you have now

An empty cluster whose storage and networking can host a stateful, zone-spread
workload. Nothing Wazuh-specific yet.

Next: [3. Cluster prerequisites](03-cluster-prerequisites.md).
