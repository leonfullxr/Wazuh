# 3. Cluster prerequisites

Wazuh needs four foundation pieces in place first. Version pins here match the
time of writing; every section below shows how to confirm the live value, and
that check usually takes about thirty seconds.

## 3.1 EBS CSI driver

Not optional. Kubernetes dropped the in-tree `kubernetes.io/aws-ebs`
provisioner, so without this driver PersistentVolumeClaims never bind and
StatefulSets stay `Pending` with little useful signal.

Either config from step 2 already installs it as an addon. Confirm:

```bash
kubectl get pods -n kube-system -l app.kubernetes.io/name=aws-ebs-csi-driver
kubectl get csidrivers ebs.csi.aws.com
```

On a cluster that does not have it yet:

```bash
eksctl create iamserviceaccount \
  --name ebs-csi-controller-sa --namespace kube-system \
  --cluster wazuh-ha \
  --role-name AmazonEKS_EBS_CSI_DriverRole \
  --role-only --attach-policy-arn arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy \
  --approve

eksctl create addon --cluster wazuh-ha --name aws-ebs-csi-driver \
  --service-account-role-arn arn:aws:iam::ACCOUNT_ID:role/AmazonEKS_EBS_CSI_DriverRole --force
```

There is also `AmazonEBSCSIDriverPolicyV2`. Follow
[the EBS CSI documentation](https://docs.aws.amazon.com/eks/latest/userguide/ebs-csi.html)
for whichever policy AWS currently lists, and attach that one.

When the StorageClass uses a customer-managed KMS key instead of the
AWS-managed key, grant the driver role `kms:CreateGrant`, `kms:Encrypt`,
`kms:Decrypt`, `kms:ReEncrypt*`, `kms:GenerateDataKey*` and `kms:DescribeKey` on
that key as well. Missing those leaves volumes `Pending` with a KMS
access-denied event.

## 3.2 StorageClass

Step 4's overlay already defines the StorageClass. No separate apply is needed
here; the point is to know what it does. Path:
[`manifests/overlay/storage-class.yaml`](manifests/overlay/storage-class.yaml).

Three fields do the important work:

- `volumeBindingMode: WaitForFirstConsumer`. Skip this and the volume is
  created in some AZ before the scheduler picks a node, locking the pod to that
  zone. With it, placement happens first and the volume is created in the same
  zone.
- `reclaimPolicy: Retain`. A deleted PVC leaves the volume behind. For a SIEM
  that is the right default: a mistaken `kubectl delete pvc` must not wipe
  indexer data.
- `type: gp3`. gp3 provisions IOPS and throughput separate from size; gp2 ties
  both to capacity. Baseline 3000 IOPS and 125 MB/s is included in the price.

Do not stand up a second StorageClass named `gp2` and point workloads at it.
Upstream already expects a class named `wazuh-storage`; the overlay redefines
that name.

## 3.3 AWS Load Balancer Controller

You need this for the agent NLBs and the dashboard ALB.

Look up the live chart version instead of pasting one:

```bash
curl -s https://aws.github.io/eks-charts/index.yaml \
  | grep -A2 'name: aws-load-balancer-controller' | head
```

At the time of writing that returns chart 3.5.0. Install:

```bash
# IAM policy. The JSON is version-specific; take it from the tag you install.
curl -sO https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.13.0/docs/install/iam_policy.json
aws iam create-policy --policy-name AWSLoadBalancerControllerIAMPolicy \
  --policy-document file://iam_policy.json

eksctl create iamserviceaccount \
  --cluster wazuh-ha --namespace kube-system \
  --name aws-load-balancer-controller \
  --attach-policy-arn arn:aws:iam::ACCOUNT_ID:policy/AWSLoadBalancerControllerIAMPolicy \
  --approve --override-existing-serviceaccounts

helm repo add eks https://aws.github.io/eks-charts && helm repo update
helm install aws-load-balancer-controller eks/aws-load-balancer-controller \
  -n kube-system \
  --set clusterName=wazuh-ha \
  --set serviceAccount.create=false \
  --set serviceAccount.name=aws-load-balancer-controller
```

Terraform path users already have the role. Skip the policy and
`iamserviceaccount` work; annotate the ServiceAccount with
`terraform output lb_controller_role_arn` instead.

Verify:

```bash
kubectl -n kube-system rollout status deployment/aws-load-balancer-controller
kubectl -n kube-system logs deployment/aws-load-balancer-controller | tail -20
```

Subnet tags are required for discovery. Without them the controller creates
nothing and logs a subnet error. Tag private subnets
`kubernetes.io/role/internal-elb=1` and public subnets
`kubernetes.io/role/elb=1`. Both step 2 configs already set these.

## 3.4 Cluster Autoscaler

This is what brings back a lost node. Single-AZ node groups mean the
replacement always lands in the correct zone.

```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/autoscaler/master/cluster-autoscaler/cloudprovider/aws/examples/cluster-autoscaler-autodiscover.yaml

kubectl -n kube-system annotate serviceaccount cluster-autoscaler \
  eks.amazonaws.com/role-arn=arn:aws:iam::ACCOUNT_ID:role/wazuh-ha-cluster-autoscaler --overwrite

kubectl -n kube-system set image deployment/cluster-autoscaler \
  cluster-autoscaler=registry.k8s.io/autoscaling/cluster-autoscaler:v1.31.0
```

Align the autoscaler minor with the cluster Kubernetes minor; the project
ships one build per Kubernetes release.

Patch the deployment so `--node-group-auto-discovery` names your cluster, and
set `--balance-similar-node-groups=false`. That second flag is intentional: the
six node groups are not interchangeable (each owns one AZ), and balancing them
as a shared pool undoes the layout.

Karpenter is a fair alternative and honors PersistentVolume zone topology when
it provisions. It is a larger move than this guide covers. If you already run
it, keep it and replace the per-AZ node groups with a NodePool that requires a
zone.

## 3.5 Confirm the foundation

```bash
kubectl get nodes -L topology.kubernetes.io/zone,wazuh.io/role
kubectl get storageclass
kubectl get pods -n kube-system
```

You want six `Ready` nodes in three zones, a `wazuh-storage` class after step 4
applies, and the CSI driver, load balancer controller and autoscaler all
running.

Before you put real data on disk, once is enough to prove a zonal volume binds
as expected:

```bash
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: zone-check
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: wazuh-storage
  resources: { requests: { storage: 1Gi } }
EOF
# Stays Pending until a pod consumes it. That is WaitForFirstConsumer working.
kubectl get pvc zone-check
kubectl delete pvc zone-check
```

Next: [4. Deploy Wazuh](04-deploy-wazuh.md).
