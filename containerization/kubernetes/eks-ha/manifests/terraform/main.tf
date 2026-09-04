# Same topology as manifests/eksctl/cluster.yaml, expressed as Terraform.
#
# Outcome: three AZs, one single-AZ managed node group per AZ per role, IRSA,
# and the four required addons. Prefer this when the cluster must live in
# Terraform state; use the eksctl file for a one-shot create.
#
# Pin module majors. terraform-aws-modules cuts breaking changes between
# majors, and "latest" in a guide goes stale. Confirm the version at
# https://registry.terraform.io/modules/terraform-aws-modules/eks/aws/latest
# and read that release's upgrade notes before bumping.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "eu-west-1"
}

variable "cluster_name" {
  type    = string
  default = "wazuh-ha"
}

variable "cluster_version" {
  type        = string
  default     = "1.35"
  description = "Check the EKS version support calendar before setting this."
}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  # Three AZs so a 3-node indexer quorum can lose one zone and still form.
  # Two AZs leave majority at the mercy of a coin flip.
  azs = slice(data.aws_availability_zones.available.names, 0, 3)

  tags = {
    project     = "wazuh"
    environment = "production"
    terraform   = "true"
  }
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.8"

  name = "${var.cluster_name}-vpc"
  cidr = "10.0.0.0/16"

  azs             = local.azs
  private_subnets = ["10.0.0.0/20", "10.0.16.0/20", "10.0.32.0/20"]
  public_subnets  = ["10.0.48.0/24", "10.0.49.0/24", "10.0.50.0/24"]

  enable_nat_gateway = true
  # Per-AZ NAT avoids a shared gateway becoming a single zone of failure for
  # egress from every other AZ.
  single_nat_gateway     = false
  one_nat_gateway_per_az = true

  enable_dns_hostnames = true
  enable_dns_support   = true

  # Subnet role tags the AWS Load Balancer Controller uses for discovery.
  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
  }

  tags = local.tags
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.24"

  cluster_name    = var.cluster_name
  cluster_version = var.cluster_version

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  cluster_endpoint_public_access = true

  # IRSA for the EBS CSI driver, load balancer controller, and cluster autoscaler.
  enable_irsa = true

  cluster_addons = {
    coredns    = { most_recent = true }
    kube-proxy = { most_recent = true }
    vpc-cni    = { most_recent = true }
    # Without EBS CSI, PVCs never bind and every StatefulSet stays Pending.
    aws-ebs-csi-driver = {
      most_recent              = true
      service_account_role_arn = module.ebs_csi_irsa.iam_role_arn
    }
  }

  cluster_enabled_log_types = [
    "api", "audit", "authenticator", "controllerManager", "scheduler"
  ]

  # One node group per AZ per role, each bound to a single subnet (single-AZ
  # ASG). The module default spreads across subnets; that breaks EBS because
  # volumes are zonal and a replacement node in another AZ leaves the pod
  # Pending forever. See 01-architecture.md.
  eks_managed_node_groups = merge(
    {
      for idx, az in local.azs : "indexer-${substr(az, -2, 2)}" => {
        subnet_ids     = [module.vpc.private_subnets[idx]]
        instance_types = ["m6i.xlarge"] # 4 vCPU, 16 GiB
        min_size       = 1
        desired_size   = 1
        max_size       = 2
        disk_size      = 50
        labels         = { "wazuh.io/role" = "indexer" }
        tags = {
          "k8s.io/cluster-autoscaler/enabled"             = "true"
          "k8s.io/cluster-autoscaler/${var.cluster_name}" = "owned"
        }
      }
    },
    {
      for idx, az in local.azs : "manager-${substr(az, -2, 2)}" => {
        subnet_ids     = [module.vpc.private_subnets[idx]]
        instance_types = ["m6i.xlarge"]
        min_size       = 1
        desired_size   = 1
        max_size       = 2
        disk_size      = 50
        labels         = { "wazuh.io/role" = "manager" }
        tags = {
          "k8s.io/cluster-autoscaler/enabled"             = "true"
          "k8s.io/cluster-autoscaler/${var.cluster_name}" = "owned"
        }
      }
    }
  )

  tags = local.tags
}

module "ebs_csi_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.39"

  role_name             = "${var.cluster_name}-ebs-csi"
  attach_ebs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa"]
    }
  }

  tags = local.tags
}

module "lb_controller_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.39"

  role_name                              = "${var.cluster_name}-lb-controller"
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }

  tags = local.tags
}

module "cluster_autoscaler_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.39"

  role_name                        = "${var.cluster_name}-cluster-autoscaler"
  attach_cluster_autoscaler_policy = true
  cluster_autoscaler_cluster_names = [module.eks.cluster_name]

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:cluster-autoscaler"]
    }
  }

  tags = local.tags
}

output "cluster_name" {
  value = module.eks.cluster_name
}

output "update_kubeconfig" {
  value = "aws eks update-kubeconfig --region ${var.region} --name ${module.eks.cluster_name}"
}

output "lb_controller_role_arn" {
  value       = module.lb_controller_irsa.iam_role_arn
  description = "Pass to the load balancer controller Helm install."
}

output "cluster_autoscaler_role_arn" {
  value = module.cluster_autoscaler_irsa.iam_role_arn
}
