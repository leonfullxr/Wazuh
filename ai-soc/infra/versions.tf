terraform {
  required_version = "= 1.16.5"

  backend "s3" {
    encrypt      = true
    use_lockfile = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.67.0"
    }
  }
}

provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.aws_account_id]
  default_tags {
    tags = {
      Service     = "ai-soc"
      Environment = var.deployment_name
      ManagedBy   = "terraform"
    }
  }
}
