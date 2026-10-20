locals {
  isolated_network_enabled = (
    var.enable_session_resources && var.qualification_profile &&
    length(var.qualification_public_isolated_subnet_ids) > 0
  )
  isolated_allowed_interface_services = toset([
    "ecr.api", "ecr.dkr", "logs", "secretsmanager", "kms",
  ])
}

resource "aws_security_group" "qualification_public_isolated" {
  count       = local.isolated_network_enabled ? 1 : 0
  name        = "${local.name}-qualification-isolated"
  description = "Qualification task network with scoped endpoint, S3, and DNS access; no Bedrock PrivateLink access"
  vpc_id      = var.vpc_id
  egress {
    description     = "S3 gateway endpoint only"
    protocol        = "tcp"
    from_port       = 443
    to_port         = 443
    prefix_list_ids = [var.s3_managed_prefix_list_id]
  }
  egress {
    description     = "Approved qualification interface endpoints"
    protocol        = "tcp"
    from_port       = 443
    to_port         = 443
    security_groups = [aws_security_group.qualification_isolated_endpoints[0].id]
  }
  egress {
    description = "VPC DNS UDP"
    protocol    = "udp"
    from_port   = 53
    to_port     = 53
    cidr_blocks = [var.vpc_cidr]
  }
  egress {
    description = "VPC DNS TCP"
    protocol    = "tcp"
    from_port   = 53
    to_port     = 53
    cidr_blocks = [var.vpc_cidr]
  }
  tags = merge(local.tags, { Purpose = "qualification-public-isolated" })
}

resource "aws_security_group" "qualification_isolated_endpoints" {
  count       = local.isolated_network_enabled ? 1 : 0
  name        = "${local.name}-qualification-endpoints"
  description = "TLS ingress for approved public-isolated qualification endpoints"
  vpc_id      = var.vpc_id
  egress      = []
  tags        = merge(local.tags, { Purpose = "qualification-isolated-endpoints" })
}

resource "aws_vpc_security_group_ingress_rule" "qualification_isolated_endpoints" {
  count                        = local.isolated_network_enabled ? 1 : 0
  security_group_id            = aws_security_group.qualification_isolated_endpoints[0].id
  referenced_security_group_id = aws_security_group.qualification_public_isolated[0].id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  description                  = "TLS from isolated qualification tasks"
}
