variable "aws_region" {
  type = string
  validation {
    condition     = can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]$", var.aws_region))
    error_message = "aws_region must be an explicit AWS Region."
  }
}

variable "aws_account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "aws_account_id must be a 12 digit account ID."
  }
}

variable "deployment_name" {
  type = string
  validation {
    condition = (
      can(regex("^[a-z][a-z0-9-]{1,30}$", var.deployment_name))
      && !can(regex("example|changeme|placeholder", lower(var.deployment_name)))
      && length("ai-soc-${var.deployment_name}-${var.aws_account_id}-invocations") <= 63
      && length("ai-soc-${var.deployment_name}-${var.aws_account_id}-cloudtrail") <= 63
    )
    error_message = "deployment_name must be a concrete lowercase identifier short enough that derived S3 bucket names stay within 63 characters."
  }
}

variable "enable_session_resources" {
  type        = bool
  default     = true
  description = "Keep hourly VPC endpoints, ALB, and service tasks enabled. Set false and apply to end a session while preserving the foundation in this state."
}

variable "vpc_id" {
  type = string
  validation {
    condition     = can(regex("^vpc-[0-9a-f]+$", var.vpc_id))
    error_message = "vpc_id must identify the provisioned VPC."
  }
}

variable "vpc_cidr" {
  type = string
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "vpc_cidr must be a valid CIDR."
  }
}

variable "s3_managed_prefix_list_id" {
  type        = string
  default     = ""
  description = "Regional EC2 managed prefix list ID for the AWS S3 service; required while session networking is enabled. Resolve and review it for aws_region before planning."
  validation {
    condition     = !var.enable_session_resources || can(regex("^pl-[0-9a-f]{8,}$", var.s3_managed_prefix_list_id))
    error_message = "s3_managed_prefix_list_id must be the regional S3 managed prefix list ID when session resources are enabled."
  }
}

variable "dynamodb_managed_prefix_list_id" {
  type        = string
  default     = ""
  description = "Regional EC2 managed prefix list ID for the AWS DynamoDB service; required while session networking is enabled. Resolve and review it for aws_region before planning."
  validation {
    condition     = !var.enable_session_resources || can(regex("^pl-[0-9a-f]{8,}$", var.dynamodb_managed_prefix_list_id))
    error_message = "dynamodb_managed_prefix_list_id must be the regional DynamoDB managed prefix list ID when session resources are enabled."
  }
}

variable "private_subnet_ids" {
  type = list(string)
  validation {
    condition     = length(var.private_subnet_ids) >= 2 && length(distinct(var.private_subnet_ids)) == length(var.private_subnet_ids) && alltrue([for id in var.private_subnet_ids : can(regex("^subnet-[0-9a-f]+$", id))])
    error_message = "At least two distinct existing private subnet IDs are required."
  }
}

variable "private_route_table_ids" {
  type = list(string)
  validation {
    condition     = length(var.private_route_table_ids) >= 2 && length(distinct(var.private_route_table_ids)) == length(var.private_route_table_ids)
    error_message = "Existing private route table IDs for the selected AZs are required."
  }
}

variable "corporate_ingress_cidrs" {
  type = list(string)
  validation {
    condition     = length(var.corporate_ingress_cidrs) > 0 && alltrue([for cidr in var.corporate_ingress_cidrs : can(cidrhost(cidr, 0))])
    error_message = "ALB ingress must be restricted to reviewed corporate CIDRs."
  }
}

variable "identity_egress_cidrs" {
  type    = list(string)
  default = []
  validation {
    condition = (
      alltrue([
        for cidr in var.identity_egress_cidrs :
        can(cidrhost(cidr, 0)) && !contains(["0.0.0.0/0", "::/0"], cidr) && (
          (strcontains(cidr, ":") && tonumber(split("/", cidr)[1]) == 128) ||
          (!strcontains(cidr, ":") && tonumber(split("/", cidr)[1]) == 32)
        )
      ])
      && (length(var.identity_egress_cidrs) > 0 || var.idp_in_vpc)
    )
    error_message = "identity_egress_cidrs must list individual HTTPS destination addresses (/32 or /128), excluding default routes; an empty list is allowed only when idp_in_vpc is true."
  }
}

variable "alb_public_key_egress_mode" {
  type = string
  validation {
    condition     = contains(["nat", "proxy", "corporate"], var.alb_public_key_egress_mode)
    error_message = "alb_public_key_egress_mode must be nat, proxy, or corporate."
  }
  validation {
    condition = (
      length(var.alb_public_key_egress_cidrs) > 0
      && (var.alb_public_key_egress_mode == "proxy") == (var.alb_public_key_https_proxy != "")
      && (!var.qualification_profile || var.alb_public_key_egress_mode == "proxy" || var.allow_unqualified_direct_identity_egress)
      && (!var.qualification_profile || var.allow_unqualified_direct_identity_egress || startswith(var.alb_public_key_https_proxy, "https://"))
    )
    error_message = "Every ALB key-fetch egress mode requires exact destination host IPs; qualification requires a TLS-protected hostname-allowlisting proxy unless allow_unqualified_direct_identity_egress is explicitly enabled as a documented non-conforming exception."
  }
}

variable "alb_public_key_egress_cidrs" {
  type    = list(string)
  default = []
  validation {
    condition = alltrue([
      for cidr in var.alb_public_key_egress_cidrs :
      can(cidrhost(cidr, 0)) && !contains(["0.0.0.0/0", "::/0"], cidr) && (
        (strcontains(cidr, ":") && tonumber(split("/", cidr)[1]) == 128) ||
        (!strcontains(cidr, ":") && tonumber(split("/", cidr)[1]) == 32)
      )
    ])
    error_message = "ALB key-fetch egress CIDRs must be host routes (/32 or /128), not broad CloudFront or internet ranges. Security groups cannot enforce the regional key URL path; direct modes limit destination IPs only, and proxy mode also requires an external host/path allowlist."
  }
}

variable "alb_public_key_https_proxy" {
  type      = string
  default   = ""
  sensitive = true
  validation {
    condition = (
      var.alb_public_key_https_proxy == ""
      || can(regex("^https://[^:/]+$", var.alb_public_key_https_proxy))
      || can(regex("^https://[^:/]+:443$", var.alb_public_key_https_proxy))
      || can(regex("^http://[^:/]+:443$", var.alb_public_key_https_proxy))
    )
    error_message = "ALB public key proxy must be https or http on TCP 443 only so task security group VPC:443 egress can reach it; use nat/corporate egress for other ports."
  }
}

variable "mcp_jwks_https_proxy" {
  type      = string
  default   = ""
  sensitive = true
  validation {
    condition = (
      var.mcp_jwks_https_proxy == ""
      || can(regex("^https://[^:/]+$", var.mcp_jwks_https_proxy))
      || can(regex("^https://[^:/]+:443$", var.mcp_jwks_https_proxy))
      || can(regex("^http://[^:/]+:443$", var.mcp_jwks_https_proxy))
    )
    error_message = "MCP JWKS proxy must be https or http on TCP 443 only; leave empty when JWKS is reached directly from the task."
  }
}

variable "allow_unqualified_direct_identity_egress" {
  type        = bool
  default     = false
  description = "Explicit non-conforming exception for qualification_profile deployments that cannot use the hostname-allowlisting proxy for public ALB key or IdP/JWKS egress. Documented as not meeting live qualification network requirements."
}

variable "qualification_proxy_allowed_hosts" {
  type        = set(string)
  default     = []
  description = "FQDNs that the qualification HTTPS CONNECT proxy may reach: the regional ALB key host and configured IdP/JWKS hosts. Keep the proxy ACL file synchronized with this set."
  validation {
    condition = alltrue([
      for host in var.qualification_proxy_allowed_hosts : can(regex("^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$", host))
    ])
    error_message = "qualification_proxy_allowed_hosts must contain hostnames only, without scheme, path, port, or wildcard."
  }
}

variable "idp_in_vpc" {
  type        = bool
  default     = false
  description = "When true, asserts the OIDC issuer and MCP JWKS origin are reachable inside the VPC CIDR without extra identity egress."
  validation {
    condition     = !var.qualification_profile || var.idp_in_vpc || var.allow_unqualified_direct_identity_egress
    error_message = "Live qualification requires an in-VPC IdP because the ALB native OIDC action cannot use the HTTPS CONNECT proxy. Set allow_unqualified_direct_identity_egress only for an explicit non-conforming exception."
  }
}

variable "oidc" {
  type = object({
    issuer            = string
    authorization     = string
    token             = string
    userinfo          = string
    client_id         = string
    client_secret_arn = string
    scope             = string
  })
  sensitive = true
  validation {
    condition = alltrue([
      for endpoint in [var.oidc.issuer, var.oidc.authorization, var.oidc.token, var.oidc.userinfo] : can(regex("^https://[^/]+", endpoint))
    ]) && length(var.oidc.client_id) > 0 && can(regex("^arn:aws[a-z-]*:secretsmanager:[^:]+:[0-9]{12}:secret:.+", var.oidc.client_secret_arn))
    error_message = "OIDC endpoints and client identity must be concrete HTTPS values with a Secrets Manager client secret ARN."
  }
}

variable "crypto_secrets" {
  type = object({
    cursor_aead_secret_arn      = string
    cursor_current_version      = string
    cursor_previous_version     = string
    cursor_current_key_id       = string
    cursor_previous_key_id      = string
    feedback_receipt_secret_arn = string
    receipt_current_version     = string
    receipt_previous_version    = string
    receipt_current_key_id      = string
    receipt_previous_key_id     = string
    csrf_secret_arn             = string
    csrf_version                = string
  })
  sensitive = true
  validation {
    condition = alltrue([
      can(regex("^arn:aws[a-z-]*:secretsmanager:[^:]+:[0-9]{12}:secret:.+", var.crypto_secrets.cursor_aead_secret_arn)),
      can(regex("^arn:aws[a-z-]*:secretsmanager:[^:]+:[0-9]{12}:secret:.+", var.crypto_secrets.feedback_receipt_secret_arn)),
      can(regex("^arn:aws[a-z-]*:secretsmanager:[^:]+:[0-9]{12}:secret:.+", var.crypto_secrets.csrf_secret_arn)),
      length(var.crypto_secrets.cursor_current_version) > 0,
      length(var.crypto_secrets.cursor_previous_version) > 0,
      length(var.crypto_secrets.receipt_current_version) > 0,
      length(var.crypto_secrets.receipt_previous_version) > 0,
      length(var.crypto_secrets.csrf_version) > 0,
      length(var.crypto_secrets.cursor_current_key_id) > 0,
      length(var.crypto_secrets.cursor_previous_key_id) > 0,
      length(var.crypto_secrets.receipt_current_key_id) > 0,
      length(var.crypto_secrets.receipt_previous_key_id) > 0,
      !can(regex("example|changeme|placeholder", lower(var.crypto_secrets.cursor_current_version))),
    ])
    error_message = "Cursor, feedback receipt, and CSRF secrets require pinned ARNs, versions, and key IDs."
  }
}

variable "alb_certificate_arn" {
  type = string
  validation {
    condition     = can(regex("^arn:aws[a-z-]*:acm:[^:]+:[0-9]{12}:certificate/[0-9a-f-]+$", var.alb_certificate_arn))
    error_message = "An existing HTTPS certificate ARN is required for the internal ALB."
  }
}

variable "service_hostname" {
  type = string
  validation {
    condition     = can(regex("^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$", var.service_hostname))
    error_message = "service_hostname must be the TLS certificate hostname without a scheme or path."
  }
}

variable "mcp_jwks_uri" {
  type = string
  validation {
    condition     = can(regex("^https://[^/]+/.+", var.mcp_jwks_uri))
    error_message = "mcp_jwks_uri must be a pinned HTTPS URL with host and path (for example a Keycloak certs endpoint)."
  }
}

variable "sites" {
  type = map(object({
    indexer_cidrs           = list(string)
    indexer_port            = number
    indexer_origin          = string
    jwt_issuer              = string
    jwt_audience            = string
    ca_secret_arn           = string
    ca_secret_version       = string
    ca_sha256               = string
    signing_key_id          = string
    mapping_profile         = string
    policy_version          = string
    dls_attestation_version = string
    pit_supported           = bool
    allowed_index_patterns  = map(list(string))
    group_role_map          = map(list(string))
    role_visibility         = map(string)
  }))
  validation {
    condition = length(var.sites) > 0 && alltrue([
      for id, site in var.sites : can(regex("^[a-z][a-z0-9_-]{0,63}$", id))
      && length(site.indexer_cidrs) > 0
      && alltrue([for cidr in site.indexer_cidrs : can(cidrhost(cidr, 0))])
      && site.indexer_port >= 1 && site.indexer_port <= 65535
      && can(regex("^https://[^/]+$", site.indexer_origin))
      && can(regex("^arn:aws[a-z-]*:secretsmanager:[^:]+:[0-9]{12}:secret:.+", site.ca_secret_arn))
      && length(site.ca_secret_version) > 0
      && can(regex("^[0-9a-f]{64}$", site.ca_sha256))
      && !can(regex("example|changeme|placeholder", lower(site.ca_secret_version)))
      && length(site.jwt_issuer) > 0 && length(site.jwt_audience) > 0
      && length(site.mapping_profile) > 0 && length(site.policy_version) > 0
      && length(site.dls_attestation_version) > 0 && length(site.group_role_map) > 0
      && alltrue([for visibility in values(site.role_visibility) : contains(["full", "filtered"], visibility)])
    ])
    error_message = "Each site needs a private indexer, pinned CA secret version, JWT settings and bounded CIDRs."
  }
}

variable "bedrock_model_arns" {
  type = list(string)
  validation {
    condition     = length(var.bedrock_model_arns) > 0 && alltrue([for arn in var.bedrock_model_arns : can(regex("^arn:aws[a-z-]*:bedrock:[a-z0-9-]+:[0-9]{12}:", arn))])
    error_message = "At least one concrete account-scoped Bedrock model ARN is required."
  }
}

variable "embedding_model_arns" {
  type    = list(string)
  default = []
  validation {
    condition     = alltrue([for arn in var.embedding_model_arns : can(regex("^arn:aws[a-z-]*:bedrock:[a-z0-9-]+:[0-9]{12}:", arn))])
    error_message = "Embedding model ARNs must be concrete and account scoped."
  }
}

variable "guardrail" {
  type = object({ identifier = string, version = string })
  validation {
    condition = (
      can(regex("^arn:aws[a-z-]*:bedrock:[a-z0-9-]+:[0-9]{12}:guardrail/[a-zA-Z0-9]+$", var.guardrail.identifier))
      && can(regex("^[1-9][0-9]*$", var.guardrail.version))
      && !can(regex("DRAFT", upper(var.guardrail.version)))
    )
    error_message = "guardrail.identifier must be a Bedrock guardrail ARN and version must be a positive number (not DRAFT)."
  }
}

variable "service_image" {
  type = string
  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.service_image)) && startswith(var.service_image, "${var.aws_account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/")
    error_message = "The service image must be an immutable digest in this account and Region's private ECR."
  }
}

variable "adot_collector_digest" {
  type = string
  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.adot_collector_digest))
    error_message = "The mirrored ADOT collector must use its exact upstream OCI manifest digest."
  }
}

variable "service_sha" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.service_sha))
    error_message = "service_sha must be the committed service Git SHA."
  }
}

variable "content_sha" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.content_sha))
    error_message = "content_sha must identify the approved content commit."
  }
}

variable "content_repository" {
  type = string
  validation {
    condition     = can(regex("^https://[^/]+", var.content_repository))
    error_message = "content_repository must be a concrete HTTPS origin."
  }
}

variable "content_pack_sha256" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.content_pack_sha256))
    error_message = "content_pack_sha256 must be the digest-pinned archive SHA-256."
  }
}

variable "content_pack_manifest_sha256" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.content_pack_manifest_sha256))
    error_message = "content_pack_manifest_sha256 must match the verified pack manifest."
  }
}

variable "docs_manifest_sha256" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.docs_manifest_sha256))
    error_message = "docs_manifest_sha256 must be a SHA-256 hex digest."
  }
}

variable "image_digest" {
  type = string
  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.image_digest))
    error_message = "image_digest must be an immutable OCI digest."
  }
}

variable "ca_bundle_pem" {
  type        = string
  sensitive   = true
  description = "Pinned platform CA bundle PEM injected into the sealed live document."
  validation {
    condition     = length(trimspace(var.ca_bundle_pem)) > 0
    error_message = "ca_bundle_pem must be non-empty."
  }
}

variable "ca_bundle_sha256" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.ca_bundle_sha256))
    error_message = "ca_bundle_sha256 must be a SHA-256 hex digest."
  }
}

variable "standing_rules" {
  type = string
  validation {
    condition     = length(trimspace(var.standing_rules)) > 0
    error_message = "standing_rules must be non-empty."
  }
}

variable "service_models" {
  type = any
  validation {
    condition     = length(var.service_models) > 0
    error_message = "At least one live model capability is required."
  }
}

variable "mapping_profiles" {
  type = any
  validation {
    condition     = length(var.mapping_profiles) > 0
    error_message = "At least one mapping profile document is required."
  }
}

variable "alarm_topic_arn" {
  type = string
  validation {
    condition     = can(regex("^arn:aws[a-z-]*:sns:[^:]+:[0-9]{12}:.+", var.alarm_topic_arn))
    error_message = "A provisioned operations alarm topic ARN is required."
  }
}

variable "task_cpu" {
  type    = number
  default = 1024
  validation {
    condition     = contains([512, 1024, 2048, 4096], var.task_cpu)
    error_message = "task_cpu must be a supported Fargate CPU size."
  }
}

variable "task_memory" {
  type    = number
  default = 2048
  validation {
    condition     = var.task_memory >= 1024 && var.task_memory <= 30720
    error_message = "task_memory must be within the supported Fargate range."
  }
}

variable "service_max_capacity" {
  type    = number
  default = 6
  validation {
    condition     = var.service_max_capacity >= 2 && var.service_max_capacity <= 20
    error_message = "Autoscaling capacity must preserve at least two tasks and stay bounded."
  }
}

variable "qualification_profile" {
  type        = bool
  default     = false
  description = "Ephemeral live-qualification switches only. Production must leave this false."
}

variable "qualification_interface_endpoint_subnet_ids" {
  type        = list(string)
  default     = []
  description = "Qualification-only: when non-empty with qualification_profile, place interface VPC endpoints in these private subnets (single-AZ cost savings). Production leaves this empty so endpoints use every private_subnet_ids entry (higher availability, more hourly ENI cost)."
  validation {
    condition = (
      length(var.qualification_interface_endpoint_subnet_ids) == 0
      || (
        var.qualification_profile
        && length(var.qualification_interface_endpoint_subnet_ids) >= 1
        && alltrue([
          for id in var.qualification_interface_endpoint_subnet_ids :
          contains(var.private_subnet_ids, id) && can(regex("^subnet-[0-9a-f]+$", id))
        ])
        && length(distinct(var.qualification_interface_endpoint_subnet_ids))
        == length(var.qualification_interface_endpoint_subnet_ids)
      )
    )
    error_message = "qualification_interface_endpoint_subnet_ids requires qualification_profile and must be a distinct subset of private_subnet_ids."
  }
}

variable "qualification_public_isolated_subnet_ids" {
  type        = list(string)
  default     = []
  description = "Existing isolated subnet IDs used for qualification tasks that must reach S3/KMS without the Bedrock private path. These are supplied by the qualification owner; this root does not create subnets or routes."
  validation {
    condition = (
      length(var.qualification_public_isolated_subnet_ids) == 0
      || (
        var.qualification_profile
        && length(distinct(var.qualification_public_isolated_subnet_ids)) == length(var.qualification_public_isolated_subnet_ids)
        && length(setsubtract(toset(var.qualification_public_isolated_subnet_ids), toset(var.private_subnet_ids))) == length(var.qualification_public_isolated_subnet_ids)
        && alltrue([for id in var.qualification_public_isolated_subnet_ids : can(regex("^subnet-[0-9a-f]+$", id))])
      )
    )
    error_message = "qualification_public_isolated_subnet_ids is qualification-only and must contain distinct existing subnet IDs."
  }
}

variable "qualification_public_isolated_route_table_ids" {
  type        = list(string)
  default     = []
  description = "Existing route table IDs associated with qualification_public_isolated_subnet_ids. The S3 gateway endpoint is associated with these route tables when supplied."
  validation {
    condition = (
      (length(var.qualification_public_isolated_route_table_ids) == 0 && length(var.qualification_public_isolated_subnet_ids) == 0)
      || (
        var.qualification_profile
        && length(distinct(var.qualification_public_isolated_route_table_ids)) == length(var.qualification_public_isolated_route_table_ids)
        && length(setsubtract(toset(var.qualification_public_isolated_route_table_ids), toset(var.private_route_table_ids))) == length(var.qualification_public_isolated_route_table_ids)
        && alltrue([for id in var.qualification_public_isolated_route_table_ids : can(regex("^rtb-[0-9a-f]+$", id))])
        && length(var.qualification_public_isolated_route_table_ids) == length(var.qualification_public_isolated_subnet_ids)
      )
    )
    error_message = "qualification_public_isolated_route_table_ids is qualification-only and must contain distinct existing route table IDs."
  }
}

variable "audit_archive_schedule_expression" {
  type        = string
  default     = "rate(1 minute)"
  description = "EventBridge schedule for the audit archive consumer. Default drains at least once per minute so SQS age stays below the 120-second AuditQueueAge alarm in docs/operations/telemetry.md."
  validation {
    condition     = can(regex("^(rate\\(|cron\\()", var.audit_archive_schedule_expression))
    error_message = "audit_archive_schedule_expression must be a rate() or cron() EventBridge expression."
  }
}

variable "enable_audit_archive_schedule" {
  type        = bool
  default     = true
  description = "Keep scheduled audit/feedback archive task launches enabled outside qualification_profile. Qualification profile remains manually scheduled. Set false and apply before draining queues and removing session networking."
}

variable "bedrock_inference_profile_foundation_model_arns" {
  type        = list(string)
  default     = []
  description = "Foundation-model ARNs routed by the configured Bedrock inference profile(s) in bedrock_model_arns and scoped for bedrock:CountTokens IAM grants."
  validation {
    condition = alltrue([
      for arn in var.bedrock_inference_profile_foundation_model_arns :
      can(regex("^arn:aws[a-z-]*:bedrock:[a-z0-9-]+::foundation-model/", arn))
    ])
    error_message = "Each foundation model ARN must use the regional foundation-model resource with an empty account segment."
  }
}

variable "enable_bedrock_model_invocation_logging" {
  type        = bool
  default     = false
  description = "Enable account-level Bedrock model invocation logging to the invocation_logs bucket. Turn on in Phase B before the first Converse call."
}

variable "enable_cloudtrail" {
  type        = bool
  default     = false
  description = "Provision an optional organization-scoped CloudTrail trail to encrypted S3 for API evidence (G047)."
}

variable "enable_bedrock_spend_budget" {
  type        = bool
  default     = false
  description = "Optional automatic IAM deny action on the application role. Enable only after verifying that the real Claude billing line is covered by the account-wide gross-cost budget."
}

variable "enable_account_cost_budgets" {
  type        = bool
  default     = true
  description = "Create unfiltered monthly account-wide gross-cost and credit-adjusted cash-cost alert budgets."
}

variable "account_gross_cost_budget_usd" {
  type        = number
  default     = 100
  description = "Monthly account-wide gross unblended cost threshold in USD, excluding credits and refunds."
  validation {
    condition     = var.account_gross_cost_budget_usd > 0
    error_message = "account_gross_cost_budget_usd must be positive."
  }
}

variable "account_cash_cost_alert_budget_usd" {
  type        = number
  default     = 25
  description = "Monthly account-wide net cash-cost alert threshold in USD, including credits and refunds."
  validation {
    condition     = var.account_cash_cost_alert_budget_usd > 0
    error_message = "account_cash_cost_alert_budget_usd must be positive."
  }
}

variable "account_cost_budget_alert_email" {
  type        = string
  default     = ""
  description = "Email recipient for account-wide gross-cost and cash-cost budget alerts."
  validation {
    condition     = var.account_cost_budget_alert_email == "" || can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.account_cost_budget_alert_email))
    error_message = "account_cost_budget_alert_email must be empty or a simple email address."
  }
}
