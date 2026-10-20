locals {
  service_origin = "https://${var.service_hostname}"
  name           = "ai-soc-${var.deployment_name}"
  tags = {
    Service     = "ai-soc"
    Environment = var.deployment_name
  }
  s3_bucket_names = {
    audit      = "${local.name}-${var.aws_account_id}-audit"
    invocation = "${local.name}-${var.aws_account_id}-invocations"
    docs       = "${local.name}-${var.aws_account_id}-docs"
    cloudtrail = "${local.name}-${var.aws_account_id}-cloudtrail"
  }
  qualification_resource_map = {
    schema_version = 1
    account_id     = var.aws_account_id
    region         = var.aws_region
    evidence = {
      bucket          = aws_s3_bucket.audit_archive.bucket
      app_prefix      = local.evidence_paths.app_prefix
      consumer_prefix = local.evidence_paths.consumer_prefix
      map_key         = local.evidence_paths.map_key
      input_prefix    = local.evidence_paths.input_prefix
      kms_key_arn     = aws_kms_key.storage.arn
    }
    cloudtrail = {
      arn                    = try(aws_cloudtrail.service[0].arn, null)
      bucket                 = var.enable_cloudtrail ? aws_s3_bucket.cloudtrail[0].bucket : null
      log_validation_enabled = var.enable_cloudtrail
    }
    invocation_logs = {
      bucket = var.enable_bedrock_model_invocation_logging ? aws_s3_bucket.invocation_logs.bucket : null
      prefix = var.enable_bedrock_model_invocation_logging ? "bedrock-invocations/" : null
      writer = "bedrock.amazonaws.com"
    }
    network = {
      vpc_id                                      = var.vpc_id
      service_subnet_ids                          = var.private_subnet_ids
      service_route_table_ids                     = var.private_route_table_ids
      public_isolated_subnet_ids                  = var.qualification_public_isolated_subnet_ids
      public_isolated_route_table_ids             = var.qualification_public_isolated_route_table_ids
      public_isolated_security_group_id           = try(aws_security_group.qualification_public_isolated[0].id, null)
      public_isolated_endpoint_security_group_id  = try(aws_security_group.qualification_isolated_endpoints[0].id, null)
      public_isolated_allowed_interface_services  = local.isolated_network_enabled ? sort(tolist(local.isolated_allowed_interface_services)) : []
      public_isolated_excluded_interface_services = ["bedrock-runtime"]
      s3_gateway_endpoint_id                      = try(aws_vpc_endpoint.s3[0].id, null)
      s3_managed_prefix_list_id                   = var.s3_managed_prefix_list_id
      dynamodb_managed_prefix_list_id             = var.dynamodb_managed_prefix_list_id
      storage_kms_key_arn                         = aws_kms_key.storage.arn
    }
    archive_consumer = {
      task_definition_arn = try(aws_ecs_task_definition.audit_consumer[0].arn, null)
      container_name      = "audit-archive"
      image               = var.service_image
      task_role_arn       = try(aws_iam_role.audit_consumer.arn, null)
    }
    service = {
      cluster_arn                = aws_ecs_cluster.service.arn
      task_security_group_id     = try(aws_security_group.tasks[0].id, null)
      endpoint_security_group_id = try(aws_security_group.endpoints[0].id, null)
      application_role_arn       = aws_iam_role.application.arn
    }
    certification_enabled = false
  }
  qualification_resource_map_json = jsonencode(local.qualification_resource_map)
  bedrock_model_resources = distinct(concat(
    var.bedrock_model_arns,
    var.bedrock_inference_profile_foundation_model_arns,
    var.embedding_model_arns,
  ))
  bedrock_count_token_resources = distinct(var.bedrock_inference_profile_foundation_model_arns)
  interface_endpoint_subnet_ids = (
    length(var.qualification_interface_endpoint_subnet_ids) > 0
    ? var.qualification_interface_endpoint_subnet_ids
    : var.private_subnet_ids
  )
  guardrail_qualified_identifier = "${var.guardrail.identifier}:${var.guardrail.version}"
  service_log_group_name         = "/ecs/${local.name}"
  service_log_group_arn          = "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:${local.service_log_group_name}"
  qualification_proxy_required_hosts = toset(distinct([
    "public-keys.auth.elb.${var.aws_region}.amazonaws.com",
    lower(nonsensitive(regex("^https://([^/:]+)", var.oidc.issuer)[0])),
    lower(regex("^https://([^/:]+)", var.mcp_jwks_uri)[0]),
  ]))
  alb_identity_provider_egress_cidrs = distinct(concat(
    var.identity_egress_cidrs,
    var.idp_in_vpc ? [var.vpc_cidr] : [],
  ))
  interface_services = toset([
    "ecr.api",
    "ecr.dkr",
    "logs",
    "monitoring",
    "kms",
    "secretsmanager",
    "sqs",
    "bedrock-runtime",
    "xray",
  ])
  ddb_tables = toset(["state"])
  foundation_inventory_addresses = concat(
    [
      "aws_kms_key.storage",
      "aws_kms_alias.storage",
      "aws_kms_key_policy.storage",
      "aws_dynamodb_table.state[\"state\"]",
      "aws_s3_bucket.audit_archive",
      "aws_s3_bucket_policy.audit_archive_qualification",
      "aws_s3_bucket.invocation_logs",
      "aws_s3_bucket.docs",
      "aws_sqs_queue.audit",
      "aws_sqs_queue.audit_dlq",
      "aws_sqs_queue.feedback",
      "aws_sqs_queue.feedback_dlq",
      "aws_cloudwatch_log_group.service",
    ],
    [for site_id in keys(var.sites) : "aws_kms_key.site_signing[\"${site_id}\"]"],
    [for site_id in keys(var.sites) : "aws_kms_alias.site_signing[\"${site_id}\"]"],
    var.enable_account_cost_budgets ? [
      "aws_budgets_budget.account_gross_cost[0]",
      "aws_budgets_budget.account_cash_cost[0]",
    ] : [],
    var.enable_bedrock_model_invocation_logging ? ["aws_bedrock_model_invocation_logging_configuration.service[0]"] : [],
    var.enable_cloudtrail ? [
      "aws_cloudtrail.service[0]",
      "aws_s3_bucket.cloudtrail[0]",
      "aws_s3_bucket_public_access_block.cloudtrail[0]",
      "aws_s3_bucket_ownership_controls.cloudtrail[0]",
      "aws_s3_bucket_versioning.cloudtrail[0]",
      "aws_s3_bucket_server_side_encryption_configuration.cloudtrail[0]",
      "aws_s3_bucket_policy.cloudtrail[0]",
    ] : [],
    [
      "aws_cloudwatch_metric_alarm.audit_queue_age",
      "aws_cloudwatch_metric_alarm.audit_dlq",
      "aws_cloudwatch_metric_alarm.recovery_lag",
      "aws_cloudwatch_metric_alarm.recovery_backlog",
      "aws_cloudwatch_metric_alarm.admission_rejections",
    ],
  )
  template_ids = [
    "alerts_rows_v1",
    "alerts_count_v1",
    "alerts_group_v1",
    "vulnerabilities_rows_v1",
    "vulnerabilities_count_v1",
    "vulnerabilities_group_v1",
  ]
  service_sites = [
    for site_id, site in var.sites : {
      environment_id            = site_id
      label                     = site_id
      enabled                   = true
      indexer_origin            = site.indexer_origin
      private_network_ref       = "site-${site_id}"
      jwt_issuer                = site.jwt_issuer
      jwt_audience              = site.jwt_audience
      kms_signing_key_arn       = aws_kms_key.site_signing[site_id].arn
      ca_secret_arn             = site.ca_secret_arn
      ca_secret_version         = site.ca_secret_version
      ca_sha256                 = site.ca_sha256
      group_role_map            = site.group_role_map
      role_visibility           = site.role_visibility
      allowed_index_patterns    = site.allowed_index_patterns
      mapping_profile           = site.mapping_profile
      policy_version            = site.policy_version
      pit_supported             = site.pit_supported
      allowed_templates         = local.template_ids
      dls_attestation_version   = site.dls_attestation_version
      composite_role_visibility = site.role_visibility
      expectations              = []
    }
  ]
  service_sealed_config = jsonencode({
    schema_version = 1
    service = {
      mode                 = "live"
      guardrail_identifier = var.guardrail.identifier
      guardrail_version    = var.guardrail.version
      sites                = local.service_sites
      models               = var.service_models
      ca_bundle_path       = "/tmp/ca-bundle.pem"
      ca_bundle_sha256     = var.ca_bundle_sha256
      audit_queue_url      = aws_sqs_queue.audit.url
    }
    alb = {
      signer_arn   = var.enable_session_resources ? aws_lb.service[0].arn : ""
      issuer       = var.oidc.issuer
      client_id    = var.oidc.client_id
      groups_claim = "groups"
    }
    mcp = {
      issuer   = var.oidc.issuer
      resource = "${local.service_origin}/mcp"
      jwks_uri = var.mcp_jwks_uri
    }
    browser_origin   = local.service_origin
    dynamodb_table   = aws_dynamodb_table.state["state"].name
    standing_rules   = var.standing_rules
    mapping_profiles = var.mapping_profiles
    content_pack = {
      uri         = "s3://${aws_s3_bucket.docs.bucket}/packs/${var.content_sha}/content.tar"
      pack_sha256 = var.content_pack_sha256
    }
    provenance = {
      service_sha          = var.service_sha
      content_repository   = var.content_repository
      content_sha          = var.content_sha
      pack_sha256          = var.content_pack_manifest_sha256
      image_digest         = var.image_digest
      docs_origin          = "https://${aws_cloudfront_distribution.docs.domain_name}"
      docs_manifest_sha256 = var.docs_manifest_sha256
      contract_version     = "1"
    }
    feedback_queue_url  = aws_sqs_queue.feedback.url
    audit_queue_url     = aws_sqs_queue.audit.url
    mcp_allowed_origins = [local.service_origin]
    ca_bundle_pem       = var.ca_bundle_pem
    qualification = var.qualification_profile ? {
      bucket     = aws_s3_bucket.audit_archive.bucket
      key        = aws_s3_object.qualification_resource_map[0].key
      version_id = aws_s3_object.qualification_resource_map[0].version_id
      sha256     = sha256(local.qualification_resource_map_json)
    } : null
  })
  interface_policy_statements = {
    "ecr.api" = [
      { Effect = "Allow", Principal = "*", Action = ["ecr:GetAuthorizationToken"], Resource = "*" },
      { Effect = "Allow", Principal = "*", Action = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"], Resource = [aws_ecr_repository.service.arn, aws_ecr_repository.adot_collector.arn] },
    ]
    "ecr.dkr" = [
      { Effect = "Allow", Principal = "*", Action = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"], Resource = [aws_ecr_repository.service.arn, aws_ecr_repository.adot_collector.arn] },
    ]
    "logs" = [
      { Effect = "Allow", Principal = "*", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.service.arn}:*" },
    ]
    "monitoring" = [
      { Effect = "Allow", Principal = "*", Action = ["cloudwatch:PutMetricData"], Resource = "*", Condition = { StringEquals = { "cloudwatch:namespace" = "AISOC/Service" } } },
    ]
    "kms" = [
      { Effect = "Allow", Principal = "*", Action = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey", "kms:Sign", "kms:GetPublicKey"], Resource = concat([aws_kms_key.storage.arn], [for key in aws_kms_key.site_signing : key.arn]) },
    ]
    "secretsmanager" = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = ["secretsmanager:GetSecretValue"]
        Resource = distinct(concat(
          [for site in values(var.sites) : site.ca_secret_arn],
          [
            var.crypto_secrets.cursor_aead_secret_arn,
            var.crypto_secrets.feedback_receipt_secret_arn,
            var.crypto_secrets.csrf_secret_arn,
          ],
        ))
      },
    ]
    "sqs" = [
      { Effect = "Allow", Principal = "*", Action = ["sqs:SendMessage"], Resource = [aws_sqs_queue.audit.arn, aws_sqs_queue.feedback.arn] },
      { Effect = "Allow", Principal = "*", Action = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes"], Resource = [aws_sqs_queue.audit.arn, aws_sqs_queue.feedback.arn] },
    ]
    "bedrock-runtime" = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = ["bedrock:InvokeModel"]
        Resource  = local.bedrock_model_resources
        Condition = {
          StringEquals = {
            "bedrock:GuardrailIdentifier" = local.guardrail_qualified_identifier
          }
        }
      },
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = ["bedrock:CountTokens"]
        Resource  = local.bedrock_count_token_resources
      },
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = ["bedrock:ApplyGuardrail"]
        Resource  = [var.guardrail.identifier]
      },
    ]
    "xray" = [
      { Effect = "Allow", Principal = "*", Action = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"], Resource = "*" },
    ]
  }
}

resource "aws_kms_key" "storage" {
  description             = "AI SOC ${var.deployment_name} encrypted data key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = local.tags
}

resource "aws_kms_alias" "storage" {
  name          = "alias/${local.name}/storage"
  target_key_id = aws_kms_key.storage.key_id
}

data "aws_iam_policy_document" "storage_key" {
  statement {
    sid    = "AccountRootAdmin"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.aws_account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  dynamic "statement" {
    for_each = var.enable_bedrock_model_invocation_logging ? [1] : []
    content {
      sid    = "BedrockInvocationLogDataKeys"
      effect = "Allow"
      principals {
        type        = "Service"
        identifiers = ["bedrock.amazonaws.com"]
      }
      actions = [
        "kms:GenerateDataKey*",
        "kms:DescribeKey",
      ]
      resources = ["*"]
      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [var.aws_account_id]
      }
      condition {
        test     = "ArnLike"
        variable = "aws:SourceArn"
        values   = ["arn:aws:bedrock:${var.aws_region}:${var.aws_account_id}:*"]
      }
      condition {
        test     = "StringEquals"
        variable = "kms:EncryptionContext:aws:s3:arn"
        values   = [aws_s3_bucket.invocation_logs.arn]
      }
    }
  }

  dynamic "statement" {
    for_each = var.enable_bedrock_model_invocation_logging ? [1] : []
    content {
      sid    = "BedrockInvocationLogGrants"
      effect = "Allow"
      principals {
        type        = "Service"
        identifiers = ["bedrock.amazonaws.com"]
      }
      actions   = ["kms:CreateGrant"]
      resources = ["*"]
      condition {
        test     = "Bool"
        variable = "kms:GrantIsForAWSResource"
        values   = ["true"]
      }
      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [var.aws_account_id]
      }
      condition {
        test     = "ArnLike"
        variable = "aws:SourceArn"
        values   = ["arn:aws:bedrock:${var.aws_region}:${var.aws_account_id}:*"]
      }
      condition {
        test     = "StringEquals"
        variable = "kms:EncryptionContext:aws:s3:arn"
        values   = [aws_s3_bucket.invocation_logs.arn]
      }
    }
  }

  statement {
    sid    = "CloudWatchLogsService"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]
    resources = ["*"]
    condition {
      test     = "ArnEquals"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = [local.service_log_group_arn]
    }
  }

  dynamic "statement" {
    for_each = var.enable_cloudtrail ? [1] : []
    content {
      sid    = "CloudTrailDelivery"
      effect = "Allow"
      principals {
        type        = "Service"
        identifiers = ["cloudtrail.amazonaws.com"]
      }
      actions = [
        "kms:GenerateDataKey*",
        "kms:Decrypt",
        "kms:DescribeKey",
      ]
      resources = ["*"]
      condition {
        test     = "StringEquals"
        variable = "aws:SourceArn"
        values   = ["arn:aws:cloudtrail:${var.aws_region}:${var.aws_account_id}:trail/${local.name}-cloudtrail"]
      }
    }
  }
}

data "aws_iam_policy_document" "storage_key_cloudfront" {
  statement {
    sid    = "CloudFrontDocsDecrypt"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.docs.arn]
    }
  }
}

data "aws_iam_policy_document" "storage_key_combined" {
  source_policy_documents = [
    data.aws_iam_policy_document.storage_key.json,
    data.aws_iam_policy_document.storage_key_cloudfront.json,
  ]
}

resource "aws_kms_key_policy" "storage" {
  key_id = aws_kms_key.storage.key_id
  policy = data.aws_iam_policy_document.storage_key_combined.json
}

resource "aws_kms_key" "site_signing" {
  for_each                 = var.sites
  description              = "AI SOC ${var.deployment_name} ${each.key} RS256 signing key"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_2048"
  deletion_window_in_days  = 30
  tags                     = merge(local.tags, { Site = each.key })
}

resource "aws_kms_alias" "site_signing" {
  for_each      = var.sites
  name          = "alias/${local.name}/${each.key}/jwt-signing"
  target_key_id = aws_kms_key.site_signing[each.key].key_id
}

resource "aws_cloudwatch_log_group" "service" {
  name              = local.service_log_group_name
  retention_in_days = 90
  kms_key_id        = aws_kms_key.storage.arn
  tags              = local.tags

  depends_on = [aws_kms_key_policy.storage]
}

resource "aws_ecr_repository" "service" {
  name                 = local.name
  image_tag_mutability = "IMMUTABLE"
  force_delete         = var.qualification_profile
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.storage.arn
  }
  image_scanning_configuration { scan_on_push = true }
  tags = local.tags
}

resource "aws_ecr_repository" "adot_collector" {
  name                 = "${local.name}-adot-collector"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = var.qualification_profile
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.storage.arn
  }
  image_scanning_configuration { scan_on_push = true }
  tags = local.tags
}

resource "aws_ecr_lifecycle_policy" "service" {
  repository = aws_ecr_repository.service.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep the latest 30 immutable service images"
      selection = {
        tagStatus     = "tagged"
        tagPrefixList = ["release-"]
        countType     = "imageCountMoreThan"
        countNumber   = 30
      }
      action = { type = "expire" }
    }]
  })
}

resource "aws_s3_bucket" "audit_archive" {
  bucket        = local.s3_bucket_names.audit
  force_destroy = false
  tags          = local.tags

  lifecycle {
    precondition {
      condition     = length(local.s3_bucket_names.audit) <= 63
      error_message = "Derived audit archive bucket name exceeds the 63-character S3 limit; shorten deployment_name."
    }
  }
}

data "aws_iam_policy_document" "audit_archive_qualification" {
  statement {
    sid       = "QualificationAppPrefixApplicationRoleOnly"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.audit_archive.arn}/${local.evidence_paths.app_prefix}*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.application.arn]
    }
  }

  statement {
    sid     = "QualificationEvidenceNeverDeleted"
    effect  = "Deny"
    actions = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
    resources = [
      "${aws_s3_bucket.audit_archive.arn}/${local.evidence_paths.app_prefix}*",
      "${aws_s3_bucket.audit_archive.arn}/${local.evidence_paths.consumer_prefix}*",
    ]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }

  statement {
    sid     = "QualificationEvidenceRequiresConditionalCreate"
    effect  = "Deny"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.audit_archive.arn}/${local.evidence_paths.app_prefix}*",
      "${aws_s3_bucket.audit_archive.arn}/${local.evidence_paths.consumer_prefix}*",
    ]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEquals"
      variable = "s3:if-none-match"
      values   = ["*"]
    }
  }

  statement {
    sid       = "ApplicationCannotWriteConsumerEvidence"
    effect    = "Deny"
    actions   = ["s3:PutObject", "s3:PutObjectTagging"]
    resources = ["${aws_s3_bucket.audit_archive.arn}/${local.evidence_paths.consumer_prefix}*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.application.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "audit_archive_qualification" {
  bucket = aws_s3_bucket.audit_archive.id
  policy = data.aws_iam_policy_document.audit_archive_qualification.json
}

resource "aws_s3_bucket" "invocation_logs" {
  bucket        = local.s3_bucket_names.invocation
  force_destroy = false
  tags          = local.tags

  lifecycle {
    precondition {
      condition     = length(local.s3_bucket_names.invocation) <= 63
      error_message = "Derived invocation logs bucket name exceeds the 63-character S3 limit; shorten deployment_name."
    }
  }
}

resource "aws_s3_bucket" "docs" {
  bucket        = local.s3_bucket_names.docs
  force_destroy = false
  tags          = local.tags

  lifecycle {
    precondition {
      condition     = length(local.s3_bucket_names.docs) <= 63
      error_message = "Derived docs bucket name exceeds the 63-character S3 limit; shorten deployment_name."
    }
  }
}

resource "aws_s3_bucket" "cloudtrail" {
  count         = var.enable_cloudtrail ? 1 : 0
  bucket        = local.s3_bucket_names.cloudtrail
  force_destroy = false
  tags          = local.tags

  lifecycle {
    precondition {
      condition     = length(local.s3_bucket_names.cloudtrail) <= 63
      error_message = "Derived CloudTrail bucket name exceeds the 63-character S3 limit; shorten deployment_name."
    }
  }
}

resource "aws_s3_bucket_public_access_block" "audit_archive" {
  bucket                  = aws_s3_bucket.audit_archive.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "invocation_logs" {
  bucket                  = aws_s3_bucket.invocation_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "docs" {
  bucket                  = aws_s3_bucket.docs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "archive" {
  for_each = {
    audit      = aws_s3_bucket.audit_archive.id
    invocation = aws_s3_bucket.invocation_logs.id
    docs       = aws_s3_bucket.docs.id
  }
  bucket = each.value
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_object" "qualification_resource_map" {
  count                  = var.qualification_profile ? 1 : 0
  bucket                 = aws_s3_bucket.audit_archive.id
  key                    = local.evidence_paths.map_key
  content                = local.qualification_resource_map_json
  content_type           = "application/json"
  server_side_encryption = "aws:kms"
  kms_key_id             = aws_kms_key.storage.arn
  source_hash            = sha256(local.qualification_resource_map_json)
  depends_on             = [aws_s3_bucket_versioning.archive, aws_s3_bucket_server_side_encryption_configuration.archive]
  tags                   = merge(local.tags, { Purpose = "qualification-resource-map" })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "archive" {
  for_each = {
    audit      = aws_s3_bucket.audit_archive.id
    invocation = aws_s3_bucket.invocation_logs.id
    docs       = aws_s3_bucket.docs.id
  }
  bucket = each.value
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.storage.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "audit" {
  bucket = aws_s3_bucket.audit_archive.id
  rule {
    id     = "audit-90-day-retention"
    status = "Enabled"
    filter { prefix = "events/" }
    expiration { days = 90 }
    noncurrent_version_expiration { noncurrent_days = 90 }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "invocations" {
  bucket = aws_s3_bucket.invocation_logs.id
  rule {
    id     = "sensitive-invocation-30-day-retention"
    status = "Enabled"
    filter { prefix = "" }
    expiration { days = 30 }
    noncurrent_version_expiration { noncurrent_days = 30 }
  }
}

data "aws_iam_policy_document" "invocation_logs_bedrock" {
  count = var.enable_bedrock_model_invocation_logging ? 1 : 0

  statement {
    sid    = "BedrockModelInvocationLogDelivery"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["bedrock.amazonaws.com"]
    }
    actions = [
      "s3:GetBucketAcl",
      "s3:ListBucketMultipartUploads",
      "s3:AbortMultipartUpload",
      "s3:ListBucket",
    ]
    resources = [aws_s3_bucket.invocation_logs.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.aws_account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:bedrock:${var.aws_region}:${var.aws_account_id}:*"]
    }
  }

  statement {
    sid    = "BedrockModelInvocationLogObjectDelivery"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["bedrock.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.invocation_logs.arn}/bedrock-invocations/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.aws_account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:bedrock:${var.aws_region}:${var.aws_account_id}:*"]
    }
  }

  statement {
    sid    = "DenyNonBedrockInvocationLogWritersAndDeletion"
    effect = "Deny"
    not_principals {
      type        = "Service"
      identifiers = ["bedrock.amazonaws.com"]
    }
    actions = ["s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"]
    resources = [
      "${aws_s3_bucket.invocation_logs.arn}/bedrock-invocations/*",
    ]
  }

  statement {
    sid    = "DenyBedrockInvocationWritesOutsideSourceAccount"
    effect = "Deny"
    principals {
      type        = "Service"
      identifiers = ["bedrock.amazonaws.com"]
    }
    actions   = ["s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"]
    resources = ["${aws_s3_bucket.invocation_logs.arn}/bedrock-invocations/*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:SourceAccount"
      values   = [var.aws_account_id]
    }
  }

  statement {
    sid    = "DenyBedrockInvocationWritesOutsideSourceArn"
    effect = "Deny"
    principals {
      type        = "Service"
      identifiers = ["bedrock.amazonaws.com"]
    }
    actions   = ["s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"]
    resources = ["${aws_s3_bucket.invocation_logs.arn}/bedrock-invocations/*"]
    condition {
      test     = "ArnNotLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:bedrock:${var.aws_region}:${var.aws_account_id}:*"]
    }
  }
}

resource "aws_s3_bucket_policy" "invocation_logs_bedrock" {
  count  = var.enable_bedrock_model_invocation_logging ? 1 : 0
  bucket = aws_s3_bucket.invocation_logs.id
  policy = data.aws_iam_policy_document.invocation_logs_bedrock[0].json
}

resource "aws_bedrock_model_invocation_logging_configuration" "service" {
  count = var.enable_bedrock_model_invocation_logging ? 1 : 0

  depends_on = [
    aws_kms_key_policy.storage,
    aws_s3_bucket_policy.invocation_logs_bedrock,
  ]

  logging_config {
    embedding_data_delivery_enabled = false
    image_data_delivery_enabled     = false
    text_data_delivery_enabled      = true
    s3_config {
      bucket_name = aws_s3_bucket.invocation_logs.bucket
      key_prefix  = "bedrock-invocations/"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  count                   = var.enable_cloudtrail ? 1 : 0
  bucket                  = aws_s3_bucket.cloudtrail[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.storage.arn
    }
    bucket_key_enabled = true
  }
}

data "aws_iam_policy_document" "cloudtrail_bucket" {
  count = var.enable_cloudtrail ? 1 : 0

  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail[0].arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${var.aws_account_id}:trail/${local.name}-cloudtrail"]
    }
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail[0].arn}/AWSLogs/${var.aws_account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${var.aws_account_id}:trail/${local.name}-cloudtrail"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id
  policy = data.aws_iam_policy_document.cloudtrail_bucket[0].json
}

resource "aws_cloudtrail" "service" {
  count                         = var.enable_cloudtrail ? 1 : 0
  name                          = "${local.name}-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail[0].bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.storage.arn
  tags                          = local.tags

  depends_on = [
    aws_s3_bucket_policy.cloudtrail[0],
    aws_s3_bucket_ownership_controls.cloudtrail[0],
    aws_kms_key_policy.storage,
    aws_s3_bucket_server_side_encryption_configuration.cloudtrail[0],
  ]
}


resource "aws_cloudfront_origin_access_control" "docs" {
  name                              = "${local.name}-docs-oac"
  description                       = "Private AI SOC immutable documentation artifacts"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "docs" {
  enabled             = true
  comment             = "AI SOC versioned approved documentation"
  default_root_object = "index.html"
  price_class         = "PriceClass_100"
  origin {
    domain_name              = aws_s3_bucket.docs.bucket_regional_domain_name
    origin_id                = "approved-docs"
    origin_path              = "/public"
    origin_access_control_id = aws_cloudfront_origin_access_control.docs.id
  }
  default_cache_behavior {
    target_origin_id       = "approved-docs"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true
    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }
    min_ttl     = 0
    default_ttl = 31536000
    max_ttl     = 31536000
  }
  restrictions {
    geo_restriction { restriction_type = "none" }
  }
  viewer_certificate { cloudfront_default_certificate = true }
  tags = local.tags
}

resource "aws_s3_bucket_policy" "docs_oac" {
  bucket = aws_s3_bucket.docs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "CloudFrontOACReadOnly"
      Effect    = "Allow"
      Principal = { Service = "cloudfront.amazonaws.com" }
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.docs.arn}/public/*"
      Condition = { StringEquals = { "AWS:SourceArn" = aws_cloudfront_distribution.docs.arn } }
    }]
  })
}

resource "aws_dynamodb_table" "state" {
  for_each     = local.ddb_tables
  name         = "${local.name}-${each.key}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"
  attribute {
    name = "pk"
    type = "S"
  }
  attribute {
    name = "sk"
    type = "S"
  }
  ttl {
    attribute_name = "ttl_epoch"
    enabled        = true
  }
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.storage.arn
  }
  point_in_time_recovery { enabled = true }
  deletion_protection_enabled = !var.qualification_profile
  tags                        = local.tags
}

resource "aws_sqs_queue" "audit_dlq" {
  name                       = "${local.name}-audit-dlq"
  message_retention_seconds  = 1209600
  kms_master_key_id          = aws_kms_key.storage.arn
  sqs_managed_sse_enabled    = false
  visibility_timeout_seconds = 60
  tags                       = local.tags
}

resource "aws_sqs_queue" "audit" {
  name                       = "${local.name}-audit"
  message_retention_seconds  = 604800
  kms_master_key_id          = aws_kms_key.storage.arn
  sqs_managed_sse_enabled    = false
  visibility_timeout_seconds = 60
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.audit_dlq.arn
    maxReceiveCount     = 10
  })
  tags = local.tags
}

resource "aws_sqs_queue" "feedback_dlq" {
  name                      = "${local.name}-feedback-dlq"
  message_retention_seconds = 1209600
  kms_master_key_id         = aws_kms_key.storage.arn
  sqs_managed_sse_enabled   = false
  tags                      = local.tags
}

resource "aws_sqs_queue" "feedback" {
  name                      = "${local.name}-feedback"
  message_retention_seconds = 604800
  kms_master_key_id         = aws_kms_key.storage.arn
  sqs_managed_sse_enabled   = false
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.feedback_dlq.arn
    maxReceiveCount     = 10
  })
  tags = local.tags
}

resource "aws_vpc_endpoint" "interface" {
  for_each          = var.enable_session_resources ? local.interface_services : toset([])
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type = "Interface"
  subnet_ids        = local.interface_endpoint_subnet_ids
  security_group_ids = (
    concat(
      [aws_security_group.endpoints[0].id],
      local.isolated_network_enabled && contains(local.isolated_allowed_interface_services, each.value)
      ? [aws_security_group.qualification_isolated_endpoints[0].id]
      : [],
    )
  )
  private_dns_enabled = true
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = local.interface_policy_statements[each.value]
  })
  tags = merge(local.tags, { Name = "${local.name}-${replace(each.value, ".", "-")}-vpce" })
}

resource "aws_vpc_endpoint" "s3" {
  count             = var.enable_session_resources ? 1 : 0
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = distinct(concat(var.private_route_table_ids, var.qualification_public_isolated_route_table_ids))
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectTagging", "s3:GetObjectVersionTagging", "s3:PutObject", "s3:PutObjectTagging"]
        Resource = concat(
          [for prefix in local.audit_archive_object_prefixes : "${aws_s3_bucket.audit_archive.arn}/${prefix}*"],
          ["${aws_s3_bucket.docs.arn}/packs/*", "arn:aws:s3:::prod-${var.aws_region}-starport-layer-bucket/*"],
        )
      },
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:ListBucket"]
        Resource  = [aws_s3_bucket.audit_archive.arn]
        Condition = {
          StringLike = {
            "s3:prefix" = [for prefix in local.audit_archive_list_prefixes : "${prefix}*"]
          }
        }
      },
    ]
  })
  tags = local.tags
}

resource "aws_vpc_endpoint" "dynamodb" {
  count             = var.enable_session_resources ? 1 : 0
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = var.private_route_table_ids
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:TransactWriteItems", "dynamodb:ConditionCheckItem"]
      Resource  = flatten([for table in aws_dynamodb_table.state : [table.arn, "${table.arn}/index/*"]])
    }]
  })
  tags = local.tags
}

resource "aws_security_group" "alb" {
  count       = var.enable_session_resources ? 1 : 0
  name        = "${local.name}-alb"
  description = "Internal HTTPS analyst ALB"
  vpc_id      = var.vpc_id
  ingress {
    description = "Approved analyst networks"
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = var.corporate_ingress_cidrs
  }
  egress {
    description = "Only service target group"
    protocol    = "tcp"
    from_port   = 8000
    to_port     = 8000
    cidr_blocks = [var.vpc_cidr]
  }
  dynamic "egress" {
    for_each = length(local.alb_identity_provider_egress_cidrs) > 0 ? [1] : []
    content {
      description = "Configured identity provider endpoints"
      protocol    = "tcp"
      from_port   = 443
      to_port     = 443
      cidr_blocks = local.alb_identity_provider_egress_cidrs
    }
  }
  tags = local.tags
}

resource "aws_security_group" "tasks" {
  count       = var.enable_session_resources ? 1 : 0
  name        = "${local.name}-tasks"
  description = "Private Fargate tasks reachable only from the internal ALB"
  vpc_id      = var.vpc_id
  ingress {
    description     = "ALB target group only"
    protocol        = "tcp"
    from_port       = 8000
    to_port         = 8000
    security_groups = [aws_security_group.alb[0].id]
  }
  egress {
    description = "AWS private interface endpoints only"
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = [var.vpc_cidr]
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
  dynamic "egress" {
    for_each = [1]
    content {
      description     = "S3 gateway endpoint for task uploads and ECR image layers"
      protocol        = "tcp"
      from_port       = 443
      to_port         = 443
      prefix_list_ids = [var.s3_managed_prefix_list_id]
    }
  }
  dynamic "egress" {
    for_each = [1]
    content {
      description     = "DynamoDB gateway endpoint for task state access"
      protocol        = "tcp"
      from_port       = 443
      to_port         = 443
      prefix_list_ids = [var.dynamodb_managed_prefix_list_id]
    }
  }
  dynamic "egress" {
    for_each = var.sites
    content {
      description = "Approved private ${egress.key} analyst indexer path"
      protocol    = "tcp"
      from_port   = egress.value.indexer_port
      to_port     = egress.value.indexer_port
      cidr_blocks = egress.value.indexer_cidrs
    }
  }
  dynamic "egress" {
    for_each = length(var.alb_public_key_egress_cidrs) > 0 ? [1] : []
    content {
      description = "Regional ALB OIDC verification public keys"
      protocol    = "tcp"
      from_port   = 443
      to_port     = 443
      cidr_blocks = var.alb_public_key_egress_cidrs
    }
  }
  dynamic "egress" {
    for_each = length(var.identity_egress_cidrs) > 0 ? [1] : []
    content {
      description = "Configured identity provider and MCP JWKS endpoints"
      protocol    = "tcp"
      from_port   = 443
      to_port     = 443
      cidr_blocks = var.identity_egress_cidrs
    }
  }
  tags = local.tags
}

resource "aws_security_group" "endpoints" {
  count       = var.enable_session_resources ? 1 : 0
  name        = "${local.name}-endpoints"
  description = "Interface endpoints accept TLS only from service tasks"
  vpc_id      = var.vpc_id
  ingress {
    protocol        = "tcp"
    from_port       = 443
    to_port         = 443
    security_groups = [aws_security_group.tasks[0].id]
  }
  tags = local.tags
}

resource "aws_lb" "service" {
  count                      = var.enable_session_resources ? 1 : 0
  name                       = substr("${local.name}-internal", 0, 32)
  internal                   = true
  load_balancer_type         = "application"
  subnets                    = var.private_subnet_ids
  security_groups            = [aws_security_group.alb[0].id]
  drop_invalid_header_fields = true
  idle_timeout               = 150
  enable_deletion_protection = !var.qualification_profile
  tags                       = local.tags
}

resource "aws_lb_target_group" "service" {
  count                = var.enable_session_resources ? 1 : 0
  name                 = substr("${local.name}-tg", 0, 32)
  port                 = 8000
  protocol             = "HTTP"
  target_type          = "ip"
  vpc_id               = var.vpc_id
  deregistration_delay = 160
  health_check {
    enabled             = true
    path                = "/health/ready"
    protocol            = "HTTP"
    matcher             = "200"
    interval            = 15
    timeout             = 3
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
  tags = local.tags
}

resource "aws_lb_listener" "https" {
  count             = var.enable_session_resources ? 1 : 0
  load_balancer_arn = aws_lb.service[0].arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = var.alb_certificate_arn
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "not found"
      status_code  = "404"
    }
  }
}

data "aws_secretsmanager_secret_version" "oidc_client" {
  count         = var.enable_session_resources ? 1 : 0
  secret_id     = var.oidc.client_secret_arn
  version_stage = "AWSCURRENT"
}

resource "aws_lb_listener_rule" "mcp_bearer" {
  count        = var.enable_session_resources ? 1 : 0
  listener_arn = aws_lb_listener.https[0].arn
  priority     = 10
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.service[0].arn
  }
  condition {
    path_pattern {
      values = ["/mcp", "/mcp/*", "/.well-known/oauth-protected-resource*"]
    }
  }
}

resource "aws_lb_listener_rule" "browser_oidc" {
  count        = var.enable_session_resources ? 1 : 0
  listener_arn = aws_lb_listener.https[0].arn
  priority     = 100
  action {
    type = "authenticate-oidc"
    authenticate_oidc {
      issuer                     = var.oidc.issuer
      authorization_endpoint     = var.oidc.authorization
      token_endpoint             = var.oidc.token
      user_info_endpoint         = var.oidc.userinfo
      client_id                  = var.oidc.client_id
      client_secret              = data.aws_secretsmanager_secret_version.oidc_client[0].secret_string
      scope                      = var.oidc.scope
      session_cookie_name        = "AISOCSession"
      session_timeout            = 3600
      on_unauthenticated_request = "authenticate"
    }
  }
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.service[0].arn
  }
  condition {
    path_pattern {
      values = ["/", "/v1/*", "/assets/*"]
    }
  }
}

resource "aws_ecs_cluster" "service" {
  name = local.name
  lifecycle {
    precondition {
      condition = (
        !var.qualification_profile || var.allow_unqualified_direct_identity_egress || (
          var.alb_public_key_egress_mode == "proxy"
          && var.alb_public_key_https_proxy != ""
          && var.idp_in_vpc
          && length(setsubtract(local.qualification_proxy_required_hosts, var.qualification_proxy_allowed_hosts)) == 0
        )
      )
      error_message = "Live qualification requires proxy mode and exact allowlisted ALB key, OIDC, and JWKS hostnames."
    }
  }
  dynamic "setting" {
    for_each = var.qualification_profile ? [] : [1]
    content {
      name  = "containerInsights"
      value = "enabled"
    }
  }
  configuration {
    execute_command_configuration {
      logging = "OVERRIDE"
      log_configuration {
        cloud_watch_log_group_name     = aws_cloudwatch_log_group.service.name
        cloud_watch_encryption_enabled = true
      }
    }
  }
  tags = local.tags
}

data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${local.name}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy" "execution_pull_logs" {
  name = "pinned-ecr-images-and-service-logs"
  role = aws_iam_role.execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["ecr:GetAuthorizationToken"], Resource = "*" },
      { Effect = "Allow", Action = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"], Resource = [aws_ecr_repository.service.arn, aws_ecr_repository.adot_collector.arn] },
      { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.service.arn}:*" },
      {
        Effect   = "Allow"
        Action   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource = [aws_kms_key.storage.arn]
        Condition = {
          StringEquals = {
            "kms:ViaService" = "logs.${var.aws_region}.amazonaws.com"
          }
        }
      },
    ]
  })
}

resource "aws_iam_role_policy" "execution_secrets" {
  name = "read-site-ca-secrets-only"
  role = aws_iam_role.execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["secretsmanager:GetSecretValue"]
      Resource = distinct(concat(
        [for site in values(var.sites) : site.ca_secret_arn],
        [
          var.crypto_secrets.cursor_aead_secret_arn,
          var.crypto_secrets.feedback_receipt_secret_arn,
          var.crypto_secrets.csrf_secret_arn,
        ],
      ))
    }]
  })
}

resource "aws_iam_role" "application" {
  name               = "${local.name}-application"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy" "application" {
  count = var.enable_session_resources ? 1 : 0
  name  = "read-only-soc-runtime"
  role  = aws_iam_role.application.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "GuardrailedBedrockInvokeModel"
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel"]
        Resource = local.bedrock_model_resources
        Condition = {
          StringEquals = {
            "bedrock:GuardrailIdentifier" = local.guardrail_qualified_identifier
            "aws:SourceVpce"              = aws_vpc_endpoint.interface["bedrock-runtime"].id
          }
        }
      },
      {
        Sid      = "BedrockApplyGuardrail"
        Effect   = "Allow"
        Action   = ["bedrock:ApplyGuardrail"]
        Resource = [var.guardrail.identifier]
        Condition = {
          StringEquals = {
            "aws:SourceVpce" = aws_vpc_endpoint.interface["bedrock-runtime"].id
          }
        }
      },
      {
        Sid      = "BedrockCountTokensWithoutGuardrail"
        Effect   = "Allow"
        Action   = ["bedrock:CountTokens"]
        Resource = local.bedrock_count_token_resources
        Condition = {
          StringEquals = {
            "aws:SourceVpce" = aws_vpc_endpoint.interface["bedrock-runtime"].id
          }
        }
      },
      {
        Sid      = "DenyMissingGuardrail"
        Effect   = "Deny"
        Action   = ["bedrock:InvokeModel"]
        Resource = local.bedrock_model_resources
        Condition = {
          Null = {
            "bedrock:GuardrailIdentifier" = "true"
          }
        }
      },
      {
        Sid      = "DenyMismatchedGuardrailIdentifier"
        Effect   = "Deny"
        Action   = ["bedrock:InvokeModel"]
        Resource = local.bedrock_model_resources
        Condition = {
          StringNotEquals = {
            "bedrock:GuardrailIdentifier" = local.guardrail_qualified_identifier
          }
        }
      },
      {
        Sid         = "DenyNonAllowlistedBedrockResources"
        Effect      = "Deny"
        Action      = ["bedrock:InvokeModel", "bedrock:CountTokens"]
        NotResource = local.bedrock_model_resources
      },
      {
        Sid      = "StateTablesOnly"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:TransactWriteItems", "dynamodb:ConditionCheckItem"]
        Resource = flatten([for table in aws_dynamodb_table.state : [table.arn, "${table.arn}/index/*"]])
      },
      {
        Sid      = "QueueOperations"
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = [aws_sqs_queue.audit.arn, aws_sqs_queue.feedback.arn]
      },
      {
        Sid    = "PinnedCaReadOnly"
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = distinct(concat(
          [for site in values(var.sites) : site.ca_secret_arn],
          [
            var.crypto_secrets.cursor_aead_secret_arn,
            var.crypto_secrets.feedback_receipt_secret_arn,
            var.crypto_secrets.csrf_secret_arn,
          ],
        ))
      },
      {
        Sid      = "PerSiteJwtSigning"
        Effect   = "Allow"
        Action   = ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"]
        Resource = [for key in aws_kms_key.site_signing : key.arn]
        Condition = {
          StringEquals = { "kms:SigningAlgorithm" = "RSASSA_PKCS1_V1_5_SHA_256" }
        }
      },
      {
        Sid      = "EncryptedAuditArchive"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.audit_archive.arn}/events/*"
      },
      {
        Sid      = "ContentPackDownload"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.docs.arn}/packs/*"
      },
      {
        Sid      = "StorageKeyUse"
        Effect   = "Allow"
        Action   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
        Resource = aws_kms_key.storage.arn
      },
      {
        Sid      = "XRayExport"
        Effect   = "Allow"
        Action   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
        Resource = "*"
      },
      {
        Sid      = "BoundedCloudWatchMetrics"
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
        Condition = {
          StringEquals = { "cloudwatch:namespace" = "AISOC/Service" }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "qualification_application_evidence" {
  count = var.qualification_profile ? 1 : 0
  name  = "qualification-application-evidence"
  role  = aws_iam_role.application.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WriteApplicationQualificationEvidence"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:PutObjectTagging"]
        Resource = "${aws_s3_bucket.audit_archive.arn}/${local.evidence_paths.app_prefix}*"
      },
      {
        Sid    = "ReadPinnedQualificationMapAndInputs"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectTagging", "s3:GetObjectVersionTagging"]
        Resource = [
          "${aws_s3_bucket.audit_archive.arn}/${local.evidence_paths.map_key}",
          "${aws_s3_bucket.audit_archive.arn}/${local.evidence_paths.input_prefix}*",
          "${aws_s3_bucket.docs.arn}/packs/*",
        ]
      },
    ]
  })
}

resource "aws_iam_role" "audit_consumer" {
  name               = "${local.name}-audit-consumer"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy" "audit_consumer" {
  name = "audit-archive-only"
  role = aws_iam_role.audit_consumer.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes"], Resource = [aws_sqs_queue.audit.arn, aws_sqs_queue.feedback.arn] },
      { Effect = "Allow", Action = ["s3:PutObject"], Resource = ["${aws_s3_bucket.audit_archive.arn}/events/*", "${aws_s3_bucket.audit_archive.arn}/feedback/*"] },
      { Effect = "Allow", Action = ["s3:PutObject", "s3:PutObjectTagging"], Resource = "${aws_s3_bucket.audit_archive.arn}/${local.evidence_paths.consumer_prefix}*" },
      { Effect = "Allow", Action = ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectTagging", "s3:GetObjectVersionTagging"], Resource = ["${aws_s3_bucket.audit_archive.arn}/${local.evidence_paths.map_key}", "${aws_s3_bucket.audit_archive.arn}/${local.evidence_paths.input_prefix}*"] },
      { Effect = "Allow", Action = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"], Resource = aws_kms_key.storage.arn },
    ]
  })
}

resource "aws_ecs_task_definition" "service" {
  count                    = var.enable_session_resources ? 1 : 0
  family                   = local.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.application.arn
  volume {
    name = "tmp"
  }
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  container_definitions = jsonencode([{
    name                   = "ai-soc"
    image                  = var.service_image
    essential              = true
    user                   = "10001:10001"
    readonlyRootFilesystem = true
    stopTimeout            = 120
    portMappings           = [{ containerPort = 8000, protocol = "tcp" }]
    mountPoints = [{
      sourceVolume  = "tmp"
      containerPath = "/tmp"
      readOnly      = false
    }]
    environment = concat(
      [
        { name = "SOC_MODE", value = "live" },
        { name = "SOC_SERVICE_SHA", value = var.service_sha },
        { name = "SOC_CONTENT_SHA", value = var.content_sha },
        { name = "SOC_SERVICE_CONFIG_JSON", value = local.service_sealed_config },
        { name = "SOC_CONFIGURATION_SHA256", value = sha256(local.service_sealed_config) },
        { name = "AWS_REGION", value = var.aws_region },
        { name = "AWS_EC2_METADATA_DISABLED", value = "true" },
        { name = "OTEL_EXPORTER_OTLP_ENDPOINT", value = "http://127.0.0.1:4317" },
        { name = "OTEL_EXPORTER_OTLP_PROTOCOL", value = "grpc" },
        { name = "OTEL_SERVICE_NAME", value = "ai-soc" },
        { name = "SOC_CLOUDWATCH_NAMESPACE", value = "AISOC/Service" },
        { name = "SOC_CURSOR_KEY_ID_CURRENT", value = var.crypto_secrets.cursor_current_key_id },
        { name = "SOC_CURSOR_KEY_ID_PREVIOUS", value = var.crypto_secrets.cursor_previous_key_id },
        { name = "SOC_RECEIPT_KEY_ID_CURRENT", value = var.crypto_secrets.receipt_current_key_id },
        { name = "SOC_RECEIPT_KEY_ID_PREVIOUS", value = var.crypto_secrets.receipt_previous_key_id },
      ],
      var.alb_public_key_https_proxy != "" ? [
        { name = "SOC_ALB_PUBLIC_KEY_HTTPS_PROXY", value = var.alb_public_key_https_proxy },
      ] : [],
      var.mcp_jwks_https_proxy != "" ? [
        { name = "SOC_MCP_JWKS_HTTPS_PROXY", value = var.mcp_jwks_https_proxy },
      ] : [],
    )
    secrets = concat(
      [for site_id, site in var.sites : {
        name      = "SOC_SITE_${upper(replace(site_id, "-", "_"))}_CA"
        valueFrom = "${site.ca_secret_arn}:::${site.ca_secret_version}"
      }],
      [
        {
          name      = "SOC_CURSOR_AEAD_CURRENT"
          valueFrom = "${var.crypto_secrets.cursor_aead_secret_arn}:::${var.crypto_secrets.cursor_current_version}"
        },
        {
          name      = "SOC_CURSOR_AEAD_PREVIOUS"
          valueFrom = "${var.crypto_secrets.cursor_aead_secret_arn}:::${var.crypto_secrets.cursor_previous_version}"
        },
        {
          name      = "SOC_FEEDBACK_RECEIPT_CURRENT"
          valueFrom = "${var.crypto_secrets.feedback_receipt_secret_arn}:::${var.crypto_secrets.receipt_current_version}"
        },
        {
          name      = "SOC_FEEDBACK_RECEIPT_PREVIOUS"
          valueFrom = "${var.crypto_secrets.feedback_receipt_secret_arn}:::${var.crypto_secrets.receipt_previous_version}"
        },
        {
          name      = "SOC_CSRF_SECRET"
          valueFrom = "${var.crypto_secrets.csrf_secret_arn}:::${var.crypto_secrets.csrf_version}"
        },
      ],
    )
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.service.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "service"
      }
    }
    healthCheck = {
      command     = ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=2)"]
      interval    = 15
      timeout     = 3
      retries     = 3
      startPeriod = 20
    }
    }, {
    name                   = "adot-collector"
    image                  = "${aws_ecr_repository.adot_collector.repository_url}@${var.adot_collector_digest}"
    essential              = true
    readonlyRootFilesystem = true
    command                = ["--config=/etc/ecs/ecs-default-config.yaml"]
    mountPoints = [{
      sourceVolume  = "tmp"
      containerPath = "/tmp"
      readOnly      = false
    }]
    environment = [{ name = "AWS_REGION", value = var.aws_region }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.service.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "adot"
      }
    }
  }])
  tags = local.tags

  lifecycle {
    precondition {
      condition = (
        length(var.alb_public_key_egress_cidrs) > 0
        && (var.alb_public_key_egress_mode == "proxy") == (var.alb_public_key_https_proxy != "")
      )
      error_message = "Every key-fetch mode needs exact destination host IPs; proxy mode also needs its proxy URL. Security groups cannot filter the documented regional key host path."
    }
    precondition {
      condition = (
        var.idp_in_vpc || var.alb_public_key_https_proxy != "" || length(var.identity_egress_cidrs) > 0
      )
      error_message = "Deployments require MCP JWKS reachability via idp_in_vpc, identity_egress_cidrs on tasks, or alb_public_key_https_proxy with the issuer host allowlisted."
    }
  }
}

resource "aws_ecs_service" "service" {
  count                              = var.enable_session_resources ? 1 : 0
  name                               = local.name
  cluster                            = aws_ecs_cluster.service.id
  task_definition                    = aws_ecs_task_definition.service[0].arn
  desired_count                      = 2
  launch_type                        = "FARGATE"
  enable_execute_command             = false
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  health_check_grace_period_seconds  = 60
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.tasks[0].id]
    assign_public_ip = false
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.service[0].arn
    container_name   = "ai-soc"
    container_port   = 8000
  }
  depends_on = [aws_lb_listener.https, aws_iam_role_policy.execution_pull_logs]
  lifecycle { ignore_changes = [desired_count] }
  tags = local.tags
}

resource "aws_appautoscaling_target" "service" {
  count              = var.enable_session_resources ? 1 : 0
  max_capacity       = var.service_max_capacity
  min_capacity       = 2
  resource_id        = "service/${aws_ecs_cluster.service.name}/${aws_ecs_service.service[0].name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "cpu" {
  count              = var.enable_session_resources ? 1 : 0
  name               = "${local.name}-cpu-target"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.service[0].resource_id
  scalable_dimension = aws_appautoscaling_target.service[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.service[0].service_namespace
  target_tracking_scaling_policy_configuration {
    target_value       = 60
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
    predefined_metric_specification { predefined_metric_type = "ECSServiceAverageCPUUtilization" }
  }
}

resource "aws_ecs_task_definition" "audit_consumer" {
  count                    = var.enable_session_resources ? 1 : 0
  family                   = "${local.name}-audit-consumer"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.audit_consumer.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  container_definitions = jsonencode([{
    name                   = "audit-archive"
    image                  = var.service_image
    essential              = true
    user                   = "10001:10001"
    readonlyRootFilesystem = true
    command                = ["python", "-m", "ai_soc.telemetry.audit_delivery"]
    environment = [
      { name = "AUDIT_QUEUE_URL", value = aws_sqs_queue.audit.url },
      { name = "FEEDBACK_QUEUE_URL", value = aws_sqs_queue.feedback.url },
      { name = "AUDIT_ARCHIVE_BUCKET", value = aws_s3_bucket.audit_archive.bucket },
      { name = "AWS_EC2_METADATA_DISABLED", value = "true" },
      { name = "AWS_REGION", value = var.aws_region },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.service.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "audit-archive"
      }
    }
  }])
  tags = local.tags
}

resource "aws_iam_role" "audit_scheduler" {
  count = var.enable_session_resources ? 1 : 0
  name  = "${local.name}-audit-scheduler"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "scheduler.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceAccount" = var.aws_account_id } }
    }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy" "audit_scheduler" {
  count = var.enable_session_resources ? 1 : 0
  role  = aws_iam_role.audit_scheduler[0].id
  name  = "run-audit-archive-task"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["ecs:RunTask"], Resource = aws_ecs_task_definition.audit_consumer[0].arn, Condition = { ArnEquals = { "ecs:cluster" = aws_ecs_cluster.service.arn } } },
      { Effect = "Allow", Action = ["iam:PassRole"], Resource = [aws_iam_role.execution.arn, aws_iam_role.audit_consumer.arn], Condition = { StringLike = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" } } },
    ]
  })
}

resource "aws_scheduler_schedule" "audit_archive" {
  count                        = var.enable_session_resources ? 1 : 0
  name                         = "${local.name}-audit-archive"
  description                  = "Drain durable audit SQS into encrypted S3 archive"
  schedule_expression          = var.audit_archive_schedule_expression
  schedule_expression_timezone = "UTC"
  state                        = var.enable_audit_archive_schedule && !var.qualification_profile ? "ENABLED" : "DISABLED"
  flexible_time_window { mode = "OFF" }
  target {
    arn      = aws_ecs_cluster.service.arn
    role_arn = aws_iam_role.audit_scheduler[0].arn
    input = jsonencode({
      containerOverrides = [{
        name    = "audit-archive"
        command = ["python", "-m", "ai_soc.telemetry.audit_delivery"]
      }]
    })
    ecs_parameters {
      task_definition_arn = aws_ecs_task_definition.audit_consumer[0].arn
      task_count          = 1
      launch_type         = "FARGATE"
      platform_version    = "1.4.0"
      network_configuration {
        assign_public_ip = false
        security_groups  = [aws_security_group.tasks[0].id]
        subnets          = var.private_subnet_ids
      }
    }
    retry_policy {
      maximum_event_age_in_seconds = 3600
      maximum_retry_attempts       = 3
    }
    dead_letter_config { arn = aws_sqs_queue.audit_dlq.arn }
  }
  depends_on = [aws_iam_role_policy.audit_scheduler]
}

resource "aws_cloudwatch_metric_alarm" "audit_queue_age" {
  alarm_name          = "${local.name}-audit-queue-age"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateAgeOfOldestMessage"
  dimensions          = { QueueName = aws_sqs_queue.audit.name }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 120
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [var.alarm_topic_arn]
  tags                = local.tags
}

resource "aws_cloudwatch_metric_alarm" "audit_dlq" {
  alarm_name          = "${local.name}-audit-dlq-not-empty"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.audit_dlq.name }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.alarm_topic_arn]
  tags                = local.tags
}

resource "aws_cloudwatch_metric_alarm" "recovery_lag" {
  alarm_name          = "${local.name}-recovery-lag"
  namespace           = "AISOC/Service"
  metric_name         = "RecoveryLagSeconds"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 120
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [var.alarm_topic_arn]
  tags                = local.tags
}

resource "aws_cloudwatch_metric_alarm" "recovery_backlog" {
  alarm_name          = "${local.name}-recovery-backlog"
  namespace           = "AISOC/Service"
  metric_name         = "RecoveryBacklog"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 1000
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [var.alarm_topic_arn]
  tags                = local.tags
}

resource "aws_cloudwatch_metric_alarm" "admission_rejections" {
  alarm_name          = "${local.name}-admission-rejections"
  namespace           = "AISOC/Service"
  metric_name         = "AdmissionRejected"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 5
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.alarm_topic_arn]
  tags                = local.tags
}

check "bedrock_spend_backstop_requires_account_budget" {
  assert {
    condition     = !var.enable_bedrock_spend_budget || var.enable_account_cost_budgets
    error_message = "The optional deny action requires enable_account_cost_budgets and attaches to its unfiltered gross-cost budget. Verify the actual Claude billing line first."
  }
}

check "account_cost_budgets_require_alert_email" {
  assert {
    condition     = !var.enable_account_cost_budgets || var.account_cost_budget_alert_email != ""
    error_message = "Set account_cost_budget_alert_email when enable_account_cost_budgets is true."
  }
}

resource "aws_iam_policy" "bedrock_spend_deny" {
  count = var.enable_bedrock_spend_budget ? 1 : 0
  name  = "${local.name}-bedrock-spend-deny"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "DenyBedrockInferenceWhenBudgetBackstopFires"
      Effect   = "Deny"
      Action   = ["bedrock:InvokeModel", "bedrock:CountTokens"]
      Resource = "*"
    }]
  })
  tags = local.tags

  lifecycle {
    precondition {
      condition = (
        var.enable_account_cost_budgets && var.account_cost_budget_alert_email != ""
      )
      error_message = "The deny backstop requires the account-wide budget and alert email. Verify the actual Claude billing line before enabling it."
    }
  }
}

# Budgets execution-role trust: https://docs.aws.amazon.com/cost-management/latest/userguide/cross-service-confused-deputy-prevention.html
data "aws_iam_policy_document" "bedrock_budget_action_assume" {
  count = var.enable_bedrock_spend_budget ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["budgets.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.aws_account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:budgets::${var.aws_account_id}:budget/${local.name}-account-gross-cost"]
    }
  }
}

data "aws_iam_policy_document" "bedrock_budget_action_attach" {
  count = var.enable_bedrock_spend_budget ? 1 : 0

  statement {
    sid    = "AttachBedrockSpendDenyOnly"
    effect = "Allow"
    actions = [
      "iam:AttachRolePolicy",
      "iam:DetachRolePolicy",
    ]
    resources = [aws_iam_role.application.arn]
    condition {
      test     = "ArnEquals"
      variable = "iam:PolicyARN"
      values   = [aws_iam_policy.bedrock_spend_deny[0].arn]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
    ]
    resources = [aws_iam_policy.bedrock_spend_deny[0].arn]
  }
}

resource "aws_budgets_budget" "account_gross_cost" {
  count        = var.enable_account_cost_budgets ? 1 : 0
  name         = "${local.name}-account-gross-cost"
  budget_type  = "COST"
  limit_amount = tostring(var.account_gross_cost_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
  cost_types {
    include_credit = false
    include_refund = false
  }
  lifecycle {
    precondition {
      condition     = var.account_cost_budget_alert_email != ""
      error_message = "Set account_cost_budget_alert_email before enabling account cost budgets."
    }
  }

  dynamic "notification" {
    for_each = var.enable_account_cost_budgets ? [50, 80, 100] : []
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = [var.account_cost_budget_alert_email]
    }
  }

  tags = local.tags
}

resource "aws_budgets_budget" "account_cash_cost" {
  count        = var.enable_account_cost_budgets ? 1 : 0
  name         = "${local.name}-account-cash-cost"
  budget_type  = "COST"
  limit_amount = tostring(var.account_cash_cost_alert_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
  cost_types {
    include_credit = true
    include_refund = true
  }
  lifecycle {
    precondition {
      condition     = var.account_cost_budget_alert_email != ""
      error_message = "Set account_cost_budget_alert_email before enabling account cost budgets."
    }
  }

  dynamic "notification" {
    for_each = var.enable_account_cost_budgets ? [50, 80, 100] : []
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = [var.account_cost_budget_alert_email]
    }
  }

  tags = local.tags
}

resource "aws_iam_role" "bedrock_budget_action" {
  count              = var.enable_bedrock_spend_budget ? 1 : 0
  name               = "${local.name}-bedrock-budget-action"
  assume_role_policy = data.aws_iam_policy_document.bedrock_budget_action_assume[0].json
  tags               = local.tags
}

resource "aws_iam_role_policy" "bedrock_budget_action" {
  count  = var.enable_bedrock_spend_budget ? 1 : 0
  name   = "attach-bedrock-spend-deny"
  role   = aws_iam_role.bedrock_budget_action[0].id
  policy = data.aws_iam_policy_document.bedrock_budget_action_attach[0].json
}

resource "aws_budgets_budget_action" "bedrock_spend_deny" {
  count              = var.enable_bedrock_spend_budget ? 1 : 0
  budget_name        = aws_budgets_budget.account_gross_cost[0].name
  action_type        = "APPLY_IAM_POLICY"
  approval_model     = "AUTOMATIC"
  notification_type  = "ACTUAL"
  execution_role_arn = aws_iam_role.bedrock_budget_action[0].arn

  action_threshold {
    action_threshold_type  = "PERCENTAGE"
    action_threshold_value = 100
  }

  definition {
    iam_action_definition {
      policy_arn = aws_iam_policy.bedrock_spend_deny[0].arn
      roles      = [aws_iam_role.application.name]
    }
  }

  subscriber {
    subscription_type = "EMAIL"
    address           = var.account_cost_budget_alert_email
  }

  depends_on = [aws_budgets_budget.account_gross_cost, aws_iam_role_policy.bedrock_budget_action]
}
