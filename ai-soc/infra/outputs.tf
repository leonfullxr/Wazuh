output "internal_alb_dns_name" {
  value = var.enable_session_resources ? aws_lb.service[0].dns_name : null
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.service.name
}

output "service_image_repository_url" {
  value = aws_ecr_repository.service.repository_url
}
output "audit_queue_url" {
  value = aws_sqs_queue.audit.url
}

output "audit_archive_bucket" {
  value = aws_s3_bucket.audit_archive.bucket
}

output "qualification_resource_map_pin" {
  description = "Immutable version and content digest for the qualification resource map; the sealed configuration pins this exact object when qualification_profile is enabled."
  value = var.qualification_profile ? {
    bucket     = aws_s3_bucket.audit_archive.bucket
    key        = aws_s3_object.qualification_resource_map[0].key
    version_id = aws_s3_object.qualification_resource_map[0].version_id
    sha256     = sha256(local.qualification_resource_map_json)
  } : null
}

output "documentation_origin" {
  value = "https://${aws_cloudfront_distribution.docs.domain_name}"
}

output "site_signing_key_arns" {
  value = { for site, key in aws_kms_key.site_signing : site => key.arn }
}

output "qualification_proxy_required_hosts" {
  value       = sort(tolist(local.qualification_proxy_required_hosts))
  description = "Required exact FQDNs for the qualification HTTPS CONNECT proxy ACL."
}

output "session_teardown_inventory" {
  description = "Deployment-derived resources and queue/task identifiers used by check-session-teardown."
  value = {
    required_addresses = local.foundation_inventory_addresses
    queue_urls = {
      audit        = aws_sqs_queue.audit.url
      audit_dlq    = aws_sqs_queue.audit_dlq.url
      feedback     = aws_sqs_queue.feedback.url
      feedback_dlq = aws_sqs_queue.feedback_dlq.url
    }
    ecs_cluster_name           = aws_ecs_cluster.service.name
    archive_task_family        = "${local.name}-audit-consumer"
    archive_schedule_name      = "${local.name}-audit-archive"
    archive_schedule_required  = var.enable_session_resources
    account_budgets_configured = var.enable_account_cost_budgets
  }
}

output "foundation_inventory_addresses" {
  description = "Expected persistent resource addresses derived from configured sites and optional AWS controls."
  value       = local.foundation_inventory_addresses
}

output "archive_task_run_configuration" {
  description = "Manual RunTask inputs for draining retained audit and feedback queues before session networking is removed."
  value = var.enable_session_resources ? {
    cluster_name        = aws_ecs_cluster.service.name
    task_definition_arn = aws_ecs_task_definition.audit_consumer[0].arn
    subnet_ids          = var.private_subnet_ids
    security_group_id   = aws_security_group.tasks[0].id
  } : null
}
