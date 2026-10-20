# Preserve the original full-deployment state addresses. With
# enable_session_resources=false, Terraform then removes these indexed
# instances while leaving foundation resources at their existing addresses.
moved {
  from = aws_vpc_endpoint.s3
  to   = aws_vpc_endpoint.s3[0]
}
moved {
  from = aws_vpc_endpoint.dynamodb
  to   = aws_vpc_endpoint.dynamodb[0]
}
moved {
  from = aws_security_group.alb
  to   = aws_security_group.alb[0]
}
moved {
  from = aws_security_group.tasks
  to   = aws_security_group.tasks[0]
}
moved {
  from = aws_security_group.endpoints
  to   = aws_security_group.endpoints[0]
}
moved {
  from = aws_lb.service
  to   = aws_lb.service[0]
}
moved {
  from = aws_lb_target_group.service
  to   = aws_lb_target_group.service[0]
}
moved {
  from = aws_lb_listener.https
  to   = aws_lb_listener.https[0]
}
moved {
  from = data.aws_secretsmanager_secret_version.oidc_client
  to   = data.aws_secretsmanager_secret_version.oidc_client[0]
}
moved {
  from = aws_lb_listener_rule.mcp_bearer
  to   = aws_lb_listener_rule.mcp_bearer[0]
}
moved {
  from = aws_lb_listener_rule.browser_oidc
  to   = aws_lb_listener_rule.browser_oidc[0]
}
moved {
  from = aws_ecs_task_definition.service
  to   = aws_ecs_task_definition.service[0]
}
moved {
  from = aws_iam_role_policy.application
  to   = aws_iam_role_policy.application[0]
}
moved {
  from = aws_ecs_service.service
  to   = aws_ecs_service.service[0]
}
moved {
  from = aws_appautoscaling_target.service
  to   = aws_appautoscaling_target.service[0]
}
moved {
  from = aws_appautoscaling_policy.cpu
  to   = aws_appautoscaling_policy.cpu[0]
}
moved {
  from = aws_ecs_task_definition.audit_consumer
  to   = aws_ecs_task_definition.audit_consumer[0]
}
moved {
  from = aws_iam_role.audit_scheduler
  to   = aws_iam_role.audit_scheduler[0]
}
moved {
  from = aws_iam_role_policy.audit_scheduler
  to   = aws_iam_role_policy.audit_scheduler[0]
}
moved {
  from = aws_scheduler_schedule.audit_archive
  to   = aws_scheduler_schedule.audit_archive[0]
}
