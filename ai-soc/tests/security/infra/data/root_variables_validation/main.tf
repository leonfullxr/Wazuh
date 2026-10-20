terraform {
  required_version = ">= 1.5.0"
}

output "identity_egress_count" {
  value = length(var.identity_egress_cidrs)
}
