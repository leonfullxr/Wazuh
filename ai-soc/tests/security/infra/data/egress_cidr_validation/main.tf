terraform {
  required_version = ">= 1.5.0"
}

variable "cidrs" {
  type = list(string)
  validation {
    condition = length(var.cidrs) > 0 && alltrue([
      for cidr in var.cidrs :
      can(cidrhost(cidr, 0)) && !contains(["0.0.0.0/0", "::/0"], cidr) && (
        (strcontains(cidr, ":") && tonumber(split("/", cidr)[1]) >= 48) ||
        (!strcontains(cidr, ":") && tonumber(split("/", cidr)[1]) >= 24)
      )
    ])
    error_message = "CIDR list must reject default routes and require /24 (IPv4) or /48 (IPv6) minimum prefix length."
  }
}

output "count" {
  value = length(var.cidrs)
}
