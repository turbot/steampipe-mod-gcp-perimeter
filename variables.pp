variable "trusted_projects" {
  type        = list(string)
  description = "A list of trusted GCP project IDs that resources can be shared with."
  default     = []
}

variable "common_dimensions" {
  type        = list(string)
  description = "A list of common dimensions to add to each control."
  default     = ["project", "location"]
}

variable "tag_dimensions" {
  type        = list(string)
  description = "A list of tags to add as dimensions to each control."
  default     = []
}

locals {
  # Common tags for the mod
  gcp_perimeter_common_tags = {
    category = "Perimeter"
    plugin   = "gcp"
    service  = "GCP"
  }

  # Local internal variable to build the SQL select clause for common
  # dimensions using a table name qualifier if required. Do not edit directly.
  common_dimensions_qualifier_sql = <<-EOQ
  %{~if contains(var.common_dimensions, "location")}, __QUALIFIER__location%{endif~}
  %{~if contains(var.common_dimensions, "project")}, __QUALIFIER__project%{endif~}
  EOQ

  # Local internal variable to build the SQL select clause for tag
  # dimensions. Do not edit directly.
  tag_dimensions_qualifier_sql = <<-EOQ
  %{~for dim in var.tag_dimensions},  __QUALIFIER__labels ->> '${dim}' as "${replace(dim, "\"", "\"\"")}"%{endfor~}
  EOQ
}

locals {
  # Local internal variable with the full SQL select clause for common
  # dimensions and tags. Do not edit directly.
  common_dimensions_sql = replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "")
  tag_dimensions_sql    = replace(local.tag_dimensions_qualifier_sql, "__QUALIFIER__", "")
} 