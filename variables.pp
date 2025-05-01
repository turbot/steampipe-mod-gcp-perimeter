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

  # SQL snippets for dimensions
  common_dimensions_sql = join("", [
    contains(var.common_dimensions, "location") ? ", location" : "",
    contains(var.common_dimensions, "project") ? ", project" : ""
  ])

  tag_dimensions_sql = length(var.tag_dimensions) > 0 ? (
    ", " + join(", ", [
      for dim in var.tag_dimensions :
      format("labels ->> '%s' as \"%s\"", dim, replace(dim, "\"", "\"\""))
    ])
  ) : ""
} 