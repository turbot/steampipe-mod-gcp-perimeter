mod "gcp_perimeter" {
  # Meta properties
  title         = "GCP Perimeter Security"
  description   = "Create dashboards and controls to analyze the perimeter security of your GCP resources."
  color         = "#EA4335"
  documentation = file("./docs/index.md")
  icon          = "/images/mods/turbot/gcp-perimeter.svg"
  categories    = ["gcp", "security", "perimeter"]

  opengraph {
    title       = "Powerpipe Mod for GCP Perimeter Security"
    description = "Create dashboards and controls to analyze the perimeter security of your GCP resources."
  }

  requires {
    plugin "gcp" {
      min_version = "1.6.0"
    }
  }
} 