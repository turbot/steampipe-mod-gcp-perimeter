mod "gcp_perimeter" {
  # Hub metadata
  title         = "GCP Perimeter"
  description   = "Run security controls across all your Google Cloud Platform projects to look for resources that are publicly accessible, shared with untrusted entities, have insecure network configurations, and more using Powerpipe and Steampipe."
  color         = "#EA4335"
  documentation = file("./docs/index.md")
  icon          = "/images/mods/turbot/gcp-perimeter.svg"
  categories    = ["gcp", "perimeter", "public cloud", "security"]

  opengraph {
    title       = "Powerpipe Mod for GCP Perimeter"
    description = "Run security controls across all your Google Cloud Platform projects to look for resources that are publicly accessible, shared with untrusted entities, have insecure network configurations, and more using Powerpipe and Steampipe."
    image       = "/images/mods/turbot/gcp-perimeter-social-graphic.png"
  }

  requires {
    plugin "gcp" {
      min_version = "1.6.0"
    }
  }
} 