# GCP Perimeter Security Mod

The GCP Perimeter Security Mod provides a set of controls to analyze and monitor the security perimeter of your Google Cloud Platform resources. This mod helps you ensure that your GCP resources are not unnecessarily exposed to the public internet and that resource sharing is limited to trusted entities.

## References

[GCP Security Best Practices](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#networking-security)

## Controls

The following benchmarks are included:

- **Public Access**: Identifies resources that are publicly accessible and may pose security risks.
- **Network Access**: Evaluates network configurations for security best practices.
- **Shared Access**: Monitors resource sharing to ensure it's limited to trusted entities.

## Requirements

- [Steampipe](https://steampipe.io/downloads)
- [GCP Plugin for Steampipe](https://hub.steampipe.io/plugins/turbot/gcp)

## Getting Started

### Installation

Download and install Steampipe (https://steampipe.io/downloads). Or use Brew:

```bash
brew tap turbot/tap
brew install steampipe
```

Install the GCP plugin with [Steampipe](https://steampipe.io):

```bash
steampipe plugin install gcp
```

Clone:

```bash
git clone https://github.com/turbot/steampipe-mod-gcp-perimeter.git
cd steampipe-mod-gcp-perimeter
```

### Usage

Start your dashboard server to get started:

```bash
steampipe dashboard
```

By default, the dashboard interface will then be launched in a new browser window at https://localhost:9194. From here, you can run benchmarks by selecting one or searching for a specific one.

Instead of running benchmarks in a dashboard, you can also run them within your terminal with the query command:

```bash
steampipe query "select * from gcp_perimeter.benchmark.public_access"
```

### Configuration

Configure your GCP credentials using the standard GCP authentication methods, or through the plugin config file (~/.steampipe/config/gcp.spc).

```hcl
connection "gcp" {
  plugin = "gcp"
  project = "YOUR_PROJECT_ID"
  credentials = "~/.gcp/credentials.json"
}
```

Variables can be customized through the powerpipe.ppvars file:

```hcl
# List of trusted GCP projects
trusted_projects = [
  "my-trusted-project-1",
  "my-trusted-project-2"
]

# Common dimensions to include in controls
common_dimensions = [
  "project",
  "location"
]

# Example tag dimensions to include (GCP labels)
tag_dimensions = [
  "environment",
  "owner",
  "cost_center"
]
``` 