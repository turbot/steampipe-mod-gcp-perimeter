# GCP Perimeter Security Mod for Powerpipe

A collection of benchmarks and controls to analyze the perimeter security of your Google Cloud Platform resources. This mod helps you ensure that your GCP resources are not unnecessarily exposed to the public internet and that resource sharing is limited to trusted entities.

## Getting Started

### Installation

Install [Powerpipe](https://powerpipe.io/downloads) and the [GCP plugin](https://hub.steampipe.io/plugins/turbot/gcp):

```bash
brew install turbot/tap/powerpipe
powerpipe plugin install gcp
```

Clone:

```bash
git clone https://github.com/turbot/steampipe-mod-gcp-perimeter.git
cd steampipe-mod-gcp-perimeter
```

### Usage

Start your dashboard server:

```bash
powerpipe server
```

By default, the dashboard interface will then be launched in a new browser window at http://localhost:9033. From here, you can run benchmarks by selecting one or searching for a specific one.

You can also run benchmarks directly from the command line:

```bash
powerpipe benchmark run gcp_perimeter.benchmark.public_access
```

### Credentials

This mod uses the credentials configured in the [GCP Plugin for Steampipe](https://hub.steampipe.io/plugins/turbot/gcp).

### Configuration

No extra configuration is required.

## Benchmarks

This mod includes the following benchmarks:

- **Public Access**: Identifies resources that are publicly accessible and may pose security risks.
- **Network Access**: Evaluates network configurations for security best practices.
- **Shared Access**: Monitors resource sharing to ensure it's limited to trusted entities.

## Contributing

If you have an idea for additional controls or just want to help maintain and extend this mod ([contribute on GitHub](https://github.com/turbot/steampipe-mod-gcp-perimeter)).

## License

This mod is licensed under the [Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0).

## References

- [GCP Security Best Practices](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#networking-security)
- [GCP Networking Documentation](https://cloud.google.com/vpc/docs/vpc)
- [GCP IAM Documentation](https://cloud.google.com/iam/docs)
- [GCP Resource Manager Documentation](https://cloud.google.com/resource-manager/docs) 