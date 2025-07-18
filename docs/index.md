# GCP Perimeter Mod

Run security controls across all your Google Cloud Platform projects to look for resources that are publicly accessible, have insecure network configurations, and check IAM policies for untrusted access.

<img src="https://raw.githubusercontent.com/turbot/steampipe-mod-gcp-perimeter/main/docs/images/gcp_perimeter_dashboard.png" width="50%" type="thumbnail"/>
<img src="https://raw.githubusercontent.com/turbot/steampipe-mod-gcp-perimeter/main/docs/images/gcp_perimeter_network_access_dashboard.png" width="50%" type="thumbnail"/>
<img src="https://raw.githubusercontent.com/turbot/steampipe-mod-gcp-perimeter/main/docs/images/gcp_perimeter_iam_policy_public_access_dashboard.png" width="50%" type="thumbnail"/>
<img src="https://raw.githubusercontent.com/turbot/steampipe-mod-gcp-perimeter/main/docs/images/gcp_perimeter_iam_policy_shared_access_dashboard.png" width="50%" type="thumbnail"/>
<img src="https://raw.githubusercontent.com/turbot/steampipe-mod-gcp-perimeter/main/docs/images/gcp_perimeter_network_access_console.png" width="50%" type="thumbnail"/>

## Documentation

- **[Benchmarks and controls →](https://hub.powerpipe.io/mods/turbot/gcp_perimeter/controls)**
- **[Named queries →](https://hub.powerpipe.io/mods/turbot/gcp_perimeter/queries)**

## Getting Started

### Installation

Install Powerpipe (https://powerpipe.io/downloads), or use Brew:

```sh
brew install turbot/tap/powerpipe
```

This mod also requires [Steampipe](https://steampipe.io) with the [GCP plugin](https://hub.steampipe.io/plugins/turbot/gcp) as the data source. Install Steampipe (https://steampipe.io/downloads), or use Brew:

```sh
brew install turbot/tap/steampipe
steampipe plugin install gcp
```

Steampipe will automatically use your default GCP credentials. Optionally, you can [setup multiple projects](https://hub.steampipe.io/plugins/turbot/gcp#multi-project-connections) or [customize GCP credentials](https://hub.steampipe.io/plugins/turbot/gcp#configuring-gcp-credentials).

Finally, install the mod:

```sh
mkdir dashboards
cd dashboards
powerpipe mod init
powerpipe mod install github.com/turbot/steampipe-mod-gcp-perimeter
```

### Browsing Dashboards

Start Steampipe as the data source:

```sh
steampipe service start
```

Start the dashboard server:

```sh
powerpipe server
```

Browse and view your dashboards at **http://localhost:9033**.

### Running Checks in Your Terminal

Instead of running benchmarks in a dashboard, you can also run them within your terminal with the `powerpipe benchmark` command:

List available benchmarks:

```sh
powerpipe benchmark list
```

Run a benchmark:

```sh
powerpipe benchmark run gcp_perimeter.benchmark.iam_policy_shared_access
```

Run a specific control:

```sh
powerpipe control run gcp_perimeter.control.compute_disk_policy_shared_access
```

Different output formats are also available, for more information please see
[Output Formats](https://powerpipe.io/docs/reference/cli/benchmark#output-formats).

### Configure Variables

The benchmarks have [input variables](https://powerpipe.io/docs/build/mod-variables#input-variables) that can be configured to better match your environment and requirements. Each variable has a default defined in its source file, e.g., `perimeter/iam_policy_shared_access.pp`, but these can be overwritten in several ways:

It's easiest to setup your vars file, starting with the sample:

```sh
cp powerpipe.ppvars.example powerpipe.ppvars
vi powerpipe.ppvars
```

Alternatively you can pass variables on the command line:

```sh
powerpipe benchmark run gcp_perimeter.benchmark.iam_policy_shared_access --var='gcp_perimeter.trusted_users=["user1@example.com", "user2@example.com"]' --var='gcp_perimeter.trusted_groups=["group1@example.com", "group2@example.com"]' --var='gcp_perimeter.trusted_domains=["domain1.com", "domain2.com"]' --var='gcp_perimeter.trusted_service_accounts=["service-account1@example.com", "service-account2@example.com"]'
```

Or through environment variables:

```sh
export PP_VAR_trusted_users='["user1@example.com", "user2@example.com"]'
export PP_VAR_trusted_groups='["group1@example.com", "group2@example.com"]'
export PP_VAR_trusted_domains='["domain1.com", "domain2.com"]'
export PP_VAR_trusted_service_accounts='["service-account1@example.com", "service-account2@example.com"]'
powerpipe control run gcp_perimeter.control.compute_disk_policy_shared_access
```

These are only some of the ways you can set variables. For a full list, please see [Passing Input Variables](https://powerpipe.io/docs/build/mod-variables#passing-input-variables).

### Common and Tag Dimensions

The benchmark queries use common properties (like `project` and `location`) and labels that are defined in the form of a default list of strings in the `variables.pp` file. These properties can be overwritten in several ways:

It's easiest to setup your vars file, starting with the sample:

```sh
cp powerpipe.ppvars.example powerpipe.ppvars
vi powerpipe.ppvars
```

Alternatively you can pass variables on the command line:

```sh
powerpipe benchmark run gcp_perimeter.benchmark.iam_policy_public_access --var 'gcp_perimeter.common_dimensions=["project", "location"]'
```

Or through environment variables:

```sh
export PP_VAR_common_dimensions='["project", "location"]'
powerpipe control run gcp_perimeter.control.bigquery_dataset_policy_prohibit_public_access
```

## Open Source & Contributing

This repository is published under the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0). Please see our [code of conduct](https://github.com/turbot/.github/blob/main/CODE_OF_CONDUCT.md). We look forward to collaborating with you!

[Steampipe](https://steampipe.io) and [Powerpipe](https://powerpipe.io) are products produced from this open source software, exclusively by [Turbot HQ, Inc](https://turbot.com). They are distributed under our commercial terms. Others are allowed to make their own distribution of the software, but cannot use any of the Turbot trademarks, cloud services, etc. You can learn more in our [Open Source FAQ](https://turbot.com/open-source).

## Get Involved

**[Join #powerpipe on Slack →](https://turbot.com/community/join)**

Want to help but don't know where to start? Pick up one of the `help wanted` issues:

- [Powerpipe](https://github.com/turbot/powerpipe/labels/help%20wanted)
- [GCP Perimeter Mod](https://github.com/turbot/steampipe-mod-gcp-perimeter/labels/help%20wanted) 