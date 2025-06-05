benchmark "network_access" {
  title         = "Network Access"
  description   = "Resources should not be exposed to the internet through network settings, firewall rules, or public IP addresses."
  documentation = file("./perimeter/docs/network_access.md")
  children = [
    benchmark.network_general_access,
    benchmark.firewall_access,
    benchmark.public_ips
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "network_general_access" {
  title         = "Network General Access"
  description   = "Resources should follow general best practices to safeguard from exposure to public access."
  documentation = file("./perimeter/docs/network_general_access.md")
  children = [
    control.cloud_function_vpc_connector,
    control.cloud_run_vpc_connector,
    control.cloud_sql_instance_private_ip,
    control.gke_cluster_private_nodes,
    control.memorystore_instance_private_ip
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "cloud_function_vpc_connector" {
  title       = "Cloud Functions should use VPC connectors"
  description = "Cloud Functions should be configured with VPC connectors to ensure secure communication with other resources."

  sql = <<-EOQ
    select
      self_link as resource,
      case
        when vpc_connector is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when vpc_connector is not null then title || ' uses VPC connector.'
        else title || ' does not use VPC connector.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      gcp_cloudfunctions_function;
  EOQ

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudFunctions"
  })
}

control "cloud_run_vpc_connector" {
  title       = "Cloud Run services should use VPC connectors"
  description = "Cloud Run services should be configured with VPC connectors to ensure secure communication with other resources."

  sql = <<-EOQ
    select
      name as resource,
      case
        when template -> 'spec' -> 'vpcAccess' ->> 'connector' is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when template -> 'spec' -> 'vpcAccess' ->> 'connector' is not null then title || ' uses VPC connector.'
        else title || ' does not use VPC connector.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      gcp_cloud_run_service;
  EOQ

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudRun"
  })
}

control "cloud_sql_instance_private_ip" {
  title       = "Cloud SQL instances should use private IP"
  description = "Cloud SQL instances should be configured to use private IP to ensure secure access within the VPC."

  sql = <<-EOQ
    select
      self_link as resource,
      case
        when ip_configuration -> 'ipv4Enabled' = 'false' then 'ok'
        else 'alarm'
      end as status,
      case
        when ip_configuration -> 'ipv4Enabled' = 'false' then title || ' uses private IP.'
        else title || ' uses public IP.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      gcp_sql_database_instance;
  EOQ

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/SQL"
  })
}

control "gke_cluster_private_nodes" {
  title       = "GKE clusters should use private nodes"
  description = "GKE clusters should be configured with private nodes to ensure workloads are not exposed to the internet."

  sql = <<-EOQ
    select
      self_link as resource,
      case
        when private_cluster_config -> 'enablePrivateNodes' = 'true' then 'ok'
        else 'alarm'
      end as status,
      case
        when private_cluster_config -> 'enablePrivateNodes' = 'true' then title || ' uses private nodes.'
        else title || ' does not use private nodes.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      gcp_kubernetes_cluster;
  EOQ

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/GKE"
  })
}

control "memorystore_instance_private_ip" {
  title       = "Memorystore instances should use private IP"
  description = "Memorystore instances should be configured to use private IP to ensure secure access within the VPC."

  sql = <<-EOQ
    select
      name as resource,
      case
        when authorized_network = 'projects/' || project || '/global/networks/default' then 'ok'
        else 'alarm'
      end as status,
      case
        when authorized_network = 'projects/' || project || '/global/networks/default' then title || ' uses private IP.'
        else title || ' not configured for private IP only.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      gcp_redis_instance;
  EOQ

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Memorystore"
  })
}

benchmark "firewall_access" {
  title         = "Firewall Access"
  description   = "Firewall rules should restrict ingress access to certain IP addresses and ports to prevent unwanted access."
  documentation = file("./perimeter/docs/firewall_access.md")
  children = [
    control.firewall_rule_restrict_ingress_all,
    control.firewall_rule_restrict_ingress_common_ports
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "firewall_rule_restrict_ingress_all" {
  title       = "VPC firewall rules should restrict ingress access from 0.0.0.0/0"
  description = "This control checks if any firewall rules allow inbound access from 0.0.0.0/0."

  sql = <<-EOQ
    select
      self_link as resource,
      case
        when direction = 'INGRESS' 
          and source_ranges ? '0.0.0.0/0' then 'alarm'
        else 'ok'
      end as status,
      case
        when direction = 'INGRESS' 
          and source_ranges ? '0.0.0.0/0' then title || ' allows ingress from 0.0.0.0/0.'
        else title || ' does not allow ingress from 0.0.0.0/0.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      gcp_compute_firewall;
  EOQ

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "firewall_rule_restrict_ingress_common_ports" {
  title       = "VPC firewall rules should restrict ingress access on common ports from 0.0.0.0/0"
  description = "This control checks if any firewall rules allow inbound access from 0.0.0.0/0 to common ports (e.g., 22, 3389, 3306)."

  sql = <<-EOQ
    with firewall_common_ports as (
      select
        self_link,
        title,
        direction,
        source_ranges,
        a -> 'ports' as ports
      from
        gcp_compute_firewall,
        jsonb_array_elements(allowed) as a
      where
        direction = 'INGRESS'
        and source_ranges ? '0.0.0.0/0'
        and (
          a -> 'ports' ? '22'
          or a -> 'ports' ? '3389'
          or a -> 'ports' ? '3306'
          or a -> 'ports' ? '1433'
          or a -> 'ports' ? '5432'
          or a -> 'ports' ? '27017'
        )
    )
    select
      f.self_link as resource,
      case
        when p.self_link is null then 'ok'
        else 'alarm'
      end as status,
      case
        when p.self_link is null then f.title || ' does not allow ingress to common ports from 0.0.0.0/0.'
        else f.title || ' allows ingress to common ports from 0.0.0.0/0.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      gcp_compute_firewall as f
      left join firewall_common_ports as p on p.self_link = f.self_link;
  EOQ

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

benchmark "public_ips" {
  title         = "Public IPs"
  description   = "Resources should not have public IP addresses, as these can expose them to the internet."
  documentation = file("./perimeter/docs/public_ips.md")
  children = [
    control.compute_instance_no_public_ip,
    control.sql_instance_no_public_ip,
    control.gke_cluster_no_public_endpoint
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "compute_instance_no_public_ip" {
  title       = "Compute instances should not have public IP addresses"
  description = "This control checks whether Compute Engine instances have public IP addresses assigned."

  sql = <<-EOQ
    select
      self_link as resource,
      case
        when network_interfaces[0] -> 'accessConfigs' is not null then 'alarm'
        else 'ok'
      end as status,
      case
        when network_interfaces[0] -> 'accessConfigs' is not null then title || ' has public IP address.'
        else title || ' does not have public IP address.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      gcp_compute_instance;
  EOQ

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "sql_instance_no_public_ip" {
  title       = "Cloud SQL instances should not have public IP addresses"
  description = "This control checks whether Cloud SQL instances have public IP addresses enabled."

  sql = <<-EOQ
    select
      self_link as resource,
      case
        when ip_configuration ->> 'ipv4Enabled' = 'true' then 'alarm'
        else 'ok'
      end as status,
      case
        when ip_configuration ->> 'ipv4Enabled' = 'true' then title || ' has public IP enabled.'
        else title || ' does not have public IP enabled.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      gcp_sql_database_instance;
  EOQ

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/SQL"
  })
}

control "gke_cluster_no_public_endpoint" {
  title       = "GKE clusters should not have public endpoints"
  description = "This control checks whether GKE clusters have public endpoints enabled."

  sql = <<-EOQ
    select
      self_link as resource,
      case
        when private_cluster_config -> 'enablePrivateEndpoint' = 'true' then 'ok'
        else 'alarm'
      end as status,
      case
        when private_cluster_config -> 'enablePrivateEndpoint' = 'true' then title || ' has private endpoint only.'
        else title || ' has public endpoint enabled.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      gcp_kubernetes_cluster;
  EOQ

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/GKE"
  })
} 