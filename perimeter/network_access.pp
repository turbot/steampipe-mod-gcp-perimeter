benchmark "network_access" {
  title         = "Network Access"
  description   = "Resources should not be exposed to the internet through VPC settings, firewall rules, or public IP addresses."
  documentation = file("./perimeter/docs/network_access.md")
  children = [
    benchmark.firewall_access,
    benchmark.network_general_access,
    benchmark.public_ips,
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
    control.cloud_run_service_public_ingress_enabled,
    control.kubernetes_cluster_master_authorized_networks,
    control.kubernetes_cluster_network_policy,
    control.redis_instance_authorized_network,
    control.sql_database_instance_authorized_networks,
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "cloud_run_service_public_ingress_enabled" {
  title       = "Cloud Run service allowing public ingress from all sources"
  description = "Detect when a Cloud Run service allows ingress from all sources by using the ALL ingress setting. This exposes the service to the public internet and increases the risk of unauthorized access."

  sql = <<-EOQ
    select
      name as resource,
      case
        when ingress = 'INGRESS_TRAFFIC_INTERNAL_ONLY'
          or ingress = 'INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER' then 'ok'
        else 'alarm'
      end as status,
      case
        when ingress = 'INGRESS_TRAFFIC_INTERNAL_ONLY' then title || ' only allows internal traffic.'
        when ingress = 'INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER' then title || ' allows internal and load balancer traffic.'
        else title || ' allows unrestricted ingress access.'
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

control "sql_database_instance_authorized_networks" {
  title       = "Cloud SQL database instances should restrict authorized networks"
  description = "Cloud SQL database instances should not allow access from 0.0.0.0/0 through authorized networks configuration and should have private IP enabled."

  sql = <<-EOQ
    with authorized_networks as (
      select
        self_link,
        title,
        a ->> 'value' as network
      from
        gcp_sql_database_instance,
        jsonb_array_elements(ip_configuration -> 'authorizedNetworks') as a
      where
        ip_configuration -> 'authorizedNetworks' is not null
    )
    select
      i.self_link as resource,
      case
        when ip_configuration ->> 'ipv4Enabled' = 'false' then 'ok'
        when a.network = '0.0.0.0/0' then 'alarm'
        else 'ok'
      end as status,
      case
        when ip_configuration ->> 'ipv4Enabled' = 'false' then i.title || ' has public IP disabled.'
        when a.network = '0.0.0.0/0' then i.title || ' allows access from 0.0.0.0/0.'
        else i.title || ' has restricted network access.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      gcp_sql_database_instance as i
      left join authorized_networks as a on a.self_link = i.self_link;
  EOQ

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/SQL"
  })
}

control "kubernetes_cluster_master_authorized_networks" {
  title       = "GKE cluster should restrict authorized networks"
  description = "GKE clusters should have master authorized networks enabled and should not allow access from 0.0.0.0/0."

  sql = <<-EOQ
    with master_networks as (
      select
        self_link,
        title,
        c ->> 'cidrBlock' as cidr_block
      from
        gcp_kubernetes_cluster,
        jsonb_array_elements(master_authorized_networks_config -> 'cidrBlocks') as c
      where
        master_authorized_networks_config is not null
        and master_authorized_networks_config ->> 'enabled' = 'true'
    )
    select
      c.self_link as resource,
      case
        when master_authorized_networks_config is null then 'alarm'
        when master_authorized_networks_config ->> 'enabled' != 'true' then 'alarm'
        when n.cidr_block = '0.0.0.0/0' then 'alarm'
        else 'ok'
      end as status,
      case
        when master_authorized_networks_config is null then c.title || ' has no master authorized networks configuration.'
        when master_authorized_networks_config ->> 'enabled' != 'true' then c.title || ' has master authorized networks disabled.'
        when n.cidr_block = '0.0.0.0/0' then c.title || ' allows access from 0.0.0.0/0.'
        else c.title || ' has restricted master access.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      gcp_kubernetes_cluster as c
      left join master_networks as n on n.self_link = c.self_link;
  EOQ

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/GKE"
  })
}

control "kubernetes_cluster_network_policy" {
  title       = "GKE clusters should enable network policy"
  description = "GKE clusters should have network policy enabled to control pod-to-pod communication through network policy rules."

  sql = <<-EOQ
    select
      self_link as resource,
      case
        when network_policy ->> 'enabled' = 'true' then 'ok'
        else 'alarm'
      end as status,
      case
        when network_policy ->> 'enabled' = 'true' then title || ' has network policy enabled.'
        else title || ' has network policy disabled.'
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

control "redis_instance_authorized_network" {
  title       = "Memorystore Redis instances should restrict authorized networks"
  description = "Memorystore Redis instances should be configured with private service access and should not use the default network."

  sql = <<-EOQ
    select
      name as resource,
      case
        when authorized_network is null then 'alarm'
        when authorized_network = 'projects/' || project || '/global/networks/default' then 'alarm'
        when connect_mode != 1 then 'alarm'
        else 'ok'
      end as status,
      case
        when authorized_network is null then title || ' has no authorized network configured.'
        when authorized_network = 'projects/' || project || '/global/networks/default' then title || ' is using default network.'
        when connect_mode != 1 then title || ' is not using private service access.'
        else title || ' has secure network configuration.'
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
    control.vpc_firewall_restrict_ingress_common_ports,
    control.vpc_firewall_restrict_ingress_tcp_udp_all,
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "vpc_firewall_restrict_ingress_tcp_udp_all" {
  title       = "VPC firewall rules should restrict ingress TCP and UDP access from 0.0.0.0/0"
  description = "This control checks if any firewall rules allow inbound TCP or UDP access from 0.0.0.0/0."

  sql = <<-EOQ
    with firewall_tcp_udp as (
      select
        self_link,
        title,
        direction,
        source_ranges,
        a ->> 'protocol' as protocol
      from
        gcp_compute_firewall,
        jsonb_array_elements(allowed) as a
      where
        direction = 'INGRESS'
        and source_ranges @> '["0.0.0.0/0"]'
        and (
          a ->> 'protocol' in ('tcp', 'udp', 'all')
        )
    )
    select
      f.self_link as resource,
      case
        when p.self_link is null then 'ok'
        else 'alarm'
      end as status,
      case
        when p.self_link is null then f.title || ' does not allow TCP/UDP access from 0.0.0.0/0.'
        else f.title || ' allows TCP/UDP access from 0.0.0.0/0.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      gcp_compute_firewall as f
      left join firewall_tcp_udp as p on p.self_link = f.self_link;
  EOQ

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "vpc_firewall_restrict_ingress_common_ports" {
  title       = "VPC firewall rules should restrict ingress access to common ports from 0.0.0.0/0 and ::/0"
  description = "This control checks if any firewall rules allow inbound access from 0.0.0.0/0 or ::/0 to common sensitive ports including SSH (22), RDP (3389), MySQL (3306), PostgreSQL (5432), MongoDB (27017), MSSQL (1433), FTP (20,21), Telnet (23), SMTP (25), SMB (445), IMAP (143), SQL Server (1433-1434), Kibana (5601), Elasticsearch (9200-9300), and others."

  sql = <<-EOQ
    with firewall_common_ports as (
      select
        self_link,
        title,
        direction,
        source_ranges,
        a -> 'ports' as ports,
        a ->> 'protocol' as protocol
      from
        gcp_compute_firewall,
        jsonb_array_elements(allowed) as a
      where
        direction = 'INGRESS'
        and (
          source_ranges @> '["0.0.0.0/0"]'
          or source_ranges @> '["::/0"]'
        )
        and (
          a ->> 'protocol' = 'all'
          or (
            (
              -- SSH
              a -> 'ports' @> '["22"]'
              -- RDP
              or a -> 'ports' @> '["3389"]'
              -- MySQL
              or a -> 'ports' @> '["3306"]'
              -- PostgreSQL
              or a -> 'ports' @> '["5432"]'
              -- MongoDB
              or a -> 'ports' @> '["27017"]'
              -- MSSQL
              or a -> 'ports' @> '["1433"]'
              -- FTP
              or a -> 'ports' @> '["20"]'
              or a -> 'ports' @> '["21"]'
              -- Telnet
              or a -> 'ports' @> '["23"]'
              -- SMTP
              or a -> 'ports' @> '["25"]'
              -- SMB
              or a -> 'ports' @> '["445"]'
              -- POP3
              or a -> 'ports' @> '["110"]'
              -- RPC
              or a -> 'ports' @> '["135"]'
              -- IMAP
              or a -> 'ports' @> '["143"]'
              -- SQL Server Browser
              or a -> 'ports' @> '["1434"]'
              -- VNC
              or a -> 'ports' @> '["5500"]'
              -- Kibana
              or a -> 'ports' @> '["5601"]'
              -- HTTP Alt
              or a -> 'ports' @> '["8080"]'
              -- Elasticsearch
              or a -> 'ports' @> '["9200"]'
              or a -> 'ports' @> '["9300"]'
            )
          )
        )
    )
    select
      f.self_link as resource,
      case
        when p.self_link is null then 'ok'
        else 'alarm'
      end as status,
      case
        when p.self_link is null then f.title || ' does not allow access to common ports from 0.0.0.0/0 or ::/0.'
        else f.title || ' allows access to common ports from 0.0.0.0/0 or ::/0.'
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
    control.cloudfunction_function_publicly_accessible,
    control.cloud_run_not_publicly_accessible,
    control.cloud_sql_not_publicly_accessible,
    control.compute_instance_not_publicly_accessible,
    control.gke_cluster_not_publicly_accessible,
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "cloudfunction_function_publicly_accessible" {
  title       = "Cloud Functions should have a public IP address"
  description = "This control checks whether Cloud Functions have public access enabled."

  sql = <<-EOQ
    select
      self_link as resource,
      case
        when vpc_connector is not null
          and ingress_settings = 'ALLOW_INTERNAL_ONLY' then 'ok'
        else 'alarm'
      end as status,
      case
        when vpc_connector is not null
          and ingress_settings = 'ALLOW_INTERNAL_ONLY' then title || ' not publicly accessible.'
        else title || ' publicly accessible.'
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

control "cloud_run_not_publicly_accessible" {
  title       = "Cloud Run services should not have a public IP address"
  description = "This control checks whether Cloud Run services have public access enabled."

  sql = <<-EOQ
    select
      name as resource,
      case
        when template -> 'spec' -> 'vpcAccess' is not null
          and ingress = 'INGRESS_TRAFFIC_INTERNAL_ONLY' then 'ok'
        else 'alarm'
      end as status,
      case
        when template -> 'spec' -> 'vpcAccess' is not null
          and ingress = 'INGRESS_TRAFFIC_INTERNAL_ONLY' then title || ' not publicly accessible.'
        else title || ' publicly accessible.'
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

control "cloud_sql_not_publicly_accessible" {
  title       = "Cloud SQL instances should not have a public IP address"
  description = "This control checks whether Cloud SQL instances have public access enabled."

  sql = <<-EOQ
    select
      self_link as resource,
      case
        when ip_configuration ->> 'ipv4Enabled' = 'true' then 'alarm'
        else 'ok'
      end as status,
      case
        when ip_configuration ->> 'ipv4Enabled' = 'true' then title || ' has public access enabled.'
        else title || ' does not have public access enabled.'
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

control "compute_instance_not_publicly_accessible" {
  title       = "Compute instances should not have a public IP address"
  description = "This control checks whether Compute Engine instances have public access enabled."

  sql = <<-EOQ
    select
      self_link as resource,
      case
        when network_interfaces[0] -> 'accessConfigs' is not null then 'alarm'
        else 'ok'
      end as status,
      case
        when network_interfaces[0] -> 'accessConfigs' is not null then title || ' has public access enabled.'
        else title || ' does not have public access enabled.'
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

control "gke_cluster_not_publicly_accessible" {
  title       = "GKE clusters should not have a public IP address"
  description = "This control checks whether GKE clusters have public access enabled."

  sql = <<-EOQ
    select
      self_link as resource,
      case
        when node_config -> 'metadata' ->> 'disable-legacy-endpoints' = 'true'
          and private_cluster_config ->> 'enablePrivateNodes' = 'true' then 'ok'
        else 'alarm'
      end as status,
      case
        when node_config -> 'metadata' ->> 'disable-legacy-endpoints' = 'true'
          and private_cluster_config ->> 'enablePrivateNodes' = 'true' then title || ' nodes do not have public access.'
        else title || ' nodes have public access.'
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