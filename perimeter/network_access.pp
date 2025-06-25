benchmark "network_access" {
  title         = "Network Access"
  description   = "Resources should not be exposed to the internet through VPC settings, firewall rules, or public IP addresses."
  documentation = file("./perimeter/docs/network_access.md")
  children = [
    benchmark.firewall_access,
    benchmark.public_ips,
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
}


benchmark "firewall_access" {
  title         = "Firewall Access"
  description   = "Firewall rules should restrict ingress access to certain IP addresses and ports to prevent unwanted access."
  documentation = file("./perimeter/docs/firewall_access.md")
  children = [
    control.vpc_firewall_restrict_ingress_common_ports,
    control.vpc_firewall_restrict_ingress_tcp_udp_all
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "vpc_firewall_restrict_ingress_tcp_udp_all" {
  title       = "VPC firewall rules should restrict ingress TCP and UDP access from 0.0.0.0/0 and ::/0"
  description = "This control checks if any firewall rules allow inbound TCP or UDP access from 0.0.0.0/0 or ::/0."

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
        and (
          source_ranges @> '["0.0.0.0/0"]'
          or source_ranges @> '["::/0"]'
        )
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
        when p.self_link is null then f.title || ' does not allow TCP/UDP access from 0.0.0.0/0 or ::/0.'
        else f.title || ' allows TCP/UDP access from 0.0.0.0/0 or ::/0.'
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
    control.cloud_run_not_publicly_accessible,
    control.cloud_sql_not_publicly_accessible,
    control.cloudfunction_function_not_publicly_accessible,
    control.gke_cluster_not_publicly_accessible
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "cloudfunction_function_not_publicly_accessible" {
  title       = "Cloud Functions should not be publicly accessible"
  description = "This control checks whether Cloud Functions have public access disabled and are configured to only allow internal traffic."

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
        when ingress = 'INGRESS_TRAFFIC_ALL' then 'alarm'
        else 'ok'
      end as status,
      case
        when ingress = 'INGRESS_TRAFFIC_ALL' then title || ' publicly accessible.'
        else title || ' not publicly accessible.'
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



control "gke_cluster_not_publicly_accessible" {
  title       = "GKE clusters should not have a public IP address"
  description = "This control checks whether GKE clusters have public access enabled."

  sql = <<-EOQ
    select
      self_link as resource,
      case
        when private_cluster_config ->> 'enablePrivateNodes' = 'true' or network_config ->> 'DefaultEnablePrivateNodes' = 'true' then 'ok'
        else 'alarm'
      end as status,
      case
        when private_cluster_config ->> 'enablePrivateNodes' = 'true' or network_config ->> 'DefaultEnablePrivateNodes' = 'true' then title || ' nodes do not have public access.'
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