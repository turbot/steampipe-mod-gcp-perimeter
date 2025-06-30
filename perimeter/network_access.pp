benchmark "network_access" {
  title         = "Network Access"
  description   = "Resources should not be exposed to the internet through VPC settings, firewall rules, or public IP addresses."
  documentation = file("./perimeter/docs/network_access.md")
  children = [
    benchmark.firewall_access,
    benchmark.public_network_access,
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
  description = "This control checks whether firewall rules allow inbound TCP or UDP access from 0.0.0.0/0 or ::/0 to prevent unrestricted access to resources."

  sql = <<-EOQ
    with firewall_tcp_udp as (
      select
        distinct self_link
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
          a ->> 'IPProtocol' in ('tcp', 'udp', 'all')
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
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "f.")}
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
        distinct self_link
      from
        gcp_compute_firewall,
        jsonb_array_elements(allowed) as a,
        jsonb_array_elements_text(a -> 'ports') as port
      where
        direction = 'INGRESS'
        and (
          source_ranges @> '["0.0.0.0/0"]'
          or source_ranges @> '["::/0"]'
        )
        and (
          a ->> 'IPProtocol' = 'all'
          or (
            port = '22'
            or (
              port like '%-%'
              and split_part(port, '-', 1) :: integer <= 22
              and split_part(port, '-', 2) :: integer >= 22
            )
            or port = '3389'
            or (
              port like '%-%'
              and split_part(port, '-', 1) :: integer <= 3389
              and split_part(port, '-', 2) :: integer >= 3389
            )
            or port = '3306'
            or (
              port like '%-%'
              and split_part(port, '-', 1) :: integer <= 3306
              and split_part(port, '-', 2) :: integer >= 3306
            )
            or port = '5432'
            or (
              port like '%-%'
              and split_part(port, '-', 1) :: integer <= 5432
              and split_part(port, '-', 2) :: integer >= 5432
            )
            or port = '27017'
            or (
              port like '%-%'
              and split_part(port, '-', 1) :: integer <= 27017
              and split_part(port, '-', 2) :: integer >= 27017
            )
            or port = '1433'
            or (
              port like '%-%'
              and split_part(port, '-', 1) :: integer <= 1433
              and split_part(port, '-', 2) :: integer >= 1433
            )
            or port = '20'
            or (
              port like '%-%'
              and split_part(port, '-', 1) :: integer <= 20
              and split_part(port, '-', 2) :: integer >= 20
            )
            or port = '21'
            or (
              port like '%-%'
              and split_part(port, '-', 1) :: integer <= 21
              and split_part(port, '-', 2) :: integer >= 21
            )
            or port = '23'
            or (
              port like '%-%'
              and split_part(port, '-', 1) :: integer <= 23
              and split_part(port, '-', 2) :: integer >= 23
            )
            or port = '25'
            or (
              port like '%-%'
              and split_part(port, '-', 1) :: integer <= 25
              and split_part(port, '-', 2) :: integer >= 25
            )
            or port = '445'
            or (
              port like '%-%'
              and split_part(port, '-', 1) :: integer <= 445
              and split_part(port, '-', 2) :: integer >= 445
            )
            or port = '110'
            or (
              port like '%-%'
              and split_part(port, '-', 1) :: integer <= 110
              and split_part(port, '-', 2) :: integer >= 110
            )
            or port = '135'
            or (
              port like '%-%'
              and split_part(port, '-', 1) :: integer <= 135
              and split_part(port, '-', 2) :: integer >= 135
            )
            or port = '143'
            or (
              port like '%-%'
              and split_part(port, '-', 1) :: integer <= 143
              and split_part(port, '-', 2) :: integer >= 143
            )
            or port = '1434'
            or (
              port like '%-%'
              and split_part(port, '-', 1) :: integer <= 1434
              and split_part(port, '-', 2) :: integer >= 1434
            )
            or port = '5500'
            or (
              port like '%-%'
              and split_part(port, '-', 1) :: integer <= 5500
              and split_part(port, '-', 2) :: integer >= 5500
            )
            or port = '5601'
            or (
              port like '%-%'
              and split_part(port, '-', 1) :: integer <= 5601
              and split_part(port, '-', 2) :: integer >= 5601
            )
            or port = '8080'
            or (
              port like '%-%'
              and split_part(port, '-', 1) :: integer <= 8080
              and split_part(port, '-', 2) :: integer >= 8080
            )
            or port = '9200'
            or (
              port like '%-%'
              and split_part(port, '-', 1) :: integer <= 9200
              and split_part(port, '-', 2) :: integer >= 9200
            )
            or port = '9300'
            or (
              port like '%-%'
              and split_part(port, '-', 1) :: integer <= 9300
              and split_part(port, '-', 2) :: integer >= 9300
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
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "f.")}
    from
      gcp_compute_firewall as f
      left join firewall_common_ports as p on p.self_link = f.self_link;
  EOQ

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

benchmark "public_network_access" {
  title         = "Public Network Access"
  description   = "Resources should not be publicly accessible through network configurations, as this can expose them to the internet."
  documentation = file("./perimeter/docs/public_network_access.md")
  children = [
    control.cloud_run_not_publicly_accessible,
    control.cloud_sql_not_publicly_accessible,
    control.cloudfunction_function_not_publicly_accessible,
    control.gke_cluster_master_authorized_networks_not_publicly_accessible,
    control.gke_cluster_nodes_not_publicly_accessible
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
  title       = "Cloud Run services should not be publicly accessible"
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
  title       = "Cloud SQL instances should not be publicly accessible"
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

control "gke_cluster_nodes_not_publicly_accessible" {
  title       = "GKE clusters nodes should not be publicly accessible"
  description = "This control checks whether GKE cluster worker nodes have private IP addresses only. Worker nodes with public IP addresses can be directly accessed from the internet, exposing node-level vulnerabilities."

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

control "gke_cluster_master_authorized_networks_not_publicly_accessible" {
  title       = "GKE cluster master authorized networks should not allow access from 0.0.0.0/0"
  description = "This control checks whether GKE cluster control plane (master) API server restricts access through master authorized networks. Clusters without authorized networks or those allowing 0.0.0.0/0 access expose the Kubernetes API server to the entire internet, potentially allowing unauthorized access to cluster."

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
        when n.cidr_block = '0.0.0.0/0' then 'alarm'
        else 'ok'
      end as status,
      case
        when master_authorized_networks_config is null then c.title || ' has no master authorized networks configuration.'
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
