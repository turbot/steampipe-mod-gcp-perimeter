benchmark "network_access" {
  title         = "Network Access"
  description   = "Resources should not have insecure network configurations that could expose sensitive data to potential attackers."
  documentation = file("./perimeter/docs/network_access.md")
  children = [
    benchmark.network_access_settings
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "network_access_settings" {
  title         = "Network Access Settings"
  description   = "Network configurations should follow security best practices to prevent unauthorized access."
  documentation = file("./perimeter/docs/network_access_settings.md")
  children = [
    control.firewall_allow_all_ingress,
    control.vpc_flow_logs_enabled,
    control.subnet_private_google_access
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "firewall_allow_all_ingress" {
  title       = "Firewall rules should not allow unrestricted ingress"
  description = "Firewall rules should not allow ingress from 0.0.0.0/0 to all ports."

  sql = <<-EOQ
    select
      self_link as resource,
      case
        when 
          direction = 'INGRESS'
          and source_ranges ?| array['0.0.0.0/0']
          and (
            allowed is null
            or allowed @> '[{"ports": ["0-65535"]}]'::jsonb
            or allowed @> '[{"ports": ["all"]}]'::jsonb
            or allowed @> '[{"ports": []}]'::jsonb
          )
        then 'alarm'
        else 'ok'
      end as status,
      case
        when 
          direction = 'INGRESS'
          and source_ranges ?| array['0.0.0.0/0']
          and (
            allowed is null
            or allowed @> '[{"ports": ["0-65535"]}]'::jsonb
            or allowed @> '[{"ports": ["all"]}]'::jsonb
            or allowed @> '[{"ports": []}]'::jsonb
          )
        then title || ' allows unrestricted ingress.'
        else title || ' does not allow unrestricted ingress.'
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

control "vpc_flow_logs_enabled" {
  title       = "VPC networks should have flow logs enabled"
  description = "VPC flow logs provide network traffic visibility and should be enabled for security monitoring."

  sql = <<-EOQ
    with network_subnets as (
      select
        n.self_link as network_self_link,
        n.name as network_name,
        split_part(n.self_link, 'projects/', 2) as project_id,
        'global' as location,
        count(s.self_link) as total_subnets,
        count(case when s.log_config_enable or s.enable_flow_logs then 1 end) as subnets_with_flow_logs
      from
        gcp_compute_network n
        left join gcp_compute_subnetwork s on s.network = n.self_link
      group by
        n.self_link,
        n.name
    )
    select
      network_self_link as resource,
      case
        when total_subnets = 0 then 'info'
        when total_subnets = subnets_with_flow_logs then 'ok'
        when subnets_with_flow_logs = 0 then 'alarm'
        else 'info'
      end as status,
      case
        when total_subnets = 0 then network_name || ' has no subnets.'
        when total_subnets = subnets_with_flow_logs then network_name || ' has flow logs enabled on all ' || total_subnets || ' subnet(s).'
        when subnets_with_flow_logs = 0 then network_name || ' has flow logs not enabled on any of the ' || total_subnets || ' subnet(s).'
        else network_name || ' has flow logs enabled on ' || subnets_with_flow_logs || ' out of ' || total_subnets || ' subnet(s).'
      end as reason,
      project_id,
      location
      ${local.tag_dimensions_sql}
    from
      network_subnets;
  EOQ

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "subnet_private_google_access" {
  title       = "Subnets should have Private Google Access enabled"
  description = "Private Google Access allows VMs to reach Google APIs and services without public IP addresses."

  sql = <<-EOQ
    select
      self_link as resource,
      case
        when private_ip_google_access then 'ok'
        else 'alarm'
      end as status,
      case
        when private_ip_google_access then title || ' has Private Google Access enabled.'
        else title || ' does not have Private Google Access enabled.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      gcp_compute_subnetwork;
  EOQ

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
} 