benchmark "public_access" {
  title         = "Public Access"
  description   = "Resources should not be publicly accessible as they could expose sensitive data to bad actors."
  documentation = file("./perimeter/docs/public_access.md")
  children = [
    benchmark.public_access_settings
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "public_access_settings" {
  title         = "Public Access Settings"
  description   = "Resources should not be publicly accessible or exposed to the internet through configurations and settings."
  documentation = file("./perimeter/docs/public_access_settings.md")
  children = [
    control.storage_bucket_public_access,
    control.compute_instance_public_ip,
    control.cloud_sql_public_ip
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "storage_bucket_public_access" {
  title       = "Storage buckets should not be publicly accessible"
  description = "Cloud Storage buckets should not grant public access to prevent unauthorized data exposure."

  sql = <<-EOQ
    select
      self_link as resource,
      case
        when iam_policy -> 'bindings' @> '[{"members": ["allUsers"]}]'::jsonb then 'alarm'
        when iam_policy -> 'bindings' @> '[{"members": ["allAuthenticatedUsers"]}]'::jsonb then 'alarm'
        else 'ok'
      end as status,
      case
        when iam_policy -> 'bindings' @> '[{"members": ["allUsers"]}]'::jsonb then title || ' grants public access to allUsers.'
        when iam_policy -> 'bindings' @> '[{"members": ["allAuthenticatedUsers"]}]'::jsonb then title || ' grants public access to allAuthenticatedUsers.'
        else title || ' does not grant public access.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      gcp_storage_bucket;
  EOQ

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Storage"
  })
}

control "compute_instance_public_ip" {
  title       = "Compute instances should not have public IPs unless required"
  description = "Compute Engine instances should not have public IP addresses unless they need to be publicly accessible."

  sql = <<-EOQ
    select
      self_link as resource,
      case
        when network_interfaces[0] -> 'accessConfigs' is not null then 'alarm'
        else 'ok'
      end as status,
      case
        when network_interfaces[0] -> 'accessConfigs' is not null then title || ' has a public IP address.'
        else title || ' does not have a public IP address.'
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

control "cloud_sql_public_ip" {
  title       = "Cloud SQL instances should not be publicly accessible"
  description = "Cloud SQL instances should not have public IP addresses unless required for specific use cases."

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