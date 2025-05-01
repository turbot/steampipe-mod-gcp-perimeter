benchmark "public_access" {
  title         = "Public Access"
  description   = "Resources should not be publicly accessible unless explicitly required."
  documentation = file("./perimeter/docs/public_access.md")

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })

  children = [
    control.storage_bucket_public_access,
    control.compute_instance_public_ip,
    control.cloud_sql_public_ip
  ]
}

control "storage_bucket_public_access" {
  title         = "Storage buckets should not be publicly accessible"
  description   = "Cloud Storage buckets should not grant public access to prevent unauthorized data exposure."
  documentation = file("./perimeter/docs/storage_bucket_public_access.md")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Storage"
  })

  sql = <<-EOQ
    select
      self_link as resource,
      case
        when iam_policy -> 'bindings' @> '[{"members": ["allUsers"]}]'::jsonb then 'alarm'
        when iam_policy -> 'bindings' @> '[{"members": ["allAuthenticatedUsers"]}]'::jsonb then 'alarm'
        else 'ok'
      end as status,
      case
        when iam_policy -> 'bindings' @> '[{"members": ["allUsers"]}]'::jsonb then 'Bucket grants public access to allUsers'
        when iam_policy -> 'bindings' @> '[{"members": ["allAuthenticatedUsers"]}]'::jsonb then 'Bucket grants public access to allAuthenticatedUsers'
        else 'Bucket does not grant public access'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      gcp_storage_bucket;
  EOQ
}

control "compute_instance_public_ip" {
  title         = "Compute instances should not have public IPs unless required"
  description   = "Compute Engine instances should not have public IP addresses unless they need to be publicly accessible."
  documentation = file("./perimeter/docs/compute_instance_public_ip.md")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })

  sql = <<-EOQ
    select
      self_link as resource,
      case
        when network_interfaces[0] -> 'accessConfigs' is not null then 'alarm'
        else 'ok'
      end as status,
      case
        when network_interfaces[0] -> 'accessConfigs' is not null then 'Instance has a public IP address'
        else 'Instance does not have a public IP address'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      gcp_compute_instance;
  EOQ
}

control "cloud_sql_public_ip" {
  title         = "Cloud SQL instances should not be publicly accessible"
  description   = "Cloud SQL instances should not have public IP addresses unless required for specific use cases."
  documentation = file("./perimeter/docs/cloud_sql_public_ip.md")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/SQL"
  })

  sql = <<-EOQ
    select
      self_link as resource,
      case
        when ip_configuration ->> 'ipv4Enabled' = 'true' then 'alarm'
        else 'ok'
      end as status,
      case
        when ip_configuration ->> 'ipv4Enabled' = 'true' then 'Instance has public IP enabled'
        else 'Instance does not have public IP enabled'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      gcp_sql_database_instance;
  EOQ
} 