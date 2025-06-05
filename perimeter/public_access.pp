benchmark "public_access" {
  title         = "Public Access"
  description   = "Resources should not be publicly accessible as they could expose sensitive data to bad actors."
  documentation = file("./perimeter/docs/public_access.md")
  children = [
    benchmark.public_access_settings,
    benchmark.resource_policy_public_access
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
    control.compute_instance_no_public_ip,
    control.gke_cluster_no_public_endpoint,
    control.sql_instance_no_public_ip
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "resource_policy_public_access" {
  title         = "Resource Policy Public Access"
  description   = "Resources should not be publicly accessible through statements in their IAM policies."
  documentation = file("./perimeter/docs/resource_policy_public_access.md")
  children = [
    control.storage_bucket_policy_public_access,
    control.pubsub_topic_policy_public_access,
    control.kms_key_policy_public_access,
    control.cloud_function_policy_public_access,
    control.cloud_run_service_policy_public_access
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
}

locals {
  resource_policy_public_sql = <<EOQ
    with public_bindings as (
      select
        __ARN_COLUMN__,
        count(*) as bindings_num
      from
        __TABLE_NAME__,
        jsonb_array_elements(iam_policy -> 'bindings') as binding,
        jsonb_array_elements_text(binding -> 'members') as member
      where
        member in ('allUsers', 'allAuthenticatedUsers')
      group by
        __ARN_COLUMN__
    )
    select
      r.__ARN_COLUMN__ as resource,
      case
        when r.iam_policy is null then 'info'
        when p.__ARN_COLUMN__ is null then 'ok'
        else 'alarm'
      end as status,
      case
        when r.iam_policy is null then title || ' does not have a defined IAM policy.'
        when p.__ARN_COLUMN__ is null then title || ' policy does not allow public access.'
        else title || ' policy contains ' || coalesce(p.bindings_num, 0) ||
        ' binding(s) that allow public access.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      __TABLE_NAME__ as r
      left join public_bindings as p on p.__ARN_COLUMN__ = r.__ARN_COLUMN__
  EOQ
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

control "gke_cluster_no_public_endpoint" {
  title       = "GKE clusters should not have public endpoints"
  description = "This control checks whether GKE clusters have public endpoints enabled."

  sql = <<-EOQ
    select
      self_link as resource,
      case
        when private_cluster_config ->> 'enablePrivateEndpoint' = 'true' 
          and private_cluster_config ->> 'privateEndpoint' is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when private_cluster_config ->> 'enablePrivateEndpoint' = 'true'
          and private_cluster_config ->> 'privateEndpoint' is not null then title || ' has private endpoint only.'
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

control "storage_bucket_policy_public_access" {
  title       = "Storage bucket policies should prohibit public access"
  description = "Check if Cloud Storage bucket policies allow public access."
  sql         = replace(replace(local.resource_policy_public_sql, "__TABLE_NAME__", "gcp_storage_bucket"), "__ARN_COLUMN__", "self_link")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Storage"
  })
}

control "pubsub_topic_policy_public_access" {
  title       = "Pub/Sub topic policies should prohibit public access"
  description = "Check if Pub/Sub topic policies allow public access."
  sql         = replace(replace(local.resource_policy_public_sql, "__TABLE_NAME__", "gcp_pubsub_topic"), "__ARN_COLUMN__", "name")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/PubSub"
  })
}

control "kms_key_policy_public_access" {
  title       = "KMS key policies should prohibit public access"
  description = "Check if Cloud KMS key policies allow public access."
  sql         = replace(replace(local.resource_policy_public_sql, "__TABLE_NAME__", "gcp_kms_key"), "__ARN_COLUMN__", "self_link")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/KMS"
  })
}

control "cloud_function_policy_public_access" {
  title       = "Cloud Function policies should prohibit public access"
  description = "Check if Cloud Function IAM policies allow public access."
  sql         = replace(replace(local.resource_policy_public_sql, "__TABLE_NAME__", "gcp_cloudfunctions_function"), "__ARN_COLUMN__", "self_link")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudFunctions"
  })
}

control "cloud_run_service_policy_public_access" {
  title       = "Cloud Run service policies should prohibit public access"
  description = "Check if Cloud Run service IAM policies allow public access."
  sql         = replace(replace(local.resource_policy_public_sql, "__TABLE_NAME__", "gcp_cloud_run_service"), "__ARN_COLUMN__", "self_link")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudRun"
  })
} 