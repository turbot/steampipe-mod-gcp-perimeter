benchmark "iam_policy_public_access" {
  title         = "IAM Policy Public Access"
  description   = "Resources should not be publicly accessible through IAM policies as they could expose sensitive data to bad actors."
  documentation = file("./perimeter/docs/iam_policy_public_access.md")
  children = [
    control.bigquery_dataset_policy_public_access,
    control.bigtable_instance_policy_public_access,
    control.billing_account_policy_public_access,
    control.cloud_function_policy_public_access,
    control.cloud_run_job_policy_public_access,
    control.cloud_run_service_policy_public_access,
    control.compute_disk_policy_public_access,
    control.compute_image_policy_public_access,
    control.compute_instance_policy_public_access,
    control.compute_node_group_policy_public_access,
    control.compute_node_template_policy_public_access,
    control.compute_resource_policy_public_access,
    control.compute_subnetwork_policy_public_access,
    control.kms_key_policy_public_access,
    control.kms_key_ring_policy_public_access,
    control.pubsub_snapshot_policy_public_access,
    control.pubsub_subscription_policy_public_access,
    control.pubsub_topic_policy_public_access,
    control.storage_bucket_policy_public_access,
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
}

locals {
  iam_policy_public_sql = <<EOQ
    with public_bindings as (
      select
        __ARN_COLUMN__,
        array_agg(distinct member) as public_members,
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
        ' binding(s) that allow public access: ' || array_to_string(p.public_members, ', ')
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      __TABLE_NAME__ as r
      left join public_bindings as p on p.__ARN_COLUMN__ = r.__ARN_COLUMN__
  EOQ
}

control "storage_bucket_policy_public_access" {
  title       = "Storage bucket policies should prohibit public access"
  description = "Check if Cloud Storage bucket policies allow public access through allUsers or allAuthenticatedUsers."
  sql         = replace(replace(local.iam_policy_public_sql, "__TABLE_NAME__", "gcp_storage_bucket"), "__ARN_COLUMN__", "self_link")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Storage"
  })
}

control "pubsub_topic_policy_public_access" {
  title       = "Pub/Sub topic policies should prohibit public access"
  description = "Check if Pub/Sub topic policies allow public access through allUsers or allAuthenticatedUsers."
  sql         = replace(replace(local.iam_policy_public_sql, "__TABLE_NAME__", "gcp_pubsub_topic"), "__ARN_COLUMN__", "name")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/PubSub"
  })
}

control "pubsub_subscription_policy_public_access" {
  title       = "Pub/Sub subscription policies should prohibit public access"
  description = "Check if Pub/Sub subscription policies allow public access through allUsers or allAuthenticatedUsers."
  sql         = replace(replace(local.iam_policy_public_sql, "__TABLE_NAME__", "gcp_pubsub_subscription"), "__ARN_COLUMN__", "name")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/PubSub"
  })
}

control "pubsub_snapshot_policy_public_access" {
  title       = "Pub/Sub snapshot policies should prohibit public access"
  description = "Check if Pub/Sub snapshot policies allow public access through allUsers or allAuthenticatedUsers."
  sql         = replace(replace(local.iam_policy_public_sql, "__TABLE_NAME__", "gcp_pubsub_snapshot"), "__ARN_COLUMN__", "name")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/PubSub"
  })
}

control "kms_key_policy_public_access" {
  title       = "KMS key policies should prohibit public access"
  description = "Check if Cloud KMS key policies allow public access through allUsers or allAuthenticatedUsers."
  sql         = replace(replace(local.iam_policy_public_sql, "__TABLE_NAME__", "gcp_kms_key"), "__ARN_COLUMN__", "self_link")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/KMS"
  })
}

control "kms_key_ring_policy_public_access" {
  title       = "KMS key ring policies should prohibit public access"
  description = "Check if Cloud KMS key ring policies allow public access through allUsers or allAuthenticatedUsers."
  sql         = replace(replace(local.iam_policy_public_sql, "__TABLE_NAME__", "gcp_kms_key_ring"), "__ARN_COLUMN__", "name")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/KMS"
  })
}

control "cloud_function_policy_public_access" {
  title       = "Cloud Function policies should prohibit public access"
  description = "Check if Cloud Function IAM policies allow public access through allUsers or allAuthenticatedUsers."
  sql         = replace(replace(local.iam_policy_public_sql, "__TABLE_NAME__", "gcp_cloudfunctions_function"), "__ARN_COLUMN__", "self_link")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudFunctions"
  })
}

control "cloud_run_service_policy_public_access" {
  title       = "Cloud Run service policies should prohibit public access"
  description = "Check if Cloud Run service IAM policies allow public access through allUsers or allAuthenticatedUsers."
  sql         = replace(replace(local.iam_policy_public_sql, "__TABLE_NAME__", "gcp_cloud_run_service"), "__ARN_COLUMN__", "self_link")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudRun"
  })
}

control "cloud_run_job_policy_public_access" {
  title       = "Cloud Run job policies should prohibit public access"
  description = "Check if Cloud Run job IAM policies allow public access through allUsers or allAuthenticatedUsers."
  sql         = replace(replace(local.iam_policy_public_sql, "__TABLE_NAME__", "gcp_cloud_run_job"), "__ARN_COLUMN__", "name")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudRun"
  })
}

control "bigquery_dataset_policy_public_access" {
  title       = "BigQuery dataset policies should prohibit public access"
  description = "Check if BigQuery dataset access settings allow public access through allUsers or allAuthenticatedUsers."

  sql = <<-EOQ
    with public_access as (
      select
        self_link,
        count(*) as access_count
      from
        gcp_bigquery_dataset,
        jsonb_array_elements(access) as a
      where
        a ->> 'specialGroup' in ('allUsers', 'allAuthenticatedUsers')
      group by
        self_link
    )
    select
      d.self_link as resource,
      case
        when p.self_link is null then 'ok'
        else 'alarm'
      end as status,
      case
        when p.self_link is null then d.title || ' does not allow public access.'
        else d.title || ' allows public access through ' || p.access_count || ' access entries.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      gcp_bigquery_dataset as d
      left join public_access as p on p.self_link = d.self_link;
  EOQ

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/BigQuery"
  })
}

control "bigtable_instance_policy_public_access" {
  title       = "Bigtable instance policies should prohibit public access"
  description = "Check if Bigtable instance IAM policies allow public access through allUsers or allAuthenticatedUsers."
  sql         = replace(replace(local.iam_policy_public_sql, "__TABLE_NAME__", "gcp_bigtable_instance"), "__ARN_COLUMN__", "name")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Bigtable"
  })
}

control "billing_account_policy_public_access" {
  title       = "Billing account policies should prohibit public access"
  description = "Check if billing account IAM policies allow public access through allUsers or allAuthenticatedUsers."
  sql         = replace(replace(local.iam_policy_public_sql, "__TABLE_NAME__", "gcp_billing_account"), "__ARN_COLUMN__", "name")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Billing"
  })
}

control "compute_disk_policy_public_access" {
  title       = "Compute disk policies should prohibit public access"
  description = "Check if Compute disk IAM policies allow public access through allUsers or allAuthenticatedUsers."
  sql         = replace(replace(local.iam_policy_public_sql, "__TABLE_NAME__", "gcp_compute_disk"), "__ARN_COLUMN__", "name")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_image_policy_public_access" {
  title       = "Compute image policies should prohibit public access"
  description = "Check if Compute image IAM policies allow public access through allUsers or allAuthenticatedUsers."
  sql         = replace(replace(local.iam_policy_public_sql, "__TABLE_NAME__", "gcp_compute_image"), "__ARN_COLUMN__", "name")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_instance_policy_public_access" {
  title       = "Compute instance policies should prohibit public access"
  description = "Check if Compute instance IAM policies allow public access through allUsers or allAuthenticatedUsers."
  sql         = replace(replace(local.iam_policy_public_sql, "__TABLE_NAME__", "gcp_compute_instance"), "__ARN_COLUMN__", "name")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_node_group_policy_public_access" {
  title       = "Compute node group policies should prohibit public access"
  description = "Check if Compute node group IAM policies allow public access through allUsers or allAuthenticatedUsers."
  sql         = replace(replace(local.iam_policy_public_sql, "__TABLE_NAME__", "gcp_compute_node_group"), "__ARN_COLUMN__", "name")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_node_template_policy_public_access" {
  title       = "Compute node template policies should prohibit public access"
  description = "Check if Compute node template IAM policies allow public access through allUsers or allAuthenticatedUsers."
  sql         = replace(replace(local.iam_policy_public_sql, "__TABLE_NAME__", "gcp_compute_node_template"), "__ARN_COLUMN__", "name")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_resource_policy_public_access" {
  title       = "Compute resource policies should prohibit public access"
  description = "Check if Compute resource IAM policies allow public access through allUsers or allAuthenticatedUsers."
  sql         = replace(replace(local.iam_policy_public_sql, "__TABLE_NAME__", "gcp_compute_resource_policy"), "__ARN_COLUMN__", "name")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_subnetwork_policy_public_access" {
  title       = "Compute subnetwork policies should prohibit public access"
  description = "Check if Compute subnetwork IAM policies allow public access through allUsers or allAuthenticatedUsers."
  sql         = replace(replace(local.iam_policy_public_sql, "__TABLE_NAME__", "gcp_compute_subnetwork"), "__ARN_COLUMN__", "name")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
} 