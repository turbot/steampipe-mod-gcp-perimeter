benchmark "iam_policy_public_access" {
  title         = "IAM Policy Public Access"
  description   = "Resources should not be publicly accessible through IAM policies as they could expose sensitive data to bad actors."
  documentation = file("./perimeter/docs/iam_policy_public_access.md")
  children = [
    control.bigquery_dataset_policy_prohibit_public_access,
    control.cloud_run_service_policy_prohibit_public_access,
    control.compute_image_policy_prohibit_public_access,
    control.kms_key_policy_prohibit_public_access,
    control.pubsub_snapshot_policy_prohibit_public_access,
    control.pubsub_subscription_policy_prohibit_public_access,
    control.pubsub_topic_policy_prohibit_public_access,
    control.storage_bucket_policy_prohibit_public_access
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
        when (r.iam_policy -> 'bindings') is null then 'skip'
        when p.__ARN_COLUMN__ is null then 'ok'
        else 'alarm'
      end as status,
      case
        when (r.iam_policy -> 'bindings') is null then title || ' does not have a defined IAM policy.'
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

control "storage_bucket_policy_prohibit_public_access" {
  title       = "Storage bucket policy should prohibit public access"
  description = "This control checks whether Cloud Storage bucket policy allows public access through allUsers or allAuthenticatedUsers."
  sql         = replace(replace(local.iam_policy_public_sql, "__TABLE_NAME__", "gcp_storage_bucket"), "__ARN_COLUMN__", "self_link")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Storage"
  })
}

control "pubsub_topic_policy_prohibit_public_access" {
  title       = "Pub/Sub topic policy should prohibit public access"
  description = "This control checks whether Pub/Sub topic policy allows public access through allUsers or allAuthenticatedUsers."
  sql         = replace(replace(local.iam_policy_public_sql, "__TABLE_NAME__", "gcp_pubsub_topic"), "__ARN_COLUMN__", "name")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/PubSub"
  })
}

control "pubsub_subscription_policy_prohibit_public_access" {
  title       = "Pub/Sub subscription policy should prohibit public access"
  description = "This control checks whether Pub/Sub subscription policy allows public access through allUsers or allAuthenticatedUsers."
  sql         = replace(replace(local.iam_policy_public_sql, "__TABLE_NAME__", "gcp_pubsub_subscription"), "__ARN_COLUMN__", "name")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/PubSub"
  })
}

control "pubsub_snapshot_policy_prohibit_public_access" {
  title       = "Pub/Sub snapshot policy should prohibit public access"
  description = "This control checks whether Pub/Sub snapshot policy allows public access through allUsers or allAuthenticatedUsers."
  sql         = replace(replace(local.iam_policy_public_sql, "__TABLE_NAME__", "gcp_pubsub_snapshot"), "__ARN_COLUMN__", "name")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/PubSub"
  })
}

control "kms_key_policy_prohibit_public_access" {
  title       = "KMS key policy should prohibit public access"
  description = "This control checks whether Cloud KMS key policy allows public access through allUsers or allAuthenticatedUsers."
  sql         = replace(replace(local.iam_policy_public_sql, "__TABLE_NAME__", "gcp_kms_key"), "__ARN_COLUMN__", "self_link")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/KMS"
  })
}

control "cloud_run_service_policy_prohibit_public_access" {
  title       = "Cloud Run service policy should prohibit public access"
  description = "This control checks whether Cloud Run service IAM policy allows public access through allUsers or allAuthenticatedUsers."
  sql         = replace(replace(local.iam_policy_public_sql, "__TABLE_NAME__", "gcp_cloud_run_service"), "__ARN_COLUMN__", "self_link")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudRun"
  })
}

control "bigquery_dataset_policy_prohibit_public_access" {
  title       = "BigQuery dataset policy should prohibit public access"
  description = "This control checks whether BigQuery dataset access settings allow public access through allUsers or allAuthenticatedUsers."

  sql = <<-EOQ
    with public_access as (
      select
        self_link,
        count(*) as access_count
      from
        gcp_bigquery_dataset,
        jsonb_array_elements(access) as a
      where
        a ->> 'iamMember' in ('allUsers', 'allAuthenticatedUsers')
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

control "compute_image_policy_prohibit_public_access" {
  title       = "Compute image policy should prohibit public access"
  description = "This control checks whether Compute image IAM policy allows public access through allUsers or allAuthenticatedUsers."
  sql         = replace(replace(local.iam_policy_public_sql, "__TABLE_NAME__", "gcp_compute_image"), "__ARN_COLUMN__", "name")

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}
