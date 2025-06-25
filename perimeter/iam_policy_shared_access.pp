# Variables for trusted principals
variable "trusted_users" {
  type        = list(string)
  default     = ["user1@example.com", "user2@example.com"]
  description = "A list of trusted Google Account emails that can be granted access to resources."
}

variable "trusted_groups" {
  type        = list(string)
  default     = ["admins@googlegroups.com", "developers@googlegroups.com"]
  description = "A list of trusted Google Groups that can be granted access to resources."
}

variable "trusted_service_accounts" {
  type        = list(string)
  default     = ["app-sa@project-id.iam.gserviceaccount.com"]
  description = "A list of trusted service accounts that can be granted access to resources."
}

variable "trusted_domains" {
  type        = list(string)
  default     = ["trusted-company.com", "trusted-partner.com"]
  description = "A list of trusted Google Workspace domains that can be granted access to resources."
}

benchmark "iam_policy_shared_access" {
  title         = "IAM Policy Shared Access"
  description   = "IAM policies should be carefully managed to prevent unintended sharing of resources with untrusted principals."
  documentation = file("./perimeter/docs/iam_policy_shared_access.md")
  children = [
    benchmark.iam_policy_shared_access_bigtable,
    benchmark.iam_policy_shared_access_billing,
    benchmark.iam_policy_shared_access_cloud_functions,
    benchmark.iam_policy_shared_access_cloud_run,
    benchmark.iam_policy_shared_access_compute,
    benchmark.iam_policy_shared_access_iam,
    benchmark.iam_policy_shared_access_kms,
    benchmark.iam_policy_shared_access_pubsub,
    benchmark.iam_policy_shared_access_storage
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "iam_policy_shared_access_compute" {
  title         = "Compute Engine IAM Policy Shared Access"
  description   = "Ensure Compute Engine resources have IAM policies that only grant access to trusted principals."
  documentation = file("./perimeter/docs/iam_policy_shared_access_compute.md")
  children = [
    control.compute_disk_policy_shared_with_trusted_domains,
    control.compute_disk_policy_shared_with_trusted_groups,
    control.compute_disk_policy_shared_with_trusted_service_accounts,
    control.compute_disk_policy_shared_with_trusted_users,
    control.compute_image_policy_shared_with_trusted_domains,
    control.compute_image_policy_shared_with_trusted_groups,
    control.compute_image_policy_shared_with_trusted_service_accounts,
    control.compute_image_policy_shared_with_trusted_users,
    control.compute_instance_policy_shared_with_trusted_domains,
    control.compute_instance_policy_shared_with_trusted_groups,
    control.compute_instance_policy_shared_with_trusted_service_accounts,
    control.compute_instance_policy_shared_with_trusted_users,
    control.compute_node_group_policy_shared_with_trusted_domains,
    control.compute_node_group_policy_shared_with_trusted_groups,
    control.compute_node_group_policy_shared_with_trusted_service_accounts,
    control.compute_node_group_policy_shared_with_trusted_users,
    control.compute_node_template_policy_shared_with_trusted_domains,
    control.compute_node_template_policy_shared_with_trusted_groups,
    control.compute_node_template_policy_shared_with_trusted_service_accounts,
    control.compute_node_template_policy_shared_with_trusted_users,
    control.compute_resource_policy_shared_with_trusted_domains,
    control.compute_resource_policy_shared_with_trusted_groups,
    control.compute_resource_policy_shared_with_trusted_service_accounts,
    control.compute_resource_policy_shared_with_trusted_users,
    control.compute_subnetwork_policy_shared_with_trusted_domains,
    control.compute_subnetwork_policy_shared_with_trusted_groups,
    control.compute_subnetwork_policy_shared_with_trusted_service_accounts,
    control.compute_subnetwork_policy_shared_with_trusted_users
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type    = "Benchmark"
    service = "GCP/Compute"
  })
}

benchmark "iam_policy_shared_access_storage" {
  title         = "Cloud Storage IAM Policy Shared Access"
  description   = "Ensure Cloud Storage resources have IAM policies that only grant access to trusted principals."
  documentation = file("./perimeter/docs/iam_policy_shared_access_storage.md")
  children = [
    control.storage_bucket_policy_shared_with_trusted_domains,
    control.storage_bucket_policy_shared_with_trusted_groups,
    control.storage_bucket_policy_shared_with_trusted_service_accounts,
    control.storage_bucket_policy_shared_with_trusted_users
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type    = "Benchmark"
    service = "GCP/Storage"
  })
}

benchmark "iam_policy_shared_access_iam" {
  title         = "IAM Service Account IAM Policy Shared Access"
  description   = "Ensure IAM service accounts have IAM policies that only grant access to trusted principals."
  documentation = file("./perimeter/docs/iam_policy_shared_access_iam.md")
  children = [
    control.iam_service_account_policy_shared_with_trusted_domains,
    control.iam_service_account_policy_shared_with_trusted_groups,
    control.iam_service_account_policy_shared_with_trusted_service_accounts,
    control.iam_service_account_policy_shared_with_trusted_users
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type    = "Benchmark"
    service = "GCP/IAM"
  })
}

benchmark "iam_policy_shared_access_kms" {
  title         = "Cloud KMS IAM Policy Shared Access"
  description   = "Ensure Cloud KMS resources have IAM policies that only grant access to trusted principals."
  documentation = file("./perimeter/docs/iam_policy_shared_access_kms.md")
  children = [
    control.kms_key_policy_shared_with_trusted_domains,
    control.kms_key_policy_shared_with_trusted_groups,
    control.kms_key_policy_shared_with_trusted_service_accounts,
    control.kms_key_policy_shared_with_trusted_users,
    control.kms_key_ring_policy_shared_with_trusted_domains,
    control.kms_key_ring_policy_shared_with_trusted_groups,
    control.kms_key_ring_policy_shared_with_trusted_service_accounts,
    control.kms_key_ring_policy_shared_with_trusted_users
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type    = "Benchmark"
    service = "GCP/KMS"
  })
}

benchmark "iam_policy_shared_access_pubsub" {
  title         = "Pub/Sub IAM Policy Shared Access"
  description   = "Ensure Pub/Sub resources have IAM policies that only grant access to trusted principals."
  documentation = file("./perimeter/docs/iam_policy_shared_access_pubsub.md")
  children = [
    control.pubsub_subscription_policy_shared_with_trusted_domains,
    control.pubsub_subscription_policy_shared_with_trusted_groups,
    control.pubsub_subscription_policy_shared_with_trusted_service_accounts,
    control.pubsub_subscription_policy_shared_with_trusted_users,
    control.pubsub_topic_policy_shared_with_trusted_domains,
    control.pubsub_topic_policy_shared_with_trusted_groups,
    control.pubsub_topic_policy_shared_with_trusted_service_accounts,
    control.pubsub_topic_policy_shared_with_trusted_users
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type    = "Benchmark"
    service = "GCP/PubSub"
  })
}

benchmark "iam_policy_shared_access_cloud_run" {
  title         = "Cloud Run IAM Policy Shared Access"
  description   = "Ensure Cloud Run resources have IAM policies that only grant access to trusted principals."
  documentation = file("./perimeter/docs/iam_policy_shared_access_cloud_run.md")
  children = [
    control.cloud_run_job_policy_shared_with_trusted_domains,
    control.cloud_run_job_policy_shared_with_trusted_groups,
    control.cloud_run_job_policy_shared_with_trusted_service_accounts,
    control.cloud_run_job_policy_shared_with_trusted_users,
    control.cloud_run_service_policy_shared_with_trusted_domains,
    control.cloud_run_service_policy_shared_with_trusted_groups,
    control.cloud_run_service_policy_shared_with_trusted_service_accounts,
    control.cloud_run_service_policy_shared_with_trusted_users
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type    = "Benchmark"
    service = "GCP/CloudRun"
  })
}

benchmark "iam_policy_shared_access_cloud_functions" {
  title         = "Cloud Functions IAM Policy Shared Access"
  description   = "Ensure Cloud Functions resources have IAM policies that only grant access to trusted principals."
  documentation = file("./perimeter/docs/iam_policy_shared_access_cloud_functions.md")
  children = [
    control.cloud_function_policy_shared_with_trusted_domains,
    control.cloud_function_policy_shared_with_trusted_groups,
    control.cloud_function_policy_shared_with_trusted_service_accounts,
    control.cloud_function_policy_shared_with_trusted_users
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type    = "Benchmark"
    service = "GCP/CloudFunctions"
  })
}

benchmark "iam_policy_shared_access_bigtable" {
  title         = "Bigtable IAM Policy Shared Access"
  description   = "Ensure Bigtable resources have IAM policies that only grant access to trusted principals."
  documentation = file("./perimeter/docs/iam_policy_shared_access_bigtable.md")
  children = [
    control.bigtable_instance_policy_shared_with_trusted_domains,
    control.bigtable_instance_policy_shared_with_trusted_groups,
    control.bigtable_instance_policy_shared_with_trusted_service_accounts,
    control.bigtable_instance_policy_shared_with_trusted_users
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type    = "Benchmark"
    service = "GCP/Bigtable"
  })
}

benchmark "iam_policy_shared_access_billing" {
  title         = "Billing IAM Policy Shared Access"
  description   = "Ensure billing resources have IAM policies that only grant access to trusted principals."
  documentation = file("./perimeter/docs/iam_policy_shared_access_billing.md")
  children = [
    control.billing_account_policy_shared_with_trusted_domains,
    control.billing_account_policy_shared_with_trusted_groups,
    control.billing_account_policy_shared_with_trusted_service_accounts,
    control.billing_account_policy_shared_with_trusted_users
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type    = "Benchmark"
    service = "GCP/Billing"
  })
}

locals {
  # SQL for checking user access
  iam_policy_shared_users_sql = <<EOQ
    with policy_analysis as (
      select
        __RESOURCE_COLUMN__ as resource_id,
        -- Count all user members
        count(*) filter (where member like 'user:%') as total_user_members,
        -- Count trusted user members
        count(*) filter (where 
          member like 'user:%' and split_part(member, 'user:', 2) = any(($1)::text[])
        ) as trusted_user_members,
        -- Collect untrusted user members (without prefix)
        array_agg(distinct split_part(member, 'user:', 2)) filter (where 
          member like 'user:%' and split_part(member, 'user:', 2) != all(($1)::text[])
        ) as untrusted_user_members
      from
        __TABLE_NAME__,
        jsonb_array_elements(iam_policy -> 'bindings') as binding,
        jsonb_array_elements_text(binding -> 'members') as member
      group by
        __RESOURCE_COLUMN__
    )
    select
      r.__RESOURCE_COLUMN__ as resource,
      case
        -- SKIP: When no user members exist
        when p.total_user_members = 0 or p.total_user_members is null then 'skip'
        -- OK: When all user members are trusted
        when p.untrusted_user_members is null then 'ok'
        -- ALARM: When there are untrusted user members
        else 'alarm'
      end as status,
      case
        when p.total_user_members = 0 or p.total_user_members is null then title || ' has no user members in IAM policy.'
        when p.untrusted_user_members is null then title || ' policy only grants access to trusted users (' || p.trusted_user_members || ' trusted users).'
        else title || ' policy grants access to ' || coalesce(array_length(p.untrusted_user_members, 1), 0) || ' untrusted user(s): ' || array_to_string(p.untrusted_user_members, ', ')
      end as reason,
      r.project,
      r.location
    from
      __TABLE_NAME__ as r
      left join policy_analysis as p on p.resource_id = r.__RESOURCE_COLUMN__
    where
      -- Only check resources where we have access to IAM policy
      r.iam_policy is not null;
  EOQ

  # SQL for checking group access
  iam_policy_shared_groups_sql = <<EOQ
    with policy_analysis as (
      select
        __RESOURCE_COLUMN__ as resource_id,
        -- Count all group members
        count(*) filter (where member like 'group:%') as total_group_members,
        -- Count trusted group members
        count(*) filter (where 
          member like 'group:%' and split_part(member, 'group:', 2) = any(($1)::text[])
        ) as trusted_group_members,
        -- Collect untrusted group members (without prefix)
        array_agg(distinct split_part(member, 'group:', 2)) filter (where 
          member like 'group:%' and split_part(member, 'group:', 2) != all(($1)::text[])
        ) as untrusted_group_members
      from
        __TABLE_NAME__,
        jsonb_array_elements(iam_policy -> 'bindings') as binding,
        jsonb_array_elements_text(binding -> 'members') as member
      group by
        __RESOURCE_COLUMN__
    )
    select
      r.__RESOURCE_COLUMN__ as resource,
      case
        -- SKIP: When no group members exist
        when p.total_group_members = 0 or p.total_group_members is null then 'skip'
        -- OK: When all group members are trusted
        when p.untrusted_group_members is null then 'ok'
        -- ALARM: When there are untrusted group members
        else 'alarm'
      end as status,
      case
        when p.total_group_members = 0 or p.total_group_members is null then title || ' has no group members in IAM policy.'
        when p.untrusted_group_members is null then title || ' policy only grants access to trusted groups (' || p.trusted_group_members || ' trusted groups).'
        else title || ' policy grants access to ' || coalesce(array_length(p.untrusted_group_members, 1), 0) || ' untrusted group(s): ' || array_to_string(p.untrusted_group_members, ', ')
      end as reason,
      r.project,
      r.location
    from
      __TABLE_NAME__ as r
      left join policy_analysis as p on p.resource_id = r.__RESOURCE_COLUMN__
    where
      -- Only check resources where we have access to IAM policy
      r.iam_policy is not null;
  EOQ

  # SQL for checking domain access
  iam_policy_shared_domains_sql = <<EOQ
    with policy_analysis as (
      select
        __RESOURCE_COLUMN__ as resource_id,
        -- Count all domain members
        count(*) filter (where member like 'domain:%') as total_domain_members,
        -- Count trusted domain members
        count(*) filter (where 
          member like 'domain:%' and split_part(member, 'domain:', 2) = any(($1)::text[])
        ) as trusted_domain_members,
        -- Collect untrusted domain members (without prefix)
        array_agg(distinct split_part(member, 'domain:', 2)) filter (where 
          member like 'domain:%' and split_part(member, 'domain:', 2) != all(($1)::text[])
        ) as untrusted_domain_members
      from
        __TABLE_NAME__,
        jsonb_array_elements(iam_policy -> 'bindings') as binding,
        jsonb_array_elements_text(binding -> 'members') as member
      group by
        __RESOURCE_COLUMN__
    )
    select
      r.__RESOURCE_COLUMN__ as resource,
      case
        -- SKIP: When no domain members exist
        when p.total_domain_members = 0 or p.total_domain_members is null then 'skip'
        -- OK: When all domain members are trusted
        when p.untrusted_domain_members is null then 'ok'
        -- ALARM: When there are untrusted domain members
        else 'alarm'
      end as status,
      case
        when p.total_domain_members = 0 or p.total_domain_members is null then title || ' has no domain members in IAM policy.'
        when p.untrusted_domain_members is null then title || ' policy only grants access to trusted domains (' || p.trusted_domain_members || ' trusted domains).'
        else title || ' policy grants access to ' || coalesce(array_length(p.untrusted_domain_members, 1), 0) || ' untrusted domain(s): ' || array_to_string(p.untrusted_domain_members, ', ')
      end as reason,
      r.project,
      r.location
    from
      __TABLE_NAME__ as r
      left join policy_analysis as p on p.resource_id = r.__RESOURCE_COLUMN__
    where
      -- Only check resources where we have access to IAM policy
      r.iam_policy is not null;
  EOQ

  # SQL for checking service account access
  iam_policy_shared_service_accounts_sql = <<EOQ
    with policy_analysis as (
      select
        __RESOURCE_COLUMN__ as resource_id,
        -- Count all service account members
        count(*) filter (where member like 'serviceAccount:%') as total_sa_members,
        -- Count trusted service account members
        count(*) filter (where 
          member like 'serviceAccount:%' and split_part(member, 'serviceAccount:', 2) = any(($1)::text[])
        ) as trusted_sa_members,
        -- Collect untrusted service account members (without prefix)
        array_agg(distinct split_part(member, 'serviceAccount:', 2)) filter (where 
          member like 'serviceAccount:%' and split_part(member, 'serviceAccount:', 2) != all(($1)::text[])
        ) as untrusted_sa_members
      from
        __TABLE_NAME__,
        jsonb_array_elements(iam_policy -> 'bindings') as binding,
        jsonb_array_elements_text(binding -> 'members') as member
      group by
        __RESOURCE_COLUMN__
    )
    select
      r.__RESOURCE_COLUMN__ as resource,
      case
        -- SKIP: When no service account members exist
        when p.total_sa_members = 0 or p.total_sa_members is null then 'skip'
        -- OK: When all service account members are trusted
        when p.untrusted_sa_members is null then 'ok'
        -- ALARM: When there are untrusted service account members
        else 'alarm'
      end as status,
      case
        when p.total_sa_members = 0 or p.total_sa_members is null then title || ' has no service account members in IAM policy.'
        when p.untrusted_sa_members is null then title || ' policy only grants access to trusted service accounts (' || p.trusted_sa_members || ' trusted service accounts).'
        else title || ' policy grants access to ' || coalesce(array_length(p.untrusted_sa_members, 1), 0) || ' untrusted service account(s): ' || array_to_string(p.untrusted_sa_members, ', ')
      end as reason,
      r.project,
      r.location
    from
      __TABLE_NAME__ as r
      left join policy_analysis as p on p.resource_id = r.__RESOURCE_COLUMN__
    where
      -- Only check resources where we have access to IAM policy
      r.iam_policy is not null;
  EOQ
}

# IAM Service Account Controls
control "iam_service_account_policy_shared_with_trusted_users" {
  title       = "IAM service account IAM policy should only grant access to trusted users"
  description = "This control checks whether service account IAM policy grants access to untrusted users."
  sql         = replace(replace(local.iam_policy_shared_users_sql, "__TABLE_NAME__", "gcp_service_account"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/IAM"
  })
}

control "iam_service_account_policy_shared_with_trusted_groups" {
  title       = "IAM service account IAM policy should only grant access to trusted groups"
  description = "This control checks whether service account IAM policy grants access to untrusted groups."
  sql         = replace(replace(local.iam_policy_shared_groups_sql, "__TABLE_NAME__", "gcp_service_account"), "__RESOURCE_COLUMN__", "name")

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/IAM"
  })
}

control "iam_service_account_policy_shared_with_trusted_domains" {
  title       = "IAM service account IAM policy should only grant access to trusted domains"
  description = "This control checks whether service account IAM policy grants access to untrusted domains."
  sql         = replace(replace(local.iam_policy_shared_domains_sql, "__TABLE_NAME__", "gcp_service_account"), "__RESOURCE_COLUMN__", "name")

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/IAM"
  })
}

control "iam_service_account_policy_shared_with_trusted_service_accounts" {
  title       = "IAM service account IAM policy should only grant access to trusted service accounts"
  description = "This control checks whether service account IAM policy grants access to untrusted service accounts."
  sql         = replace(replace(local.iam_policy_shared_service_accounts_sql, "__TABLE_NAME__", "gcp_service_account"), "__RESOURCE_COLUMN__", "name")

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/IAM"
  })
}

# Storage Bucket Controls
control "storage_bucket_policy_shared_with_trusted_users" {
  title       = "Storage bucket IAM policy should only grant access to trusted users"
  description = "This control checks whether Cloud Storage bucket IAM policy grants access to untrusted users."
  sql         = replace(replace(local.iam_policy_shared_users_sql, "__TABLE_NAME__", "gcp_storage_bucket"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Storage"
  })
}

control "storage_bucket_policy_shared_with_trusted_groups" {
  title       = "Storage bucket IAM policy should only grant access to trusted groups"
  description = "This control checks whether Cloud Storage bucket IAM policy grants access to untrusted groups."
  sql         = replace(replace(local.iam_policy_shared_groups_sql, "__TABLE_NAME__", "gcp_storage_bucket"), "__RESOURCE_COLUMN__", "name")

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Storage"
  })
}

control "storage_bucket_policy_shared_with_trusted_domains" {
  title       = "Storage bucket IAM policy should only grant access to trusted domains"
  description = "This control checks whether Cloud Storage bucket IAM policy grants access to untrusted domains."
  sql         = replace(replace(local.iam_policy_shared_domains_sql, "__TABLE_NAME__", "gcp_storage_bucket"), "__RESOURCE_COLUMN__", "name")

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Storage"
  })
}

control "storage_bucket_policy_shared_with_trusted_service_accounts" {
  title       = "Storage bucket IAM policy should only grant access to trusted service accounts"
  description = "This control checks whether Cloud Storage bucket IAM policy grants access to untrusted service accounts."
  sql         = replace(replace(local.iam_policy_shared_service_accounts_sql, "__TABLE_NAME__", "gcp_storage_bucket"), "__RESOURCE_COLUMN__", "name")

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Storage"
  })
}

control "compute_disk_policy_shared_with_trusted_users" {
  title       = "Compute disk IAM policy should only grant access to trusted users"
  description = "This control checks whether Compute disk IAM policy grants access to untrusted users."
  sql         = replace(replace(local.iam_policy_shared_users_sql, "__TABLE_NAME__", "gcp_compute_disk"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_disk_policy_shared_with_trusted_groups" {
  title       = "Compute disk IAM policy should only grant access to trusted groups"
  description = "This control checks whether Compute disk IAM policy grants access to untrusted groups."
  sql         = replace(replace(local.iam_policy_shared_groups_sql, "__TABLE_NAME__", "gcp_compute_disk"), "__RESOURCE_COLUMN__", "name")

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_disk_policy_shared_with_trusted_domains" {
  title       = "Compute disk IAM policy should only grant access to trusted domains"
  description = "This control checks whether Compute disk IAM policy grants access to untrusted domains."
  sql         = replace(replace(local.iam_policy_shared_domains_sql, "__TABLE_NAME__", "gcp_compute_disk"), "__RESOURCE_COLUMN__", "name")

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_disk_policy_shared_with_trusted_service_accounts" {
  title       = "Compute disk IAM policy should only grant access to trusted service accounts"
  description = "This control checks whether Compute disk IAM policy grants access to untrusted service accounts."
  sql         = replace(replace(local.iam_policy_shared_service_accounts_sql, "__TABLE_NAME__", "gcp_compute_disk"), "__RESOURCE_COLUMN__", "name")

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_image_policy_shared_with_trusted_users" {
  title       = "Compute image IAM policy should only grant access to trusted users"
  description = "This control checks whether Compute image IAM policy grants access to untrusted users."
  sql         = replace(replace(local.iam_policy_shared_users_sql, "__TABLE_NAME__", "gcp_compute_image"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_image_policy_shared_with_trusted_groups" {
  title       = "Compute image IAM policy should only grant access to trusted groups"
  description = "This control checks whether Compute image IAM policy grants access to untrusted groups."
  sql         = replace(replace(local.iam_policy_shared_groups_sql, "__TABLE_NAME__", "gcp_compute_image"), "__RESOURCE_COLUMN__", "name")

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_image_policy_shared_with_trusted_domains" {
  title       = "Compute image IAM policy should only grant access to trusted domains"
  description = "This control checks whether Compute image IAM policy grants access to untrusted domains."
  sql         = replace(replace(local.iam_policy_shared_domains_sql, "__TABLE_NAME__", "gcp_compute_image"), "__RESOURCE_COLUMN__", "name")

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_image_policy_shared_with_trusted_service_accounts" {
  title       = "Compute image IAM policy should only grant access to trusted service accounts"
  description = "This control checks whether Compute image IAM policy grants access to untrusted service accounts."
  sql         = replace(replace(local.iam_policy_shared_service_accounts_sql, "__TABLE_NAME__", "gcp_compute_image"), "__RESOURCE_COLUMN__", "name")

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_instance_policy_shared_with_trusted_users" {
  title       = "Compute instance IAM policy should only grant access to trusted users"
  description = "This control checks whether Compute Engine instance IAM policy grants access to untrusted users."
  sql         = replace(replace(local.iam_policy_shared_users_sql, "__TABLE_NAME__", "gcp_compute_instance"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_instance_policy_shared_with_trusted_groups" {
  title       = "Compute instance IAM policy should only grant access to trusted groups"
  description = "This control checks whether Compute Engine instance IAM policy grants access to untrusted groups."
  sql         = replace(replace(local.iam_policy_shared_groups_sql, "__TABLE_NAME__", "gcp_compute_instance"), "__RESOURCE_COLUMN__", "name")

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_instance_policy_shared_with_trusted_domains" {
  title       = "Compute instance IAM policy should only grant access to trusted domains"
  description = "This control checks whether Compute Engine instance IAM policy grants access to untrusted domains."
  sql         = replace(replace(local.iam_policy_shared_domains_sql, "__TABLE_NAME__", "gcp_compute_instance"), "__RESOURCE_COLUMN__", "name")

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_instance_policy_shared_with_trusted_service_accounts" {
  title       = "Compute instance IAM policy should only grant access to trusted service accounts"
  description = "This control checks whether Compute Engine instance IAM policy grants access to untrusted service accounts."
  sql         = replace(replace(local.iam_policy_shared_service_accounts_sql, "__TABLE_NAME__", "gcp_compute_instance"), "__RESOURCE_COLUMN__", "name")

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_node_group_policy_shared_with_trusted_users" {
  title       = "Compute node group IAM policy should only grant access to trusted users"
  description = "This control checks whether Compute node group IAM policy grants access to untrusted users."
  sql         = replace(replace(local.iam_policy_shared_users_sql, "__TABLE_NAME__", "gcp_compute_node_group"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_node_group_policy_shared_with_trusted_groups" {
  title       = "Compute node group IAM policy should only grant access to trusted groups"
  description = "This control checks whether Compute node group IAM policy grants access to untrusted groups."
  sql         = replace(replace(local.iam_policy_shared_groups_sql, "__TABLE_NAME__", "gcp_compute_node_group"), "__RESOURCE_COLUMN__", "name")

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_node_group_policy_shared_with_trusted_domains" {
  title       = "Compute node group IAM policy should only grant access to trusted domains"
  description = "This control checks whether Compute node group IAM policy grants access to untrusted domains."
  sql         = replace(replace(local.iam_policy_shared_domains_sql, "__TABLE_NAME__", "gcp_compute_node_group"), "__RESOURCE_COLUMN__", "name")

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_node_group_policy_shared_with_trusted_service_accounts" {
  title       = "Compute node group IAM policy should only grant access to trusted service accounts"
  description = "This control checks whether Compute node group IAM policy grants access to untrusted service accounts."
  sql         = replace(replace(local.iam_policy_shared_service_accounts_sql, "__TABLE_NAME__", "gcp_compute_node_group"), "__RESOURCE_COLUMN__", "name")

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_node_template_policy_shared_with_trusted_users" {
  title       = "Compute node template IAM policy should only grant access to trusted users"
  description = "This control checks whether Compute node template IAM policy grants access to untrusted users."
  sql         = replace(replace(local.iam_policy_shared_users_sql, "__TABLE_NAME__", "gcp_compute_node_template"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_node_template_policy_shared_with_trusted_groups" {
  title       = "Compute node template IAM policy should only grant access to trusted groups"
  description = "This control checks whether Compute node template IAM policy grants access to untrusted groups."
  sql         = replace(replace(local.iam_policy_shared_groups_sql, "__TABLE_NAME__", "gcp_compute_node_template"), "__RESOURCE_COLUMN__", "name")

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_node_template_policy_shared_with_trusted_domains" {
  title       = "Compute node template IAM policy should only grant access to trusted domains"
  description = "This control checks whether Compute node template IAM policy grants access to untrusted domains."
  sql         = replace(replace(local.iam_policy_shared_domains_sql, "__TABLE_NAME__", "gcp_compute_node_template"), "__RESOURCE_COLUMN__", "name")

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_node_template_policy_shared_with_trusted_service_accounts" {
  title       = "Compute node template IAM policy should only grant access to trusted service accounts"
  description = "This control checks whether Compute node template IAM policy grants access to untrusted service accounts."
  sql         = replace(replace(local.iam_policy_shared_service_accounts_sql, "__TABLE_NAME__", "gcp_compute_node_template"), "__RESOURCE_COLUMN__", "name")

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_resource_policy_shared_with_trusted_users" {
  title       = "Compute resource policy IAM policy should only grant access to trusted users"
  description = "This control checks whether Compute resource IAM policy grants access to untrusted users."
  sql         = replace(replace(local.iam_policy_shared_users_sql, "__TABLE_NAME__", "gcp_compute_resource_policy"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_resource_policy_shared_with_trusted_groups" {
  title       = "Compute resource policy IAM policy should only grant access to trusted groups"
  description = "This control checks whether Compute resource IAM policy grants access to untrusted groups."
  sql         = replace(replace(local.iam_policy_shared_groups_sql, "__TABLE_NAME__", "gcp_compute_resource_policy"), "__RESOURCE_COLUMN__", "name")

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_resource_policy_shared_with_trusted_domains" {
  title       = "Compute resource policy IAM policy should only grant access to trusted domains"
  description = "This control checks whether Compute resource IAM policy grants access to untrusted domains."
  sql         = replace(replace(local.iam_policy_shared_domains_sql, "__TABLE_NAME__", "gcp_compute_resource_policy"), "__RESOURCE_COLUMN__", "name")

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_resource_policy_shared_with_trusted_service_accounts" {
  title       = "Compute resource policy IAM policy should only grant access to trusted service accounts"
  description = "This control checks whether Compute resource IAM policy grants access to untrusted service accounts."
  sql         = replace(replace(local.iam_policy_shared_service_accounts_sql, "__TABLE_NAME__", "gcp_compute_resource_policy"), "__RESOURCE_COLUMN__", "name")

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_subnetwork_policy_shared_with_trusted_users" {
  title       = "Compute subnetwork IAM policy should only grant access to trusted users"
  description = "This control checks whether Compute subnetwork IAM policy grants access to untrusted users."
  sql         = replace(replace(local.iam_policy_shared_users_sql, "__TABLE_NAME__", "gcp_compute_subnetwork"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_subnetwork_policy_shared_with_trusted_groups" {
  title       = "Compute subnetwork IAM policy should only grant access to trusted groups"
  description = "This control checks whether Compute subnetwork IAM policy grants access to untrusted groups."
  sql         = replace(replace(local.iam_policy_shared_groups_sql, "__TABLE_NAME__", "gcp_compute_subnetwork"), "__RESOURCE_COLUMN__", "name")

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_subnetwork_policy_shared_with_trusted_domains" {
  title       = "Compute subnetwork IAM policy should only grant access to trusted domains"
  description = "This control checks whether Compute subnetwork IAM policy grants access to untrusted domains."
  sql         = replace(replace(local.iam_policy_shared_domains_sql, "__TABLE_NAME__", "gcp_compute_subnetwork"), "__RESOURCE_COLUMN__", "name")

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_subnetwork_policy_shared_with_trusted_service_accounts" {
  title       = "Compute subnetwork IAM policy should only grant access to trusted service accounts"
  description = "This control checks whether Compute subnetwork IAM policy grants access to untrusted service accounts."
  sql         = replace(replace(local.iam_policy_shared_service_accounts_sql, "__TABLE_NAME__", "gcp_compute_subnetwork"), "__RESOURCE_COLUMN__", "name")

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "cloud_run_job_policy_shared_with_trusted_users" {
  title       = "Cloud Run job IAM policy should only grant access to trusted users"
  description = "This control checks whether Cloud Run job IAM policy grants access to untrusted users."
  sql         = replace(replace(local.iam_policy_shared_users_sql, "__TABLE_NAME__", "gcp_cloud_run_job"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudRun"
  })
}

control "cloud_run_job_policy_shared_with_trusted_groups" {
  title       = "Cloud Run job IAM policy should only grant access to trusted groups"
  description = "This control checks whether Cloud Run job IAM policy grants access to untrusted groups."
  sql         = replace(replace(local.iam_policy_shared_groups_sql, "__TABLE_NAME__", "gcp_cloud_run_job"), "__RESOURCE_COLUMN__", "name")

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudRun"
  })
}

control "cloud_run_job_policy_shared_with_trusted_domains" {
  title       = "Cloud Run job IAM policy should only grant access to trusted domains"
  description = "This control checks whether Cloud Run job IAM policy grants access to untrusted domains."
  sql         = replace(replace(local.iam_policy_shared_domains_sql, "__TABLE_NAME__", "gcp_cloud_run_job"), "__RESOURCE_COLUMN__", "name")

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudRun"
  })
}

control "cloud_run_job_policy_shared_with_trusted_service_accounts" {
  title       = "Cloud Run job IAM policy should only grant access to trusted service accounts"
  description = "This control checks whether Cloud Run job IAM policy grants access to untrusted service accounts."
  sql         = replace(replace(local.iam_policy_shared_service_accounts_sql, "__TABLE_NAME__", "gcp_cloud_run_job"), "__RESOURCE_COLUMN__", "name")

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudRun"
  })
}

control "cloud_run_service_policy_shared_with_trusted_users" {
  title       = "Cloud Run service IAM policy should only grant access to trusted users"
  description = "This control checks whether Cloud Run service IAM policy grants access to untrusted users."
  sql         = replace(replace(local.iam_policy_shared_users_sql, "__TABLE_NAME__", "gcp_cloud_run_service"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudRun"
  })
}

control "cloud_run_service_policy_shared_with_trusted_groups" {
  title       = "Cloud Run service IAM policy should only grant access to trusted groups"
  description = "This control checks whether Cloud Run service IAM policy grants access to untrusted groups."
  sql         = replace(replace(local.iam_policy_shared_groups_sql, "__TABLE_NAME__", "gcp_cloud_run_service"), "__RESOURCE_COLUMN__", "name")

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudRun"
  })
}

control "cloud_run_service_policy_shared_with_trusted_domains" {
  title       = "Cloud Run service IAM policy should only grant access to trusted domains"
  description = "This control checks whether Cloud Run service IAM policy grants access to untrusted domains."
  sql         = replace(replace(local.iam_policy_shared_domains_sql, "__TABLE_NAME__", "gcp_cloud_run_service"), "__RESOURCE_COLUMN__", "name")

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudRun"
  })
}

control "cloud_run_service_policy_shared_with_trusted_service_accounts" {
  title       = "Cloud Run service IAM policy should only grant access to trusted service accounts"
  description = "This control checks whether Cloud Run service IAM policy grants access to untrusted service accounts."
  sql         = replace(replace(local.iam_policy_shared_service_accounts_sql, "__TABLE_NAME__", "gcp_cloud_run_service"), "__RESOURCE_COLUMN__", "name")

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudRun"
  })
}

control "cloud_function_policy_shared_with_trusted_users" {
  title       = "Cloud Function IAM policy should only grant access to trusted users"
  description = "This control checks whether Cloud Function IAM policy grants access to untrusted users."
  sql         = replace(replace(local.iam_policy_shared_users_sql, "__TABLE_NAME__", "gcp_cloudfunctions_function"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudFunctions"
  })
}

control "cloud_function_policy_shared_with_trusted_groups" {
  title       = "Cloud Function IAM policy should only grant access to trusted groups"
  description = "This control checks whether Cloud Function IAM policy grants access to untrusted groups."
  sql         = replace(replace(local.iam_policy_shared_groups_sql, "__TABLE_NAME__", "gcp_cloudfunctions_function"), "__RESOURCE_COLUMN__", "name")

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudFunctions"
  })
}

control "cloud_function_policy_shared_with_trusted_domains" {
  title       = "Cloud Function IAM policy should only grant access to trusted domains"
  description = "This control checks whether Cloud Function IAM policy grants access to untrusted domains."
  sql         = replace(replace(local.iam_policy_shared_domains_sql, "__TABLE_NAME__", "gcp_cloudfunctions_function"), "__RESOURCE_COLUMN__", "name")

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudFunctions"
  })
}

control "cloud_function_policy_shared_with_trusted_service_accounts" {
  title       = "Cloud Function IAM policy should only grant access to trusted service accounts"
  description = "This control checks whether Cloud Function IAM policy grants access to untrusted service accounts."
  sql         = replace(replace(local.iam_policy_shared_service_accounts_sql, "__TABLE_NAME__", "gcp_cloudfunctions_function"), "__RESOURCE_COLUMN__", "name")

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudFunctions"
  })
}

control "billing_account_policy_shared_with_trusted_users" {
  title       = "Billing account IAM policy should only grant access to trusted users"
  description = "This control checks whether billing account IAM policy grants access to untrusted users."
  sql         = replace(replace(local.iam_policy_shared_users_sql, "__TABLE_NAME__", "gcp_billing_account"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Billing"
  })
}

control "billing_account_policy_shared_with_trusted_groups" {
  title       = "Billing account IAM policy should only grant access to trusted groups"
  description = "This control checks whether billing account IAM policy grants access to untrusted groups."
  sql         = replace(replace(local.iam_policy_shared_groups_sql, "__TABLE_NAME__", "gcp_billing_account"), "__RESOURCE_COLUMN__", "name")

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Billing"
  })
}

control "billing_account_policy_shared_with_trusted_domains" {
  title       = "Billing account IAM policy should only grant access to trusted domains"
  description = "This control checks whether billing account IAM policy grants access to untrusted domains."
  sql         = replace(replace(local.iam_policy_shared_domains_sql, "__TABLE_NAME__", "gcp_billing_account"), "__RESOURCE_COLUMN__", "name")

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Billing"
  })
}

control "billing_account_policy_shared_with_trusted_service_accounts" {
  title       = "Billing account IAM policy should only grant access to trusted service accounts"
  description = "This control checks whether billing account IAM policy grants access to untrusted service accounts."
  sql         = replace(replace(local.iam_policy_shared_service_accounts_sql, "__TABLE_NAME__", "gcp_billing_account"), "__RESOURCE_COLUMN__", "name")

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Billing"
  })
}

control "bigtable_instance_policy_shared_with_trusted_users" {
  title       = "Bigtable instance IAM policy should only grant access to trusted users"
  description = "This control checks whether Bigtable instance IAM policy grants access to untrusted users."
  sql         = replace(replace(local.iam_policy_shared_users_sql, "__TABLE_NAME__", "gcp_bigtable_instance"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Bigtable"
  })
}

control "bigtable_instance_policy_shared_with_trusted_groups" {
  title       = "Bigtable instance IAM policy should only grant access to trusted groups"
  description = "This control checks whether Bigtable instance IAM policy grants access to untrusted groups."
  sql         = replace(replace(local.iam_policy_shared_groups_sql, "__TABLE_NAME__", "gcp_bigtable_instance"), "__RESOURCE_COLUMN__", "name")

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Bigtable"
  })
}

control "bigtable_instance_policy_shared_with_trusted_domains" {
  title       = "Bigtable instance IAM policy should only grant access to trusted domains"
  description = "This control checks whether Bigtable instance IAM policy grants access to untrusted domains."
  sql         = replace(replace(local.iam_policy_shared_domains_sql, "__TABLE_NAME__", "gcp_bigtable_instance"), "__RESOURCE_COLUMN__", "name")

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Bigtable"
  })
}

control "bigtable_instance_policy_shared_with_trusted_service_accounts" {
  title       = "Bigtable instance IAM policy should only grant access to trusted service accounts"
  description = "This control checks whether Bigtable instance IAM policy grants access to untrusted service accounts."
  sql         = replace(replace(local.iam_policy_shared_service_accounts_sql, "__TABLE_NAME__", "gcp_bigtable_instance"), "__RESOURCE_COLUMN__", "name")

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Bigtable"
  })
}

# KMS Key Controls
control "kms_key_policy_shared_with_trusted_users" {
  title       = "KMS key IAM policy should only grant access to trusted users"
  description = "This control checks whether Cloud KMS key IAM policy grants access to untrusted users."
  sql         = replace(replace(local.iam_policy_shared_users_sql, "__TABLE_NAME__", "gcp_kms_key"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/KMS"
  })
}

control "kms_key_policy_shared_with_trusted_groups" {
  title       = "KMS key IAM policy should only grant access to trusted groups"
  description = "This control checks whether Cloud KMS key IAM policy grants access to untrusted groups."
  sql         = replace(replace(local.iam_policy_shared_groups_sql, "__TABLE_NAME__", "gcp_kms_key"), "__RESOURCE_COLUMN__", "name")

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/KMS"
  })
}

control "kms_key_policy_shared_with_trusted_domains" {
  title       = "KMS key IAM policy should only grant access to trusted domains"
  description = "This control checks whether Cloud KMS key IAM policy grants access to untrusted domains."
  sql         = replace(replace(local.iam_policy_shared_domains_sql, "__TABLE_NAME__", "gcp_kms_key"), "__RESOURCE_COLUMN__", "name")

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/KMS"
  })
}

control "kms_key_policy_shared_with_trusted_service_accounts" {
  title       = "KMS key IAM policy should only grant access to trusted service accounts"
  description = "This control checks whether Cloud KMS key IAM policy grants access to untrusted service accounts."
  sql         = replace(replace(local.iam_policy_shared_service_accounts_sql, "__TABLE_NAME__", "gcp_kms_key"), "__RESOURCE_COLUMN__", "name")

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/KMS"
  })
}

# KMS Key Ring Controls
control "kms_key_ring_policy_shared_with_trusted_users" {
  title       = "KMS key ring IAM policy should only grant access to trusted users"
  description = "This control checks whether Cloud KMS key ring IAM policy grants access to untrusted users."
  sql         = replace(replace(local.iam_policy_shared_users_sql, "__TABLE_NAME__", "gcp_kms_key_ring"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/KMS"
  })
}

control "kms_key_ring_policy_shared_with_trusted_groups" {
  title       = "KMS key ring IAM policy should only grant access to trusted groups"
  description = "This control checks whether Cloud KMS key ring IAM policy grants access to untrusted groups."
  sql         = replace(replace(local.iam_policy_shared_groups_sql, "__TABLE_NAME__", "gcp_kms_key_ring"), "__RESOURCE_COLUMN__", "name")

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/KMS"
  })
}

control "kms_key_ring_policy_shared_with_trusted_domains" {
  title       = "KMS key ring IAM policy should only grant access to trusted domains"
  description = "This control checks whether Cloud KMS key ring IAM policy grants access to untrusted domains."
  sql         = replace(replace(local.iam_policy_shared_domains_sql, "__TABLE_NAME__", "gcp_kms_key_ring"), "__RESOURCE_COLUMN__", "name")

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/KMS"
  })
}

control "kms_key_ring_policy_shared_with_trusted_service_accounts" {
  title       = "KMS key ring IAM policy should only grant access to trusted service accounts"
  description = "This control checks whether Cloud KMS key ring IAM policy grants access to untrusted service accounts."
  sql         = replace(replace(local.iam_policy_shared_service_accounts_sql, "__TABLE_NAME__", "gcp_kms_key_ring"), "__RESOURCE_COLUMN__", "name")

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/KMS"
  })
}

# Pub/Sub Topic Controls
control "pubsub_topic_policy_shared_with_trusted_users" {
  title       = "Pub/Sub topic IAM policy should only grant access to trusted users"
  description = "This control checks whether Pub/Sub topic IAM policy grants access to untrusted users."
  sql         = replace(replace(local.iam_policy_shared_users_sql, "__TABLE_NAME__", "gcp_pubsub_topic"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/PubSub"
  })
}

control "pubsub_topic_policy_shared_with_trusted_groups" {
  title       = "Pub/Sub topic IAM policy should only grant access to trusted groups"
  description = "This control checks whether Pub/Sub topic IAM policy grants access to untrusted groups."
  sql         = replace(replace(local.iam_policy_shared_groups_sql, "__TABLE_NAME__", "gcp_pubsub_topic"), "__RESOURCE_COLUMN__", "name")

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/PubSub"
  })
}

control "pubsub_topic_policy_shared_with_trusted_domains" {
  title       = "Pub/Sub topic IAM policy should only grant access to trusted domains"
  description = "This control checks whether Pub/Sub topic IAM policy grants access to untrusted domains."
  sql         = replace(replace(local.iam_policy_shared_domains_sql, "__TABLE_NAME__", "gcp_pubsub_topic"), "__RESOURCE_COLUMN__", "name")

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/PubSub"
  })
}

control "pubsub_topic_policy_shared_with_trusted_service_accounts" {
  title       = "Pub/Sub topic IAM policy should only grant access to trusted service accounts"
  description = "This control checks whether Pub/Sub topic IAM policy grants access to untrusted service accounts."
  sql         = replace(replace(local.iam_policy_shared_service_accounts_sql, "__TABLE_NAME__", "gcp_pubsub_topic"), "__RESOURCE_COLUMN__", "name")

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/PubSub"
  })
}

# Pub/Sub Subscription Controls
control "pubsub_subscription_policy_shared_with_trusted_users" {
  title       = "Pub/Sub subscription IAM policy should only grant access to trusted users"
  description = "This control checks whether Pub/Sub subscription IAM policy grants access to untrusted users."
  sql         = replace(replace(local.iam_policy_shared_users_sql, "__TABLE_NAME__", "gcp_pubsub_subscription"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/PubSub"
  })
}

control "pubsub_subscription_policy_shared_with_trusted_groups" {
  title       = "Pub/Sub subscription IAM policy should only grant access to trusted groups"
  description = "This control checks whether Pub/Sub subscription IAM policy grants access to untrusted groups."
  sql         = replace(replace(local.iam_policy_shared_groups_sql, "__TABLE_NAME__", "gcp_pubsub_subscription"), "__RESOURCE_COLUMN__", "name")

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/PubSub"
  })
}

control "pubsub_subscription_policy_shared_with_trusted_domains" {
  title       = "Pub/Sub subscription IAM policy should only grant access to trusted domains"
  description = "This control checks whether Pub/Sub subscription IAM policy grants access to untrusted domains."
  sql         = replace(replace(local.iam_policy_shared_domains_sql, "__TABLE_NAME__", "gcp_pubsub_subscription"), "__RESOURCE_COLUMN__", "name")

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/PubSub"
  })
}

control "pubsub_subscription_policy_shared_with_trusted_service_accounts" {
  title       = "Pub/Sub subscription IAM policy should only grant access to trusted service accounts"
  description = "This control checks whether Pub/Sub subscription IAM policy grants access to untrusted service accounts."
  sql         = replace(replace(local.iam_policy_shared_service_accounts_sql, "__TABLE_NAME__", "gcp_pubsub_subscription"), "__RESOURCE_COLUMN__", "name")

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/PubSub"
  })
} 