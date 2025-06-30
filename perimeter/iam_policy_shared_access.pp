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
    control.compute_disk_policy_shared_access,
    control.compute_image_policy_shared_access,
    control.compute_instance_policy_shared_access,
    control.compute_node_group_policy_shared_access,
    control.compute_node_template_policy_shared_access,
    control.compute_resource_policy_shared_access,
    control.compute_subnetwork_policy_shared_access
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
    control.storage_bucket_policy_shared_access
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
    control.iam_service_account_policy_shared_access
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
    control.kms_key_policy_shared_access,
    control.kms_key_ring_policy_shared_access
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
    control.pubsub_subscription_policy_shared_access,
    control.pubsub_topic_policy_shared_access
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
    control.cloud_run_job_policy_shared_access,
    control.cloud_run_service_policy_shared_access
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
    control.cloud_function_policy_shared_access
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
    control.bigtable_instance_policy_shared_access
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
    control.billing_account_policy_shared_access
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type    = "Benchmark"
    service = "GCP/Billing"
  })
}

locals {
  # Consolidated SQL for checking all principal types in one query
  iam_policy_shared_access_sql = <<EOQ
    with policy_analysis as (
      select
        __RESOURCE_COLUMN__ as resource_id,
        -- Count all members
        count(*) as total_members,
        -- Count project-level members
        count(*) filter (where member like 'project%') as project_members,
        -- Count trusted members (excluding project-level)
        count(*) filter (where 
          member not like 'project%' and (
            (member like 'user:%' and split_part(member, 'user:', 2) = any(($1)::text[]))
            or
            (member like 'group:%' and split_part(member, 'group:', 2) = any(($2)::text[]))
            or
            (member like 'domain:%' and split_part(member, 'domain:', 2) = any(($3)::text[]))
            or
            (member like 'serviceAccount:%' and split_part(member, 'serviceAccount:', 2) = any(($4)::text[]))
          )
        ) as trusted_members,
        -- Collect untrusted members for alarm messages
        array_agg(distinct member) filter (where 
          member not like 'project%' and not (
          (member like 'user:%' and split_part(member, 'user:', 2) = any(($1)::text[]))
            or
            (member like 'group:%' and split_part(member, 'group:', 2) = any(($2)::text[]))
            or
            (member like 'domain:%' and split_part(member, 'domain:', 2) = any(($3)::text[]))
            or
            (member like 'serviceAccount:%' and split_part(member, 'serviceAccount:', 2) = any(($4)::text[]))
          )
        ) as untrusted_members
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
        -- SKIP: When no members exist
        when (r.iam_policy -> 'bindings') is null or jsonb_array_length(r.iam_policy -> 'bindings') = 0 then 'skip'
        -- INFO: When only project-level roles are assigned
        when p.total_members = p.project_members then 'info'
        -- OK: When all non-project members are trusted
        when p.untrusted_members is null and (p.trusted_members > 0 or p.project_members > 0) then 'ok'
        -- ALARM: When there are untrusted members
        else 'alarm'
      end as status,
      case
        when (r.iam_policy -> 'bindings') is null or jsonb_array_length(r.iam_policy -> 'bindings') = 0 then title || ' has no IAM policy members.'
        when p.total_members = p.project_members then title || ' only has project-level role assignments (' || p.project_members || ' members).'
        when p.untrusted_members is null and (p.trusted_members > 0 or p.project_members > 0) then title || ' policy only grants access to trusted principals (' || coalesce(p.trusted_members, 0) || ' trusted + ' || coalesce(p.project_members, 0) || ' project-level).'
        else title || ' policy contains ' || coalesce(array_length(p.untrusted_members, 1), 0) || ' untrusted member(s): ' || array_to_string(p.untrusted_members, ', ')
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

# IAM Service Account Control
control "iam_service_account_policy_shared_access" {
  title       = "IAM service account IAM policies should only grant access to trusted principals"
  description = "This control checks whether service account IAM policies grant access to untrusted users, groups, domains, or service accounts."
  sql         = replace(replace(local.iam_policy_shared_access_sql, "__TABLE_NAME__", "gcp_service_account"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/IAM"
  })
}

# Storage Bucket Control
control "storage_bucket_policy_shared_access" {
  title       = "Storage bucket IAM policies should only grant access to trusted principals"
  description = "This control checks whether Cloud Storage bucket IAM policies grant access to untrusted users, groups, domains, or service accounts."
  sql         = replace(replace(local.iam_policy_shared_access_sql, "__TABLE_NAME__", "gcp_storage_bucket"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Storage"
  })
}

# Compute Controls
control "compute_disk_policy_shared_access" {
  title       = "Compute disk IAM policies should only grant access to trusted principals"
  description = "This control checks whether Compute disk IAM policies grant access to untrusted users, groups, domains, or service accounts."
  sql         = replace(replace(local.iam_policy_shared_access_sql, "__TABLE_NAME__", "gcp_compute_disk"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_image_policy_shared_access" {
  title       = "Compute image IAM policies should only grant access to trusted principals"
  description = "This control checks whether Compute image IAM policies grant access to untrusted users, groups, domains, or service accounts."
  sql         = replace(replace(local.iam_policy_shared_access_sql, "__TABLE_NAME__", "gcp_compute_image"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_instance_policy_shared_access" {
  title       = "Compute instance IAM policies should only grant access to trusted principals"
  description = "This control checks whether Compute Engine instance IAM policies grant access to untrusted users, groups, domains, or service accounts."
  sql         = replace(replace(local.iam_policy_shared_access_sql, "__TABLE_NAME__", "gcp_compute_instance"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_node_group_policy_shared_access" {
  title       = "Compute node group IAM policies should only grant access to trusted principals"
  description = "This control checks whether Compute node group IAM policies grant access to untrusted users, groups, domains, or service accounts."
  sql         = replace(replace(local.iam_policy_shared_access_sql, "__TABLE_NAME__", "gcp_compute_node_group"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_node_template_policy_shared_access" {
  title       = "Compute node template IAM policies should only grant access to trusted principals"
  description = "This control checks whether Compute node template IAM policies grant access to untrusted users, groups, domains, or service accounts."
  sql         = replace(replace(local.iam_policy_shared_access_sql, "__TABLE_NAME__", "gcp_compute_node_template"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_resource_policy_shared_access" {
  title       = "Compute resource policy IAM policies should only grant access to trusted principals"
  description = "This control checks whether Compute resource IAM policies grant access to untrusted users, groups, domains, or service accounts."
  sql         = replace(replace(local.iam_policy_shared_access_sql, "__TABLE_NAME__", "gcp_compute_resource_policy"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_subnetwork_policy_shared_access" {
  title       = "Compute subnetwork IAM policies should only grant access to trusted principals"
  description = "This control checks whether Compute subnetwork IAM policies grant access to untrusted users, groups, domains, or service accounts."
  sql         = replace(replace(local.iam_policy_shared_access_sql, "__TABLE_NAME__", "gcp_compute_subnetwork"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

# Cloud Run Controls
control "cloud_run_job_policy_shared_access" {
  title       = "Cloud Run job IAM policies should only grant access to trusted principals"
  description = "This control checks whether Cloud Run job IAM policies grant access to untrusted users, groups, domains, or service accounts."
  sql         = replace(replace(local.iam_policy_shared_access_sql, "__TABLE_NAME__", "gcp_cloud_run_job"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudRun"
  })
}

control "cloud_run_service_policy_shared_access" {
  title       = "Cloud Run service IAM policies should only grant access to trusted principals"
  description = "This control checks whether Cloud Run service IAM policies grant access to untrusted users, groups, domains, or service accounts."
  sql         = replace(replace(local.iam_policy_shared_access_sql, "__TABLE_NAME__", "gcp_cloud_run_service"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudRun"
  })
}

# Cloud Function Control
control "cloud_function_policy_shared_access" {
  title       = "Cloud Function IAM policies should only grant access to trusted principals"
  description = "This control checks whether Cloud Function IAM policies grant access to untrusted users, groups, domains, or service accounts."
  sql         = replace(replace(local.iam_policy_shared_access_sql, "__TABLE_NAME__", "gcp_cloudfunctions_function"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudFunctions"
  })
}

# Billing Control
control "billing_account_policy_shared_access" {
  title       = "Billing account IAM policies should only grant access to trusted principals"
  description = "This control checks whether billing account IAM policies grant access to untrusted users, groups, domains, or service accounts."
  sql         = replace(replace(local.iam_policy_shared_access_sql, "__TABLE_NAME__", "gcp_billing_account"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Billing"
  })
}

# Bigtable Control
control "bigtable_instance_policy_shared_access" {
  title       = "Bigtable instance IAM policies should only grant access to trusted principals"
  description = "This control checks whether Bigtable instance IAM policies grant access to untrusted users, groups, domains, or service accounts."
  sql         = replace(replace(local.iam_policy_shared_access_sql, "__TABLE_NAME__", "gcp_bigtable_instance"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Bigtable"
  })
}

# KMS Controls
control "kms_key_policy_shared_access" {
  title       = "KMS key IAM policies should only grant access to trusted principals"
  description = "This control checks whether Cloud KMS key IAM policies grant access to untrusted users, groups, domains, or service accounts."
  sql         = replace(replace(local.iam_policy_shared_access_sql, "__TABLE_NAME__", "gcp_kms_key"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/KMS"
  })
}

control "kms_key_ring_policy_shared_access" {
  title       = "KMS key ring IAM policies should only grant access to trusted principals"
  description = "This control checks whether Cloud KMS key ring IAM policies grant access to untrusted users, groups, domains, or service accounts."
  sql         = replace(replace(local.iam_policy_shared_access_sql, "__TABLE_NAME__", "gcp_kms_key_ring"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/KMS"
  })
}

# Pub/Sub Controls
control "pubsub_topic_policy_shared_access" {
  title       = "Pub/Sub topic IAM policies should only grant access to trusted principals"
  description = "This control checks whether Pub/Sub topic IAM policies grant access to untrusted users, groups, domains, or service accounts."
  sql         = replace(replace(local.iam_policy_shared_access_sql, "__TABLE_NAME__", "gcp_pubsub_topic"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/PubSub"
  })
}

control "pubsub_subscription_policy_shared_access" {
  title       = "Pub/Sub subscription IAM policies should only grant access to trusted principals"
  description = "This control checks whether Pub/Sub subscription IAM policies grant access to untrusted users, groups, domains, or service accounts."
  sql         = replace(replace(local.iam_policy_shared_access_sql, "__TABLE_NAME__", "gcp_pubsub_subscription"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/PubSub"
  })
} 