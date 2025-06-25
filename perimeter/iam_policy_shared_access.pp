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
    control.bigtable_instance_policy_shared_with_trusted_principals,
    control.billing_account_policy_shared_with_trusted_principals,
    control.cloud_function_policy_shared_with_trusted_principals,
    control.cloud_run_job_policy_shared_with_trusted_principals,
    control.cloud_run_service_policy_shared_with_trusted_principals,
    control.compute_disk_policy_shared_with_trusted_principals,
    control.compute_image_policy_shared_with_trusted_principals,
    control.compute_instance_policy_shared_with_trusted_principals,
    control.compute_node_group_policy_shared_with_trusted_principals,
    control.compute_node_template_policy_shared_with_trusted_principals,
    control.compute_resource_policy_shared_with_trusted_principals,
    control.compute_subnetwork_policy_shared_with_trusted_principals,
    control.iam_service_account_policy_shared_with_trusted_principals,
    control.kms_key_policy_shared_with_trusted_principals,
    control.kms_key_ring_policy_shared_with_trusted_principals,
    control.pubsub_subscription_policy_shared_with_trusted_principals,
    control.pubsub_topic_policy_shared_with_trusted_principals,
    control.storage_bucket_policy_shared_with_trusted_principals
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
}

locals {
  # For resources with direct IAM policy access
  iam_policy_shared_sql = <<EOQ
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
            (member like 'serviceAccount:%' and split_part(member, 'serviceAccount:', 2) = any(($3)::text[]))
            or
            (member like 'domain:%' and split_part(member, 'domain:', 2) = any(($4)::text[]))
          )
        ) as trusted_members,
        -- Collect untrusted members for alarm messages
        array_agg(distinct member) filter (where 
          member not like 'project%' and not (
            (member like 'user:%' and split_part(member, 'user:', 2) = any(($1)::text[]))
            or
            (member like 'group:%' and split_part(member, 'group:', 2) = any(($2)::text[]))
            or
            (member like 'serviceAccount:%' and split_part(member, 'serviceAccount:', 2) = any(($3)::text[]))
            or
            (member like 'domain:%' and split_part(member, 'domain:', 2) = any(($4)::text[]))
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

control "iam_service_account_policy_shared_with_trusted_principals" {
  title       = "IAM service account IAM policies should only grant access to trusted principals"
  description = "This control checks whether service account IAM policies grant access to untrusted users, groups, service accounts, or domains."
  sql         = replace(replace(local.iam_policy_shared_sql, "__TABLE_NAME__", "gcp_service_account"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/IAM"
  })
}

control "storage_bucket_policy_shared_with_trusted_principals" {
  title       = "Storage bucket IAM policies should only grant access to trusted principals"
  description = "This control checks whether Cloud Storage bucket IAM policies and ACLs grant access to untrusted users, groups, service accounts, or domains."
  sql         = replace(replace(local.iam_policy_shared_sql, "__TABLE_NAME__", "gcp_storage_bucket"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Storage"
  })
}

control "bigtable_instance_policy_shared_with_trusted_principals" {
  title       = "Bigtable instance IAM policies should only grant access to trusted principals"
  description = "This control checks whether Bigtable instance IAM policies grant access to untrusted users, groups, service accounts, or domains."
  sql         = replace(replace(local.iam_policy_shared_sql, "__TABLE_NAME__", "gcp_bigtable_instance"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Bigtable"
  })
}

control "compute_instance_policy_shared_with_trusted_principals" {
  title       = "Compute instance IAM policies should only grant access to trusted principals"
  description = "This control checks whether Compute Engine instance IAM policies grant access to untrusted users, groups, service accounts, or domains."
  sql         = replace(replace(local.iam_policy_shared_sql, "__TABLE_NAME__", "gcp_compute_instance"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "pubsub_subscription_policy_shared_with_trusted_principals" {
  title       = "Pub/Sub subscription IAM policies should only grant access to trusted principals"
  description = "This control checks whether Pub/Sub subscription IAM policies grant access to untrusted users, groups, service accounts, or domains."
  sql         = replace(replace(local.iam_policy_shared_sql, "__TABLE_NAME__", "gcp_pubsub_subscription"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/PubSub"
  })
}

control "kms_key_policy_shared_with_trusted_principals" {
  title       = "KMS key IAM policies should only grant access to trusted principals"
  description = "This control checks whether Cloud KMS key IAM policies grant access to untrusted users, groups, service accounts, or domains."
  sql         = replace(replace(local.iam_policy_shared_sql, "__TABLE_NAME__", "gcp_kms_key"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/KMS"
  })
}

control "pubsub_topic_policy_shared_with_trusted_principals" {
  title       = "Pub/Sub topic IAM policies should only grant access to trusted principals"
  description = "This control checks whether Pub/Sub topic IAM policies grant access to untrusted users, groups, service accounts, or domains."
  sql         = replace(replace(local.iam_policy_shared_sql, "__TABLE_NAME__", "gcp_pubsub_topic"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/PubSub"
  })
}

control "cloud_run_service_policy_shared_with_trusted_principals" {
  title       = "Cloud Run service IAM policies should only grant access to trusted principals"
  description = "This control checks whether Cloud Run service IAM policies grant access to untrusted users, groups, service accounts, or domains."
  sql         = replace(replace(local.iam_policy_shared_sql, "__TABLE_NAME__", "gcp_cloud_run_service"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudRun"
  })
}

control "cloud_function_policy_shared_with_trusted_principals" {
  title       = "Cloud Function IAM policies should only grant access to trusted principals"
  description = "This control checks whether Cloud Function IAM policies grant access to untrusted users, groups, service accounts, or domains."
  sql         = replace(replace(local.iam_policy_shared_sql, "__TABLE_NAME__", "gcp_cloudfunctions_function"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudFunctions"
  })
}

control "billing_account_policy_shared_with_trusted_principals" {
  title       = "Billing account IAM policies should only grant access to trusted principals"
  description = "This control checks whether billing account IAM policies grant access to untrusted users, groups, service accounts, or domains."
  sql         = replace(replace(local.iam_policy_shared_sql, "__TABLE_NAME__", "gcp_billing_account"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Billing"
  })
}

control "compute_disk_policy_shared_with_trusted_principals" {
  title       = "Compute disk IAM policies should only grant access to trusted principals"
  description = "This control checks whether Compute disk IAM policies grant access to untrusted users, groups, service accounts, or domains."
  sql         = replace(replace(local.iam_policy_shared_sql, "__TABLE_NAME__", "gcp_compute_disk"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_image_policy_shared_with_trusted_principals" {
  title       = "Compute image IAM policies should only grant access to trusted principals"
  description = "This control checks whether Compute image IAM policies grant access to untrusted users, groups, service accounts, or domains."
  sql         = replace(replace(local.iam_policy_shared_sql, "__TABLE_NAME__", "gcp_compute_image"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_node_group_policy_shared_with_trusted_principals" {
  title       = "Compute node group IAM policies should only grant access to trusted principals"
  description = "This control checks whether Compute node group IAM policies grant access to untrusted users, groups, service accounts, or domains."
  sql         = replace(replace(local.iam_policy_shared_sql, "__TABLE_NAME__", "gcp_compute_node_group"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_node_template_policy_shared_with_trusted_principals" {
  title       = "Compute node template IAM policies should only grant access to trusted principals"
  description = "This control checks whether Compute node template IAM policies grant access to untrusted users, groups, service accounts, or domains."
  sql         = replace(replace(local.iam_policy_shared_sql, "__TABLE_NAME__", "gcp_compute_node_template"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_resource_policy_shared_with_trusted_principals" {
  title       = "Compute resource IAM policies should only grant access to trusted principals"
  description = "This control checks whether Compute resource IAM policies grant access to untrusted users, groups, service accounts, or domains."
  sql         = replace(replace(local.iam_policy_shared_sql, "__TABLE_NAME__", "gcp_compute_resource_policy"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "compute_subnetwork_policy_shared_with_trusted_principals" {
  title       = "Compute subnetwork IAM policies should only grant access to trusted principals"
  description = "This control checks whether Compute subnetwork IAM policies grant access to untrusted users, groups, service accounts, or domains."
  sql         = replace(replace(local.iam_policy_shared_sql, "__TABLE_NAME__", "gcp_compute_subnetwork"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "cloud_run_job_policy_shared_with_trusted_principals" {
  title       = "Cloud Run job IAM policies should only grant access to trusted principals"
  description = "This control checks whether Cloud Run job IAM policies grant access to untrusted users, groups, service accounts, or domains."
  sql         = replace(replace(local.iam_policy_shared_sql, "__TABLE_NAME__", "gcp_cloud_run_job"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/CloudRun"
  })
}

control "kms_key_ring_policy_shared_with_trusted_principals" {
  title       = "KMS key ring IAM policies should only grant access to trusted principals"
  description = "This control checks whether Cloud KMS key ring IAM policies grant access to untrusted users, groups, service accounts, or domains."
  sql         = replace(replace(local.iam_policy_shared_sql, "__TABLE_NAME__", "gcp_kms_key_ring"), "__RESOURCE_COLUMN__", "name")

  param "trusted_users" {
    description = "A list of trusted Google Account emails."
    default     = var.trusted_users
  }

  param "trusted_groups" {
    description = "A list of trusted Google Groups."
    default     = var.trusted_groups
  }

  param "trusted_service_accounts" {
    description = "A list of trusted service accounts."
    default     = var.trusted_service_accounts
  }

  param "trusted_domains" {
    description = "A list of trusted Google Workspace domains."
    default     = var.trusted_domains
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/KMS"
  })
} 