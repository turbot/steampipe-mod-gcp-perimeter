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
    # Identity & Access
    control.iam_policy_shared_service_account,
    control.iam_policy_shared_billing_account,
    # Storage & Databases
    control.iam_policy_shared_storage_bucket,
    control.iam_policy_shared_bigtable_instance,
    # Compute & Serverless
    control.iam_policy_shared_compute_instance,
    control.iam_policy_shared_compute_disk,
    control.iam_policy_shared_compute_image,
    control.iam_policy_shared_compute_node_group,
    control.iam_policy_shared_compute_node_template,
    control.iam_policy_shared_compute_resource_policy,
    control.iam_policy_shared_compute_subnetwork,
    control.iam_policy_shared_cloud_function,
    control.iam_policy_shared_cloud_run,
    control.iam_policy_shared_cloud_run_job,
    # Messaging & Integration
    control.iam_policy_shared_pubsub_topic,
    control.iam_policy_shared_pubsub_subscription,
    # Security & Encryption
    control.iam_policy_shared_kms_key,
    control.iam_policy_shared_kms_key_ring
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
}

locals {
  # For resources with direct IAM policy access
  iam_policy_shared_sql = <<EOQ
    with untrusted_bindings as (
      select
        __RESOURCE_COLUMN__ as resource_id,
        array_agg(distinct member) as untrusted_members,
        count(*) as untrusted_bindings_num
      from
        __TABLE_NAME__,
        jsonb_array_elements(iam_policy -> 'bindings') as binding,
        jsonb_array_elements_text(binding -> 'members') as member
      where
        (
          (member like 'user:%' and 
          split_part(member, 'user:', 2) != any(($1)::text[]))
          or
          (member like 'group:%' and 
          split_part(member, 'group:', 2) != any(($2)::text[]))
          or
          (member like 'serviceAccount:%' and 
          split_part(member, 'serviceAccount:', 2) != any(($3)::text[]))
          or
          (member like 'domain:%' and 
          split_part(member, 'domain:', 2) != any(($4)::text[]))
        )
        -- Exclude project-level roles which are managed separately
        and member not like 'project%'
      group by
        __RESOURCE_COLUMN__
    )
    select
      r.__RESOURCE_COLUMN__ as resource,
      case
        when r.iam_policy is null then 'info'
        when u.resource_id is null then 'ok'
        else 'alarm'
      end as status,
      case
        when r.iam_policy is null then title || ' does not have a defined IAM policy.'
        when u.resource_id is null then title || ' policy only grants access to trusted principals.'
        else title || ' policy contains ' || coalesce(u.untrusted_bindings_num, 0) ||
        ' binding(s) with untrusted principals: ' || array_to_string(u.untrusted_members, ', ')
      end as reason,
      r.project,
      r.location
    from
      __TABLE_NAME__ as r
      left join untrusted_bindings as u on u.resource_id = r.__RESOURCE_COLUMN__
    where
      -- Only check resources where we have access to IAM policy
      r.iam_policy is not null;
  EOQ

  # For storage buckets that use ACLs
  storage_bucket_shared_sql = <<EOQ
    with bucket_acls as (
      select
        name as resource_id,
        jsonb_array_elements(acl) as acl_entry
      from
        gcp_storage_bucket
    ),
    untrusted_access as (
      select
        resource_id,
        array_agg(distinct acl_entry ->> 'entity') as untrusted_entities,
        count(*) as untrusted_access_count
      from
        bucket_acls
      where
        acl_entry ->> 'entity' not like 'project-%'
        and acl_entry ->> 'entity' not in ('private', 'projectPrivate')
        and (
          (acl_entry ->> 'entity' like 'user-%' and 
          split_part(acl_entry ->> 'entity', 'user-', 2) != any(($1)::text[]))
          or
          (acl_entry ->> 'entity' like 'group-%' and 
          split_part(acl_entry ->> 'entity', 'group-', 2) != any(($2)::text[]))
          or
          (acl_entry ->> 'entity' like 'serviceAccount-%' and 
          split_part(acl_entry ->> 'entity', 'serviceAccount-', 2) != any(($3)::text[]))
          or
          (acl_entry ->> 'entity' like 'domain-%' and 
          split_part(acl_entry ->> 'entity', 'domain-', 2) != any(($4)::text[]))
        )
      group by
        resource_id
    )
    select
      b.name as resource,
      case
        when b.acl is null then 'info'
        when u.resource_id is null then 'ok'
        else 'alarm'
      end as status,
      case
        when b.acl is null then title || ' does not have defined ACLs.'
        when u.resource_id is null then title || ' only grants access to trusted principals.'
        else title || ' grants access to ' || coalesce(u.untrusted_access_count, 0) ||
        ' untrusted entities: ' || array_to_string(u.untrusted_entities, ', ')
      end as reason,
      b.project,
      b.location
    from
      gcp_storage_bucket as b
      left join untrusted_access as u on u.resource_id = b.name;
  EOQ
}

control "iam_policy_shared_service_account" {
  title       = "Service account IAM policies should only grant access to trusted principals"
  description = "Check if service account IAM policies grant access to untrusted users, groups, service accounts, or domains."
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

control "iam_policy_shared_storage_bucket" {
  title       = "Storage bucket IAM policies should only grant access to trusted principals"
  description = "Check if Cloud Storage bucket IAM policies and ACLs grant access to untrusted users, groups, service accounts, or domains."
  sql         = local.storage_bucket_shared_sql

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

control "iam_policy_shared_bigtable_instance" {
  title       = "Bigtable instance IAM policies should only grant access to trusted principals"
  description = "Check if Bigtable instance IAM policies grant access to untrusted users, groups, service accounts, or domains."
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

control "iam_policy_shared_compute_instance" {
  title       = "Compute instance IAM policies should only grant access to trusted principals"
  description = "Check if Compute Engine instance IAM policies grant access to untrusted users, groups, service accounts, or domains."
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

control "iam_policy_shared_pubsub_subscription" {
  title       = "Pub/Sub subscription IAM policies should only grant access to trusted principals"
  description = "Check if Pub/Sub subscription IAM policies grant access to untrusted users, groups, service accounts, or domains."
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

control "iam_policy_shared_kms_key" {
  title       = "KMS key IAM policies should only grant access to trusted principals"
  description = "Check if Cloud KMS key IAM policies grant access to untrusted users, groups, service accounts, or domains."
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

control "iam_policy_shared_pubsub_topic" {
  title       = "Pub/Sub topic IAM policies should only grant access to trusted principals"
  description = "Check if Pub/Sub topic IAM policies grant access to untrusted users, groups, service accounts, or domains."
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

control "iam_policy_shared_cloud_run" {
  title       = "Cloud Run service IAM policies should only grant access to trusted principals"
  description = "Check if Cloud Run service IAM policies grant access to untrusted users, groups, service accounts, or domains."
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

control "iam_policy_shared_cloud_function" {
  title       = "Cloud Function IAM policies should only grant access to trusted principals"
  description = "Check if Cloud Function IAM policies grant access to untrusted users, groups, service accounts, or domains."
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

control "iam_policy_shared_billing_account" {
  title       = "Billing account IAM policies should only grant access to trusted principals"
  description = "Check if billing account IAM policies grant access to untrusted users, groups, service accounts, or domains."
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

control "iam_policy_shared_compute_disk" {
  title       = "Compute disk IAM policies should only grant access to trusted principals"
  description = "Check if Compute disk IAM policies grant access to untrusted users, groups, service accounts, or domains."
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

control "iam_policy_shared_compute_image" {
  title       = "Compute image IAM policies should only grant access to trusted principals"
  description = "Check if Compute image IAM policies grant access to untrusted users, groups, service accounts, or domains."
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

control "iam_policy_shared_compute_node_group" {
  title       = "Compute node group IAM policies should only grant access to trusted principals"
  description = "Check if Compute node group IAM policies grant access to untrusted users, groups, service accounts, or domains."
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

control "iam_policy_shared_compute_node_template" {
  title       = "Compute node template IAM policies should only grant access to trusted principals"
  description = "Check if Compute node template IAM policies grant access to untrusted users, groups, service accounts, or domains."
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

control "iam_policy_shared_compute_resource_policy" {
  title       = "Compute resource IAM policies should only grant access to trusted principals"
  description = "Check if Compute resource IAM policies grant access to untrusted users, groups, service accounts, or domains."
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

control "iam_policy_shared_compute_subnetwork" {
  title       = "Compute subnetwork IAM policies should only grant access to trusted principals"
  description = "Check if Compute subnetwork IAM policies grant access to untrusted users, groups, service accounts, or domains."
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

control "iam_policy_shared_cloud_run_job" {
  title       = "Cloud Run job IAM policies should only grant access to trusted principals"
  description = "Check if Cloud Run job IAM policies grant access to untrusted users, groups, service accounts, or domains."
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

control "iam_policy_shared_kms_key_ring" {
  title       = "KMS key ring IAM policies should only grant access to trusted principals"
  description = "Check if Cloud KMS key ring IAM policies grant access to untrusted users, groups, service accounts, or domains."
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