benchmark "shared_access" {
  title         = "Shared Access"
  description   = "Resource sharing should be isolated to reduce the blast radius in case of a breach."
  documentation = file("./perimeter/docs/shared_access.md")
  children = [
    benchmark.trusted_access
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "trusted_access" {
  title         = "Trusted Access"
  description   = "Resource sharing configurations should be limited to trusted entities."
  documentation = file("./perimeter/docs/trusted_access.md")
  children = [
    control.cross_project_service_account_use,
    control.vpc_shared_outside_org,
    control.kms_key_shared_outside_org
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "cross_project_service_account_use" {
  title       = "Service accounts should not be shared across projects"
  description = "Service accounts should be managed within their own projects to maintain clear security boundaries."

  sql = <<-EOQ
    with service_account_bindings as (
      select
        p.project_id as project_id,
        sa.email as service_account_email,
        split_part(sa.email, '@', 2) as service_account_project_domain
      from
        gcp_project p,
        gcp_service_account sa
      where
        p.project_id != split_part(split_part(sa.email, '@', 2), '.iam.gserviceaccount.com', 1)
    )
    select
      service_account_email as resource,
      case
        when service_account_email is not null then 'alarm'
        else 'ok'
      end as status,
      case
        when service_account_email is not null then service_account_email || ' is used across projects.'
        else service_account_email || ' is used within its own project.'
      end as reason,
      project_id
      ${local.tag_dimensions_sql}
    from
      service_account_bindings;
  EOQ

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/IAM"
  })
}

control "vpc_shared_outside_org" {
  title       = "VPC networks should not be shared outside the organization"
  description = "VPC networks should only be shared with projects within the same organization."

  sql = <<-EOQ
    with shared_vpcs as (
      select
        n.self_link,
        n.name,
        p.project_id,
        xpn.name as shared_project_name,
        xpn.project_id as shared_project_id
      from
        gcp_compute_network n
        left join gcp_project p on n.project_id = p.project_id
        left join gcp_compute_shared_vpc_host_project host on p.project_id = host.project_id
        left join gcp_compute_shared_vpc_service_project xpn on host.project_id = xpn.host_project_id
      where
        xpn.project_id not in (select project_id from unnest($1::text[]) as project_id)
        and xpn.project_id is not null
    )
    select
      self_link as resource,
      case
        when shared_project_id is not null then 'alarm'
        else 'ok'
      end as status,
      case
        when shared_project_id is not null then name || ' is shared with untrusted project: ' || shared_project_id
        else name || ' is not shared with untrusted projects.'
      end as reason,
      project_id
      ${local.tag_dimensions_sql}
    from
      shared_vpcs;
  EOQ

  param "trusted_projects" {
    default = var.trusted_projects
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/Compute"
  })
}

control "kms_key_shared_outside_org" {
  title       = "KMS keys should not be shared outside the organization"
  description = "Cloud KMS keys should only be shared with trusted projects within the organization."

  sql = <<-EOQ
    with key_bindings as (
      select
        k.self_link,
        k.name,
        k.project_id,
        split_part(m.name, ':', 2) as bound_project_id
      from
        gcp_kms_key k,
        jsonb_array_elements(iam_policy -> 'bindings') as binding,
        jsonb_array_elements_text(binding -> 'members') as m
      where
        m.name like 'projectViewer:%'
        or m.name like 'projectEditor:%'
        or m.name like 'projectOwner:%'
    )
    select
      self_link as resource,
      case
        when bound_project_id not in (select p from unnest($1::text[]) as p) then 'alarm'
        else 'ok'
      end as status,
      case
        when bound_project_id not in (select p from unnest($1::text[]) as p) then name || ' is shared with untrusted project: ' || bound_project_id
        else name || ' is only shared with trusted projects.'
      end as reason,
      project_id
      ${local.tag_dimensions_sql}
    from
      key_bindings;
  EOQ

  param "trusted_projects" {
    default = var.trusted_projects
  }

  tags = merge(local.gcp_perimeter_common_tags, {
    service = "GCP/KMS"
  })
} 